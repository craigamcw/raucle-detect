"""Lightweight FastAPI server for Raucle Detect REST API.

Start via the CLI::

    raucle-detect serve --port 8000

Or directly with uvicorn::

    uvicorn raucle_detect.server:app --host 0.0.0.0 --port 8000

Authentication
--------------
Set the ``RAUCLE_DETECT_API_KEY`` environment variable to require callers to
pass ``Authorization: Bearer <key>`` on every request.  If the variable is
unset the server runs unauthenticated (suitable for localhost-only use).

Rate limiting
-------------
Set ``RAUCLE_DETECT_RATE_LIMIT`` (requests per minute per IP, default 120) and
``RAUCLE_DETECT_BURST_LIMIT`` (burst allowance, default 20) to tune limits.

Endpoints
---------
POST /scan          Scan a single prompt
POST /scan/batch    Scan multiple prompts
POST /scan/output   Scan LLM output
POST /scan/tool     Scan tool call arguments
GET  /rules         List loaded detection rules
GET  /health        Health check
GET  /metrics       Prometheus-compatible counters (plain text)
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from collections import defaultdict
from typing import Any

from raucle_detect import __version__
from raucle_detect.scanner import Scanner, ScanResult

try:
    from fastapi import FastAPI, HTTPException, Request  # type: ignore[import-untyped]
    from fastapi.responses import PlainTextResponse  # type: ignore[import-untyped]
    from pydantic import BaseModel, Field  # type: ignore[import-untyped]
except ImportError as exc:
    raise ImportError(
        "FastAPI and Pydantic are required for the server.\n"
        "Install them with:  pip install raucle-detect[server]"
    ) from exc


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

_mode = os.environ.get("RAUCLE_DETECT_MODE", "standard")
_rules_dir = os.environ.get("RAUCLE_DETECT_RULES_DIR")
_api_key = os.environ.get("RAUCLE_DETECT_API_KEY", "")  # empty = no auth
_rate_limit_rpm = int(os.environ.get("RAUCLE_DETECT_RATE_LIMIT", "120"))
_burst_limit = int(os.environ.get("RAUCLE_DETECT_BURST_LIMIT", "20"))

_scanner = Scanner(mode=_mode, rules_dir=_rules_dir)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Prompt text to scan")
    context: dict[str, Any] | None = Field(default=None, description="Optional context metadata")
    mode: str | None = Field(default=None, description="Override scanner mode for this request")


class BatchScanRequest(BaseModel):
    prompts: list[str] = Field(..., min_length=1, description="List of prompts to scan")
    mode: str | None = Field(default=None, description="Override scanner mode")
    workers: int = Field(default=4, ge=1, le=32, description="Concurrency level")


class OutputScanRequest(BaseModel):
    output: str = Field(..., min_length=1, description="LLM output text to scan")
    original_prompt: str | None = Field(
        default=None, description="Original user prompt for context"
    )
    mode: str | None = Field(default=None, description="Override scanner mode")


class ToolCallScanRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool call arguments")
    mode: str | None = Field(default=None, description="Override scanner mode")


class ScanResponse(BaseModel):
    verdict: str
    confidence: float
    injection_detected: bool
    categories: list[str]
    attack_technique: str
    layer_scores: dict[str, float]
    matched_rules: list[str]
    action: str
    scan_time_ms: float


class BatchScanResponse(BaseModel):
    results: list[ScanResponse]
    total: int
    scan_time_ms: float


class HealthResponse(BaseModel):
    status: str
    version: str
    mode: str
    rules_loaded: int
    auth_enabled: bool


# ---------------------------------------------------------------------------
# Prometheus-style metrics counters
# ---------------------------------------------------------------------------

_metrics_lock = threading.Lock()
_counters: dict[str, int] = defaultdict(int)
_histograms: dict[str, list[float]] = defaultdict(list)
_MAX_HISTOGRAM_SAMPLES = 1000  # cap per-endpoint to avoid unbounded growth


def _record(endpoint: str, verdict: str, elapsed_ms: float) -> None:
    with _metrics_lock:
        _counters["raucle_requests_total"] += 1
        _counters[f"raucle_requests_total{{endpoint=\"{endpoint}\"}}"] += 1
        _counters[f"raucle_verdict_total{{verdict=\"{verdict}\"}}"] += 1
        bucket = _histograms[f"raucle_scan_duration_ms{{endpoint=\"{endpoint}\"}}"]
        if len(bucket) < _MAX_HISTOGRAM_SAMPLES:
            bucket.append(elapsed_ms)


def _metrics_text() -> str:
    lines: list[str] = [
        "# HELP raucle_requests_total Total number of scan requests",
        "# TYPE raucle_requests_total counter",
    ]
    with _metrics_lock:
        for key, val in sorted(_counters.items()):
            lines.append(f"{key} {val}")

        lines += [
            "",
            "# HELP raucle_scan_duration_ms Scan latency in milliseconds",
            "# TYPE raucle_scan_duration_ms summary",
        ]
        for key, samples in sorted(_histograms.items()):
            if samples:
                avg = sum(samples) / len(samples)
                p99 = sorted(samples)[int(len(samples) * 0.99)]
                lines.append(f'{key},quantile="avg"}} {avg:.2f}')
                lines.append(f'{key},quantile="0.99"}} {p99:.2f}')
                lines.append(f'{key}_count}} {len(samples)}')

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket per client IP)
# ---------------------------------------------------------------------------

class _TokenBucket:
    """Simple per-IP token bucket for rate limiting."""

    __slots__ = ("tokens", "last_refill")

    def __init__(self, capacity: float) -> None:
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, capacity: float, refill_rate: float) -> bool:
        """Return True if the request is allowed (token consumed), False if rate-limited."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(capacity, self.tokens + elapsed * refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


_rate_buckets: dict[str, _TokenBucket] = {}
_rate_buckets_lock = threading.Lock()
_RATE_CAPACITY = float(_burst_limit)
_RATE_REFILL = _rate_limit_rpm / 60.0  # tokens per second


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if request is within rate limit, False if it should be rejected."""
    if _rate_limit_rpm <= 0:
        return True
    with _rate_buckets_lock:
        if client_ip not in _rate_buckets:
            _rate_buckets[client_ip] = _TokenBucket(_RATE_CAPACITY)
        return _rate_buckets[client_ip].consume(_RATE_CAPACITY, _RATE_REFILL)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Raucle Detect",
    description="Prompt injection detection API",
    version=__version__,
)


# ---------------------------------------------------------------------------
# Middleware: auth + rate limiting
# ---------------------------------------------------------------------------

@app.middleware("http")
async def _auth_and_rate_limit(request: Request, call_next):  # type: ignore[no-untyped-def]
    # Skip auth + rate limiting for health and metrics (allow monitoring without creds)
    if request.url.path in ("/health", "/metrics"):
        return await call_next(request)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        from fastapi.responses import JSONResponse

        _counters["raucle_rate_limited_total"] += 1
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Slow down and retry."},
            headers={"Retry-After": "60"},
        )

    # API key authentication
    if _api_key:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            from fastapi.responses import JSONResponse

            _counters["raucle_auth_failures_total"] += 1
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing Authorization header. Use: Bearer <api-key>"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        provided_key = auth_header[len("Bearer "):]
        if not secrets.compare_digest(provided_key.encode(), _api_key.encode()):
            from fastapi.responses import JSONResponse

            _counters["raucle_auth_failures_total"] += 1
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key."},
            )

    return await call_next(request)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/scan", response_model=ScanResponse)
def scan_prompt(req: ScanRequest) -> ScanResponse:
    """Scan a single prompt for injection attacks."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan(req.prompt, context=req.context, mode=req.mode)
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan", result.verdict, elapsed_ms)
    return ScanResponse(**result.to_dict(), scan_time_ms=round(elapsed_ms, 2))


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(req: BatchScanRequest) -> BatchScanResponse:
    """Scan multiple prompts concurrently."""
    if len(req.prompts) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 prompts per batch")

    start = time.perf_counter()
    results = _scanner.scan_batch(req.prompts, workers=req.workers, mode=req.mode)
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan/batch", "BATCH", elapsed_ms)

    return BatchScanResponse(
        results=[ScanResponse(**r.to_dict(), scan_time_ms=0) for r in results],
        total=len(results),
        scan_time_ms=round(elapsed_ms, 2),
    )


@app.post("/scan/output", response_model=ScanResponse)
def scan_output(req: OutputScanRequest) -> ScanResponse:
    """Scan LLM output for data leakage, injection, and exfiltration."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan_output(
        req.output,
        original_prompt=req.original_prompt,
        mode=req.mode,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan/output", result.verdict, elapsed_ms)
    return ScanResponse(**result.to_dict(), scan_time_ms=round(elapsed_ms, 2))


@app.post("/scan/tool", response_model=ScanResponse)
def scan_tool_call(req: ToolCallScanRequest) -> ScanResponse:
    """Scan tool call arguments for dangerous patterns."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan_tool_call(
        req.tool_name,
        req.arguments,
        mode=req.mode,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan/tool", result.verdict, elapsed_ms)
    return ScanResponse(**result.to_dict(), scan_time_ms=round(elapsed_ms, 2))


@app.get("/rules")
def list_rules() -> list[dict[str, Any]]:
    """List all loaded detection rules."""
    return _scanner.list_rules()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Health check."""
    return HealthResponse(
        status="ok",
        version=__version__,
        mode=_scanner.mode,
        rules_loaded=len(_scanner.list_rules()),
        auth_enabled=bool(_api_key),
    )


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    """Prometheus-compatible plain-text metrics."""
    return _metrics_text()
