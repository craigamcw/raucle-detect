"""Lightweight FastAPI server for PromptGuard REST API.

Start via the CLI::

    promptguard serve --port 8000

Or directly with uvicorn::

    uvicorn promptguard.server:app --host 0.0.0.0 --port 8000

Endpoints
---------
POST /scan          Scan a single prompt
POST /scan/batch    Scan multiple prompts
GET  /rules         List loaded detection rules
GET  /health        Health check
"""

from __future__ import annotations

import os
import time
from typing import Any

from promptguard import __version__
from promptguard.scanner import Scanner, ScanResult

try:
    from fastapi import FastAPI, HTTPException  # type: ignore[import-untyped]
    from pydantic import BaseModel, Field  # type: ignore[import-untyped]
except ImportError as exc:
    raise ImportError(
        "FastAPI and Pydantic are required for the server.\n"
        "Install them with:  pip install promptguard[server]"
    ) from exc


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


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

_mode = os.environ.get("PROMPTGUARD_MODE", "standard")
_rules_dir = os.environ.get("PROMPTGUARD_RULES_DIR")

_scanner = Scanner(mode=_mode, rules_dir=_rules_dir)

app = FastAPI(
    title="PromptGuard",
    description="Prompt injection detection API",
    version=__version__,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/scan", response_model=ScanResponse)
def scan_prompt(req: ScanRequest) -> ScanResponse:
    """Scan a single prompt for injection attacks."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan(req.prompt, context=req.context, mode=req.mode)
    elapsed_ms = (time.perf_counter() - start) * 1000

    return ScanResponse(
        **result.to_dict(),
        scan_time_ms=round(elapsed_ms, 2),
    )


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(req: BatchScanRequest) -> BatchScanResponse:
    """Scan multiple prompts concurrently."""
    if len(req.prompts) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 prompts per batch")

    start = time.perf_counter()
    results = _scanner.scan_batch(req.prompts, workers=req.workers, mode=req.mode)
    elapsed_ms = (time.perf_counter() - start) * 1000

    return BatchScanResponse(
        results=[
            ScanResponse(**r.to_dict(), scan_time_ms=0) for r in results
        ],
        total=len(results),
        scan_time_ms=round(elapsed_ms, 2),
    )


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
    )
