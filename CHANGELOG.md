# Changelog

## 0.4.0 (2026-05-13)

### Compliance & Audit (EU AI Act / SOC 2 ready)

- **Tamper-evident hash-chained audit log** (`HashChainSink`) — every detection event is hash-chained to its predecessor; Ed25519-signed Merkle-root checkpoints anchor the chain at configurable intervals. `AuditVerifier` detects any past-record tampering and pinpoints the first invalid index. Resumes existing chains seamlessly. CLI: `raucle-detect audit verify` and `audit keygen`.
- **Signed JWS verdict receipts** (`VerdictSigner` / `VerdictVerifier`) — every scan can emit a compact JWS receipt (Ed25519, `typ=raucle-receipt/v1`) containing input hash, ruleset hash, model version, and timestamp. Downstream SIEMs/gateways can verify decisions without trusting transport logs. The `crit=raucle/v1` header prevents generic JWT libraries from accidentally accepting these as auth tokens. CLI: `raucle-detect verify-receipt`.
- **`ScanResult.receipt`** field — present when a `VerdictSigner` is configured.
- REST endpoints: `POST /verdict/verify`, `GET /audit/status`.

### Outcome Verification

- **`OutcomeVerifier`** — classifies whether a malicious prompt actually *landed*: `LANDED`, `REFUSED`, or `UNCERTAIN`. Combines refusal-pattern detection, canary-leak checks, system-prompt-leak heuristics, secret-leak detection, and sensitive tool-call diffs. The single metric CISOs actually care about — cuts noise from prompts that *attempted* but were refused.
- REST endpoint: `POST /verify/outcome`.

### Model Context Protocol (MCP)

- **MCP server mode** (`raucle-detect mcp serve`) — speaks JSON-RPC 2.0 over stdio per the MCP 2024-11-05 spec. Exposes 8 tools to any MCP-compatible client (Claude Desktop, Cursor, Continue.dev, Cline): `detect_injection`, `scan_output`, `scan_tool_call`, `verify_outcome`, `scan_mcp_manifest`, `list_rules`, `embed_canary`, `check_canary_leak`. Zero external MCP SDK dependency.
- **MCP manifest static scanner** (`raucle-detect mcp scan`) — finds tool-poisoning attacks in other MCP servers: hidden instruction tags (`<IMPORTANT>`, `<SYSTEM>`, `[INST]`), invisible Unicode, direct injection phrases, rug-pull indicators, baked-in credentials, SSRF targets, dangerous tool names. Outputs JSON or **SARIF 2.1.0** for GitHub Advanced Security ingestion.

### Scanner integration

- `Scanner` now accepts optional `audit_sink`, `verdict_signer`, `model_version`, and `tenant` parameters. When wired, every `scan`, `scan_output`, and `scan_tool_call` automatically writes to the audit chain and attaches a signed receipt to the result.
- Server reads `RAUCLE_DETECT_AUDIT_PATH`, `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM`, `RAUCLE_DETECT_VERDICT_KEY_PEM`, `RAUCLE_DETECT_MODEL_VERSION`, `RAUCLE_DETECT_TENANT` from env.

### Dependencies

- New optional extra: `raucle-detect[compliance]` pulls `cryptography>=42.0` for Ed25519 signing/verification. Core install remains zero-dependency.

### Stats

- 5 new modules: `audit.py`, `verdicts.py`, `outcome.py`, `mcp_scanner.py`, `mcp_server.py`
- 5 new CLI commands: `audit verify`, `audit keygen`, `verify-receipt`, `mcp serve`, `mcp scan`
- 3 new REST endpoints: `/verdict/verify`, `/verify/outcome`, `/audit/status`
- SARIF output for GitHub code-scanning integration

## 0.3.0 (2026-05-13)

### New Features

- **Canary watermarking** (`CanaryManager`) — embed invisible tokens in system prompts to detect if the model is manipulated into leaking its instructions. Three concealment strategies: zero-width Unicode encoding, semantic sentence injection, and HTML comment. Supports HMAC-signed tokens for offline verification.
- **Attack export & replay** (`AttackLog`) — collect scan results and export to JSONL, Garak, PyRIT, or PromptBench format so production detections feed back into your test suite automatically.
- **Rule mutation fuzzer** (`raucle-detect rules fuzz`) — auto-generates leet-speak, homoglyph, zero-width, base64, ROT13, reversed, and case-flip variants of seed attack phrases, then measures what percentage each rule catches. Highlights low-coverage rules.
- **API authentication** — set `RAUCLE_DETECT_API_KEY` to require `Authorization: Bearer <key>` on all scan endpoints. Uses `secrets.compare_digest` to prevent timing attacks.
- **Rate limiting** — built-in token-bucket rate limiter per client IP. Configure via `RAUCLE_DETECT_RATE_LIMIT` (req/min) and `RAUCLE_DETECT_BURST_LIMIT`. Returns HTTP 429 with `Retry-After` header.
- **Prometheus metrics** (`GET /metrics`) — plain-text request counters, verdict histograms, per-endpoint latency (avg + p99), rate-limit and auth-failure counters. Scrape directly with Prometheus.
- **Docker Compose** (`docker-compose.yml`) — one-command deployment with all env vars documented.

### Bug Fixes

- **Negation window expanded** (`classifier.py`) — increased from 10 to 40 characters before a keyword, catching phrases like "I am NOT asking you to ignore".
- **Position bonus gameable bypass fixed** (`classifier.py`) — the 1.5× position multiplier no longer fires when benign preamble text appears in the first 100 characters, preventing "please help me: ignore all previous instructions" bypass.
- **Pattern compilation cached** (`patterns.py`) — `_compile_pattern()` is now module-level LRU-cached (2048 entries). `scan_with_rules()` no longer recompiles the same regex on every call; all `Scanner` instances share compiled patterns.
- **YAML rule schema validation** (`rules.py`) — rules are validated for required fields (`id`, `name`, `category`, `patterns`, `score`), score range (0–1), severity values, and valid regex patterns. Invalid rules are skipped with an error log instead of crashing at match time.
- **Session memory leak fixed** (`middleware.py`) — sessions idle longer than `session_ttl` seconds (default 1 hour) are automatically evicted. Added `active_session_count()` for monitoring.
- **Encoding error transparency** (`cli.py`) — file decoding with `errors='replace'` now counts and reports replacement characters to stderr instead of silently swallowing them.

### Stats

- 3 new modules: `canary.py`, `export.py`, `mutator.py`
- REST API: 7 endpoints (added `/metrics`; `/health` now reports `auth_enabled`)
- `HealthResponse` includes `auth_enabled` field

## 0.2.0 (2026-03-27)

### New Features

- **Output scanning** (`scan_output()`) — detect data leakage, system prompt exfiltration, and injection in LLM responses
- **Tool call validation** (`scan_tool_call()`) — block shell injection, path traversal, SQL injection, and SSRF in tool arguments
- **Session scanner** (`SessionScanner`) — multi-turn attack detection with escalation tracking, cumulative risk scoring, and trend analysis
- **Middleware interface** (`RaucleMiddleware`) — framework-agnostic `pre_process()`, `post_process()`, `pre_tool_call()` hooks with alert/block callbacks
- **OpenClaw plugin** (`plugins/openclaw/`) — real-time agent protection via `before_prompt_build` hook
- **RAG poisoning rules** (RAG-001 to RAG-004) — document injection, retrieval manipulation, invisible text, citation poisoning
- **Agent attack rules** (AGT-001 to AGT-005) — goal hijacking, tool abuse, memory manipulation, action coercion, privilege escalation
- **Output-specific rules** (OUT-001 to OUT-003) — system prompt leak, injection in output, exfiltration channels
- **Tool call rules** (TOOL-001 to TOOL-004) — dangerous shell commands, path traversal, SQL injection, SSRF

### Improvements

- **Weighted heuristic classifier** — position-aware scoring, negation detection, density bonuses (replaced flat keyword counting)
- **Broadened PI-004 patterns** — catches "print/show/display your system prompt" and variants
- **ReDoS protection** — risky regex patterns capped at 10K chars
- **Input size limits** — 1MB file cap in CLI, 100K char truncation in scanner
- **Worker count clamping** — batch scan workers clamped to CPU count
- **`ScanResult.notes` field** — reports truncation and other scan metadata

### Stats

- 55 rules, 250+ patterns (was 39 rules, 180+ patterns in 0.1.0)
- 208 tests passing (was 95 in 0.1.0)
- REST API: 5 endpoints (`/scan`, `/scan/batch`, `/scan/output`, `/scan/tool`, `/health`)

## 0.1.0 (2026-03-25)

- Initial release
- 39 detection rules across 6 categories
- Pattern matching + heuristic semantic classifier
- Python library, CLI tool, REST API
- Three sensitivity modes (strict/standard/permissive)
- YAML custom rule framework
- Zero mandatory dependencies
