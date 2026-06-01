# Changelog

## 0.16.2 (2026-06-01) — security hardening (round 3 + blind cross-check)

Two independent adversarial audits (a multi-agent finder/refutation workflow plus
a blind independent pass) and manual verification of every fix. No receipt wire-format
change; five-language byte-identity preserved. 20 new security regression tests.

- **Provers:** `SQLClauseProver` no longer returns PROVEN for a query reading a
  forbidden table via `EXCEPT`/`INTERSECT`/`MINUS`; default forbidden tokens add
  `INTO`/`MERGE`/`CREATE`; `URLPolicyProver` returns UNDECIDED for `forbid_query_keys`
  over an open query-key grammar (declare `query_keys_closed: true` to prove it).
- **Adapters:** the AutoGen adapter now enforces the token's `agent_id` scope (was
  recorded in the receipt but not checked); the LangChain adapter fails closed when a
  `forbidden_values` blacklist can't be enforced on an opaque string tool input.
- **Provenance verifier:** binds receipt `agent_id` to the capability statement,
  enforces statement `expires_at`, and requires the JOSE `kid` to equal `agent_key_id`
  (matching the TS/Go/Rust/C# verifiers).
- **Audit:** keyless verification of a chain declaring `signed=true` now fails closed
  (was reporting valid); `allow_nan=False` in canonical JSON; a non-hex (tampered) leaf
  hash yields `valid=False` instead of crashing.
- **Server:** request body / batch size caps, rate-bucket eviction (+ opt-in
  `RAUCLE_TRUST_PROXY`), and `/metrics` gated behind auth when an API key is set.
- **Other:** multimodal media/pixel/page caps; fixed a dead SSRF-pinning path in
  `fetch_feed`; CLI keygen writes private keys 0600 atomically; MCP no longer echoes
  raw exception text; conformance harness only claims five-language parity when all
  five run; formal-proof claims in README / Lean docs scoped to what is actually
  mechanised (the runtime gate enforces more than the Lean model proves).

## 0.16.1 (2026-06-01) — CLI developer-experience fix

No behaviour or wire-format changes. Polishes the command-line surface.

- **CLI:** expected user errors (missing file, invalid JSON, missing optional
  extra, malformed input) now print a one-line `error: ...` to stderr with a
  non-zero exit code instead of a raw Python traceback. Genuinely unexpected
  errors still raise a stack trace for debugging.
- **CLI:** `--help` description now reflects the product — verifiable
  authorization & audit (capability tokens, SMT/Lean-proven policies, signed
  provenance receipts), not just prompt-injection detection.

## 0.16.0 (2026-06-01) — security hardening (round 2 + re-audit)

A full security-focused audit + confirmation re-audit. All CRITICAL/HIGH/MEDIUM
findings closed with regression tests; receipt wire format unchanged (five-language
byte-identity preserved). New `docs/security-model.md` documents the trust model.

- **Gate:** reject non-finite numbers (NaN/Inf no longer satisfy numeric bounds);
  agent_id grammar forbids trailing/double dots; revocation denies descendants of a
  revoked ancestor when a resolver is configured.
- **Provenance:** SANITISATION may only clear taint tags the agent's
  `sanitisation_authority` permits (verifier-side); unknown `agent_key_id` is a
  violation when capabilities are supplied; `from_jws` hardened (size caps, duplicate
  keys rejected, strict `alg`/`crit`).
- **Audit chain:** signed chains require a head checkpoint covering the final index;
  `verify_chain(expected_head=...)` external anchor; unsigned/unknown chains are invalid
  when a key is supplied.
- **Provers:** `SQLClauseProver` no longer returns PROVEN for comma-join / subquery
  table references it can't soundly resolve (UNDECIDED instead); `URLPolicyProver`
  `max_path_depth` is UNDECIDED over prefix grammars.
- **Scanner:** ReDoS fixed — per-pattern length cap on ALL patterns, bounded wildcard
  spans, per-scan wall-clock budget (an 82s pathological scan is now ~0.01s).
- **Feed:** `fetch_feed` is https-only, blocks private/loopback/metadata IPs, pins the
  validated IP (no DNS-rebind), rejects redirects, caps body size.
- **Keys/supply chain:** private keys written `0600`; `*.pem`/`*.key` git-ignored; CI
  actions pinned to commit SHAs.

## 0.15.0 (2026-06-01) — security hardening

Pre-launch end-to-end audit. Closes gate-authorisation bypasses, hardens the
proof/verifier guarantees, and makes the reference implementations genuinely
interoperable.

### Security (gate)
- **Agent-id privilege escalation fixed.** Agent matching required a bare
  prefix, so a token for `agent:billing` authorised `agent:billing-evil`.
  Now requires exact match or a dot-delimited descendant (`agent:billing.x`);
  same fix in `attenuate()`.
- **Constraint bypass-by-omission fixed.** Value constraints were skipped when
  the named field was absent, so aliasing/omitting an argument bypassed them.
  Positive/bound constraints (`allowed_values`, `starts_with`, `max_value`,
  `min_value`) now **fail closed** on an absent field. (Documented limitation:
  `forbidden_values` blacklists can still be aliased without the tool schema —
  prefer `allowed_values`.)
- **Fail-open/DoS fixed.** Numeric bounds raised an unhandled `TypeError` on
  non-numeric args; non-numeric/bool now DENY, and the whole constraint check
  is wrapped so any error is a DENY, never a propagated exception.
- **Strict proof mode binds to enforced constraints.** A token can no longer
  cite a PROVEN proof over an unrelated policy; in strict mode `policy_hash`
  must equal the hash of the token's own constraints.

### Security (provenance)
- **Verifier-side capability enforcement.** `ProvenanceVerifier` accepts an
  optional `capabilities=` map and independently rejects receipts whose
  model/tool the issuing agent's `CapabilityStatement` does not permit (the
  cross-check the docstring already claimed). Adds `capability_violations`.

### Reference implementations
- **All five impls are now byte-identical.** The TS/Go/Rust/C# ports had each
  diverged from the Python reference and could not reproduce its receipt IDs.
  Reworked to match byte-for-byte; added `reference/conformance.py` proving
  identical `receipt_hash` across all five for every published test vector.

### Docs / claims
- Every quickstart snippet now runs verbatim (`[compliance]` install, real
  `HashChainSink`/`prove`/`audit verify` APIs, dead links removed).
- Eval claims scoped to the evidence (banking-suite '100%', restated latency,
  per-receipt vs one-time-Lean verification).
- Package metadata: author email + URLs corrected to live targets.

## 0.14.0 (2026-06-01)

### Capability constraints

- **`starts_with` prefix constraint** is now a first-class capability
  constraint, enforced at the gate (`{"starts_with": {"field": "prefix"}}`)
  and supported in attenuation (a child may extend a prefix, never broaden
  it). This was referenced in the docs/examples but previously unsupported;
  the headline quickstart now mints **and enforces** as written.
- **Unknown constraint keys now raise** instead of being silently dropped,
  so a mis-cased key (e.g. `allowedValues` vs `allowed_values`) can no
  longer produce a token that enforces less than intended.

### Capability gate — revocation

- `CapabilityGate` now accepts `revoked_token_ids` and exposes a
  `revoke(token_id)` method. A revoked token, or any child citing it as
  `parent_id`, is DENY'd before expiry — the early-revocation path that
  complements short TTLs.

### Fixes & docs

- `__version__` now tracks the package version (was stale at `0.7.0`).
- Spec: added non-normative appendices — related work (vs Biscuit /
  Macaroons / in-toto / SLSA / C2PA / VCs), canonical-form rationale, and
  the token lifetime/revocation model.
- Legal/governance docs name the registered entity, **epic28 Ltd (trading
  as Raucle)**, so the dual-licence relicensing grant is unambiguous.
- CI: bumped `actions/checkout`→v5, `setup-python`→v6 (Node-20 retires
  2026-06-16).

## 0.13.0 (2026-05-28)

### Security — fail-loud cryptographic configuration (HOLD SCOPE FIX 1)

Six places in the codebase used `try / except: pass` patterns that silently
degraded cryptographic guarantees when configuration was wrong. Banking and
healthcare deployers explicitly do NOT want a silent fallback — they want a
loud failure they can act on. The behaviour is now:

- **Explicit config + broken = REFUSE.** Operator misconfigured the
  deployment; raise `ConfigurationError`, exit non-zero.
- **No config + safe default exists = WARN.** Log a prominent WARNING and
  continue in explicitly-marked unsigned mode.
- **Never silent.**

Specifics:

- `raucle_detect/errors.py` — new module exposing two named exception types:
  `ConfigurationError` (broken explicit config) and `PolicyUnproven` (strict
  mint mode refused).
- `raucle_detect.server._init_compliance()` — extracted from import-time
  init. When `RAUCLE_DETECT_VERDICT_KEY_PEM` or
  `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM` is set but unparseable, raises
  `ConfigurationError` (module import fails; uvicorn refuses to start).
  When no key is configured at all, emits a `WARNING` and continues in
  unsigned mode.
- `VerdictSigner.__init__` and `Ed25519Signer.__init__` — replaced
  `except Exception: self._public_pem = b""` with a `logger.error(...)` +
  `raise ConfigurationError(...)`. A signer that cannot expose its public
  key cannot produce verifiable receipts; the swallowed-error path produced
  receipts that looked normal but were silently unverifiable.
- `audit.sink_from_env()` — when `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM` is set
  but invalid, raises `ConfigurationError` instead of warning and returning
  an unsigned sink.
- `HashChainSink.__init__` — when no signer is supplied, emits a prominent
  `WARNING` at construction. **Every newly-created chain now writes a
  `chain_meta` header on line 1** carrying `{signed: bool, version, key_id?,
  signature?, created_at}`. The header is Ed25519-signed when a signer is
  present.
- `AuditVerifier` — reads the header and surfaces
  `report.signed_mode ∈ {"signed", "unsigned", "unknown"}` plus
  `report.chain_key_id`. Rejects signed checkpoints appearing in chains
  whose header declares `signed=false` (forgery indicator). Rejects
  checkpoints whose `key_id` does not match the header's `key_id`
  (cross-chain splice indicator). Legacy chains without a header remain
  verifiable but report `signed_mode == "unknown"`.

### Security — strict proof-enforced mint mode (HOLD SCOPE FIX 2)

Until now, `cap mint --policy-proof-hash` was advisory: a caller could pass
any string. Tokens cited proofs they had no structural relationship to. The
new strict mint mode makes the relationship enforceable:

- `Capability` gains two new optional fields, `grammar_hash` and
  `policy_hash`. Both nullable; backward-compatible default-absent. When
  set, they're covered by `token_id` and the signature.
- `CapabilityIssuer(..., require_proof=False)` is the new default; passing
  `require_proof=True` (or setting `RAUCLE_REQUIRE_PROOF=1`) enables strict
  mode. In strict mode, `mint()` requires a `ProofResult` whose `status` is
  `PROVEN` — anything else (absent, REFUTED, UNDECIDED) raises
  `PolicyUnproven`. The bound `policy_proof_hash`, `grammar_hash`, and
  `policy_hash` are taken from the supplied `ProofResult` so the linkage is
  structural, not advisory.
- Even outside strict mode, `mint(proof_result=...)` refuses to bind a
  non-PROVEN proof and refuses to bind contradictory hashes.
- `CapabilityGate` gains `proof_enforcement_mode ∈ {"off", "lenient",
  "strict"}` and `trusted_proofs: dict[str, ProofResult]`. Defence-in-depth
  at gate time: `"lenient"` warns on missing/invalid proof; `"strict"`
  denies. Default `"off"` preserves existing behaviour. (Registry-fetcher
  ships in a follow-up; current cache is in-memory + caller-supplied.)
- CLI: `raucle-detect cap mint --require-proof --proof-result PATH` for the
  strict path. `--policy-proof-hash` still works for the legacy advisory
  path.
- `raucle-detect prove json|url|sql` already returned exit-code 2 on REFUTED
  and 1 on UNDECIDED — both non-zero, both pipeline-fail by `set -e`. Now
  asserted by tests so CI never silently regresses.

15 new tests across `tests/test_audit.py`, `tests/test_verdicts.py`,
`tests/test_capability.py`, `tests/test_server_init.py`,
`tests/test_cli_exit_codes.py`.

## 0.12.0 (2026-05-27)

### Microsoft Agent Governance Toolkit integration — now first-class

raucle's contribution at [microsoft/agent-governance-toolkit#2610](https://github.com/microsoft/agent-governance-toolkit/pull/2610) — adding `proof_artefact` and `verification_pointers` carry-through on AGT's `BackendDecision` — **merged upstream on 2026-05-27** (commit `25abf72`, accepted by Microsoft maintainer Imran Siddique). raucle's reference integration ships in this release as a first-class module.

- **`raucle_detect.integrations.agt_backend.RauclePolicyBackend`** — implements AGT's `agent_os.policies.backends.ExternalPolicyBackend` Protocol. Plug raucle into any AGT-governed agent through the same seam OPA and Cedar already use. The backend reads the in-force capability token from the asyncio-ContextVar that the Agent Framework middleware also uses, so a single primed token covers both integration paths.
- Every `BackendDecision` raucle returns carries the cited `proof_artefact` (the policy proof hash from the capability token) and a `verification_pointers` dict (issuer pubkey URL, policy registry URL, optional Lean development URL). AGT's `PolicyEvaluator` propagates both into `PolicyDecision.audit_entry`, so any AGT audit-chain consumer immediately gets offline-verifiable evidence attached to every raucle-rendered decision.
- Graceful degradation — the backend detects whether the installed AGT carries the merged fields and silently drops them on older installs. raucle deployments survive pre-merge AGT.
- 7 tests in `tests/test_agt_backend.py`. Skipped automatically when `agent_os` is not installed; passing 7/7 against `microsoft/agent-governance-toolkit@main` post-merge.

This is the second of the three Microsoft-stack integrations. v0.11.0 shipped the Agent Framework `FunctionMiddleware`; v0.12.0 ships the AGT backend; the third (Azure AI Foundry MCP Gateway sidecar) ships when the recorded walkthrough lands.

### Stub-shape integration deprecated

The pre-merge `raucle_detect.integrations.agt` module — containing the `IPolicyProvider` stub we originally proposed (Microsoft instead chose to keep the existing `ExternalPolicyBackend` Protocol they already ship, which we then extended) — remains importable for one minor version and will be removed in v0.13.0. New consumers should use `raucle_detect.integrations.agt_backend.RauclePolicyBackend`.

## Unreleased

### Relicensed: MIT → AGPL-3.0-or-later + commercial

raucle-detect is now dual-licensed. The default open-source licence becomes the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later); a commercial licence is available from epic28 Ltd (trading as Raucle) for organisations whose use is incompatible with AGPL terms.

The change protects the project from being absorbed into closed-source commercial forks while preserving full openness for self-hosting enterprises, academic research, security audits, and contributors. Self-hosting inside a single organisation for internal use — the dominant use case in our regulated-fintech ICP — is unaffected.

Versions tagged on or before commit `ac9aed0` remain available under the MIT licence under which they were released. See [LICENSING.md](LICENSING.md) for the rationale and [COMMERCIAL.md](COMMERCIAL.md) for commercial-licence details.

## 0.10.0 (2026-05-14)

### Capability-based agent permissions — unforgeable tool handles

Every prompt-injection mitigation in 2026 still asks an LLM, in English, not to misuse its tools. v0.10.0 replaces that polite request with an OS-style capability discipline: a tool refuses to execute unless the caller presents an Ed25519-signed `Capability` token whose constraints are satisfied by the actual call arguments. Prompt injection becomes structurally irrelevant for tool calls — the malicious instruction has nothing to act with.

- **`Capability`** — the token. Binds `(agent_id, tool, constraints, nbf, exp, parent_id, policy_proof_hash, issuer, key_id)` under one Ed25519 signature. Constraint schema mirrors v0.9.0's `JSONSchemaProver` policy keys: `forbidden_values`, `allowed_values`, `max_value`/`min_value`, `required_present`, `forbidden_field_combinations`.
- **`CapabilityIssuer`** — mints fresh tokens; attenuates parents into more-restricted children.
- **`CapabilityIssuer.attenuate()`** — the killer property. A child cannot outlive its parent. A child's bounds can only narrow (min of two `max_value`s; intersection of two `allowed_values`; union of two `forbidden_values`). A child's `agent_id` must be a prefix-extension of the parent's. Broadening is structurally impossible.
- **`CapabilityGate`** — the choke point. `check(token, tool, args)` verifies issuer pinning, signature, `token_id` binding, time bounds, tool match, agent match, and every constraint against the supplied args. Optional `parent_resolver` walks the full attenuation chain. Fails closed by default.
- **`policy_proof_hash`** — a token can cite a v0.9.0 `ProofResult.hash`, claiming "these constraints are formally complete over this tool's schema". The proof, the receipt, the audit chain, and the capability all reference each other by hash. The trust graph closes.
- **CLI** — `raucle-detect cap keygen | mint | verify | check | attenuate`. Exit codes: 0 OK / ALLOW, 2 INVALID / DENY.
- 20 new tests covering signing, expiry, tampering, every attenuation invariant, full chain verification, and serialisation round-trip.

This is Move #2 of the revolutionary roadmap. With v0.9.0 (proofs over the tool grammar) and v0.10.0 (unforgeable handles to invoke that tool), the strongest agent-safety story on the market is now MIT-licensed open source.

## 0.9.0 (2026-05-14)

### Formal verification of bounded guardrails — proofs, not statistics

Every other AI security product on the market ships with the same line: *"tested against 10,000 attacks."* That is statistics over a sample. For bounded sub-languages — tool-call JSON, URL allowlists, read-only SQL — we can do dramatically better: produce an actual **proof** that no string in the grammar bypasses a given policy. v0.9.0 is the first release of that machinery.

- **`JSONSchemaProver`** — SMT-backed (Z3). Given a JSON Schema (type=object with primitive properties + enum + min/max) and a policy (`forbidden_values`, `max_value` / `min_value`, `required_present`, `forbidden_field_combinations`), returns `PROVEN` or a **concrete counterexample tool-call**. The right thing to point at every agent's tool-call interface.
- **`URLPolicyProver`** — enumerative. `require_https`, `forbid_query_keys`, `host_allowlist` (with `*.example.com` wildcards), `max_path_depth`. Counterexamples are concrete URLs.
- **`SQLClauseProver`** — bounded read-only-ish policy over a finite set of statement templates. `forbidden_tokens` (DROP, DELETE, TRUNCATE…), `allow_statement_chaining`, `allowed_tables`. Counterexamples include the offending template plus the rule that broke.
- **`ProofResult`** — canonical-JSON-hashed artifact carrying `(status, prover, prover_version, grammar_hash, policy_hash, counterexample, notes, timeout_ms)`. The hash drops straight into the v0.5.0 receipt and v0.4.0 audit chain — proof artifacts become first-class citizens of the trust graph.
- **`UnsupportedGrammar`** — explicit refusal. Recursive schemas, arbitrary string regex constraints, and full SQL grammars raise instead of pretending to prove something they can't. Honest scope beats lying coverage.
- **CLI** — `raucle-detect prove json --schema tool.json --policy policy.json`, `prove url --grammar grammar.json --policy policy.json`, `prove sql --grammar grammar.json --policy policy.json`. Exit codes: 0 PROVEN, 2 REFUTED, 1 UNDECIDED.
- **Optional `[proof]` extra** — `pip install 'raucle-detect[proof]'` pulls Z3. Core stays dependency-free.
- 19 new tests covering positive proofs, refutation paths with concrete counterexample inspection, hash determinism, and the rejection of unsupported grammars.

This is the depth play. The v0.8.0 feed is breadth — fast distribution of known badness. v0.9.0 is depth — cryptographic guarantees about declared interfaces. Together they bracket the field.

Move #3 of the revolutionary roadmap.

## 0.8.0 (2026-05-14)

### Federated signed-IOC feeds — Sigstore-shaped threat intel for AI

Every new deployment that subscribes makes every other deployment safer. Novel jailbreaks discovered by one team propagate to every gateway worldwide, cryptographically signed, no central authority, no API token.

- **`SignedIOC`** — content-addressed Indicator of Compromise. Fields: `kind` (`regex` | `substring` | `unicode_signature`), `pattern`, `severity`, `categories`, `issuer`, `key_id`, `issued_at`, optional `revokes` / `expires_at`. Body is canonical-JSON-hashed; `content_hash` is the identifier; Ed25519 `signature` is mandatory.
- **`Feed`** — a bundle of IOCs from one issuer, plus a Merkle root over sorted content hashes and one manifest signature. Every IOC is *also* individually signed, so partial copies remain verifiable offline.
- **`IOCSigner`** — publisher API. `generate(issuer=...)`, `sign_ioc(...)`, `build_feed(...)`, `save_private_key(...)`. Pure Ed25519 (`cryptography` extra).
- **`FeedStore`** — consumer API. Directory-backed, pinned-pubkey verification on every merge, honours intra-issuer `revokes`, drops expired IOCs. Renders the live set as pattern rules consumable by `Scanner(feed_store=...)`.
- **`Scanner(feed_store=...)`** — one new keyword. Feed-derived rules merge alongside built-ins and custom YAML, with `source: "feed:<issuer>"` carried through to `matched_rules` so downstream audit/receipt can attribute every hit.
- **Trust model** — no global root. Consumers pin one issuer pubkey per feed. Multiple feeds compose. Hostile cross-issuer revocations are silently ignored: an issuer can only revoke its own IOCs.
- **CLI** — `raucle-detect feed keygen`, `feed sign`, `feed verify`, `feed pull`, `feed list`.
- **Composition** — feed-derived rules participate in the ruleset hash bound into every v0.4.0 audit-chain entry and v0.5.0 signed receipt. Subscribing to a feed mutates the verdict surface in a way that is itself attestable.

This is the network-effect layer. Move #6 of the frontier roadmap.

## 0.7.0 (2026-05-14)

### Multimodal scanning — the 2026 attack surface

Attackers are no longer typing `ignore all previous instructions`. They hide it inside images (OCR + invisible-pixel encoding), audio (steganography), ASCII art (the ArtPrompt class), EXIF metadata, PDF streams, and zero-width Unicode wrapped around innocent-looking text. This release adds the detection layer text-only scanners miss.

- **`strip_invisible_unicode(text)`** — dep-free, always available. Strips zero-width spaces (U+200B/C/D), bidi overrides (U+202A–E, U+2066–9), variation selectors (U+FE00–F, U+E0100–1EF), word joiners (U+2060–4), the entire **tag-character block** (U+E0001–7F) used in 2024-era invisible-prompt attacks, the BOM, and the soft hyphen. Returns the cleaned string plus a list of every codepoint that was hidden, so the finding can be surfaced rather than silently sanitised away.
- **`detect_ascii_art(text)`** — dep-free heuristic for the **ArtPrompt** class. Identifies blocks of 5+ consecutive art-shaped rows (high fill-character density, low alphanumerics), then matches each 6-column slice against a library of 13 letter glyphs (A, B, E, G, I, N, O, P, R, S, T, U, V) at a 70% structural-similarity threshold. Catches the canonical "draw the word IGNORE in `#` characters and ask the model to read it" attack without needing OCR.
- **`MultimodalScanner`** — orchestrator that wraps a `Scanner` and pre-processes input through every detector. Returns a typed `MultimodalScanResult` with a `combined_verdict` that auto-escalates to MALICIOUS when any HIGH-severity finding is present — *seeing* invisible-Unicode in prose is itself evidence of bad intent, separate from what the scrubbed text scans as.
- **Image scanning** via Tesseract OCR + EXIF inspection. Extracts text from `.png`/`.jpg`/etc., inspects EXIF for prompt-bearing metadata, concatenates everything, and feeds it back through the standard text scanner. Requires the `[multimodal]` extra (Pillow + pytesseract + tesseract on PATH).
- **PDF scanning** via `pypdf` stream extraction. Same pattern: extract text, scrub, scan.

### New CLI

- **`raucle-detect scan-image <path>`** — full pipeline. `--mode`, `--rules-dir`, `--format table|json`. Exit code 0/1/2 by verdict.
- **`raucle-detect scan-pdf <path>`** — same options.
- **`raucle-detect scrub <text>`** — quick utility. Reports every invisible codepoint in the input and prints the scrubbed text.

### Deliberately not done yet

- Audio steganography — needs librosa/audio deps; deferred to a future release with its own `[audio]` extra.
- Image-pixel-encoded prompts (least-significant-bit steganography) — separate detector, separate PR.
- Multimodal LLM input correlation — Scanner currently treats text and image as separate scans.

### Stats

- 1 new module (`multimodal.py`)
- 3 new CLI commands (`scan-image`, `scan-pdf`, `scrub`)
- 22 new tests (20 dep-free + 2 that gracefully skip without Pillow/pypdf)
- 333 tests passing total
- New optional dependency group: `pip install 'raucle-detect[multimodal]'`

### Compatibility

All new functionality additive. `Scanner` unchanged. Existing chains, receipts, replay flows continue to work. Version 0.6.0 → 0.7.0.

## 0.6.0 (2026-05-14)

### Counterfactual replay — the SOC killer feature

Given any provenance chain produced by v0.5.0, you can now re-run every guardrail decision in it against a *different* policy and see exactly what would have changed. Answers the question every incident response actually needs: *"if we'd had stricter rules on last Tuesday, would we have caught this?"*

- **`InputStore`** — JSONL-backed, append-only, hash-verified mapping of `input_hash → original_text`. Lives alongside (not inside) the provenance chain so receipts stay privacy-by-default. Tampered entries are detected on lookup and reported as missing rather than silently returning the wrong prompt.
- **`Replayer`** — walks every `guardrail_scan` receipt in a chain, looks up the original input in the store, re-runs against a fresh `Scanner` configured with the counterfactual policy, and emits a typed diff.
- **`ReplayResult`** — separates **unchanged**, **newly blocked**, **newly allowed**, **newly alerted**, and **missing-input** receipts. Each `ReplayChange` carries the original receipt hash, the verdict transition, and a one-line explanation pulled from the new scan's matched rules.
- **Scanner integration** — pass `input_store=` to `Scanner()` and every `scan` / `scan_output` / `scan_tool_call` automatically persists the input text to the store. Opt-in, zero-cost when not configured.

### CLI

- **`raucle-detect provenance replay <chain> --input-store <store>`** — table or JSON output. Flags: `--mode` (strict/standard/permissive), `--rules-dir` for custom rule packs, `--show-unchanged` to include receipts whose verdict didn't change. Exit code 0 always (replay always succeeds at the analysis level; the diff is the output).

### How it works end-to-end

```python
from raucle_detect import AgentIdentity, ProvenanceLogger, Scanner
from raucle_detect.replay import InputStore

identity = AgentIdentity.generate(agent_id="agent:gateway")
with (
    ProvenanceLogger(agent=identity, sink_path="audit/chain.jsonl") as log,
    InputStore.open("audit/inputs.jsonl") as inputs,
):
    scanner = Scanner(mode="standard", provenance_logger=log, input_store=inputs)
    scanner.scan(user_prompt)   # writes signed receipt + persists prompt
```

Then, days later, after a near-miss:

```bash
raucle-detect provenance replay audit/chain.jsonl \
    --input-store audit/inputs.jsonl \
    --mode strict
```

→ table of every receipt whose verdict would have changed, with the rule that would have fired.

### What this is uniquely possible because of

Counterfactual replay is the first feature that *requires* the v0.5.0 provenance primitive. Every other guardrail vendor would have to log raw prompts in plaintext to do this; raucle does it from hash-keyed receipts plus a separately-managed input store, so the *signed* audit trail never has to carry the content. That separation is what makes the feature deployable in regulated environments.

### Stats

- 1 new module (`replay.py`)
- 1 new CLI subcommand (`provenance replay`)
- 13 new tests (input store round-trip, idempotency, tamper detection, malformed-line handling, Scanner auto-save, same-policy/strict-policy/missing-input replay, non-guardrail-receipt handling, result-view sanity)
- 311 tests passing total

### Compatibility

- All new parameters optional. Scanner gains an optional `input_store=` kwarg.
- No new mandatory dependencies; replay uses the existing crypto stack from v0.4.0/v0.5.0.
- Version 0.5.0 → 0.6.0.

## 0.5.0 (2026-05-14)

### AI Provenance Graph — cryptographic chain-of-custody for the agentic stack

The first open-source implementation of end-to-end signed provenance for multi-agent / multi-tool LLM workflows. Every step (user input, model call, tool call, retrieval, guardrail scan, agent handoff, sanitisation, merge) emits a signed receipt that composes into a Merkle DAG. Given any output you can reconstruct the entire causal chain back to the original input and prove nothing in the chain has been tampered with. The LLM-equivalent of certificate transparency + SBOM + DNSSEC.

- **`AgentIdentity`** — Ed25519 keypair plus a self-signed capability statement listing the agent's permitted models, tools, and data classifications. Acts as the agent's "TLS certificate".
- **`ProvenanceReceipt`** — compact JWS (EdDSA, `typ=provenance-receipt/v1`) binding `(agent_id, parent_receipts, operation, input_hash, output_hash, taint, timestamp)`. Hashes only — receipts never carry the raw prompt/output, privacy by default.
- **`ProvenanceLogger`** — high-level API: `record_user_input`, `record_model_call`, `record_tool_call`, `record_retrieval`, `record_guardrail_scan`, `record_agent_handoff`, `record_sanitisation`, `record_merge`. Auto-inherits taint from parents so callers can't accidentally drop it. Enforces capability allowlists at write time.
- **`ProvenanceVerifier`** — verifies (a) every signature, (b) every parent link exists, (c) taint monotonicity (descendants ⊇ parents, unless a `sanitisation` step explicitly removes specific tags). `trace()` walks the DAG backwards; `to_dot()` exports Graphviz for visualisation.
- **Auto-emit from `Scanner`** — pass `provenance_logger=` to `Scanner()` and every `scan` / `scan_output` / `scan_tool_call` automatically emits a `guardrail_scan` receipt with the verdict + ruleset hash. `ScanResult.provenance_hash` is the new receipt's hash. Downstream steps cite it as a parent, so the chain proves the guardrail actually ran before each model/tool call.

### CLI

- **`raucle-detect provenance keygen <agent_id>`** — generates Ed25519 keypair + capability statement. `--allowed-models` / `--allowed-tools` / `--ttl-days` shape the statement.
- **`raucle-detect provenance verify <chain> --pubkeys …`** — verifies signatures, DAG integrity, and taint monotonicity. Accepts capability statement JSON files or raw PEM keys.
- **`raucle-detect provenance trace <receipt> --chain …`** — walks the DAG backwards from a leaf to all roots; table or JSON output.
- **`raucle-detect provenance graph <receipt> --chain … --out g.dot`** — exports Graphviz DOT for visualisation.

### Receipt format (v1)

JWS header includes `typ=provenance-receipt/v1`, `crit=["raucle/v1"]`, `kid=<agent_key_id>`. Payload fields: `iss`, `iat`, `agent_id`, `agent_key_id`, `operation`, `parents` (list), `input_hash`, `output_hash`, `model`/`tool`/`corpus` (operation-specific), `ruleset_hash`, `guardrail_verdict`, `taint` (sorted list), optional `tenant`. Receipt's own hash = `sha256(compact_jws)` — content-addressed, deterministic.

### Stats

- 1 new module (`provenance.py` — ~600 lines)
- 1 new CLI subcommand with 4 actions (`keygen`, `verify`, `trace`, `graph`)
- 28 new tests (DAG composition, taint monotonicity, signature verification, tampering detection, capability enforcement, Scanner auto-emit)
- 293 tests passing total

### Compatibility

- All new parameters are optional. `ScanResult` gains an optional `provenance_hash` field.
- Requires `raucle-detect[compliance]` extra (already present in 0.4.0) for the `cryptography` dependency.
- Version 0.4.0 → 0.5.0.

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
