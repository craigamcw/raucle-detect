# Evidence artefacts — what auditors can request

For each Raucle primitive, this document lists the specific artefacts an audit team can request from the operator, where each artefact lives in a typical deployment, and what an auditor verifies.

## Capability tokens (`cap:v1`)

| Artefact | Where it lives | Auditor verification |
|---|---|---|
| Policy files | Version-controlled (recommended: same repo as the agent code), one JSON file per suite/domain | Read the `_intent` and `_policy_notes` fields. Cross-reference against documented user-task templates. |
| Pre-registration hashes | Document committed to repo before any production rollout (e.g. `PRE-REGISTRATION.md`) | Re-hash each policy file. Confirm matches against the pre-registration entry valid on the audit date. |
| Trusted-issuer map | Gate-instance configuration (e.g. `/etc/raucle/trusted_issuers.json`) | Cross-reference each `(key_id, public_key_pem)` pair against documented roles. Confirm key rotation cadence is followed. |
| Issuer private keys | HSM or KMS — **NOT** in the audit-accessible filesystem | Verify HSM access logs. Confirm no plaintext private-key material exists outside the HSM. |
| Sample tokens | Captured from production audit log; one per tool/per agent-id | Verify Ed25519 signature against the pinned public key. Verify `token_id` matches SHA-256 of the canonical body. Verify expiry was respected by the consumer. |

## Verified policy proofs (`proof:v1`)

| Artefact | Where it lives | Auditor verification |
|---|---|---|
| Proof artefacts | One JSON file per `(schema, policy)` pair the operator runs in production | Verify Ed25519 signature. Verify `status: PROVEN`. Re-run the proof locally against the prover named in `prover` field. |
| Schema files | Same repo as the agent code | Hash the schema; confirm matches `proof.schema_hash`. |
| Cross-validation proofs | Recommended: a second `proof:v1` artefact produced by a different SMT solver | Verify both proofs reach `status: PROVEN`. |
| Lean development | `paper/lean/` in the raucle-detect repo | Run `lake build`. Confirm zero `sorry`s, zero errors. Toolchain pinned in `lean-toolchain`. |

## Gate decision events (`gate-decision:v1`)

| Artefact | Where it lives | Auditor verification |
|---|---|---|
| Decision-event log | Append-only file or SIEM index | Walk the chain backwards from any recent event. Verify each `prev_event_hash` matches the prior event's body hash. |
| Checkpoint events | Same log, emitted every N events | Verify Merkle root at each checkpoint. Verify checkpoint signature against the documented audit-signing key. |
| Audit-signing public key | Public file (e.g. `audit.pub.pem` distributed with the agent's docs) | Re-verify the most recent checkpoint signature using the published public key. |
| SIEM rules | SIEM platform configuration | Verify alerts fire on (a) chain-integrity failure, (b) abnormal denial-rate spike, (c) unknown `deny_check` identifier (vendor-specific extension). |

## Receipt chain (provenance, `raucle_detect.provenance`)

| Artefact | Where it lives | Auditor verification |
|---|---|---|
| Receipt log | Per-agent JSONL file or SIEM index | Walk back from any output to its originating user input. Verify each receipt's signature. |
| Capability statements | Same repo, distributed with agent identity | Verify `allowed_models` and `allowed_tools` match agent-runtime configuration. |
| Audit-chain integration | Configured via `Scanner(provenance_logger=…)` | Sample any scan from the period under audit. Walk the receipt chain to its source. |

## Empirical evaluation evidence

| Artefact | Where it lives | Auditor verification |
|---|---|---|
| Eval results | `paper/eval/results.json` | Reproduce on the audit team's own hardware. Numbers should match within run-to-run variance. |
| Latency measurements | `paper/eval/latency-*.json` | Reproduce locally. Confirm p50/p95/p99 fall within stated bands. |
| Pre-registration | `paper/eval/PRE-REGISTRATION.md` | Hashes match policy files at git revision of measurement. |
| Static-verifier output | `paper/eval/verify_policies.py` stdout | Run locally. 0/2737 attack scenarios is the current upper bound. |

## What to verify on a quarterly basis

Suggested quarterly audit checklist for a production Raucle deployment:

- [ ] Issuer keys rotated per documented schedule.
- [ ] HSM access logs reviewed; no anomalous access.
- [ ] Most recent checkpoint signature verifies under the published audit key.
- [ ] CI build passing on every policy change committed since last audit.
- [ ] Sample 10 random tokens from the audit log; all verify cleanly.
- [ ] Sample 10 random DENY events; structured `deny_check` and `deny_reason` are interpretable.
- [ ] Re-run the static verifier; 100% block rate confirmed.
- [ ] Receipt-chain spot-check: trace one production output back to its user input.
- [ ] Lean development still compiles on the pinned toolchain version.

## What auditors should NOT need access to

- The issuer private signing key (HSM-only).
- Production user data beyond what's necessary for the spot checks (most checks operate on hashes, not plaintext).
- The model weights or training data (out of scope for Raucle's controls).
