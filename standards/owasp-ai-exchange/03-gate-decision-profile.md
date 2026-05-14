# Control Pattern: Capability Gate Decision Profile

**Submission target:** OWASP AI Exchange — Threats Through Use, Observability and Audit.
**Profile identifier:** `gate-decision:v1`
**Status:** draft for public comment.
**Last updated:** 2026-05-14.

## What this control addresses

A capability gate (the runtime component that consumes `cap:v1` tokens and emits ALLOW/DENY) is the single most security-relevant decision surface in an agent deployment. This contribution standardises the **decision-event format** the gate emits so that:

- SIEM/SOC tooling can ingest events from any conforming gate without per-vendor adapters.
- Audit chains can be linked across heterogeneous gate implementations.
- Incident response can reconstruct exactly why any specific tool call was authorised or denied.
- Regulatory reporting (GDPR Article 30, HIPAA audit logs, SOX 404 ICFR) has a uniform substrate.

The decision-event profile is decoupled from the token and proof profiles (`cap:v1`, `proof:v1`); a gate may consume those formats and emit events in this format, or substitute alternative inputs while preserving the event format.

## Threat model

This control addresses the **observability** dimension of agent security:

- **TT.OBS** Unobservable Tool Calls (a malicious or buggy agent invokes a tool with no audit trail).
- **TT.TF**  Tampered Audit Trail (an attacker modifies the audit log to hide their actions).
- **TT.RC**  Reconstruction Failure (three days after an incident, the operator cannot answer "what happened?").

The control does **not** address attack *prevention* — that is the role of `cap:v1` (capability discipline) and `proof:v1` (policy completeness).

## The `gate-decision:v1` event format

One decision = one event. Events are append-only and may be chained.

```json
{
  "version":           "gate-decision:v1",
  "event_id":          "evt:9f2c8a…",
  "timestamp":         "2026-05-14T13:47:22.183Z",
  "decision":          "ALLOW",
  "deny_reason":       null,
  "deny_check":        null,
  "tool":              "transfer_funds",
  "agent_id":          "agent:billing.invoice",
  "caller_session":    "session:42c1a8…",
  "args_hash":         "sha256:b1f3e2d4…",
  "token_id":          "cap:8f3a91…",
  "issuer_key_id":     "8fa2ffa741ba6e3a",
  "policy_proof_hash": "sha256:7c3e94…",
  "gate_id":           "gate.platform.example",
  "gate_version":      "raucle-detect/0.10.0",
  "prev_event_hash":   "sha256:a5e8c1d7…",
  "chain_index":       18472,
  "signature":         null
}
```

### Field semantics

| Field | Type | Required | Notes |
|---|---|---|---|
| `version` | string | yes | `gate-decision:v1`. |
| `event_id` | string | yes | `evt:` + first 24 hex of SHA-256 over canonical body. |
| `timestamp` | string (RFC 3339) | yes | ISO 8601 UTC, millisecond precision. |
| `decision` | string | yes | `ALLOW` or `DENY`. |
| `deny_reason` | string \| null | yes | Human-readable reason. Required if `decision = DENY`; null otherwise. |
| `deny_check` | string \| null | yes | Machine identifier of the gate check that failed. One of: `issuer_pinning`, `signature`, `token_id_binding`, `time_bounds`, `tool_match`, `agent_scope`, `constraint`, `chain_resolution`, or a vendor-specific extension prefixed `x-`. Null if `decision = ALLOW`. |
| `tool` | string | yes | The tool name the agent attempted. |
| `agent_id` | string | yes | The principal the gate checked against. |
| `caller_session` | string \| null | optional | A deployment-specific session identifier, if available. |
| `args_hash` | string | yes | SHA-256 over the canonical-JSON serialisation of the call arguments. The full args are NOT included by default (PII concerns); deployments MAY include them under a separate field if their threat model permits. |
| `token_id` | string \| null | yes | The presented token's id. Null if `decision = DENY` and the cause was a missing/malformed token. |
| `issuer_key_id` | string \| null | optional | Convenience pointer to the issuer; can be recovered from the token. |
| `policy_proof_hash` | string \| null | optional | Mirrors the token's policy_proof_hash for direct queryability. |
| `gate_id` | string | yes | Deployment-specific identifier of the gate instance. |
| `gate_version` | string | yes | Implementation + version (e.g. `raucle-detect/0.10.0`). |
| `prev_event_hash` | string \| null | yes | SHA-256 of the previous event's canonical body. Null only for the first event in a chain. |
| `chain_index` | integer | yes | Monotonically increasing sequence number within a chain. |
| `signature` | string \| null | yes | Optional Ed25519 signature over the canonical body. If absent, the event is hash-chained but unsigned; chain-level signatures may be applied periodically at checkpoint events (see "Chain checkpointing"). |

### Canonical-JSON serialisation

Identical to `cap:v1`. The `event_id` and `signature` fields are excluded from the canonical body for hashing/signing.

## Chain integrity

Events form an append-only hash chain. Each event's `prev_event_hash` references the previous event's `event_id`. Any tampering with an event in the middle of the chain invalidates every subsequent event's `prev_event_hash`.

Operators MAY emit a special **checkpoint event** every N regular events:

```json
{
  "version":           "gate-decision:v1",
  "event_id":          "evt:checkpoint:…",
  "timestamp":         "…",
  "decision":          "CHECKPOINT",
  "merkle_root":       "sha256:…",
  "covered_indices":   [18000, 18999],
  "gate_id":           "…",
  "gate_version":      "…",
  "prev_event_hash":   "…",
  "chain_index":       19000,
  "signature":         "MEUCIQ…"
}
```

Checkpoints carry a Merkle root over the `event_id`s of the events they cover, plus a mandatory `signature` field. The signature key may differ from the gate's issuer key (recommended: a separate audit-signing key with its own HSM and rotation cadence).

A consumer verifying chain integrity walks back through `prev_event_hash` pointers, validates Merkle roots at every checkpoint, and rejects the chain on any mismatch.

## Decision-check vocabulary

The `deny_check` field uses a small fixed vocabulary so that SIEM rules can be written against it without per-gate variation.

| Identifier | Cause |
|---|---|
| `issuer_pinning` | Token's `key_id` not in the gate's trusted-issuer map. |
| `signature` | Ed25519 verification failed. |
| `token_id_binding` | `token_id` did not match SHA-256 of canonical body. |
| `time_bounds` | `now < not_before` or `now ≥ expires_at`. |
| `tool_match` | Requested tool not the token's bound tool. |
| `agent_scope` | Caller's `agent_id` not equal to or sub-scope of the token's. |
| `constraint` | One of the token's constraints failed against the actual `args`. |
| `chain_resolution` | A parent in the attenuation chain could not be resolved or did not verify. |

Vendor-specific extensions prefixed with `x-` are permitted; SIEMs should treat unknown identifiers as opaque.

## Privacy and PII

The default profile does not include call `args` in the event, only the `args_hash`. Deployments handling regulated data (HIPAA, PCI-DSS, banking PII) SHOULD audit which call arguments are safe to log in plaintext and configure the gate accordingly. Some implementations support per-argument redaction policies; this profile does not standardise the redaction-policy format.

## Cryptographic dependencies

- **Ed25519** for optional event signatures and mandatory checkpoint signatures.
- **SHA-256** for `event_id`, `args_hash`, `prev_event_hash`, and Merkle roots.
- Canonical-JSON encoding identical to `cap:v1`.

## Reference implementation

MIT-licensed Python implementation in `raucle_detect/audit.py`. Hash-chained sink, Merkle-root checkpointing, signed checkpoints, full verification path. Used by the gate in `raucle_detect/capability.py` and the end-to-end demo in `examples/end_to_end/`.

## Composition with `cap:v1` and `proof:v1`

A gate consuming `cap:v1` tokens and optionally checking `proof:v1` policy proofs emits `gate-decision:v1` events. The three profiles compose without further glue:

```
cap:v1 token  ──┐
                ├─→  gate  ──→  gate-decision:v1 event  ──→  audit chain
proof:v1     ───┘                                          │
                                                            └─→  SIEM
```

Every cross-reference is by hash. An incident-response query "show me every decision that authorised tool X under issuer Y in the past 24 hours" is a simple SIEM filter against the standard event fields.

## Interoperability test vectors

- Vector 1: One ALLOW event, no chain.
- Vector 2: Three-event chain (ALLOW, DENY-constraint, ALLOW).
- Vector 3: Chain with one checkpoint event.
- Vector 4: Chain with a tampered intermediate event; verification MUST fail.
- Vector 5: Chain spanning two gate instances (different `gate_id`); verification MUST succeed.

## Open questions for review

1. **Privacy default.** Should the profile default to `args_hash` only, or define an explicit redaction policy field?
2. **Checkpoint cadence.** Should the profile mandate a minimum checkpoint frequency, or leave it to operators?
3. **Cross-gate chain merging.** Currently a chain is per-gate. Should the profile standardise merging chains across gates, or leave that to higher-level systems?

## What we ask of OWASP AI Exchange

Acceptance as an informational control pattern under "Observability and Audit". Specifically:

- A control entry that references this document.
- Cross-references to `cap:v1` and `proof:v1`.
- Acceptance of the `gate-decision:v1` identifier.

The three profiles together (`cap:v1`, `proof:v1`, `gate-decision:v1`) form a complete substrate for agent-tool-call security with cryptographic chain-of-custody. We propose that OWASP AI Exchange list them as a coherent triple under the broader "Indirect Prompt Injection" mitigation cluster.
