# Control Pattern: Verified Policy Proof Artefact

**Submission target:** OWASP AI Exchange — Threats Through Use, Tool Misuse mitigations.
**Profile identifier:** `proof:v1`
**Status:** draft for public comment.
**Last updated:** 2026-05-14.

## What this control addresses

Capability tokens (`cap:v1`) constrain *what an agent can do*. They do not constrain *whether the constraints are right*. A tool's JSON Schema may permit values the operator did not consider; the policy authored by the operator may not cover every such value; the gap is where attacks live.

This contribution defines `proof:v1`, a content-addressed, signed artefact certifying that a security policy is **complete** over a tool's declared JSON Schema. A policy is complete when no string satisfying the schema also violates the policy. Verifying completeness is the operator's claim that the policy covers the entire input surface the tool accepts.

The artefact is verifier-agnostic: any SMT implementation (Z3, CVC5, Vampire, Yices) can produce a `proof:v1` document. The artefact format does not depend on the prover's internal trace; it commits to the (schema, policy) pair and the prover's verdict.

## Threat model

This control specifically addresses:

- **TT.TM** Tool Misuse via policy/schema disagreement (the policy intended to forbid X, but the schema permitted X through a path the operator missed).
- **TT.PE** Policy escalation through schema corners (legitimate arguments at the boundary of the schema bypass the policy).

The control does **not** address:

- Side-channel exfiltration within otherwise-policy-compliant values.
- Schema bugs (if the schema itself is too permissive for the tool's actual semantics, no proof can fix that — that is a deployment-correctness problem).

## The `proof:v1` artefact format

```json
{
  "version":          "proof:v1",
  "proof_id":         "proof:7c3e94…",
  "schema_hash":      "sha256:f528bd9e…",
  "policy_hash":      "sha256:5634991f…",
  "tool":             "transfer_funds",
  "prover":           "z3",
  "prover_version":   "4.16.0",
  "status":           "PROVEN",
  "counterexample":   null,
  "notes":            [],
  "timeout_ms":       5000,
  "issued_at":        1747225200,
  "issuer":           "platform.example",
  "key_id":           "8fa2ffa741ba6e3a",
  "signature":        "MEUCIQ…"
}
```

### Field semantics

| Field | Type | Required | Notes |
|---|---|---|---|
| `version` | string | yes | `proof:v1` for this revision. |
| `proof_id` | string | yes | `proof:` followed by first 24 hex chars of SHA-256 over the canonical body. |
| `schema_hash` | string | yes | SHA-256 over the canonical-JSON serialisation of the tool's JSON Schema. The hash binds the proof to a specific schema; any schema change invalidates the proof. |
| `policy_hash` | string | yes | SHA-256 over the canonical-JSON serialisation of the policy. Same binding semantics. |
| `tool` | string | yes | Tool name the schema describes. Same regex as `cap:v1.tool`. |
| `prover` | string | yes | Identifier of the SMT solver used. Recognised values: `z3`, `cvc5`, `vampire`, `yices`. |
| `prover_version` | string | yes | Version string the solver reports. |
| `status` | string | yes | One of `PROVEN`, `REFUTED`, `UNDECIDED`. |
| `counterexample` | object \| null | yes | When `status = REFUTED`, the concrete argument assignment that satisfies the schema and violates the policy. Null otherwise. |
| `notes` | array of strings | yes | Diagnostic notes from the prover or the encoding step. May be empty. |
| `timeout_ms` | integer | yes | Solver timeout in effect when the proof was attempted. |
| `issued_at` | integer | yes | Unix epoch seconds. |
| `issuer` | string | yes | Free-form identifier for the issuing authority. |
| `key_id` | string | yes | Same as `cap:v1.key_id`. |
| `signature` | string | yes | Ed25519 signature over the canonical body, excluding `proof_id` and `signature`. |

## Schema subset supported by `proof:v1`

A conforming prover MUST support at least the following JSON Schema subset and SHOULD reject schemas outside it with `status: UNDECIDED` and an explanatory note:

- Top-level `type: object` with declared `properties` and optional `required` array.
- Property types: `string`, `number`, `integer`, `boolean`.
- `enum` on string properties (any number of enum values).
- `minimum` / `maximum` on numeric properties.
- No nested objects (reserved for `proof:v2`).
- No arrays (reserved for `proof:v2`).
- No `oneOf` / `anyOf` / `allOf` (reserved for `proof:v2`).
- No regex (`pattern`) constraints on strings (reserved for `proof:v2`).

The supported subset is deliberately conservative. Tools whose schemas exceed it can be wrapped in adapter schemas that are within the subset, or admitted via separate runtime constraints with explicit `notes`.

## Policy vocabulary

Identical to `cap:v1`'s constraint vocabulary. A `proof:v1` artefact certifies the same set of constraint kinds.

## Semantics

`status: PROVEN` certifies the formal claim:

> For every assignment to the schema's properties that satisfies the schema, the policy holds.

Equivalently: no string satisfying the schema also satisfies the negation of the policy.

`status: REFUTED` certifies the formal claim:

> There exists an assignment to the schema's properties that satisfies the schema and violates the policy. The `counterexample` field gives one such assignment.

`status: UNDECIDED` reflects a solver timeout, an out-of-subset schema, or an internal error. It is informational only; consuming systems MUST treat `UNDECIDED` the same as the absence of a proof.

## Composition with `cap:v1`

A capability token may set `policy_proof_hash = proof_id` to bind the token to a specific proof. A conforming gate that consumes such a token MAY additionally verify:

- The proof artefact has `status: PROVEN`.
- The proof's `tool` matches the token's `tool`.
- The proof's `policy_hash` matches the hash of the policy implicitly defined by the token's `constraints` (or is at least as tight; see "Tightness check" below).
- The proof's `schema_hash` matches the hash of the schema the tool actually accepts.

Gates that do not perform these additional checks treat `policy_proof_hash` as an informational reference only.

### Tightness check

A token's constraints are "at least as tight" as a referenced policy if, for every constraint kind, the token's bound is at least as tight as the policy's. The lattice meet operation is the same as in `cap:v1` attenuation. A gate performing the tightness check rejects tokens whose constraints are looser than the referenced proof's policy.

## Verifier independence

`proof:v1` is **verifier-independent**: the artefact does not contain proof traces or solver-internal data. Two implementations using different SMT solvers can produce semantically-equivalent `proof:v1` artefacts that hash differently (different `prover` / `prover_version` / `notes` fields) but make identical formal claims.

Operators concerned about prover correctness MAY cross-validate by producing two `proof:v1` artefacts using different solvers and checking that both report `PROVEN`. This is the recommended deployment pattern for safety-critical applications.

## Cryptographic dependencies

- **Ed25519** signatures.
- **SHA-256** for hash fields.
- Canonical-JSON encoding identical to `cap:v1`.

## Reference implementation

MIT-licensed Python implementation in `raucle_detect/prove.py`. ~530 lines. Uses Z3 via `z3-solver`. Lean 4 mechanisation of the policy-proof composition theorem (Theorem 3 in the accompanying paper) lives in `paper/lean/VCD/Composition.lean`.

## Interoperability test vectors

- Vector 1: Trivially-PROVEN proof over a single-enum schema.
- Vector 2: REFUTED proof with concrete counterexample.
- Vector 3: PROVEN proof binding a token's `policy_proof_hash`; companion `cap:v1` token in `cap_vectors/`.
- Vector 4: Out-of-subset schema → `UNDECIDED` with informative `notes`.

## Open questions for review

1. **Schema subset.** Is the conservative subset the right starting point, or should `proof:v1` include `oneOf`/`anyOf` from the outset?
2. **Multi-solver attestation.** Should the artefact format directly support "this policy was proven by both Z3 and CVC5"? Currently expressed via two separate `proof:v1` artefacts; could be one combined artefact.
3. **Counterexample completeness.** When `status: REFUTED`, should the counterexample be the prover's witness as-is, or a normalised representative? The reference implementation produces witnesses as-is.

## What we ask of OWASP AI Exchange

Acceptance as an informational control pattern under "Tool Misuse mitigations". Specifically:

- A control entry that references this document.
- A cross-reference to the `cap:v1` control pattern, noting that `proof:v1` is the policy-completeness companion.
- Acceptance of the `proof:v1` identifier.
