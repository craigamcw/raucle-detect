# Proposal: fail-closed redesign of the prover, gate, and verifier

**Status:** Draft for review (not yet implemented)
**Author:** drafted 2026-06-01 after six cross-model (Codex) adversarial rounds
**Scope:** `raucle_detect/prove.py`, `raucle_detect/capability.py`, `raucle_detect/provenance.py`
**Non-goal:** this does NOT replace a human security review / pentest of the same modules.

## 1. Why

Six independent cross-model audit rounds each found real HIGH-severity issues on
current code, and two were unsound *fixes* introduced earlier in the same effort.
The findings are not unrelated — they share one root cause:

> The prover, gate, and verifier **enumerate what is bad and allow the rest**
> (blacklists, FROM/JOIN-only table scanning, permissive input parsing,
> "includes" checks). Every round found a new shape that the enumeration missed.

A non-exhaustive list of the same bug wearing different hats:

| Round | Instance | Class |
|---|---|---|
| 2 | LangChain blacklist evaporates on string-wrapped args | blacklist fails open |
| 4 | `forbidden_values` misses values nested in list/dict args | blacklist fails open |
| 5 | scalar `forbidden_values: {role:"admin"}` split into chars | input not validated |
| 3 | `JSONSchemaProver` ignores constraint fields outside the schema | enumerate-bad |
| 3→6 | `additionalProperties:false` unsound under `patternProperties` | enumerate-bad |
| 6 | SQL prover misses non-FROM table access (`COPY`, `SELECT INTO`) | enumerate-bad |
| 4/6 | `allowed_tables` union let grammar broaden policy | permissive merge |
| 6 | gate chain-walk never checked child ⊑ parent | invariant not enforced |

Patching instances has hit diminishing returns. The durable fix is to flip the
default for all three components from **allow-unless-known-bad** to
**deny/UNDECIDED-unless-known-good**.

## 2. Design principles

1. **Fail closed by default.** Any input the component does not *fully and
   soundly* understand yields the safe verdict: `DENY` (gate), `UNDECIDED`
   (prover), or reject (verifier). Never the permissive verdict on uncertainty.
2. **Whitelist the modelled surface; reject the rest, loudly.** Each component
   declares the exact inputs it can reason about. Anything outside that set is
   refused at the boundary, not silently best-effort'd.
3. **One validation chokepoint per trust boundary.** Constraints are
   schema-validated once at mint/load; receipts/headers once at parse. No
   per-field ad-hoc validation scattered across call sites (that is how the
   scalar-`forbidden_values` and collection-arg holes survived).
4. **Soundness over completeness.** It is acceptable for the prover to return
   `UNDECIDED` for a query it *could* in principle prove; it is never acceptable
   to return `PROVEN` for one it cannot. The gate may DENY a call it cannot
   prove safe; it must never ALLOW one it cannot.
5. **Every relaxation is explicit and opt-in.** Bearer-mode (no caller identity),
   ungated tools, permissive token lists — all require a named flag, default off.

## 3. Component redesigns

### 3.1 `prove.py` — provers return PROVEN only on a closed, modelled grammar

**JSON Schema prover.**
- Maintain an explicit allowlist of supported schema keywords
  (`type`, `properties`, `required`, `additionalProperties`, plus metadata).
  Any other object-level keyword (`patternProperties`, `propertyNames`, `allOf`,
  `anyOf`, `oneOf`, `not`, `if`/`then`/`else`, `$ref`, `dependentSchemas`, …) →
  the proof is `UNDECIDED`. (Implemented in round 3/6; this formalises it as the
  contract, with a single `_unsupported_schema_keywords()` guard.)
- A policy field not modelled by the schema is handled by `additionalProperties`
  semantics (already fixed), but the *default* is: if the prover cannot prove the
  field is unreachable, it is reachable.

**SQL clause prover.**
- The FROM/JOIN regex extractor is sound only for plain `SELECT`/`WITH` queries
  whose table access is entirely via `FROM`/`JOIN`. Define that as the modelled
  grammar. Anything else (`COPY`, `SELECT … INTO`, `MERGE`, table-functions,
  CTEs that write, dialect-specific forms) → `UNDECIDED` (implemented round 6;
  formalise as a single `_is_modelled_select()` gate).
- **Stretch goal (recommended):** replace the regex extractor with `sqlglot`
  (optional `[proof]` dependency) to parse the statement and enumerate every
  table reference soundly across dialects. This removes the entire class rather
  than approximating it. If adopted, the regex path becomes the fallback that
  only ever yields `UNDECIDED`.

**URL prover.** Already conservative (UNDECIDED on open grammars, apex-exclusion
fixed). Audit for the same "modelled-keyword allowlist" treatment of grammar keys.

### 3.2 `capability.py` — one constraint validator, deny-by-default gate

**Single constraint schema validator** (`_validate_constraints`), called by both
`mint()` and `Capability.from_dict()` (load). It is the only place constraints
are accepted. It enforces, per constraint kind, the exact value *shape*:
- `forbidden_values` / `allowed_values`: `{field: list[scalar]}` — reject strings,
  scalars, nested non-scalars (round-5 fix; centralise it here).
- `max_value` / `min_value`: `{field: int}` — reject floats/strings/bools.
- `starts_with`: `{field: str}`.
- `required_present`: `list[str]`.
- `forbidden_field_combinations`: `list[list[str]]`.
- Any unknown constraint key → reject (already done via `_normalise`'s unknown-key
  check; move it into the validator).
A malformed constraint is a `ValueError` at mint/load — never a silently
weakened, signed policy.

**Constraint checker (`_check_constraints`) handles values uniformly.** Flatten
collection-valued args once (round-4 fix) and apply every check to the flattened
scalar set, so no constraint kind can be bypassed by wrapping a value in a
list/dict. Positive constraints already fail closed on absent fields; keep that.

**Gate chain-walk enforces attenuation** (round-6 fix): every link must be a
valid narrowing (`_attenuation_violation`). Formalise that attenuation soundness
is checked by the gate independently of the issuer's correctness.

**Deny-by-default everywhere:** any exception evaluating a constraint is already a
DENY; extend the same posture to every new code path.

### 3.3 `provenance.py` — strict-by-default verification

Most of this is implemented across rounds 2–6; the proposal is to make it the
*documented contract* and add a single `_validate_receipt_strict()` that runs:
- JOSE header: exact `alg`/`typ`/`crit`/`kid`/`raucle/v1`, no extra keys (done).
- Canonical (JCS) byte-equality of header and payload (done, round 6).
- Payload `typ`/`iss`, required-fields-per-operation, root rule, merge arity,
  sorted/unique `parents`/`taint` (done, rounds 3/5).
- Capability-statement signature + key binding before trusting allowlists (done,
  round 4).
- Float rejection in canonical JSON (done, round 3).
The reference TS/Go/Rust/C# verifiers now match (round 6 F5). The contract:
**a receipt any verifier accepts, all five accept; a receipt any rejects, all reject.**

## 4. Migration / backward-compatibility

Flipping to fail-closed will change some outcomes. None weaken security; all are
in the safe direction, but they are behaviour changes worth a minor version bump:
- Some inputs that previously returned `PROVEN` now return `UNDECIDED` (schemas
  with unmodelled keywords, non-SELECT SQL). Callers relying on those need to
  narrow their grammar or accept UNDECIDED.
- Some malformed constraint shapes that previously minted now raise at mint.
- Non-canonical receipts that previously verified now fail (they were already
  out of spec).
Document each in CHANGELOG under a clear "stricter by default" heading; consider
a one-release deprecation window with a warning where feasible.

## 5. Test strategy

- **Fail-closed invariant tests:** property/fuzz tests asserting that for randomly
  mutated schemas/SQL/constraints/receipts, the verdict is never the permissive
  one unless the input is in the explicitly-modelled set.
- **Differential tests:** the five reference impls must agree on accept/reject for
  a corpus of valid and adversarial receipts (extend `conformance.py`).
- Keep every round-2..6 regression test (they pin the specific holes).

## 6. What this does not do

It does not prove the provers are *correct*, only that they are *conservative*.
The SMT/Lean soundness and the JOSE/JCS crypto handling still warrant a **human
security review / paid pentest** before external exposure. This redesign reduces
the attack surface to a small, explicitly-modelled core; the human review should
target that core.

## 7. Suggested sequencing

1. Review + approve this design.
2. Implement §3.2 (capability validator + uniform checker) — highest-value, most
   self-contained.
3. Implement §3.1 (prover whitelisting; decide on the `sqlglot` stretch goal).
4. Implement §3.3 consolidation (`_validate_receipt_strict`).
5. Run a fresh Codex cross-model pass against the redesigned code (the spec above
   is the checklist).
6. Human security review of the reduced core.
7. Release (minor bump; "stricter by default" CHANGELOG section).
