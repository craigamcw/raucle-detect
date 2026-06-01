# Lean 4 mechanisation — Verified Capability Discipline

Skeleton for the three soundness theorems referenced in `paper/DRAFT.md` §4.

**Status:** all three theorems are proved — `lake build` completes with zero
errors, zero warnings, and zero `sorry`s (see `STATUS.md`). The proofs cover the
data model and algorithms within the modelled scope (below), not the full runtime
gate.

## Files

- `Basic.lean` — data model: `Constraint`, `Policy`, `Token`, `GateDecision`.
- `Attenuation.lean` — Theorem 1: attenuation cannot broaden permissions.
- `Gate.lean` — Theorem 2: gate soundness.
- `Composition.lean` — Theorem 3: policy-proof composition.

## Build

```
elan default leanprover/lean4:v4.10.0
lake update
lake build
```

## Proof boundary (what the Lean model covers — and does not)

The mechanisation is intentionally a model of the gate, narrower than the
runtime implementation. Stating this precisely so the claim is not overread:

**Gate soundness (`Gate.lean`) models these constraint kinds:** `allowed_values`,
`forbidden_values`, `max_value`/`min_value`, `required_present`. The theorem
`gate_soundness` shows that an ALLOW implies these are satisfied over the
caller-supplied relevant-field list.

**NOT in the Lean model (enforced by the Python runtime gate + tests, not yet
mechanised):** `starts_with`, `forbidden_field_combinations`, dot-delimited
`agent_id` scope, the revocation denylist, expiry/`not_before`, signature and
issuer verification, and strict-mode proof binding. Extending the Lean `Policy`
and `Gate.check` to cover these is tracked future work.

**Composition (`Composition.lean`)** assumes prover soundness as an explicit
`axiom prover_soundness` — the Z3 provers in `prove.py` are NOT themselves
verified in Lean. Theorem 3 therefore establishes that attenuation preserves a
cited proof's policy *given* that axiom; it does not prove the prover correct.

## Trust assumptions

The mechanisation establishes correctness of the **data model and algorithms**
within the scope above. It does not mechanise:

- Ed25519 bit-level correctness (trusted oracle; see [BHB22] for an independently verified specification).
- Z3 solver soundness for the supported fragment (trusted oracle / explicit axiom; cross-validation against CVC5 recommended for production).
- The bridge from the Python implementation to the Lean model (maintained by structural correspondence; a future paper could mechanise this via PyLean or equivalent).
