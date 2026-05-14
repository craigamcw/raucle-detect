# Lean 4 mechanisation — Verified Capability Discipline

Skeleton for the three soundness theorems referenced in `paper/DRAFT.md` §4.

**Status:** structural skeleton with proof obligations marked `sorry`. Compiles under Lean 4 + Mathlib once filled in; nothing here has been machine-checked yet.

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

## Outstanding proof obligations

Each `sorry` in the files corresponds to a paragraph in the paper's Section 4. The proofs are straightforward case analyses; the work is mechanical lattice reasoning. Estimated effort: 2-3 days of focused work for someone fluent in Lean 4 + Mathlib's order-theory library.

## Trust assumptions

The mechanisation establishes correctness of the **data model and algorithms**. It does not mechanise:

- Ed25519 bit-level correctness (treated as a trusted oracle; see [BHB22] for an independently verified specification).
- Z3 solver soundness for the supported fragment (treated as a trusted oracle; cross-validation against CVC5 recommended for production).
- The bridge from the Python implementation to the Lean model (we maintain it by structural correspondence; a future paper could mechanise this via PyLean or equivalent).
