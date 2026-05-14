# Lean development — status

**Toolchain:** Lean 4.10.0 + Mathlib 4.10.0.
**Build status:** `lake build` completes cleanly with warnings on remaining `sorry`s. No errors.

## What is verified

| Definition / Theorem | File | Status |
|---|---|---|
| `Policy` (record + lattice meet) | `VCD/Basic.lean` | type-checks |
| `Tighter` relation | `VCD/Basic.lean` | type-checks |
| `Token` (record) | `VCD/Basic.lean` | type-checks |
| `AgentId.extendsB` (Bool) | `VCD/Basic.lean` | type-checks |
| `attenuate` (function) | `VCD/Attenuation.lean` | type-checks |
| `Tighter.refl` | `VCD/Attenuation.lean` | **proved** |
| `meet_tighter` cases 1, 5, 6 (forbidden_values, required_present, forbidden_combos) | `VCD/Attenuation.lean` | **proved** |
| `meet_tighter` cases 2, 3, 4 (allowed_values, max_value, min_value) | `VCD/Attenuation.lean` | `sorry` |
| `attenuation_soundness` (Theorem 1) | `VCD/Attenuation.lean` | `sorry` |
| `Gate.check` (function) | `VCD/Gate.lean` | type-checks |
| `satisfies_field`, `Policy.satisfiesArgs` | `VCD/Gate.lean` | type-checks |
| `gate_soundness` (Theorem 2) | `VCD/Gate.lean` | `sorry` |
| `tighter_implies_satisfies` | `VCD/Composition.lean` | `sorry` |
| `policy_proof_composition` (Theorem 3) | `VCD/Composition.lean` | **proved modulo the two sorrys it cites** |

## What's left

Five `sorry`s. All are mechanical case analysis over finite cases plus the `simp` discipline to reduce `match` expressions after `cases`. The proofs are not difficult conceptually; the friction is Lean's tactic ergonomics around `match`+`cases` interaction.

Estimated effort for a Lean-fluent author: ~half a day to one day.

## How to reproduce the build

```bash
# Install Lean toolchain
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
source ~/.elan/env

cd paper/lean
elan toolchain install leanprover/lean4:v4.10.0
elan default leanprover/lean4:v4.10.0
lake update           # ~5 min, fetches Mathlib + transitive deps
lake exe cache get    # ~2 min, downloads precompiled Mathlib .olean files
lake build            # ~30 sec for the VCD files on top of cached Mathlib
```

First-time disk usage: ~4.5 GB (Mathlib is large).

## Notes for the co-author

The cleanest path to closing the three inner `meet_tighter` cases is probably:

```lean
intro f s hq
refine ⟨_, ?_, ?_⟩
case _ =>
  -- show the existential witness matches the match expression
  simp only [Policy.meet, hq]
  cases hp : p.allowed_values f <;> rfl
case _ =>
  -- show the subset relation
  ...
```

The trick is committing to the witness *before* doing the case split, so the
match-reduction proof and the subset-relation proof are separate goals.

`attenuation_soundness` will benefit from refactoring `attenuate` to lift its
guard into a named definition (so `split` finds the right `if`).
