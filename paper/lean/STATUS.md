# Lean development — status

**Toolchain:** Lean 4.10.0 + Mathlib 4.10.0.
**Build status:** `lake build` completes cleanly. No errors. Two `sorry`s remain.

## What is verified (compiler-checked)

| Definition / Theorem | File | Status |
|---|---|---|
| `Policy` (record + lattice meet) | `VCD/Basic.lean` | type-checks |
| `Tighter` relation | `VCD/Basic.lean` | type-checks |
| `Token` (record) | `VCD/Basic.lean` | type-checks |
| `AgentId.extendsB` (Bool) | `VCD/Basic.lean` | type-checks |
| `attenuate` (function) | `VCD/Attenuation.lean` | type-checks |
| `Tighter.refl` | `VCD/Attenuation.lean` | **proved** |
| `meet_tighter` (all 6 cases) | `VCD/Attenuation.lean` | **proved** |
| `attenuation_soundness` (**Theorem 1**) | `VCD/Attenuation.lean` | **PROVED** |
| `Gate.check`, `satisfies_field`, `satisfiesArgs` | `VCD/Gate.lean` | type-checks |
| `gate_soundness` (Theorem 2) | `VCD/Gate.lean` | `sorry` |
| `tighter_implies_satisfies_field` (helper) | `VCD/Composition.lean` | `sorry` |
| `tighter_implies_satisfies` | `VCD/Composition.lean` | **proved modulo helper** |
| `policy_proof_composition` (**Theorem 3**) | `VCD/Composition.lean` | **PROVED modulo helper + gate** |

## Headline

**Theorem 1 (attenuation soundness) is fully proved.** Every constraint dimension's monotonicity is mechanically verified. The lattice meet is shown to be tighter than its left operand on all six constraint kinds (`forbidden_values`, `allowed_values`, `max_value`, `min_value`, `required_present`, `forbidden_combos`). The `attenuate` function's output is shown to satisfy the soundness theorem from the structural guard in its definition.

**Theorem 3 (policy-proof composition) is structurally proved.** The composition argument compiles against the imported axioms (`gate_soundness` and `tighter_implies_satisfies_field`). Closing those two `sorry`s closes the whole theorem.

## What's left

Two `sorry`s:

1. **`tighter_implies_satisfies_field`** (`Composition.lean`): per-field constraint monotonicity. Case analysis on `args f` (none vs some w) and on each of `q`'s constraint kinds. Each subcase applies one of the six conjuncts in `Tighter`. Estimated ~30 lines, ~1-2 hours for a Lean-fluent author.

2. **`gate_soundness`** (`Gate.lean`): walk through the eight gate checks. The structure is `cases hk : K t.key_id` then six `if-then-else` rungs in the `some` branch. `split_ifs at h with h1 h2 ...` is the right tactic but I hit hypothesis-naming issues across the negations and `decide` calls. Estimated ~40 lines, ~half a day for a Lean-fluent author.

Both proofs are conceptually straightforward and mechanically tractable. Neither needs further insight; both need fluent execution.

## How to reproduce

```bash
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
source ~/.elan/env
cd paper/lean
elan toolchain install leanprover/lean4:v4.10.0
elan default leanprover/lean4:v4.10.0
lake update           # ~5 min, fetches Mathlib + transitive deps
lake exe cache get    # ~2 min, downloads precompiled Mathlib .olean files
lake build            # ~30 sec
```

First-time disk usage: ~4.5 GB.

## Co-author handoff

The remaining two `sorry`s are the cleanest possible handoff:

- **`tighter_implies_satisfies_field`** is purely combinatorial: six subconjuncts, each a per-field application of a subset / monotonicity lemma. Anyone fluent in Lean's `Finset`/`Decidable` APIs closes this in an afternoon.
- **`gate_soundness`** is more tactical: needs the right `split_ifs` / `simp` combination to handle the `decide` calls and double-negations cleanly. Maybe a day.

A Lean co-author closing these two opens the entire trust-graph attestation argument in Section 4 of the paper.

## Notes from the iteration

The structural refactors that landed in iteration 1 (Bool-valued predicates everywhere; `satisfies` over a finite `fields` list, not `∀ String`) made iteration 2 dramatically easier. The decidable-instance synthesis problems that blocked progress in iteration 1 are entirely gone.

The key tactic insight for `meet_tighter`: after `unfold`, use `dsimp only` to expose the match, then `rw [hq]` to substitute the *first* scrutinee (because `Tighter` is `(meet p q) ⊑ p`, the hypothesis is about `p` not `q`), then `cases hq2 : q.allowed_values f` to split on the second scrutinee. The witness commits before the case-split via `⟨…, rfl, …⟩`.

The key insight for `attenuation_soundness`: `split_ifs at h` (Mathlib) targets `if` specifically, not `match`, so it doesn't get confused by the inner `match a.narrower_agent_id`. The `else` branch auto-closes because `none = some c` is decidable, so the proof only has the `then` branch.
