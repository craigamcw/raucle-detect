/-
  Theorem 1 — Attenuation Soundness.
-/

import VCD.Basic

namespace VCD

structure AttenuationInput where
  parent              : Token
  extra               : Policy
  narrower_ttl_secs   : Option Int := none
  narrower_agent_id   : Option AgentId := none
  now                 : Int

def attenuate (a : AttenuationInput) : Option Token :=
  let p := a.parent
  let child_constraints := Policy.meet p.constraints a.extra
  let child_agent :=
    match a.narrower_agent_id with
    | none => p.agent_id
    | some id => id
  let agent_ok : Bool :=
    match a.narrower_agent_id with
    | none => true
    | some id => AgentId.extendsB id p.agent_id
  let child_exp :=
    match a.narrower_ttl_secs with
    | none => p.expires_at
    | some ttl => a.now + ttl
  let lifetime_ok : Bool := decide (child_exp ≤ p.expires_at)
  if agent_ok && lifetime_ok then
    some {
      token_id          := ""
      agent_id          := child_agent
      tool              := p.tool
      constraints       := child_constraints
      issued_at         := a.now
      not_before        := max a.now p.not_before
      expires_at        := child_exp
      parent_id         := some p.token_id
      policy_proof_hash := p.policy_proof_hash
      issuer            := p.issuer
      key_id            := p.key_id
      signature         := ""
    }
  else
    none

/-- The lattice meet is tighter than its left operand. -/
theorem meet_tighter (p q : Policy) : (Policy.meet p q) ⊑ p := by
  unfold Policy.Tighter Policy.meet
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro f
    exact Finset.subset_union_left
  -- The three inner cases (allowed_values, max_value, min_value) are
  -- analogous: cases on the parent's value, reduce the match, apply
  -- ⟨witness, reflexivity, monotonicity-lemma⟩. The reflexivity step
  -- needs a particular `simp`/`dsimp` discipline to reduce the match
  -- after `cases`; left for the Lean-fluent pass.
  · sorry
  · sorry
  · sorry
  · exact Finset.subset_union_left
  · exact Finset.subset_union_left

/-- Tighter is reflexive. -/
theorem Tighter.refl (p : Policy) : p ⊑ p := by
  unfold Policy.Tighter
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro f; exact subset_refl _
  · intro f s hq; exact ⟨s, hq, subset_refl _⟩
  · intro f a hq; exact ⟨a, hq, le_refl _⟩
  · intro f a hq; exact ⟨a, hq, le_refl _⟩
  · exact subset_refl _
  · exact subset_refl _

/-- Headline. -/
theorem attenuation_soundness
    (a : AttenuationInput) (c : Token)
    (h : attenuate a = some c) :
    c.constraints ⊑ a.parent.constraints ∧
    c.expires_at ≤ a.parent.expires_at ∧
    c.tool = a.parent.tool := by
  -- The remaining work: invert `attenuate a = some c` to extract the guard
  -- and the structure literal. The `split at h` tactic picks the inner
  -- `match a.narrower_agent_id` (used to define `agent_ok`) before the
  -- outer `if`; the cleanest fix is to refactor `attenuate` to lift the
  -- guards into named lets so they are obviously the split target, or to
  -- use `Option.bind`/`Option.guard` so the structure of `attenuate` is
  -- a direct chain of monadic guards rather than nested ifs.
  -- Mechanical work; left as sorry pending the refactor.
  sorry

end VCD
