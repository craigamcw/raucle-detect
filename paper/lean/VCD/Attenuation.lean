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
  -- allowed_values: hq is about outer p (Tighter's q); first scrutinee is p's.
  · intro f s hq
    dsimp only
    rw [hq]
    cases hq2 : q.allowed_values f with
    | none => exact ⟨s, rfl, subset_refl _⟩
    | some a => exact ⟨s ∩ a, rfl, Finset.inter_subset_left⟩
  -- max_value: meet returns min; need min ≤ a
  · intro f a hq
    dsimp only
    rw [hq]
    cases hq2 : q.max_value f with
    | none => exact ⟨a, rfl, le_refl _⟩
    | some b => exact ⟨min a b, rfl, min_le_left a b⟩
  -- min_value: meet returns max; need a ≤ max
  · intro f a hq
    dsimp only
    rw [hq]
    cases hq2 : q.min_value f with
    | none => exact ⟨a, rfl, le_refl _⟩
    | some b => exact ⟨max a b, rfl, le_max_left a b⟩
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
  simp only [attenuate] at h
  split_ifs at h with hguard
  obtain rfl := (Option.some.inj h).symm
  rw [Bool.and_eq_true] at hguard
  refine ⟨meet_tighter _ _, ?_, rfl⟩
  exact of_decide_eq_true hguard.2

end VCD
