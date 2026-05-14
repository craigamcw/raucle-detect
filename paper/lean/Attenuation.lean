/-
  Theorem 1 — Attenuation Soundness.

  Claim: if `c` is in the image of `attenuate(p, ·)`, then c ⊑ p (c is at least
  as tight as p) along every constraint dimension, and `c.expires_at ≤ p.expires_at`.
-/

import VCD.Basic

namespace VCD

/-- A representation of the runtime `attenuate` operation: it takes a parent
    token plus an "extra" policy to merge, plus optionally a narrower TTL or
    a narrower agent-id, and returns a child token. -/
structure AttenuationInput where
  parent              : Token
  extra               : Policy
  narrower_ttl_secs   : Option Int := none
  narrower_agent_id   : Option AgentId := none
  -- Current time, used to compute the child's expiry.
  now                 : Int

/-- The attenuate function. Pure; does not perform cryptographic operations.
    The actual signing is modelled separately as a trusted post-step. -/
def attenuate (a : AttenuationInput) : Option Token :=
  let p := a.parent
  let child_constraints := Policy.meet p.constraints a.extra
  let child_agent :=
    match a.narrower_agent_id with
    | none => p.agent_id
    | some id => id
  let agent_ok :=
    a.narrower_agent_id.isNone ∨ AgentId.extends child_agent p.agent_id
  let child_exp :=
    match a.narrower_ttl_secs with
    | none => p.expires_at
    | some ttl => a.now + ttl
  let lifetime_ok := child_exp ≤ p.expires_at
  if h : agent_ok ∧ lifetime_ok then
    some {
      token_id          := ""  -- to be assigned post-canonicalisation
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

/-! ### Lattice meet establishes Tighter -/

theorem meet_tighter (p q : Policy) : (Policy.meet p q) ⊑ p := by
  unfold Policy.Tighter Policy.meet
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- forbidden_values is a union → result ⊇ p
    intro f
    -- p.forbidden_values f ⊆ p.forbidden_values f ∪ q.forbidden_values f
    sorry
  · -- allowed_values is an intersection where both defined
    sorry
  · -- max_value is the min
    sorry
  · -- min_value is the max
    sorry
  · -- required_present is a union
    sorry
  · -- forbidden_combos is a union
    sorry

/-! ### The headline theorem -/

theorem attenuation_soundness
    (a : AttenuationInput) (c : Token)
    (h : attenuate a = some c) :
    c.constraints ⊑ a.parent.constraints ∧
    c.expires_at ≤ a.parent.expires_at ∧
    c.tool = a.parent.tool ∧
    AgentId.extends c.agent_id a.parent.agent_id := by
  -- Unpack `attenuate` and case on the guard.
  unfold attenuate at h
  -- The conditional in `attenuate` ensures `agent_ok ∧ lifetime_ok` before
  -- emitting `some _`. Destructuring `h` gives us both facts.
  sorry

end VCD

/-
  Proof obligations remaining (each `sorry` above):

  1. `meet_tighter`: six straightforward lattice arguments over Finset.
     Mathlib's `Finset.subset_union_left` / `Finset.inter_subset_left`
     dispatch most of them in 2-3 lines apiece.

  2. `attenuation_soundness`: case-split the `if h : agent_ok ∧ lifetime_ok`,
     in the `some` branch use `meet_tighter` for the constraint half,
     and the guard for the expiry/agent halves.

  Estimated effort: ~150 lines, half a day for a Lean-fluent proof author.
-/
