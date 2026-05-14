/-
  Theorem 3 — Policy-Proof Composition.

  Claim: if Prove(S, P) returns PROVEN with hash h, and a token t has
  policy_proof_hash = h and constraints t.constraints ⊑ P, then every call
  accepted by Gate.check with t satisfies both P and S.

  This is the link that ties the SMT-prover's claim to the gate's enforcement.
-/

import VCD.Basic
import VCD.Gate
import VCD.Attenuation

namespace VCD

-- The "schema language": the set of well-formed argument bindings.
opaque SchemaLang : (schema : String) → CallArgs → Prop

-- The prover, modelled as a trusted oracle over (schema, policy) hashes.
-- A PROVEN result means: ∀ args ∈ SchemaLang(schema). satisfies(policy, args).
inductive ProofStatus where
  | proven
  | refuted (counterexample : CallArgs)
  | undecided
deriving Repr

structure ProofResult where
  status        : ProofStatus
  grammar_hash  : String
  policy_hash   : String
  proof_hash    : String

-- The prover-oracle property we depend on.
axiom prover_soundness
    (schema : String) (P : Policy) (ρ : ProofResult)
    (h : ρ.status = ProofStatus.proven) :
    ∀ args : CallArgs, SchemaLang schema args → satisfies P args

/-! ### The composition theorem -/

theorem policy_proof_composition
    (K : TrustedIssuers) (schema : String) (P : Policy)
    (ρ : ProofResult) (t : Token) (call : Call) (now : Int)
    (h_proof   : ρ.status = ProofStatus.proven)
    (h_cite    : t.policy_proof_hash = some ρ.proof_hash)
    (h_tighter : t.constraints ⊑ P)
    (h_lang    : SchemaLang schema call.args)
    (h_gate    : Gate.check K t call now = .allow) :
    satisfies P call.args ∧ SchemaLang schema call.args := by
  -- From `h_gate` and `gate_soundness`, call.args satisfies t.constraints.
  -- From `h_tighter` (t ⊑ P) and a lattice-monotonicity lemma, args also
  -- satisfies P.
  -- `h_lang` gives the schema-conformance half directly.
  refine ⟨?_, h_lang⟩
  -- Step 1: extract the gate-soundness fact.
  have h_sound := gate_soundness K t call now h_gate
  obtain ⟨_, h_sat_tok, _, _, _, _⟩ := h_sound
  -- Step 2: tighter constraints imply satisfaction transfers.
  sorry  -- tighter_implies_satisfies lemma — see below

/-- Monotonicity of `satisfies` under the constraint lattice.
    If t ⊑ P and args satisfies t, then args satisfies P. -/
theorem tighter_implies_satisfies
    (p q : Policy) (args : CallArgs)
    (h_tight : p ⊑ q) (h_sat : satisfies p args) :
    satisfies q args := by
  unfold satisfies at h_sat ⊢
  obtain ⟨h_fields, h_combos⟩ := h_sat
  refine ⟨?_, ?_⟩
  · intro f
    -- A value forbidden under q is also forbidden under p (since q ⊆ p_forbidden);
    -- absence of violation under p implies absence under q.
    sorry
  · intro combo h_combo_q
    -- Every combo forbidden under q is also forbidden under p.
    sorry

end VCD

/-
  Proof obligations remaining:

  1. `tighter_implies_satisfies`: per-constraint-kind argument. The narrowing
     direction of the lattice (p ⊑ q means p constrains *more*) is what makes
     "satisfies p" the *stronger* property; satisfaction therefore transfers
     downward. Six small cases.

  2. `policy_proof_composition`: one application of `tighter_implies_satisfies`
     plus the schema-conformance pass-through. ~30 lines after the helper lands.

  Estimated effort: ~250 lines total, one day for a Lean-fluent author.
-/
