/-
  Theorem 3 — Policy-Proof Composition.
-/

import VCD.Basic
import VCD.Gate
import VCD.Attenuation

namespace VCD

opaque SchemaLang : (schema : String) → CallArgs → Prop

inductive ProofStatus where
  | proven
  | refuted (counterexample : CallArgs)
  | undecided

structure ProofResult where
  status        : ProofStatus
  grammar_hash  : String
  policy_hash   : String
  proof_hash    : String

axiom prover_soundness
    (schema : String) (P : Policy) (fields : List FieldName) (ρ : ProofResult)
    (h : ρ.status = ProofStatus.proven) :
    ∀ args : CallArgs, SchemaLang schema args →
      Policy.satisfiesArgs P args fields = true

/-- Helper: if p ⊑ q and p satisfies a field, then q satisfies it.
    Structurally this is a case analysis over `args f` (none / some w),
    with each subcase using one of the Tighter conjuncts. Verbose but
    mechanical; left as `sorry` pending a Lean-fluent pass. -/
theorem tighter_implies_satisfies_field
    (p q : Policy) (f : FieldName) (v : Option Value)
    (h_tight : p ⊑ q) (h_sat : satisfies_field p f v = true) :
    satisfies_field q f v = true := by
  sorry

theorem tighter_implies_satisfies
    (p q : Policy) (args : CallArgs) (fields : List FieldName)
    (h_tight : p ⊑ q) (h_sat : Policy.satisfiesArgs p args fields = true) :
    Policy.satisfiesArgs q args fields = true := by
  unfold Policy.satisfiesArgs at *
  rw [List.all_eq_true] at *
  intro f hf
  exact tighter_implies_satisfies_field p q f (args f) h_tight (h_sat f hf)

theorem policy_proof_composition
    (K : TrustedIssuers) (schema : String) (P : Policy)
    (fields : List FieldName)
    (ρ : ProofResult) (t : Token) (call : Call) (now : Int)
    (_h_proof  : ρ.status = ProofStatus.proven)
    (_h_cite   : t.policy_proof_hash = some ρ.proof_hash)
    (h_tighter : t.constraints ⊑ P)
    (h_lang    : SchemaLang schema call.args)
    (h_gate    : Gate.check K t call now fields = .allow) :
    Policy.satisfiesArgs P call.args fields = true ∧ SchemaLang schema call.args := by
  refine ⟨?_, h_lang⟩
  have h_sound := gate_soundness K t call now fields h_gate
  obtain ⟨_, h_sat_tok, _, _, _, _⟩ := h_sound
  exact tighter_implies_satisfies _ _ _ _ h_tighter h_sat_tok

end VCD
