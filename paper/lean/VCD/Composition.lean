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

/-- Oracle property: PROVEN means every schema-conformant args satisfies the policy.
    We axiomatise the prover; its bit-level correctness is out of scope for this
    paper and treated as a trusted external dependency. -/
axiom prover_soundness
    (schema : String) (P : Policy) (fields : List FieldName) (ρ : ProofResult)
    (h : ρ.status = ProofStatus.proven) :
    ∀ args : CallArgs, SchemaLang schema args →
      Policy.satisfiesArgs P args fields = true

theorem tighter_implies_satisfies
    (p q : Policy) (args : CallArgs) (fields : List FieldName)
    (h_tight : p ⊑ q) (h_sat : Policy.satisfiesArgs p args fields = true) :
    Policy.satisfiesArgs q args fields = true := by
  sorry

theorem policy_proof_composition
    (K : TrustedIssuers) (schema : String) (P : Policy)
    (fields : List FieldName)
    (ρ : ProofResult) (t : Token) (call : Call) (now : Int)
    (h_proof   : ρ.status = ProofStatus.proven)
    (h_cite    : t.policy_proof_hash = some ρ.proof_hash)
    (h_tighter : t.constraints ⊑ P)
    (h_lang    : SchemaLang schema call.args)
    (h_gate    : Gate.check K t call now fields = .allow) :
    Policy.satisfiesArgs P call.args fields = true ∧ SchemaLang schema call.args := by
  refine ⟨?_, h_lang⟩
  have h_sound := gate_soundness K t call now fields h_gate
  obtain ⟨_, h_sat_tok, _, _, _, _⟩ := h_sound
  exact tighter_implies_satisfies _ _ _ _ h_tighter h_sat_tok

end VCD
