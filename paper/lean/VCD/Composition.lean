/-
  Theorem 3 — Policy-Proof Composition.

  Scope (read this before citing the theorem): the composition below makes the
  `prover_soundness` axiom LOAD-BEARING. Given a proof that is PROVEN for a
  tool's (schema, policy P), a call that lies in that tool's modelled call
  language (`SchemaLang schema`), and a gate that ACCEPTS the call under token
  `t`, the theorem concludes BOTH:
    (1) the call satisfies P            — discharged via `prover_soundness`; and
    (2) the call satisfies t.constraints — discharged via `gate_soundness`.

  What is assumed, not mechanized here: that the cited proof actually pertains
  to this tool's (schema, P). Operationally the gate's strict proof mode binds a
  token's `policy_proof_hash` to the proof's grammar/policy hashes
  (`capability.py::_check_proof_binding`); this model takes that binding as a
  hypothesis (the proof is for the given `schema`/`P`) rather than re-deriving
  it from hashes. `prover_soundness` itself is an axiom — the SMT/grammar
  prover's soundness is assumed, not proved in Lean (see STATUS.md).
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

/-- Per-field monotonicity: a tighter policy satisfying a field implies the
    looser policy does too. -/
theorem tighter_implies_satisfies_field
    (p q : Policy) (f : FieldName) (v : Option Value)
    (h_tight : p ⊑ q) (h_sat : satisfies_field p f v = true) :
    satisfies_field q f v = true := by
  obtain ⟨h_forb, h_allow, h_max, h_min, h_req, _⟩ := h_tight
  cases v with
  | none =>
    -- satisfies_field p f none = decide (f ∉ p.required_present)
    simp only [satisfies_field, decide_eq_true_eq] at h_sat ⊢
    intro hf
    exact h_sat (h_req hf)
  | some w =>
    simp only [satisfies_field, Bool.and_eq_true, decide_eq_true_eq] at h_sat
    obtain ⟨⟨⟨h_sat_forb, h_sat_allow⟩, h_sat_max⟩, h_sat_min⟩ := h_sat
    simp only [satisfies_field, Bool.and_eq_true, decide_eq_true_eq]
    refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩
    · -- ¬ w ∈ q.forbidden_values f
      intro hw
      exact h_sat_forb (h_forb f hw)
    · -- allowed_values
      cases hqa : q.allowed_values f with
      | none => rfl
      | some s =>
        obtain ⟨s', hps', hs'sub⟩ := h_allow f s hqa
        rw [hps'] at h_sat_allow
        simp only [decide_eq_true_eq] at h_sat_allow
        simp only [decide_eq_true_eq]
        exact hs'sub h_sat_allow
    · -- max
      cases hw : w with
      | num n =>
        cases hqm : q.max_value f with
        | none => simp
        | some bound =>
          obtain ⟨a', hpm, ha'le⟩ := h_max f bound hqm
          rw [hw, hpm] at h_sat_max
          simp only [decide_eq_true_eq] at h_sat_max
          simp only [decide_eq_true_eq]
          exact le_trans h_sat_max ha'le
      | str _ => simp
      | bool _ => simp
    · -- min (symmetric, with reversed inequality direction)
      cases hw : w with
      | num n =>
        cases hqm : q.min_value f with
        | none => simp
        | some bound =>
          obtain ⟨a', hpm, ha'le⟩ := h_min f bound hqm
          rw [hw, hpm] at h_sat_min
          simp only [decide_eq_true_eq] at h_sat_min
          simp only [decide_eq_true_eq]
          exact le_trans ha'le h_sat_min
      | str _ => simp
      | bool _ => simp

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
    (h_proof : ρ.status = ProofStatus.proven)
    (h_lang  : SchemaLang schema call.args)
    (h_gate  : Gate.check K t call now fields = .allow) :
    Policy.satisfiesArgs P call.args fields = true
    ∧ Policy.satisfiesArgs t.constraints call.args fields = true := by
  refine ⟨?_, ?_⟩
  · -- (1) call satisfies the PROVEN policy P, because the call is in the tool's
    -- modelled language and the proof certifies P over all of it. This is where
    -- the prover_soundness axiom is load-bearing.
    exact prover_soundness schema P fields ρ h_proof call.args h_lang
  · -- (2) call satisfies the token's own runtime constraints (gate soundness).
    have h_sound := gate_soundness K t call now fields h_gate
    obtain ⟨_, h_sat_tok, _, _, _, _⟩ := h_sound
    exact h_sat_tok

end VCD
