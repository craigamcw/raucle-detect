/-
  Theorem 2 — Gate Soundness.
-/

import VCD.Basic

namespace VCD

abbrev TrustedIssuers := String → Option String

opaque Ed25519Verify : String → String → String → Bool
opaque Sha256Hex : String → String
opaque canonBody : Token → String

def Token.idBinds (t : Token) : Bool :=
  t.token_id = "cap:" ++ (Sha256Hex (canonBody t)).take 24

def satisfies_field (p : Policy) (f : FieldName) (v : Option Value) : Bool :=
  match v with
  | none => decide (f ∉ p.required_present)
  | some w =>
    decide (w ∉ p.forbidden_values f) &&
    (match p.allowed_values f with
     | none => true
     | some s => decide (w ∈ s)) &&
    (match w, p.max_value f with
     | .num n, some bound => decide (n ≤ bound)
     | _, _ => true) &&
    (match w, p.min_value f with
     | .num n, some bound => decide (bound ≤ n)
     | _, _ => true)

def Policy.satisfiesArgs (p : Policy) (args : CallArgs) (fields : List FieldName) : Bool :=
  fields.all (fun f => satisfies_field p f (args f))

def Gate.check
    (K : TrustedIssuers) (t : Token) (call : Call)
    (now : Int) (relevant_fields : List FieldName) : GateDecision :=
  match K t.key_id with
  | none => .deny "unknown key_id"
  | some pem =>
    if ¬ Ed25519Verify pem (canonBody t) t.signature then
      .deny "bad signature"
    else if ¬ t.idBinds then
      .deny "token_id mismatch"
    else if decide (now < t.not_before) then
      .deny "not yet valid"
    else if decide (now ≥ t.expires_at) then
      .deny "expired"
    else if t.tool ≠ call.tool then
      .deny "tool mismatch"
    else if ¬ Policy.satisfiesArgs t.constraints call.args relevant_fields then
      .deny "constraint violated"
    else
      .allow

theorem gate_soundness
    (K : TrustedIssuers) (t : Token) (call : Call) (now : Int)
    (fields : List FieldName)
    (h : Gate.check K t call now fields = .allow) :
    t.tool = call.tool ∧
    Policy.satisfiesArgs t.constraints call.args fields = true ∧
    (∃ pem, K t.key_id = some pem ∧ Ed25519Verify pem (canonBody t) t.signature = true) ∧
    t.idBinds = true ∧
    now ≥ t.not_before ∧ now < t.expires_at := by
  simp only [Gate.check] at h
  cases hk : K t.key_id with
  | none =>
    rw [hk] at h
    cases h
  | some pem =>
    rw [hk] at h
    -- Walk through six nested ifs by explicit by_cases.
    by_cases h_sig : Ed25519Verify pem (canonBody t) t.signature = true
    case neg => simp [h_sig] at h
    case pos =>
      by_cases h_id : t.idBinds = true
      case neg => simp [h_sig, h_id] at h
      case pos =>
        by_cases h_nb : now < t.not_before
        case pos => simp [h_sig, h_id, h_nb] at h
        case neg =>
          by_cases h_exp : now ≥ t.expires_at
          case pos => simp [h_sig, h_id, h_nb, h_exp] at h
          case neg =>
            by_cases h_tool : t.tool = call.tool
            case neg => simp [h_sig, h_id, h_nb, h_exp, h_tool] at h
            case pos =>
              by_cases h_sat : Policy.satisfiesArgs t.constraints call.args fields = true
              case neg => simp [h_sig, h_id, h_nb, h_exp, h_tool, h_sat] at h
              case pos =>
                exact ⟨h_tool, h_sat, ⟨pem, rfl, h_sig⟩, h_id,
                       le_of_not_lt h_nb, lt_of_not_le h_exp⟩

end VCD
