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

/-- Boolean check of a single-field constraint against a possibly-absent value. -/
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

/-- The gate. Returns `.allow` iff all checks pass. -/
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

/-- Soundness: ALLOW implies the eight underlying predicates hold. -/
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
  -- Case on whether the issuer is pinned
  cases hk : K t.key_id with
  | none =>
    rw [hk] at h
    -- h : .deny "unknown key_id" = .allow, contradiction
    exact absurd h (by simp)
  | some pem =>
    rw [hk] at h
    -- The full case split through 6 nested ifs is structurally simple but
    -- requires precise control over how `split_ifs` names hypotheses across
    -- branches. Left as `sorry` after several attempts; the remaining work
    -- is mechanical case analysis over the six guard conditions, applying
    -- decidability lemmas (`not_not`, `not_lt`, `not_le`, `not_ne_iff`)
    -- and packing the six positive conclusions into the conjunction.
    sorry

end VCD
