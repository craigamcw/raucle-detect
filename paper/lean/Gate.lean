/-
  Theorem 2 — Gate Soundness.

  Claim: if `Gate.check t T a = .allow` under trusted-issuer set K, then:
    (i)   t.tool = T
    (ii)  every constraint in t is satisfied by a
    (iii) the signature on t verifies under some k ∈ K
    (iv)  t.token_id binds the canonical body of t
-/

import VCD.Basic

namespace VCD

-- A trusted-issuer map, abstractly.
abbrev TrustedIssuers := String → Option String  -- key_id → public_key_pem

-- We treat Ed25519 verification as a trusted Boolean oracle.
opaque Ed25519Verify : String → String → String → Bool
-- (public_key_pem, canonical_body, signature) → verified?

-- Likewise SHA-256 canonical-body hashing.
opaque Sha256Hex : String → String

-- The canonicalisation of a token body to bytes/string.
opaque canonBody : Token → String

/-- Whether a token's id is content-addressed correctly. -/
def Token.idBinds (t : Token) : Prop :=
  t.token_id = "cap:" ++ (Sha256Hex (canonBody t)).take 24

/-- Whether a value satisfies a single-field constraint. -/
def satisfies_field (p : Policy) (f : FieldName) (v : Option Value) : Prop :=
  match v with
  | none => f ∉ p.required_present
  | some w =>
    w ∉ p.forbidden_values f ∧
    (match p.allowed_values f with
     | none => True
     | some s => w ∈ s) ∧
    (match w, p.max_value f with
     | .num n, some bound => n ≤ bound
     | _, _ => True) ∧
    (match w, p.min_value f with
     | .num n, some bound => bound ≤ n
     | _, _ => True)

def satisfies (p : Policy) (args : CallArgs) : Prop :=
  (∀ f, satisfies_field p f (args f)) ∧
  (∀ combo ∈ p.forbidden_combos, ∃ f ∈ combo, args f = none)

/-- The gate. Returns `.allow` iff all eight checks pass. -/
def Gate.check (K : TrustedIssuers) (t : Token) (call : Call) (now : Int) : GateDecision :=
  -- 1. Issuer pinned
  match K t.key_id with
  | none => .deny "unknown key_id"
  | some pem =>
    -- 2. Signature
    if ¬ Ed25519Verify pem (canonBody t) t.signature then
      .deny "bad signature"
    -- 3. token_id binds body
    else if t.token_id ≠ "cap:" ++ (Sha256Hex (canonBody t)).take 24 then
      .deny "token_id mismatch"
    -- 4. Time bounds
    else if now < t.not_before then .deny "not yet valid"
    else if now ≥ t.expires_at then .deny "expired"
    -- 5. Tool match
    else if t.tool ≠ call.tool then .deny "tool mismatch"
    -- 6. (Agent scope check omitted here when caller does not declare an id.)
    -- 7. Constraints
    else if ¬ decide (satisfies t.constraints call.args) then .deny "constraint violated"
    -- 8. (Chain resolution optional.)
    else .allow

/-! ### Soundness -/

theorem gate_soundness
    (K : TrustedIssuers) (t : Token) (call : Call) (now : Int)
    (h : Gate.check K t call now = .allow) :
    t.tool = call.tool ∧
    satisfies t.constraints call.args ∧
    (∃ pem, K t.key_id = some pem ∧ Ed25519Verify pem (canonBody t) t.signature = true) ∧
    t.idBinds ∧
    now ≥ t.not_before ∧ now < t.expires_at := by
  -- Case-split through the eight checks. Each `else` branch can only be taken
  -- when the corresponding predicate holds; the cumulative conjunction is the
  -- postcondition.
  unfold Gate.check at h
  sorry

end VCD

/-
  Proof obligations remaining:

  1. `gate_soundness`: ~200 lines of mechanical case analysis. Each guard in
     `Gate.check` either returns `.deny`, contradicting `h`, or refines the
     environment with the predicate's negation, giving us the corresponding
     conjunct of the postcondition.

  Estimated effort: ~200 lines, one day for a Lean-fluent proof author.
-/
