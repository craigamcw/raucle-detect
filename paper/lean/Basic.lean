/-
  Verified Capability Discipline — data model.

  Mirrors the runtime types defined in `raucle_detect/capability.py`.
  Field names are kept identical so the structural correspondence is obvious.
-/

import Mathlib.Data.Finset.Basic
import Mathlib.Order.Lattice

namespace VCD

-- A field name is a string identifier.
abbrev FieldName := String

-- A primitive value: enough to express the supported JSON Schema fragment.
inductive Value where
  | str  : String → Value
  | num  : Int → Value     -- integers; rationals modelled as scaled ints
  | bool : Bool → Value
deriving DecidableEq, Repr

-- The supported constraint kinds. Each is a relation over (field, args).
structure Policy where
  forbidden_values  : FieldName → Finset Value := fun _ => ∅
  allowed_values    : FieldName → Option (Finset Value) := fun _ => none  -- none = unrestricted
  max_value         : FieldName → Option Int := fun _ => none
  min_value         : FieldName → Option Int := fun _ => none
  required_present  : Finset FieldName := ∅
  forbidden_combos  : Finset (Finset FieldName) := ∅

namespace Policy

/-- The pointwise lattice meet — "tightening" — used by `attenuate`. -/
def meet (p q : Policy) : Policy where
  forbidden_values := fun f => p.forbidden_values f ∪ q.forbidden_values f
  allowed_values   := fun f =>
    match p.allowed_values f, q.allowed_values f with
    | none, none => none
    | some a, none => some a
    | none, some b => some b
    | some a, some b => some (a ∩ b)
  max_value := fun f =>
    match p.max_value f, q.max_value f with
    | none, none => none
    | some a, none => some a
    | none, some b => some b
    | some a, some b => some (min a b)
  min_value := fun f =>
    match p.min_value f, q.min_value f with
    | none, none => none
    | some a, none => some a
    | none, some b => some b
    | some a, some b => some (max a b)
  required_present := p.required_present ∪ q.required_present
  forbidden_combos := p.forbidden_combos ∪ q.forbidden_combos

/-- p is tighter-or-equal to q iff p constrains at least as much as q
    along every dimension. -/
def Tighter (p q : Policy) : Prop :=
  (∀ f, q.forbidden_values f ⊆ p.forbidden_values f) ∧
  (∀ f, ∀ s, q.allowed_values f = some s →
      ∃ s', p.allowed_values f = some s' ∧ s' ⊆ s) ∧
  (∀ f a, q.max_value f = some a → ∃ a', p.max_value f = some a' ∧ a' ≤ a) ∧
  (∀ f a, q.min_value f = some a → ∃ a', p.min_value f = some a' ∧ a ≤ a') ∧
  (q.required_present ⊆ p.required_present) ∧
  (q.forbidden_combos ⊆ p.forbidden_combos)

infix:50 " ⊑ " => Tighter

end Policy

-- An agent identifier; we model the prefix-extension scope relation.
abbrev AgentId := String

def AgentId.extends (child parent : AgentId) : Prop :=
  child = parent ∨ (parent.length > 0 ∧ child.startsWith (parent ++ "."))

-- A tool identifier.
abbrev Tool := String

-- A token. `signature` is opaque here; we treat Ed25519 as a trusted oracle.
structure Token where
  token_id          : String
  agent_id          : AgentId
  tool              : Tool
  constraints       : Policy
  issued_at         : Int
  not_before        : Int
  expires_at        : Int
  parent_id         : Option String := none
  policy_proof_hash : Option String := none
  -- Opaque cryptographic fields:
  issuer            : String
  key_id            : String
  signature         : String

-- A call site: tool + concrete arguments.
abbrev CallArgs := FieldName → Option Value

structure Call where
  tool : Tool
  args : CallArgs

-- The gate's decision type.
inductive GateDecision where
  | allow
  | deny (reason : String)
deriving Repr

end VCD
