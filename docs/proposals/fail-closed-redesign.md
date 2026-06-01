# Proposal: fail-closed redesign of the prover, gate, and verifier

**Status:** Draft v2 — incorporates the cross-model (Codex) design review (§8); not yet implemented
**Author:** drafted 2026-06-01 after six cross-model (Codex) adversarial rounds
**Scope:** `raucle_detect/prove.py`, `raucle_detect/capability.py`, `raucle_detect/provenance.py`
**Non-goal:** this does NOT replace a human security review / pentest of the same modules.

## 1. Why

Six independent cross-model audit rounds each found real HIGH-severity issues on
current code, and two were unsound *fixes* introduced earlier in the same effort.
The findings are not unrelated — they share one root cause:

> The prover, gate, and verifier **enumerate what is bad and allow the rest**
> (blacklists, FROM/JOIN-only table scanning, permissive input parsing,
> "includes" checks). Every round found a new shape that the enumeration missed.

A non-exhaustive list of the same bug wearing different hats:

| Round | Instance | Class |
|---|---|---|
| 2 | LangChain blacklist evaporates on string-wrapped args | blacklist fails open |
| 4 | `forbidden_values` misses values nested in list/dict args | blacklist fails open |
| 5 | scalar `forbidden_values: {role:"admin"}` split into chars | input not validated |
| 3 | `JSONSchemaProver` ignores constraint fields outside the schema | enumerate-bad |
| 3→6 | `additionalProperties:false` unsound under `patternProperties` | enumerate-bad |
| 6 | SQL prover misses non-FROM table access (`COPY`, `SELECT INTO`) | enumerate-bad |
| 4/6 | `allowed_tables` union let grammar broaden policy | permissive merge |
| 6 | gate chain-walk never checked child ⊑ parent | invariant not enforced |

Patching instances has hit diminishing returns. The durable fix is to flip the
default for all three components from **allow-unless-known-bad** to
**deny/UNDECIDED-unless-known-good**.

## 2. Design principles

1. **Fail closed by default.** Any input the component does not *fully and
   soundly* understand yields the safe verdict: `DENY` (gate), `UNDECIDED`
   (prover), or reject (verifier). Never the permissive verdict on uncertainty.
2. **Whitelist the modelled surface; reject the rest, loudly.** Each component
   declares the exact inputs it can reason about. Anything outside that set is
   refused at the boundary, not silently best-effort'd.
3. **One validation chokepoint per trust boundary.** Constraints are
   schema-validated once at mint/load; receipts/headers once at parse. No
   per-field ad-hoc validation scattered across call sites (that is how the
   scalar-`forbidden_values` and collection-arg holes survived).
4. **Soundness over completeness.** It is acceptable for the prover to return
   `UNDECIDED` for a query it *could* in principle prove; it is never acceptable
   to return `PROVEN` for one it cannot. The gate may DENY a call it cannot
   prove safe; it must never ALLOW one it cannot.
5. **Every relaxation is explicit and opt-in.** Bearer-mode (no caller identity),
   ungated tools, permissive token lists — all require a named flag, default off.

## 3. Component redesigns

### 3.1 `prove.py` — provers return PROVEN only on a closed, modelled grammar

**JSON Schema prover.**
- Maintain an explicit allowlist of supported schema keywords
  (`type`, `properties`, `required`, `additionalProperties`, plus metadata).
  Any other object-level keyword (`patternProperties`, `propertyNames`, `allOf`,
  `anyOf`, `oneOf`, `not`, `if`/`then`/`else`, `$ref`, `dependentSchemas`, …) →
  the proof is `UNDECIDED`. (Implemented in round 3/6; this formalises it as the
  contract, with a single `_unsupported_schema_keywords()` guard.)
- A policy field not modelled by the schema is handled by `additionalProperties`
  semantics (already fixed), but the *default* is: if the prover cannot prove the
  field is unreachable, it is reachable.

**SQL clause prover.**
- The FROM/JOIN regex extractor is sound only for plain `SELECT`/`WITH` queries
  whose table access is entirely via `FROM`/`JOIN`. Define that as the modelled
  grammar. Anything else (`COPY`, `SELECT … INTO`, `MERGE`, table-functions,
  CTEs that write, dialect-specific forms) → `UNDECIDED` (implemented round 6;
  formalise as a single `_is_modelled_select()` gate).
- **Stretch goal (recommended):** replace the regex extractor with `sqlglot`
  (optional `[proof]` dependency) to parse the statement and enumerate every
  table reference soundly across dialects. This removes the entire class rather
  than approximating it. If adopted, the regex path becomes the fallback that
  only ever yields `UNDECIDED`.

**URL prover.** Already conservative (UNDECIDED on open grammars, apex-exclusion
fixed). Audit for the same "modelled-keyword allowlist" treatment of grammar keys.

### 3.2 `capability.py` — one constraint validator, deny-by-default gate

**Single constraint schema validator** (`_validate_constraints`), called by both
`mint()` and `Capability.from_dict()` (load). It is the only place constraints
are accepted. It enforces, per constraint kind, the exact value *shape*:
- `forbidden_values` / `allowed_values`: `{field: list[scalar]}` — reject strings,
  scalars, nested non-scalars (round-5 fix; centralise it here).
- `max_value` / `min_value`: `{field: int}` — reject floats/strings/bools.
- `starts_with`: `{field: str}`.
- `required_present`: `list[str]`.
- `forbidden_field_combinations`: `list[list[str]]`.
- Any unknown constraint key → reject (already done via `_normalise`'s unknown-key
  check; move it into the validator).
A malformed constraint is a `ValueError` at mint/load — never a silently
weakened, signed policy.

**Constraint checker (`_check_constraints`) handles values uniformly.** Flatten
collection-valued args once (round-4 fix) and apply every check to the flattened
scalar set, so no constraint kind can be bypassed by wrapping a value in a
list/dict. Positive constraints already fail closed on absent fields; keep that.

**Gate chain-walk enforces attenuation** (round-6 fix): every link must be a
valid narrowing (`_attenuation_violation`). Formalise that attenuation soundness
is checked by the gate independently of the issuer's correctness.

**Deny-by-default everywhere:** any exception evaluating a constraint is already a
DENY; extend the same posture to every new code path.

### 3.3 `provenance.py` — strict-by-default verification

Most of this is implemented across rounds 2–6; the proposal is to make it the
*documented contract* and add a single `_validate_receipt_strict()` that runs:
- JOSE header: exact `alg`/`typ`/`crit`/`kid`/`raucle/v1`, no extra keys (done).
- Canonical (JCS) byte-equality of header and payload (done, round 6).
- Payload `typ`/`iss`, required-fields-per-operation, root rule, merge arity,
  sorted/unique `parents`/`taint` (done, rounds 3/5).
- Capability-statement signature + key binding before trusting allowlists (done,
  round 4).
- Float rejection in canonical JSON (done, round 3).

**Corrections from the Codex design review (these were OVERCLAIMED above):**
- **Canonical byte-equality is Python-only.** Only `provenance.py` re-encodes and
  compares (`provenance.py:614`). The reference verifiers (`receipt.ts:232`,
  `receipt.go:306`, `receipt.rs:255`, `Receipt.cs:153`) parse and validate but do
  NOT re-encode and compare bytes — so the "all five agree" parity claim is
  currently FALSE for canonicality. Closing it requires porting the canonical
  check to all four reference impls.
- **The JSONL envelope is not strict.** `verify_chain` parses the wrapper record
  (`{receipt_hash, jws, ...}`) with plain `json.loads` (`provenance.py:1148`), so
  duplicate `receipt_hash`/`jws` keys are an envelope-malleability hole even
  though the inner JWS is strictly parsed. The envelope must use the same
  duplicate-key-rejecting parser (cf. the audit-chain fix, round-5 F2).

## 4. Migration / backward-compatibility

Flipping to fail-closed will change some outcomes. None weaken security; all are
in the safe direction, but they are behaviour changes worth a minor version bump:
- Some inputs that previously returned `PROVEN` now return `UNDECIDED` (schemas
  with unmodelled keywords, non-SELECT SQL). Callers relying on those need to
  narrow their grammar or accept UNDECIDED.
- Some malformed constraint shapes that previously minted now raise at mint.
- Non-canonical receipts that previously verified now fail (they were already
  out of spec).
Document each in CHANGELOG under a clear "stricter by default" heading; consider
a one-release deprecation window with a warning where feasible.

## 5. Test strategy

- **Fail-closed invariant tests:** property/fuzz tests asserting that for randomly
  mutated schemas/SQL/constraints/receipts, the verdict is never the permissive
  one unless the input is in the explicitly-modelled set.
- **Differential tests:** the five reference impls must agree on accept/reject for
  a corpus of valid and adversarial receipts (extend `conformance.py`).
- Keep every round-2..6 regression test (they pin the specific holes).

## 6. What this does not do

It does not prove the provers are *correct*, only that they are *conservative*.
The SMT/Lean soundness and the JOSE/JCS crypto handling still warrant a **human
security review / paid pentest** before external exposure. This redesign reduces
the attack surface to a small, explicitly-modelled core; the human review should
target that core.

## 7. Suggested sequencing

1. Review + approve this design.
2. **Build the Modelled Language Registry first (§8.1)** — every other fix hangs
   off it; it is the structural backbone, not a doc artefact.
3. Fix the three immediately-real bugs (§8.10): prover policy-key allowlist
   (decorative proof inputs), reference-verifier canonical parity, JSONL envelope
   duplicate-key rejection.
4. Implement §3.2 (capability validator + uniform checker) — highest-value, most
   self-contained.
3. Implement §3.1 (prover whitelisting; decide on the `sqlglot` stretch goal).
4. Implement §3.3 consolidation (`_validate_receipt_strict`).
5. Run a fresh Codex cross-model pass against the redesigned code (the spec above
   is the checklist).
6. Human security review of the reduced core.
7. Release (minor bump; "stricter by default" CHANGELOG section).

## 8. Revisions from the cross-model (Codex) design review

The review confirmed the direction (fail-closed is the right answer to six
enumerate-bad rounds) and surfaced gaps the v1 design missed. All accepted.

### 8.1 The central artefact: a Modelled Language Registry (NEW — top priority)

Replace the prose allowlists with one normative registry table. Every input
dimension the system reasons about has a row; each row specifies **validator,
semantics, conservative fallback, and tests**. A key not in the registry is
unreachable code-wise — adding one is impossible without filling every column.
Dimensions to cover:

| Dimension | Examples | Conservative fallback |
|---|---|---|
| JSON Schema keywords | `type, properties, required, additionalProperties` | unknown keyword → UNDECIDED |
| **Policy constraint keys (prover)** | `forbidden_values, max/min_value, required_present, forbidden_field_combinations` | unmodelled key → UNDECIDED |
| Capability constraint kinds (gate) | + `allowed_values, starts_with` | unknown key → reject at mint |
| SQL AST node types | `SELECT, WITH, FROM, JOIN, WHERE…` | unknown node → UNDECIDED |
| URL grammar keys | `schemes, hosts, path_prefixes, query_keys[_closed]` | unknown key → UNDECIDED |
| Verifier envelope fields | `receipt_hash, jws` | duplicate/unknown → reject |

### 8.2 Highest-risk gap: prover policy language ≠ gate policy language

The JSON prover encodes only `forbidden_values`/bounds/`required_present`/
`forbidden_field_combinations` (`prove.py:275,301,311`) — it does **not** model
`allowed_values` or `starts_with`, which the gate DOES enforce
(`capability.py:1140,1147`). So a policy carrying `allowed_values`/`starts_with`
can be "PROVEN" while those keys were silently ignored — **decorative proof
inputs** bound into a token's `policy_proof_hash`. Fix: the prover MUST whitelist
the *policy language*; an unmodelled policy key → UNDECIDED (never a PROVEN that
omitted it). This is the single most important change.

### 8.3 Schema-keyword rule must be semantic, not a keyword list

Property-level keywords (`pattern`, `minLength`, `const`, `format`, …) are
currently ignored (`prove.py:204` only checks top-level keys). Invariant to add:
**an ignored schema assertion is permitted only if ignoring it makes the model an
over-approximation** (i.e. the prover considers MORE inputs than the schema
allows, so a PROVEN still holds). Any keyword that narrows typing/reachability in
a way the model doesn't capture → UNDECIDED.

### 8.4 SQL: "plain SELECT/WITH via FROM/JOIN" is not a grammar

Enumerate explicit accept/reject for: quoted/qualified identifiers, table
functions, lateral joins, `UNNEST`, `VALUES`, CTE shadowing, dialect-specific
SELECT forms, `WITH` recursive/writable CTEs. **sqlglot** (stretch) is right only
with a **pinned dialect + version**, an **AST-node allowlist**, and
**unknown-node → UNDECIDED**; a parser whose tree diverges from the target DB
dialect is itself a soundness risk. Highest assurance: validate against the
target DB's own parser under a no-execute restricted role.

### 8.5 Constraint validator (§3.2) must reject non-JSON value domains

Beyond list-vs-scalar: reject non-JSON-serialisable Python types (sets, tuples,
bytes), `None` unless explicitly supported, `bool` in numeric positions, floats
anywhere in token material, field names that aren't valid syntax, and duplicate
field names after Unicode normalisation. Mixed scalar domains where `==` is
ambiguous (e.g. `1` vs `True`, `"1"` vs `1`) must be defined or rejected.

### 8.6 Collection-arg semantics must be EXACT (not just "apply every check")

For each constraint kind, define the rule for a collection-valued arg, or reject
collections for scalar constraints. E.g. `allowed_values`: pass iff **every**
element is allowed (not "any"); `max_value`: **every** scalar must be numeric and
within bound; blacklist: deny if **any** contained scalar is forbidden (current
behaviour, `capability.py:1130`). Undefined semantics here is how the round-4
hole appeared.

### 8.7 Attenuation: default-DENY on unresolved chain

Currently the gate only walks the chain when a `parent_resolver` is configured
(`capability.py:931`). A token with a `parent_id` but no resolver must **DENY**,
not silently trust issuer correctness — otherwise the redesign keeps an opt-out
hole. Also: the meet-based check (`merge(parent,child)==child`,
`capability.py:709`) is only sound if every constraint kind has a reviewed
partial order + meet; the registry (§8.1) makes adding a kind without its
validator/checker/normaliser/meet/tests impossible (keep the unknown-key
rejection at `capability.py:302`).

### 8.8 Migration: verification paths never warn-and-accept

Real-world breakage will be common (`$ref`/`oneOf`/`allOf`/`pattern` schemas;
CTEs/quoted-idents/vendor SQL; possibly tuple/set-ish constraints; non-canonical
existing receipts). The rule: **verification/gate paths reject; only
authoring/proving tools emit a compatibility warning.** No warn-and-accept on a
trust boundary.

### 8.9 Human review scope (§6 made concrete)

A human must still cover: policy/schema *intent* vs encoding; whether the gate is
actually on the execution path (off-path gate defeats everything); SQL dialect
equivalence; key distribution + revocation; proof-cache trust; operational
logging; CLI/wrapper behaviour; and whether hash-only argument recording is
sufficient for the audit story.

### 8.10 Immediately-real bugs surfaced (fix during implementation)

Not just design — these are live on `main`:
1. **Decorative proof inputs** (§8.2) — prover ignores `allowed_values`/
   `starts_with`. Soundness/claim-integrity.
2. **Reference verifiers lack canonical byte-equality** (§3.3 correction).
3. **JSONL envelope duplicate-key hole** (`provenance.py:1148`).

### 8.11 Verdict (Codex)

Right direction; fail-closed boundaries are the only sane response. Highest-risk
gap: §3.1 lacked a policy-key allowlist (§8.2). Required change before
implementation: build the Modelled Language Registry (§8.1) first; every other
fix hangs off it.
