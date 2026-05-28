# 5. Prove a policy

**Time: 10 min · Pre-req: `pip install 'raucle-detect[proof]'` (pulls Z3)**

Every other product in this space says "we have policies." Raucle's policies can be **proven**: an SMT solver decides whether *every string the tool's JSON Schema admits* satisfies the policy, or produces a concrete counterexample call as the refutation.

By the end of this tutorial you will have:

- written a tool's JSON Schema,
- written a policy over that schema (forbidden values, max amount, required fields),
- proven the policy holds with `JSONSchemaProver`,
- extracted a counterexample when it doesn't,
- minted a capability token citing the proof's content-address,
- produced a receipt that an auditor can verify *and* re-prove offline.

---

## Why this matters

A configured policy says "we set max_value to 10000."
A proven policy says "no input satisfying the JSON Schema can exceed 10000, regardless of the LLM's intent or the attacker's prompt — here is the SMT proof, content-addressed, citeable, re-checkable offline."

The difference is what an auditor needs.

---

## Step 1 — install with the proof extra

```bash
pip install 'raucle-detect[proof]'
```

This pulls in `z3-solver` (Microsoft Research's SMT solver). Add `[proof]` to your existing extras — it composes with `[agent-framework]`, `[compliance]`, etc.

---

## Step 2 — define the tool's JSON Schema

A `lookup_customer` tool that takes a customer ID and an optional fields list:

```python
schema = {
    "type": "object",
    "properties": {
        "customer_id": {
            "type": "string",
            "pattern": "^C-[0-9]+$",  # must start C- followed by digits
        },
        "fields": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["name", "address", "phone", "ssn"],
            },
        },
    },
    "required": ["customer_id"],
}
```

The prover reads this. It understands `type`, `enum`, `pattern` (a bounded subset), `minimum`/`maximum` for numbers, `required`, `properties`, and a few more — see the spec at `docs/spec/json-schema-proof-v1.md` for the exact decidable subset.

---

## Step 3 — write the policy

We don't want the `ssn` field exposed without elevated trust:

```python
policy = {
    # No field-list ever includes "ssn".
    "forbidden_values": {
        "fields": ["ssn"],
    },
}
```

`forbidden_values` is the simplest policy form. Others (full list in `docs/spec/policy-v1.md`):

- `allowed_values`: complement — only listed values are permitted.
- `max_value` / `min_value`: numeric bounds.
- `required_present`: tuples of fields that must coexist when one does.
- `forbidden_field_combinations`: tuples that must not coexist.

---

## Step 4 — prove it

```python
from raucle_detect.proof import JSONSchemaProver

prover = JSONSchemaProver()
result = prover.prove(schema=schema, policy=policy, timeout_ms=5000)

print(f"status            : {result.status}")  # PROVEN | REFUTED | UNDECIDED
print(f"prover            : {result.prover} {result.prover_version}")
print(f"grammar hash      : {result.grammar_hash}")
print(f"policy hash       : {result.policy_hash}")
print(f"content-address   : {result.hash}")
```

Expected output:

```
status            : PROVEN
prover            : raucle.json-schema 0.9.0
grammar hash      : sha256:abc123...
policy hash       : sha256:def456...
content-address   : sha256:9f8a...
```

That `content-address` is what your tokens cite. It's a hash over the (status, prover, grammar_hash, policy_hash, counterexample, notes) tuple — content-addressed, deterministic, citeable in receipts.

---

## Step 5 — break it on purpose

Drop the `enum` constraint on `fields` so the schema admits arbitrary strings, but keep the policy forbidding `"ssn"`:

```python
schema["properties"]["fields"]["items"].pop("enum")

result = prover.prove(schema=schema, policy=policy, timeout_ms=5000)
print(f"status            : {result.status}")
if result.status == "REFUTED":
    print("counterexample    :")
    print("  ", result.counterexample)
```

Output:

```
status            : REFUTED
counterexample    :
   {'customer_id': 'C-0', 'fields': ['ssn']}
```

The prover **constructed a concrete call** that satisfies the schema but violates the policy. This is the counterexample you'd hand to whoever wrote the schema — it's actionable, not abstract.

(With the `enum` constraint back in place, no string in the schema admits `"ssn"` in `fields`, so the policy is provably watertight.)

---

## Step 6 — cite the proof in a capability token

A token cites the proof by its content-address:

```python
from raucle_detect.capability import CapabilityIssuer

issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")

# Re-prove with the enum in place
schema["properties"]["fields"]["items"]["enum"] = ["name", "address", "phone", "ssn"]
result = prover.prove(schema=schema, policy=policy)

token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={
        "forbidden_values": {"fields": ["ssn"]},
    },
    ttl_seconds=300,
    policy_proof_hash=result.hash,   # <— cites the proof
)
```

Every receipt emitted under this token carries `policy_proof_hash` pointing at `result.hash`. Downstream, an auditor:

1. Fetches the receipt.
2. Fetches the published proof artefact at that hash from the issuer's policy registry.
3. Verifies the receipt's signature.
4. Re-runs the proof on their own Z3 to confirm soundness.
5. Inspects the cited Lean theorem (`VCD.TokenCitingProofConforms`) which says: *if a token cites a proof of a policy P over schema S, every call the gate accepts under that token satisfies P.*

That's the full chain. The receipt is provable, not merely declared.

---

## Step 7 — publish the proof

For an auditor to step 2 above, the proof has to be reachable. The simplest publication is a file under your issuer's `.well-known`:

```bash
mkdir -p /var/www/.well-known/raucle-policies
# Re-run the prove + dump:
python3 -c "
from raucle_detect.proof import JSONSchemaProver
import json, sys
prover = JSONSchemaProver()
schema = $schema_python
policy = $policy_python
result = prover.prove(schema=schema, policy=policy)
sys.stdout.write(result.to_canonical_json())
" > /var/www/.well-known/raucle-policies/$(python3 -c '...hash...').json
```

Now any receipt citing that hash points at a reachable artefact. (We're skipping the issuer-signature on the proof file for tutorial brevity; the production-grade pattern is in `docs/operations/publish-policy-registry.md`.)

If you're using [Raucle Cloud](https://cloud.raucle.com), the registry is hosted for you and the URL is auto-populated into every receipt's `verification_pointers.policy_registry`.

---

## What you've built

A policy that is **structurally enforced**, not configured. The auditor can re-prove it without trusting raucle. The cite-chain — token → proof artefact → Lean theorem — is what makes the difference between "we set max_value=10000" and "we hold a proof that max_value=10000 is satisfied for every well-formed call."

---

## Where next

- **[Policy recipes](../guides/policy-recipes.md)** — patterns: amount caps, regex allowlists, required-field-combination rules, "no SSN unless elevated capability".
- **[URLPolicyProver](../guides/url-policy.md)** — same idea, for URL allowlists (require_https, host_allowlist with wildcards, max_path_depth).
- **[SQLClauseProver](../guides/sql-policy.md)** — same idea, for bounded SQL templates (forbidden_tokens, allowed_tables).
- **[Lean development](../../paper/README.md)** — the soundness theorems backing the prover (`VCD.GateAllowImpliesPolicy`, `VCD.TokenCitingProofConforms`).

If you'd rather author policies in a UI with a live "Prove" button and a counterexample browser, that's [Raucle Cloud's](https://cloud.raucle.com) Policies workspace (phase 5b — shipping shortly).
