# 1. Hello, receipt

**Time: 5 min · Pre-req: Python 3.10+**

By the end of this tutorial you will have:

- generated an Ed25519 keypair,
- minted a capability token,
- run the gate against a tool call,
- produced a signed receipt,
- and verified that receipt's signature from the command line.

No agent framework. No LLM. No network. Just the gate and the primitives.

---

## Step 1 — install

```bash
pip install raucle-detect
```

(If `pip` complains about Python version, ensure you're on 3.10 or newer.)

---

## Step 2 — generate an issuer keypair

Issuers mint capability tokens. In production, you'd run one issuer per platform team (KYC platform, payments platform, etc.). For this tutorial we generate one inline.

Create `hello_receipt.py`:

```python
from raucle_detect.capability import CapabilityIssuer, CapabilityGate

# An issuer + its keypair. In production, persist this PEM somewhere
# safe (HashiCorp Vault, AWS KMS-wrapped, etc.). For this tutorial,
# we keep it in memory.
issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
print(f"issuer    : {issuer.issuer}")
print(f"key id    : {issuer.key_id}")
print(f"public pem: {issuer.public_key_pem[:64]}...")
```

Run it:

```bash
python3 hello_receipt.py
```

You should see your issuer identity and the first 64 chars of the Ed25519 public key.

---

## Step 3 — mint a capability token

A capability token authorises *one agent* to call *one tool*, subject to constraints.

Add to your script:

```python
token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={
        # "Only look up customer IDs that start with C-"
        "starts_with": {"customer_id": "C-"},
    },
    ttl_seconds=60,  # token expires in 60 seconds
)
print(f"\ntoken: {token}")
```

Re-run. You'll see a JSON-encoded token with `issuer`, `agent_id`, `tool`, `constraints`, `nbf`, `exp`, `signature`, and a few other fields.

The token is **signed by the issuer's private key**. Tampering with any field invalidates the signature; the gate will reject it.

---

## Step 4 — build a gate

The gate enforces tokens. It needs to know which issuers' public keys it trusts.

```python
gate = CapabilityGate(
    trusted_issuers={issuer.key_id: issuer.public_key_pem},
)
```

A gate in production is configured with the public keys of *every* trusted issuer in your organisation. An unknown issuer's tokens are rejected automatically.

---

## Step 5 — check a tool call

The agent suggests it wants to call `lookup_customer` with a specific argument. The gate decides whether to allow it:

```python
decision = gate.check(
    token,
    tool="lookup_customer",
    agent_id="agent:kyc-prod",
    args={"customer_id": "C-1042"},
)
print(f"\nallowed : {decision.allowed}")
print(f"reason  : {decision.reason}")
```

This should print `allowed : True`.

Now try a call that violates the constraint:

```python
bad_decision = gate.check(
    token,
    tool="lookup_customer",
    agent_id="agent:kyc-prod",
    args={"customer_id": "X-9999"},  # doesn't start with "C-"
)
print(f"\nallowed : {bad_decision.allowed}")
print(f"reason  : {bad_decision.reason}")
```

`allowed : False` with a reason explaining which constraint failed.

---

## Step 6 — emit a signed receipt

Receipts are the audit artefact. They're content-addressed JSON + an Ed25519 signature, written to a hash-chained log.

```python
from raucle_detect.audit import HashChainSink, Ed25519Signer

signer = Ed25519Signer.generate()
sink = HashChainSink("./receipts.log", signer=signer)

# Append a receipt for the ALLOW above:
receipt = sink.append({
    "agent_id":         "agent:kyc-prod",
    "tool":             "lookup_customer",
    "decision":         "ALLOW" if decision.allowed else "DENY",
    "reason":           decision.reason,
    "args_hash":        sink.hash_args({"customer_id": "C-1042"}),
    "policy_proof_hash": token.policy_proof_hash,
    "issuer":           issuer.issuer,
    "key_id":           issuer.key_id,
})

print(f"\nreceipt hash: {receipt['hash']}")
print(f"signature   : {receipt['signature'][:32]}...")
```

A new file `receipts.log` exists in your directory. Each line is one signed receipt. The file is **append-only and hash-chained**: each row's hash includes the previous row's hash, so tampering anywhere shows up immediately.

---

## Step 7 — verify offline

This is the bit that matters: anyone with the receipt + the signer's public key can verify it, without contacting raucle or your platform.

```bash
raucle-detect receipt verify \
    --log receipts.log \
    --pubkey "$(python3 -c 'from raucle_detect.audit import Ed25519Signer; print(Ed25519Signer.generate().public_key_pem)')" \
    --strict
```

(In a real flow, you'd publish the signer's public key alongside the receipts and the verifier loads it once. The one-liner above generates a fresh key, which won't match — use the actual `signer.public_key_pem` from your script. The intent is to show you the command shape.)

A correct invocation returns exit code 0 and prints `OK · n receipts verified · chain intact`.

---

## What you've built

A working **gated tool-call pipeline** with cryptographic accountability:

- **Capability token** — signed authorisation, agent-scoped, time-bounded, constraint-bound.
- **Gate** — enforces tokens. Sub-100 µs per check.
- **Receipt** — signed record of the decision. Hash-chained log. Verifiable offline.

The receipt is your audit artefact. Whatever you build on top — Microsoft Agent Framework, LangChain, AutoGen, custom — emits one of these per tool call.

---

## Where next

- **[2. Agent Framework integration](02-agent-framework.md)** — wire the gate into Microsoft Agent Framework's middleware chain.
- **[3. LangChain integration](03-langchain.md)** — same for LangChain / LangGraph.
- **[5. Prove a policy](06-prove-a-policy.md)** — turn `constraints={...}` into a *proof* that no string in the tool's schema can violate the policy.
- **[Receipt format spec](../../spec/receipt-v1.md)** — the on-wire format, in detail.

If you want a system-of-record for the receipts you just produced — search, share with auditors, audit-pack export — [Raucle Cloud](https://cloud.raucle.com) hosts that.
