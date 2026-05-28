# 2. Microsoft Agent Framework integration

**Time: 10 min · Pre-req: Python 3.10+, an Agent Framework agent.**

Add raucle to a Microsoft Agent Framework agent in one line of middleware.

By the end you'll have:

- raucle's `RaucleFunctionMiddleware` registered on a `ChatAgent`,
- a capability token primed for the session,
- every tool call producing a signed receipt,
- denied calls short-circuited cleanly via the framework's documented `MiddlewareTermination` path.

This is the **recommended integration** for AI-agent platforms on Microsoft's stack. The Agent Framework GA'd 2026-04-03; raucle's middleware is verified against `agent-framework` 1.6+.

---

## Step 1 — install

```bash
pip install 'raucle-detect[agent-framework]'
```

This pulls in `agent-framework>=1.6` alongside the raucle engine.

---

## Step 2 — your existing agent (no raucle)

For comparison, here's a vanilla Agent Framework agent with one tool:

```python
from agent_framework import ChatAgent, tool

@tool(approval_mode="never_require")
def lookup_customer(customer_id: str) -> str:
    # In production, this hits your customer DB.
    return f"Customer {customer_id}: name=Alice, status=active"

agent = ChatAgent(
    chat_client=...,           # your model client
    tools=[lookup_customer],
)
```

This is the baseline. Tool calls dispatch directly. There is no record of *who* asked, *which* policy authorised it, or *what* arguments were inspected. An auditor sees nothing.

---

## Step 3 — add raucle

Five lines of changes:

```python
from agent_framework import ChatAgent, tool
from raucle_detect.capability import CapabilityIssuer, CapabilityGate
from raucle_detect.audit import HashChainSink, Ed25519Signer
from raucle_detect.integrations.agent_framework import (        # NEW
    RaucleFunctionMiddleware,                                    # NEW
    set_in_force_token,                                          # NEW
)                                                                # NEW

# Issuer + gate. In production these are persisted; we generate
# inline for the tutorial.
issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

# Receipt sink — signed, hash-chained log file.
signer = Ed25519Signer.generate()
sink   = HashChainSink("./receipts.log", signer=signer)

@tool(approval_mode="never_require")
def lookup_customer(customer_id: str) -> str:
    return f"Customer {customer_id}: name=Alice, status=active"

agent = ChatAgent(chat_client=..., tools=[lookup_customer])
agent.middleware.add(                                            # NEW
    RaucleFunctionMiddleware(gate=gate, sink=sink),              # NEW
)                                                                # NEW
```

That's the integration. The middleware sits between `agent.run()` and the tool dispatch; every tool call passes through it.

---

## Step 4 — prime a session token

A *session* — one user conversation, one agent invocation, one batch job — runs under one capability token. Mint it when the session opens:

```python
token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={
        # Restrict customer-ID prefix
        "starts_with": {"customer_id": "C-"},
    },
    ttl_seconds=300,  # 5 minutes
)
set_in_force_token(token)
```

`set_in_force_token` binds the token to the current asyncio context, so concurrent sessions get independent tokens automatically. The middleware reads it on every tool call.

If your platform mints a fresh token per HTTP request, call `set_in_force_token` at the top of each request handler — same idea.

---

## Step 5 — run the agent

```python
import asyncio

async def main():
    reply = await agent.run("Look up customer C-1042 for me, please.")
    print(reply)

asyncio.run(main())
```

The agent's LLM produces a function call to `lookup_customer(customer_id="C-1042")`. The middleware:

1. Reads the in-force capability token from the context.
2. Calls `gate.check(token, tool="lookup_customer", agent_id=..., args={"customer_id":"C-1042"})`.
3. Constraint passes (`C-1042` starts with `C-`). Decision = ALLOW.
4. Appends a signed receipt to `receipts.log`.
5. Allows the framework to dispatch the actual tool.

The output is the agent's reply, exactly as before.

---

## Step 6 — see a denial

Ask for a customer ID that violates the constraint:

```python
async def main():
    reply = await agent.run("Look up customer X-9999.")
    print(reply)

asyncio.run(main())
```

The LLM still produces a function call to `lookup_customer(customer_id="X-9999")`. But:

1. The gate finds the constraint violated. Decision = DENY.
2. The middleware appends a signed DENY receipt.
3. The middleware raises `MiddlewareTermination` with a structured refusal payload — the documented Agent Framework path for short-circuiting a tool call.
4. The framework returns the refusal to the LLM.
5. The LLM produces a natural-language refusal to the user.

No PR. No prompt-engineering. The malicious call **structurally cannot execute** — the gate is on the only code path to the tool.

---

## Step 7 — read the receipts

`receipts.log` now has at least two lines (one ALLOW + one DENY). Each line is one signed receipt:

```bash
head -2 receipts.log
```

You'll see two JSON objects with:

- `agent_id`, `tool`, `decision`, `reason`
- `policy_proof_hash` (cited from the token)
- `args_hash` (sha256 of the actual call args — the args themselves stay local)
- `signature` (Ed25519 over the canonical-JSON receipt)
- `prev_hash`, `this_hash` (the hash-chain — tampering anywhere shows up downstream)

Verify the chain:

```bash
raucle-detect receipt verify --log receipts.log --pubkey <PEM>
```

Exit 0 = every receipt's signature is valid and the chain is intact.

---

## Step 8 — optionally ship receipts to Raucle Cloud

If you want a system-of-record — searchable list, audit-pack export, share-link to a regulator — point the sink at Raucle Cloud's ingest endpoint:

```python
from raucle_detect.audit import CloudSink

sink = CloudSink(
    api_base="https://api.raucle.com",
    api_key="rk_...",  # from cloud.raucle.com → Settings → API keys
    signer=signer,
)
agent.middleware.add(RaucleFunctionMiddleware(gate=gate, sink=sink))
```

Same hash chain, same signature semantics — the cloud just stores and indexes the receipts. The gate still runs locally; no hot-path network call. **Self-hosters can skip this entirely**; the gate works without cloud.

(`CloudSink` ships in raucle-detect v0.13.0+. If you're on v0.12.x, use `HashChainSink` and run an upload job nightly — example in `docs/operations/upload-receipts-to-cloud.md`.)

---

## What you've built

A Microsoft Agent Framework agent where **every tool call is gated by a capability token and produces a signed receipt**. Prompt-injection attacks against the tool-call surface — instructing the LLM to call a sensitive tool with attacker-supplied arguments — are now structurally blocked, not heuristically discouraged.

The receipt is what an auditor sees. It cites the issuer, the policy proof hash, the Lean theorem identifier, the agent ID, the tool, the args hash, the decision, and a timestamp. They verify it offline with `python3 + cryptography`. No vendor trust required.

---

## Where next

- **[5. Prove a policy](06-prove-a-policy.md)** — produce a `policy_proof_hash` that demonstrates *no* string in the tool's schema can violate the constraints. Every receipt citing this proof inherits the guarantee.
- **[6. AGT backend](07-agt-backend.md)** — run raucle as a Microsoft Agent Governance Toolkit `ExternalPolicyBackend`. The contract for this merged upstream on 2026-05-27.
- **[Tightening constraints](../guides/constraint-recipes.md)** — patterns for common gating needs: amount caps, regex allowlists, time-of-day rules, two-person rule.
- **[Backup + key rotation](../operations/key-rotation.md)** — production operations.

If you want to share a session's receipts with a regulator — time-limited URL, no auditor login, verifier bundle download — that's [Raucle Cloud's](https://cloud.raucle.com) `Share` feature.
