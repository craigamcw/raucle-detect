# Microsoft Agent Framework × raucle — end-to-end demo

This demo shows the **`RaucleFunctionMiddleware`** integration against
a real Microsoft Agent Framework agent. Two tools are registered with
the agent:

- `crm.lookup_customer` — *authorised* by the in-force capability token.
- `payments.transfer_funds` — *NOT authorised* by the same token.

The agent attempts both tool calls. The middleware:

1. Mints a capability token at session start, scoped to the
   `lookup_customer` tool only.
2. Allows the `lookup_customer` call → tool runs → emits an **ALLOW**
   receipt to the audit chain.
3. Refuses the `transfer_funds` call → tool never runs → emits a
   **DENY** receipt naming the constraint that failed.

The agent observes both outcomes. The audit log contains two signed,
hash-chained receipts that any third party can verify offline using
the issuer's published public key.

## Run

```bash
pip install 'raucle[agent-framework]'
python examples/agent_framework_demo/demo.py
```

You will see, in order:

```
─── session opens ───
  ✓ issuer key generated         (acme.bank.kyc-platform)
  ✓ token minted                 (tool=crm.lookup_customer, ttl=60s)
  ✓ token bound to session

─── agent runs ───
  Agent calls crm.lookup_customer(customer_id="C-1042")
    raucle gate:    ALLOW       (constraints satisfied)
    tool returns:   {"name": "Emma Smith", "tier": "premium"}
    receipt #1:     emitted to ./receipts.log

  Agent calls payments.transfer_funds(to="GB29...", amount=4.00)
    raucle gate:    DENY        (tool not in token's allowed-tool set)
    tool runs?:     no
    agent sees:     structured refusal
    receipt #2:     emitted to ./receipts.log

─── verifier confirms offline ───
  ✓ both receipts signature-valid against published issuer key
  ✓ ALLOW receipt's call_args_hash satisfies policy_proof_hash 4b78...
  ✓ DENY  receipt's decision_reason cites the failed constraint
  No contact with the operator required.
```

## What the demo *doesn't* require

- No OpenAI / Azure / Anthropic API key. The agent uses a deterministic
  scripted "chat client" that emits both tool calls in sequence. The
  middleware contract is what matters; the LLM is not part of the
  receipt-emission story.
- No persistent infrastructure. The audit log is a single file
  (`./receipts.log`); the issuer key is generated in-memory and
  discarded at end of run.

For a real deployment, swap the scripted chat client for an
`OpenAIChatClient` / `AzureChatClient`, persist the issuer key in an
HSM, and point the `HashChainSink` at durable storage.

## Files

- `demo.py` — the end-to-end script.
- `policies.py` — the policy fixture, the same shape AgentDojo and the
  paper's empirical eval use.
- `tools.py` — the two example tool implementations.
- `verify.py` — the offline-verifier walkthrough (the regulator path).

## Status

This demo lands milestone **M2** in
[`docs/proposals/agent-framework-middleware.md`](../../docs/proposals/agent-framework-middleware.md):
*working two-tool demo, ALLOW + DENY captured by canonical scenario,
run end-to-end inside Agent Framework's `ChatAgent`.*

Known limitations vs. production deployment (also tracked in the
proposal's Open Questions section):

- Streaming responses are recorded as the call, not the materialised
  stream. M4 fix.
- Downstream middleware mutating `context.result` after raucle has
  emitted its receipt is not detected. M4 sealed-sub-chain fix.
- Token resolution defaults to an asyncio `ContextVar`; production
  deployments will want a session-scoped resolver wired into their
  identity stack.
