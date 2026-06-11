# LangChain × raucle — prompt injection caught, receipt verified

A **fully runnable** demo: no API key, no network, no model download. It shows
the three things raucle adds to a LangChain agent, end to end, in ~2 seconds:

1. **A legitimate tool call passes the gate** — the user asked to pay a $45
   invoice; the in-force capability token allows exactly that.
2. **A prompt-injected tool call is blocked** — a retrieved document tells the
   agent to wire $9,900 to an attacker; the gate denies it *before execution*,
   regardless of how convincing the injection was.
3. **Both decisions are independently verifiable offline** — the signed,
   hash-chained receipt log replays for any third party, and rewriting the
   `DENY` receipt to claim `ALLOW` breaks verification.

```bash
pip install 'raucle[compliance,langchain]'
python examples/langchain_demo/demo.py
```

Expected output (abridged):

```
Scene 1 — agent calls transfer_funds({'to': 'acct:cleaner-co', 'amount': 45})
  ALLOWED by gate  -> TRANSFERRED 45 -> acct:cleaner-co

Scene 2 — agent calls transfer_funds({'to': 'acct:attacker-919', 'amount': 9900})
  DENIED by gate   -> raucle denied 'transfer_funds': constraint violated: ...

Scene 3 — offline verification of the signed receipt chain
  chain valid: True   events: 2   mode: signed
  receipt: ALLOW transfer_funds
  receipt: DENY  transfer_funds  (constraint violated: ...)
  tampered copy valid: False  (DENY flipped to ALLOW -> chain breaks)
```

## Why the "agent brain" is scripted

The model's decisions are scripted (`AGENT_PLANNED_CALLS`) so the demo is
deterministic and runs in CI as a self-test. This is not a shortcut — it is
the architectural point: **the gate never trusts the model's reasoning.** A
poisoned document and a legitimate request reach the gate through the same
LangChain callback path (`tool.run(..., callbacks=[RaucleCallbackHandler])`),
and only the Ed25519-signed constraints on the in-force token decide. Swap in
a real `create_tool_calling_agent` + LLM and the gate's behaviour is
byte-for-byte identical.

To wire a real agent, see the quick-start in
[`raucle/integrations/langchain.py`](../../raucle/integrations/langchain.py)
— the handler attaches to an `AgentExecutor` via `callbacks=[handler]`.

The exit code is a self-check (0 = allow ran, deny blocked, chain verified,
tamper detected), enforced in CI by
[`tests/test_langchain_integration.py`](../../tests/test_langchain_integration.py).
