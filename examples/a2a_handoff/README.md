# A2A per-skill authorisation — the open standards slot, filled

A runnable two-agent demo of the **Raucle ⇄ A2A binding**
([`standards/a2a/README.md`](../../standards/a2a/README.md)): verifiable per-skill
authorisation for Agent-to-Agent calls, with no change to A2A's wire format.

```
pip install 'raucle-detect[compliance]'
python examples/a2a_handoff/demo.py
```

## The problem

[A2A](https://a2a-protocol.org/) lets agents discover and invoke each other's
skills via an **Agent Card** — but defines no **per-skill authorisation a third
party can verify**. When agent A asks agent B to run a skill, nothing in the
protocol produces portable evidence that A was authorised, nor a verifiable
record of the hand-off. As of mid-2026 fine-grained per-skill authorisation is
still an open work item in the spec.

## The binding

- **B** advertises the extension in its Agent Card and publishes its issuer
  public key (and an optional per-skill **capability hash**) in the Card metadata.
- **A** emits a signed `agent_handoff` provenance receipt naming the skill +
  target, and attaches it to the A2A `Message` (`metadata` + `extensions`).
- **B — or any third party, offline** — verifies the receipt against A's
  published key and confirms: valid signature, canonical payload (§6),
  `operation == agent_handoff`, target matches this agent, skill is advertised,
  and (if required) the receipt cites the proven capability.

The demo shows one authorised hand-off **AUTHORISED**, then three bad ones
(unadvertised skill, missing capability, signed by a key not in A's Card) all
**REJECTED** by the same offline check.

## Why it matters

Whoever fills A2A's per-skill-authorisation slot with a portable, verifiable
mechanism sets the pattern. This binding does it with an artifact any party
checks offline against a pinned key — exactly what a regulator examining a
multi-agent workflow needs, and what an unsigned RPC or a single-vendor guardrail
cannot provide. The Python helper is `raucle_detect/a2a.py`; the TypeScript
sibling is [`reference/a2a-provenance`](../../reference/a2a-provenance), and the
receipts share the Raucle provenance header + canonical JSON, so they are
wire-compatible across implementations.
