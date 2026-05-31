# Raucle ⇄ A2A binding — verifiable per-skill authorisation for Agent-to-Agent

**Status:** Draft profile, 2026-05-31. Extension URI:
`https://raucle.com/spec/a2a/provenance/v1`.

[A2A](https://a2a-protocol.org/) lets agents discover and invoke each
other's skills via an **Agent Card** and `message/send`. What it does
not define is **per-skill authorisation that a third party can verify**:
when agent A asks agent B to run a skill, nothing in the protocol
produces portable evidence that A was *authorised* to invoke that skill,
nor a verifiable record of the hand-off. This profile fills that slot
using the [Raucle Provenance Receipt](../../docs/spec/provenance/v1.md) —
without changing A2A's wire format, by using A2A's own extension and
metadata mechanisms.

## The binding in one paragraph

An agent advertises support by declaring an `AgentExtension` with the
URI above in its Agent Card, and publishes its receipt **issuer public
key** plus an optional per-skill **capability hash** in the Card
`metadata` under that URI. When agent A invokes a skill on agent B, A
attaches a signed **`agent_handoff` provenance receipt** to the
`Message` (in `metadata`, and lists the extension URI in the message's
`extensions` field). B — or any third party, offline — verifies the
receipt against A's published key, confirms the receipt names the skill
being invoked, and (if a capability hash is declared) confirms the call
was within an authorised, policy-proven envelope. The hand-off is now
portable, attributable evidence, not an unverifiable RPC.

## 1. Agent Card declaration

Declare the extension and publish the binding parameters. A2A serves
the Agent Card at the well-known discovery path (per A2A §8).

```jsonc
{
  "name": "Acme Payments Agent",
  "url": "https://agents.acme.example/pay",
  "version": "1.4.0",
  "skills": [
    { "id": "transfer", "name": "Transfer funds", "description": "...",
      "inputSchema": { /* JSON Schema */ } }
  ],
  "extensions": [
    {
      "uri": "https://raucle.com/spec/a2a/provenance/v1",
      "description": "Signed provenance receipts + per-skill capability authorisation for inter-agent calls.",
      "version": "1",
      "required": false
    }
  ],
  "metadata": {
    "https://raucle.com/spec/a2a/provenance/v1": {
      "receipt_version": "1",
      "issuer": { "iss": "https://acme.example/raucle", "key_id": "k_pay1",
                  "public_key": "<base64 raw Ed25519 public key>" },
      "skill_capabilities": {
        "transfer": "<sha256 capability/policy hash the caller must satisfy>"
      }
    }
  }
}
```

- `issuer.public_key` is what verifiers pin to check receipts — no shared
  secret, works offline and cross-vendor.
- `skill_capabilities[skillId]` (optional) binds a skill to a *proven*
  capability/policy hash (see the provenance spec §3 + the SMT-proven
  policy in raucle-detect). Absent ⇒ receipts are emitted/verified but
  no capability envelope is enforced.

## 2. Per-call hand-off receipt

When A invokes a skill on B, A emits an `agent_handoff` receipt and
attaches it to the outgoing `Message`:

```jsonc
{
  "messageId": "…",
  "role": "ROLE_USER",
  "parts": [ /* the skill input */ ],
  "extensions": ["https://raucle.com/spec/a2a/provenance/v1"],
  "metadata": {
    "https://raucle.com/spec/a2a/provenance/v1": {
      "receipt": "<Compact JWS provenance receipt, operation=agent_handoff>"
    }
  }
}
```

The receipt payload (provenance spec §4) is `operation: "agent_handoff"`,
signed by A's issuer key, chained (`parents`) to A's session/task root,
with the target skill + callee bound in `x_`-namespaced fields:

```jsonc
{
  "iss": "https://a-corp.example/raucle", "iat": 1748736000,
  "agent_id": "agent:a-corp.orchestrator", "agent_key_id": "k_a1",
  "operation": "agent_handoff",
  "parents": ["<A's task-root receipt id>"],
  "input_hash": "<sha256 of the canonical skill input>",
  "output_hash": "<sha256 of the canonical skill input>",
  "taint": ["untrusted_user"],
  "x_a2a_skill": "transfer",
  "x_a2a_target": "https://agents.acme.example/pay"
}
```

`x_a2a_skill` / `x_a2a_target` are `x_`-extension fields — fully valid
under provenance spec §14, ignored by non-A2A verifiers.

## 3. Verification (callee, or any third party, offline)

1. Resolve A's Agent Card; read the issuer public key under the
   extension URI.
2. `verify()` the receipt JWS against that key (provenance spec §9):
   signature, `typ`, `crit`, content-addressed id.
3. Confirm `operation == "agent_handoff"`, `x_a2a_target` matches B's
   URL, and `x_a2a_skill` is one of B's advertised skills.
4. If B declares a `skill_capabilities[skill]` hash, require the receipt
   to cite a capability whose `policy_proof_hash` matches — i.e. the
   call is within a *proven* authorisation envelope, not just signed.
5. B records the receipt; it chains into B's own provenance graph, so an
   auditor can later replay the cross-agent flow end to end.

## Why this matters

A2A had 150+ participating orgs and **no per-skill authorisation slot**.
Whoever fills it with a portable, verifiable mechanism sets the pattern.
This binding does it with an artifact any party can check offline against
a pinned key — exactly what a regulator examining a multi-agent workflow
needs, and exactly what a single-vendor guardrail cannot provide. It is
proposed for upstream discussion; the reference helper that builds and
verifies these receipts is in
[`reference/a2a-provenance`](../../reference/a2a-provenance).
