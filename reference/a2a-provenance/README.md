# @raucle/a2a-provenance

Verifiable **per-skill authorisation for [A2A](https://a2a-protocol.org/)**
(Agent-to-Agent), via signed [provenance receipts](../../docs/spec/provenance/v1.md).

A2A lets agents discover and invoke each other's skills but defines no
portable, third-party-verifiable authorisation for those calls. This
helper fills that slot **without changing A2A's wire format** — using
A2A's own `extensions` + `metadata` — per the
[binding profile](../../standards/a2a/README.md).

```ts
import { raucleAgentCardExtension, raucleCardMetadata, emitHandoff,
         attachToMessage, verifyHandoff, exportPublicKeyB64 } from "@raucle/a2a-provenance";

// Caller A advertises support + its issuer key on its Agent Card:
card.extensions = [raucleAgentCardExtension()];
card.metadata   = raucleCardMetadata({ iss, keyId, publicKey: await exportPublicKeyB64(pub) });

// On invoking B's skill, A emits an agent_handoff receipt and attaches it:
const receipt = await emitHandoff({ issuer, skill: "transfer", targetUrl: B.url, input, parents: [taskRootId] });
const message = attachToMessage(a2aMessage, receipt);

// B (or any third party, offline) verifies it against A's published key:
const { ok, skill, reason } = await verifyHandoff(receiptJws, callerCard, calleeCard);
```

`verifyHandoff` checks: the receipt's signature against the caller's
pinned key, `operation == agent_handoff`, the target matches this agent,
the skill is one this agent advertises, and — if the callee binds the
skill to a proven capability hash — that the receipt cites it. 6 tests
cover the happy path + forged-key / wrong-target / unadvertised-skill /
missing-capability rejections.

Built on [`../provenance-ts`](../provenance-ts); receipts are
byte-identical to the Python/Go/Rust/C# implementations. MIT-licensed.
Build the sibling first: `(cd ../provenance-ts && npm i && npm run build)`.
