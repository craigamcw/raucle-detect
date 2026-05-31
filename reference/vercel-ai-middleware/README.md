# @raucle/vercel-ai-middleware

Capability gating + signed [provenance receipts](https://raucle.com/spec/provenance/v1)
for **Vercel AI SDK** (`ai` ≥ 4) tool calls.

It wraps each tool's `execute` — the only path from the model's intent to a
real side effect — so every tool call is checked against a policy *before*
it runs, and every ALLOW/DENY decision emits an Ed25519-signed,
content-addressed receipt. Because receipts come from the
[TypeScript reference implementation](../provenance-ts), their IDs are
byte-identical to receipts emitted by the Python/Go/Rust/C# implementations.

## Use

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { webcrypto } from "node:crypto";
import { createRaucleSession } from "@raucle/vercel-ai-middleware";

const { privateKey } = (await webcrypto.subtle.generateKey(
  { name: "Ed25519" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;

const raucle = await createRaucleSession({
  issuer: { privateKey, iss: "https://acme.example/raucle", agentId: "agent:acme.web", keyId: "k_web1" },
  policies: {
    transferFunds: { maxValue: { amount: 10_000 }, allowedValues: { currency: ["GBP", "EUR"] } },
  },
  onReceipt: (r) => audit.append(r),   // stream to a SIEM / audit log
});

const result = await generateText({
  model: openai("gpt-4o"),
  prompt: "Pay invoice 4821",
  tools: raucle.gateTools({ transferFunds, lookupBalance }),
});
```

A tool call that violates its policy is blocked **before execution** (a
`RauclePolicyDenied` is thrown by default, or set `failClosed: false` to
return a structured denial the model can react to). Either way a signed
`guardrail_scan` receipt is emitted, chained to the session-root receipt.

## Policy

The built-in evaluator supports the capability constraint kinds:
`allowedValues`, `forbiddenValues`, `maxValue`, `minValue`,
`requiredPresent`, `forbiddenFieldCombinations` (per tool). For anything
richer — e.g. an SMT-proven policy or a hosted gate — pass a custom
`gate(toolName, args) => { decision, reason }`, which can be backed by an
HTTP call to a raucle gate service.

## Develop

```bash
# build the receipt library this depends on, then test:
(cd ../provenance-ts && npm install && npm run build)
npm install && npm test
```

The published package depends on `@raucle/provenance`; in this repo it
imports the sibling reference implementation directly. MIT-licensed.
