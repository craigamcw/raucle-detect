# raucle Gateway for MCP — build spec (DRAFT, v2)

> Status: DRAFT. Generalises the Azure Foundry MCP sidecar
> ([`foundry-mcp-gateway.md`](foundry-mcp-gateway.md)). **v2 corrects a
> fundamental error in v1: gating the MCP protocol is NOT credential custody.**
> Not yet implemented.

## The correction that shapes everything

Gating MCP `tools/call` controls what the model *asks* an MCP server to do. It
does **not** control what that server *can* do: the MCP server still holds the
real downstream credential (the GitHub/Slack/Snowflake token) and can act at
startup, on a timer, or via non-tool paths with no receipt. So "no receipt = no
action" is **false** for any design that hands a long-lived credential to a
subprocess and merely proxies its JSON-RPC.

Therefore the enforcement boundary is **the downstream service credential / egress
point, not the MCP protocol.** MCP is a convenient *interface* to gate the
model's requests; custody must live one layer down.

## The claim (corrected)

> raucle holds the downstream credential. The agent and the MCP server receive
> only **per-call, short-lived, gate-scoped credentials** minted after an ALLOW —
> or reach the service only through raucle's egress proxy. A standing credential
> that could act without a receipt is never issued to anything the model
> controls.

That is custody-grade and auditor-credible. "If the host routes through us" is
not.

## Three custody mechanisms (pick per integration)

1. **Egress proxy (strongest).** raucle is the network path to the *real service
   API* (not just the MCP server). The MCP server / agent has no direct route or
   token; every call to the service passes raucle's gate and is receipted.
   **Requires an explicit network non-bypass control** (the agent/server cannot
   reach the downstream API except through raucle — egress allowlist / no direct
   route); without it this degrades to cooperation.
2. **Per-call credential broker.** raucle holds the service credential and, on
   each gate ALLOW, mints a short-lived, narrowly-scoped token (OAuth
   token-exchange, STS, signed request) for that one call. No reusable standing
   credential reaches the agent/server. The minted credential MUST be tightly
   bound — audience, scope, resource, and method/path where the service supports
   it, very short TTL, replay resistance, and ideally argument/body binding or a
   receipt nonce — or a malicious MCP server can reuse/exfiltrate it within its
   validity window. **Where the service only supports broad short-lived tokens,
   "per-call" is an overclaim**: it beats standing credentials but is not strict
   no-receipt/no-action unless paired with egress enforcement (mechanism 1).
3. **Trusted-upstream (weakest, explicit).** The upstream MCP server is contracted
   not to act independently of gated calls. Acceptable only when 1 and 2 are
   impossible; the receipt then proves cooperation, and the spec MUST say so.

A pure MCP proxy with a long-lived token in the subprocess env is **none of
these** — it is demo-grade, not custody-grade.

## The MCP relay (must be transparent and full-surface)

Whatever the custody mechanism, the MCP-facing component is a **transparent
bidirectional JSON-RPC relay**, not a `tools/call` forwarder. It MUST preserve
the full session: `initialize` + capability negotiation, request/response IDs and
ordering, notifications, server-initiated messages, `resources/*`, `prompts/*`,
`sampling`, `elicitation`, `roots`, logging, progress, cancellation, stderr
passthrough, EOF/shutdown, and timeouts. Gating is **method-aware across the
whole surface** — any method with a side effect or data egress (not only
`tools/call`; also resource reads, prompt retrieval, elicitation) is a gate point
and a receipt. A naive tools-only proxy breaks real hosts and leaves side-channels
ungated.

## Modes

**Mode B — remote reverse proxy (custody-grade; build for the core claim).**
The MCP client points at the gateway; the upstream service is reachable *only*
through it (egress proxy, mechanism 1) or the gateway brokers per-call creds
(mechanism 2). Full-surface relay over streamable-HTTP/SSE, including
server-to-client traffic. This is where "no receipt = no action" is true.

**Mode A — local stdio wrapper (demo / dogfood ONLY; explicitly non-custody).**
Host launches `raucle-mcp`, which spawns the real server over stdio and relays the
full session, gating method-aware. Useful to demo on Claude Desktop / Cursor and
to dogfood the relay + receipt format. It does **not** deliver the custody claim
unless paired with mechanism 1/2 (which stdio usually can't). Label it as such in
all copy — never sell stdio as custody-grade.

## Where the receipt is emitted

At each gated method: agent/issuer, cited policy proof, capability token chain,
the method + a **hash** of arguments (privacy by default), ALLOW/DENY. Identical
receipt format + hash-chain sink as every other raucle adapter, so a Foundry,
remote-proxy, and Claude-Desktop receipt verify the same way.

## Coverage — honest surface

Covers: service actions whose credential is custodied to raucle (mechanism 1/2),
reached via a gated MCP method. Does NOT cover: native in-process function-calling
where the agent holds the credential (→ priority-2 native decorator, same custody
problem applies — the decorator only helps if raucle brokers the credential);
non-MCP egress; any path where a standing credential lives outside raucle. The
gateway MUST warn when it detects a likely uncustodied direct-credential path.

## Reuse vs net-new

- **Reuse:** `CapabilityGate`, `CapabilityIssuer`, `HashChainSink`,
  `Ed25519Signer`, receipt format, the Foundry forwarder as the relay seed.
- **Net-new (and the real work):** the full-surface transparent JSON-RPC relay;
  method-aware gating; and the **credential architecture** (egress proxy and/or
  per-call credential broker — OAuth token-exchange / STS). The credential broker
  is the moat and the hard part, not the proxy.

## MVP order (corrected — custody before compatibility)

1. **Relay + one credential-broker integration (Mode B).** Pick one service with
   clean per-call scoping (e.g. a cloud API with STS / OAuth token-exchange).
   Prove "no receipt = no action" end-to-end for that one service. This is the
   defensible claim; build it first.
2. **Full-surface stdio relay (Mode A)** as the demo/dogfood surface, labelled
   non-custody.
3. Second and third broker integrations; `tools/list` filtering; custody-check
   warning.

## Biggest risk (named)

Building a compatibility proxy demo that works, then discovering the defensible
claim needs the harder per-server credential architecture. Mitigate by building
the credential broker for ONE service first (step 1), not the proxy matrix.
MCP-transport churn (stdio vs SSE vs streamable-HTTP) — keep the framing layer
thin, pin to the current spec.
