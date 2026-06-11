# MCP capability-binding profiles

Additive authorization conventions for the [Model Context Protocol](https://modelcontextprotocol.io),
built on the [`cap:v1`](../owasp-ai-exchange/01-capability-token.md) token and
[Provenance Receipt v1](../../docs/spec/provenance/v1.md) specs.

| Profile | Status | What it adds |
|---|---|---|
| [`mcp-cap:v1` — Capability binding](01-capability-binding.md) | Draft 2026-06-12 | Declares gated tools + their trust anchor in `tools/list`; attaches a signed-decision receipt to each `tools/call` result. Both via MCP's `_meta`, no protocol change. |

Reference implementation: `raucle/mcp_auth.py`; conformance test
`tests/test_mcp_auth.py`. The credential-custody MCP server in
`raucle/broker/` is a conforming server.

See also the architecture proposal
[`raucle-mcp-gateway.md`](../../docs/proposals/raucle-mcp-gateway.md), which
explains why custody must live at the downstream credential, not the MCP
protocol — this profile specifies the *interface binding*; the gateway proposal
specifies *custody*.
