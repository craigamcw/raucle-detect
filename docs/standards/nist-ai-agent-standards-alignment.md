# Raucle ↔ NIST AI Agent Standards Initiative

How **raucle**'s primitives align with the
[NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
(announced by CAISI on 17 Feb 2026), whose early related work includes an NCCoE
project / draft concept paper on **AI agent identity and authorization** —
Raucle's core lane.

> **Scope & honesty note.** The initiative is **early** — convenings, an RFI on
> agent security threats/mitigations, and an NCCoE concept paper on *agent
> identity and authorization*; the technical standards are **not yet published**.
> This document therefore makes **no conformance claim**. It is a **positioning
> and candidate-input** map: where Raucle's *shipped* primitives line up with the
> initiative's stated focus areas, and where Raucle is a candidate reference for
> the identity/authorization work. Capability/proof caveats below match
> the [OWASP mapping](owasp-agentic-top10-mapping.md) and the
> [spec](../spec/provenance/v1.md).

## The initiative (three pillars)

1. **Industry-led standards** — convenings + gap analyses informing voluntary guidelines.
2. **Community-led protocols** — lowering barriers to interoperable agent protocols (incl. open-source funding).
3. **Research investment** — agent **authentication, identity infrastructure**, and security evaluation.

A related early **NCCoE project / draft concept paper** addresses **agent
identity & authorization**, and an **RFI on agent security threats and
mitigations** ran in early 2026. (Both public comment periods have since closed
— RFI 9 Mar, concept paper 2 Apr 2026; NCCoE status: *reviewing comments*.)

## Alignment map

| NIST focus area | Raucle primitive | Status |
|---|---|---|
| **Agent identity & authentication** | An agent is an Ed25519 keypair (`AgentIdentity`); a **capability token** binds `(agent_id, tool, constraints, validity, parent)`, **signed by the issuer key** (`CapabilityIssuer`). `agent_id` is a stable, dot-scoped identifier. | **Shipped.** |
| **Authorization & delegation** | Tool calls are gated against the token's signed constraints (fail-closed). **Delegation = attenuation**: a parent mints a child that can only *narrow* permissions, never broaden; chains are verifiable link-by-link. Tokens are short-lived; **revocation** denies a token (and its descendants **when a parent resolver is configured**). | **Shipped.** |
| **Action accountability / audit** | Every step emits a content-addressed, EdDSA-signed **provenance receipt**, independently verifiable **offline** by a third party (no trust in the issuing agent required). | **Shipped.** |
| **Interoperability** | The receipt + canonicalisation are a **published, versioned spec** with **five byte-identical reference implementations** (Python/TS/Go/Rust/C#). Active cross-system interop with the A2A/APS `action_ref` work (a shared JCS+SHA-256 canonicalisation fixture). | **Shipped + in progress.** |
| **Verifiable authorization (the strong claim)** | In **strict proof mode**, a decision binds to a machine-checked policy via `policy_hash`: a Z3 proof (over **prover-encodable** keys and modelled schema fragments) that no admitted call violates the policy, with gate soundness mechanised in **Lean 4** (composition assumes prover soundness as a stated axiom). Proof binding is **opt-in**. | **Shipped (opt-in, scoped).** |
| **Security evaluation** | The paper evaluation harness (`paper/eval`) runs an executed-effect evaluation against AgentDojo-style suites (parts still scaffolded). | **Partial / evolving.** |

## Engagement on-ramp

The relevant NIST/NCCoE inputs are the **identity & authorization concept paper**
and the **agent-security RFI** (both comment periods closed in early 2026; NCCoE
is reviewing comments — watch for the next draft/comment window). Raucle is a
natural **candidate reference** for the identity/authorization work: signed,
attenuable capability tokens are a
working instance of "scoped agent authorization with verifiable delegation," and
the offline-verifiable receipt is a working instance of "auditable authorization
decisions." The interoperability pillar is where the published spec + five
reference implementations + the A2A/APS fixture give Raucle something concrete to
contribute rather than just comment on.

## Honest boundaries

- **No conformance claim** against standards that do not yet exist; this is alignment + candidate input only.
- **Delegation/revocation depth** is real but **resolver-dependent** for deep ancestry (otherwise token + immediate parent).
- **Proof binding** is opt-in (strict mode); the Z3 proof covers prover-encodable policy keys over modelled schema fragments, and the Lean composition theorem rests on a prover-soundness axiom.
- Raucle is an authorization + verifiable-audit layer — **not** an identity *provider*, a transport-security layer, or a sandbox.

---

*Companion to the [OWASP Top 10 for Agentic Applications mapping](owasp-agentic-top10-mapping.md),
the [Provenance Receipt v1 spec](../spec/provenance/v1.md), and the
[cap:v1 capability-token profile](../../standards/owasp-ai-exchange/01-capability-token.md).
Corrections welcome.*
