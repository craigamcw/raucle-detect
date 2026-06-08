# Raucle ↔ OWASP Top 10 for Agentic Applications (2026)

This document maps **raucle-detect**'s primitives to the
[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
(published Dec 2025, risk codes **ASI01–ASI10**), so a security reviewer can see
exactly which risk each Raucle control addresses — and, just as importantly,
where Raucle is **not** the right control.

> **Honesty note.** Raucle is an **authorization + verifiable-audit** layer, not a
> sandbox, a model-alignment technique, or a content scanner for every modality.
> The "Posture" column below is deliberate: **Prevent** (an action is refused
> before it happens), **Prove** (a machine-checked completeness guarantee),
> **Detect** (a signal is raised), **Audit** (an independently verifiable record
> is produced), or **Partial / out of scope**. We do not claim Prevent where we
> only Audit. ASI titles/IDs track the 2026 release; confirm against the
> canonical OWASP document for any compliance use.

## Raucle primitives referenced below

| Primitive | What it is |
|---|---|
| **Capability gate + token** (`raucle_detect.capability`) | Ed25519-signed, attenuable pre-action authorization: a tool refuses to run unless the call satisfies the token's signed constraints. Fail-closed by default. |
| **Constraint prover** (`raucle_detect.prove`, Z3) + **Lean 4 theorems** | Proves *no well-formed call admitted by the tool's input schema can satisfy a policy violation* (a property of the envelope, settled ahead of time); attenuation + gate soundness are mechanised in Lean. |
| **Provenance receipts** (`raucle_detect.provenance`) | Compact-JWS (EdDSA), content-addressed, taint-tracking chain-of-custody; every step (`model_call`, `tool_call`, `retrieval`, `agent_handoff`, `sanitisation`, …) is signed and independently verifiable offline. |
| **Guardrail / multimodal scanning** (`raucle_detect` scanners) | Detects injection / hidden-instruction patterns in inputs and retrieved content; emits a signed `guardrail_scan` receipt with a ruleset hash. |
| **Revocation + attenuation** | Token denylist (revokes a compromised agent's tokens *and* descendants when a resolver is wired); children can only narrow, never broaden. |

## The mapping

| ID | Risk | Raucle control | Posture |
|---|---|---|---|
| **ASI01** | Agent Goal Hijack | A hijacked goal still cannot invoke a tool outside the agent's **signed capability constraints** — the gate enforces authorization independently of the (possibly poisoned) objective. Untrusted input is **taint-tagged** and the attempt is recorded in a signed receipt. | **Prevent** (tool-action blast radius) + **Audit**. *Does not* prevent the hijack of the model's reasoning itself. |
| **ASI02** | Tool Misuse & Exploitation | Capability **constraints bind tool arguments** (`allowed_values`, `max_value`, `forbidden_field_combinations`, …); the **Z3 prover** certifies the policy admits no violating call over the declared schema; **Lean** proves gate soundness. | **Prevent** + **Prove**. |
| **ASI03** | Identity & Privilege Abuse | `agent_id` is dot-scoped and cannot over-authorize descendants (`agent:a` ≠ `agent:a..evil`); tokens are short-lived; **attenuation** only narrows; **revocation** denies a compromised identity and its children. | **Prevent**. |
| **ASI04** | Agentic Supply-Chain Vulnerabilities | Provenance receipts **content-address and sign** every step (incl. `ruleset_hash`, grammar/policy hashes; optional TEE attestation), so tampering or substitution in the tool/plugin/MCP chain is **detectable after the fact**. | **Audit / Attest** — *not* a dependency vetter or sandbox. |
| **ASI05** | Unexpected Code Execution | If code-exec is exposed as a **gated tool**, its arguments are constrained and the invocation is recorded; otherwise Raucle only provides a post-hoc receipt. Raucle does **not** sandbox execution. | **Partial / out of scope** (use a sandbox as the primary control; Raucle adds authorization + audit). |
| **ASI06** | Memory & Context Poisoning | **Taint propagation**: untrusted/retrieved content is tagged and the tag flows monotonically through the chain — only an explicit, signed `sanitisation` receipt may clear it. **Guardrail scanning** flags injected instructions in retrieved content; `retrieval` receipts record the corpus. | **Detect** + **Audit** (poison provenance). |
| **ASI07** | Insecure Inter-Agent Communication | `agent_handoff` receipts are **EdDSA-signed and content-addressed**; the A2A binding publishes a per-skill **capability hash** on the Agent Card so a recipient can pin what it is accepting. | **Authenticate / Audit** inter-agent messages (transport encryption is the network layer's job). |
| **ASI08** | Cascading Failures | The provenance **DAG** lets an operator trace propagation across agents/tools **back to the root cause**, and counterfactual replay scopes the blast radius. | **Audit / Trace** — enables rapid containment, does not itself stop propagation. |
| **ASI09** | Human–Agent Trust Exploitation | Receipts are **independently verifiable offline** by a third party: an auditor confirms "this action was authorized against a *proven* policy and here is the evidence" rather than trusting the agent's self-report. This is Raucle's core thesis. | **Audit / Verify**. |
| **ASI10** | Rogue Agents | A content-addressed, signed provenance chain plus **revocation** (deny a compromised agent's tokens and descendants) gives cross-session detection and containment of an agent acting harmfully while appearing legitimate. | **Detect / Contain / Audit**. |

## Where Raucle is strong vs. complementary

- **Strong / primary control:** ASI02 (tool misuse — Prevent + Prove), ASI03 (identity/privilege — Prevent), ASI09 (human trust — Verify), ASI01 (tool blast-radius — Prevent), ASI10 (rogue agents — Contain).
- **Audit / detection layer (pairs with another primary control):** ASI04, ASI06, ASI07, ASI08.
- **Out of scope as a primary control:** ASI05 (use a code sandbox; Raucle adds authorization + an audit receipt).

## Why this matters

Raucle clusters tightly on the **authorization, identity, and verifiable-audit**
half of the agentic threat model — the half where "the agent promised it
behaved" must become "here is offline-verifiable proof it was authorized." For
the risks it does not prevent, it provides the **evidence trail** a responder or
auditor needs. Pairing Raucle with a sandbox (ASI05) and dependency vetting
(ASI04) covers the remainder.

---

*Maintained alongside the [Provenance Receipt v1 spec](../spec/provenance/v1.md)
and the [cap:v1 capability-token profile](../../standards/owasp-ai-exchange/01-capability-token.md).
Corrections welcome — open an issue if a posture reads as an overclaim.*
