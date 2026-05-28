# Getting started with raucle-detect

Add raucle to your agent in **under ten minutes**.

raucle gates every tool call your agent makes, produces a cryptographically-signed receipt of every decision (ALLOW or DENY), and is **structurally** safe against prompt-injection of the tool-call path — not heuristically.

This guide is task-first. Pick a path. Run the code. You'll have a working signed receipt at the end of every track.

---

## Choose your path

| If you have… | Start here | Time |
|---|---|---|
| Just curiosity / Python + nothing else | **[1. Hello, receipt](01-hello-receipt.md)** — mint a token, run the gate, verify a signed receipt. No agent framework needed. | 5 min |
| Microsoft Agent Framework (GA April 2026) | **[2. Agent Framework](02-agent-framework.md)** — drop-in `FunctionMiddleware`. One line. | 10 min |
| LangChain / LangGraph | **[3. LangChain](03-langchain.md)** — wrap your tool list with raucle's gated wrapper. | 10 min |
| AutoGen / a custom agent loop | **[4. Custom integration](05-custom.md)** — call the gate from wherever your agent dispatches tool calls. | 10 min |
| You want to prove a policy is sound, not just configured | **[5. Prove a policy](06-prove-a-policy.md)** — SMT-backed `ProofResult`, content-addressed, citeable. | 10 min |
| Microsoft Agent Governance Toolkit | **[6. AGT backend](07-agt-backend.md)** — drop-in `ExternalPolicyBackend`. *raucle's contract merged upstream 2026-05-27.* | 10 min |

> **Already running raucle in production?** Skip to the [Operations guide](../operations/README.md) (in progress) — backup, key rotation, gate-flag fail-closed, audit-chain export.

---

## Install

```bash
# Engine only — gate, capability tokens, audit, receipts:
pip install raucle-detect

# Plus SMT prover (Z3, for prove-a-policy and counterexample extraction):
pip install 'raucle-detect[proof]'

# Plus Microsoft Agent Framework adapter:
pip install 'raucle-detect[agent-framework]'

# Everything:
pip install 'raucle-detect[all]'
```

Python 3.10+. macOS / Linux / Windows.

---

## What raucle replaces

If you've spent any time on AI agent security in 2026 you've seen the same three patterns:

- **Heuristic prompt-injection classifiers** (Lakera Guard, Microsoft Prompt Shields, AWS Bedrock policy controls). Detect-and-block. Best-case 86% recall on text. Cannot establish a bound. Their published log says *"we think it's fine"*; a regulator wants *evidence*.
- **Constitutional rules in the system prompt.** Asks the model politely. Surrenders to anything the attacker can negotiate around. Provides nothing to an auditor.
- **Permission systems retrofitted onto LLM output.** Authorise based on the model's claim about what it's about to do, after the model has been compromised.

raucle replaces **the safe part of the agent loop** — the actual tool dispatch — with a verified gate. The LLM's role shrinks to *suggesting* a tool call. The gate decides whether it runs, citing a token, a policy proof, and a Lean theorem. The receipt of that decision is what an auditor sees.

This is structural. The attack surface for tool misuse becomes 0 of 2,737 catalogued scenarios across AgentDojo and InjecAgent, with a formal upper bound proving why. The mechanism is independent of the LLM, the prompt, the attacker's vocabulary.

---

## How this guide is organised

Every tutorial ends with the same artefact: **a signed receipt printed to your terminal**, plus the exact shell command to verify its signature offline. If your receipt verifies, raucle is doing what it says.

The receipts you produce here use **your own Ed25519 keypair**, generated locally. raucle's open-source engine never phones home — there's no telemetry, no licence check, no network call on the hot path.

Optional: when you want a system-of-record for receipts (search, share with auditors, audit-pack export), [Raucle Cloud](https://cloud.raucle.com) hosts that. The runtime gate stays local.

---

## Common questions while you're here

**Does raucle replace my existing prompt-injection defence?**
No, it stacks. The heuristic shields stop *speech*; raucle stops *action*. Run shields if you've got them — they're complementary. The strongest configuration is shields + raucle.

**Does it slow my agent?**
Sub-100 µs per gate decision (p50) on commodity hardware. Indistinguishable in end-to-end agent wall time; on three of eight measured open-weight models, raucle-enabled agents finish *faster* than the no-defence baseline because the gate terminates attacker-induced reasoning loops early.

**Open-source licence?**
AGPL-3.0-or-later. Self-hosting inside a single organisation for internal use — the dominant use case — is unaffected. Commercial licences available from `commercial@raucle.com` for use that's incompatible with AGPL terms.

**Does it work without Z3 / cryptography / etc.?**
The gate and capability layer need only the standard library + the `cryptography` package. The SMT prover needs Z3 (via the `[proof]` extra). Receipt verification anywhere downstream needs only `python3 + cryptography`.

---

Ready? Start with **[1. Hello, receipt](01-hello-receipt.md)**.
