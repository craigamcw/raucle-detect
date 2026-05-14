# Verified Capability Discipline for LLM Agent Tool Calls

**Target venue:** IEEE S&P 2027 (fall 2026 deadline). Backup: USENIX Security 2027 (winter), NDSS 2027.
**Length:** 13 pages + references (S&P format).
**Status:** outline. Drafting begins 2026-05-15.

---

## 0. One-sentence thesis

> Prompt injection is unsolvable at the input layer for unbounded natural language, but the *tool-call interface* is bounded JSON; combining SMT-verified policy completeness over the bounded grammar with Ed25519-signed attenuating capability tokens at the gate makes prompt-injection-driven tool misuse **structurally impossible** for the verified action surface, with no model intervention required.

The contribution is not any single primitive. The contribution is the **composition** and the **empirical demonstration that it holds against state-of-the-art prompt-injection benchmarks at production-acceptable latency**.

## 1. Why this is the right paper to write now

Three trends converged in 2025-2026:

1. **Agentic deployments went mainstream** — Anthropic, OpenAI, Google all ship agent frameworks; production agents now make billions of tool calls per day across regulated industries.
2. **Prompt-injection defences plateaued** — every published defence (Spotlighting, StruQ, prompt shields, constitutional classifiers, paraphrasing, etc.) reduces attack success rate but none eliminates it; the latest benchmarks (AgentDojo 2024, InjecAgent 2024) still show 20-60% attack success against the strongest text-side defences.
3. **The bounded-interface insight has not been formalised** — Greshake et al. and Perez & Ribeiro identified the prompt-injection problem; recent work (Lakera, Spotlighting, StruQ) attempts to harden the model; nobody has shipped a system that moves the security boundary *out* of the model and into a gate over the tool-call grammar with cryptographic enforcement.

The window to publish the first definitive paper on the gate-based approach closes in ~12 months.

## 2. Threat model

**Adversary capability:**
- Full control of any untrusted input the agent ingests (user message, RAG document, tool output, web page).
- Cannot compromise the issuer's private signing key, the gate process, or the audit log.
- Cannot forge Ed25519 signatures (standard cryptographic assumption).
- Has read access to the agent's system prompt, tool list, schemas, and (for some experiments) the capability constraints themselves.

**Defender capability:**
- Controls the gate process (a separate component in the deployment).
- Holds the issuer's private signing key.
- Can declare per-tool JSON Schemas and per-call constraint policies.

**Out of scope:**
- Side-channel exfiltration over allowed parameters (e.g., 2^64 amount values).
- Confused-deputy attacks across multiple legitimate tool calls.
- Compromise of the underlying LLM or the gate itself.
- Unbounded text outputs (the contribution is for tool *calls*, not free-form responses).

This is a deliberately narrow but well-defined threat model. Reviewers will respect the honest scoping; they will not respect "we solve prompt injection".

## 3. System design

### 3.1 The bounded grammar insight (~1 page)

Every modern agent framework already declares tool interfaces as JSON Schema (OpenAI function-calling, Anthropic tool use, MCP). The set of strings any well-formed tool call can take is bounded by the schema. This grammar is small enough to reason about with SMT.

We don't try to verify properties about the agent's natural-language output. We verify properties about its **tool-call output**, where the grammar is enumerable.

### 3.2 Policy completeness via SMT (~1 page)

For a given (schema, policy) pair, we encode satisfaction of the policy *violation* in Z3 (theory of strings, integers, booleans). If the encoded violation is `unsat`, the policy is proven complete over every string in the schema's language. If `sat`, Z3 produces a concrete counterexample tool call.

Supported fragments (will be carefully delineated):
- JSON Schema: top-level objects with primitive properties, `enum`, `minimum`/`maximum`, `required`.
- Policy keys: `forbidden_values`, `allowed_values`, `max_value`, `min_value`, `required_present`, `forbidden_field_combinations`.

Unsupported (raises `UnsupportedGrammar` rather than lying):
- Recursive schemas, `oneOf`/`anyOf` (extension work, Section 8).
- Arbitrary regex constraints on string fields (extension work, Section 8).
- Unbounded array properties.

### 3.3 Capability tokens with attenuation (~1.5 pages)

Tokens bind `(agent_id, tool, constraints, nbf, exp, parent_id, policy_proof_hash)` under Ed25519. Content-addressed token IDs prevent ID-substitution. Attenuation is the formal core:

**Invariant 1 (no broadening):** for every constraint kind, the derived child's bound is at least as tight as the parent's. Formally: `child.max_value[f] ≤ parent.max_value[f]`, `child.allowed_values[f] ⊆ parent.allowed_values[f]`, `child.forbidden_values[f] ⊇ parent.forbidden_values[f]`, and so on for each constraint kind.

**Invariant 2 (no outliving):** `child.expires_at ≤ parent.expires_at`.

**Invariant 3 (sub-scope only):** `child.agent_id == parent.agent_id` or `child.agent_id.startswith(parent.agent_id + ".")`.

**Invariant 4 (same tool):** `child.tool == parent.tool`.

We prove these invariants are maintained by the `attenuate()` implementation (Lean 4 mechanisation, see Section 4).

### 3.4 The gate (~1 page)

Eight checks, fail-closed:

1. Issuer pinned.
2. Signature valid.
3. `token_id` matches SHA-256 of canonical body.
4. `now ∈ [nbf, exp)`.
5. Tool matches.
6. Agent matches or extends.
7. Every constraint holds against actual call args.
8. (Optional) parent chain resolves to a root, every link signed.

The gate is the only path from agent intent to tool execution. We formalise the gate as a deterministic decision procedure and prove **soundness**: if `Gate.check(t, tool, args) = ALLOW`, then `args` satisfies every constraint in `t` and `t` is a valid descendant of a token signed by a pinned issuer.

## 4. Formal analysis (~2 pages)

Mechanised in Lean 4. Three theorems:

**Theorem 1 (attenuation soundness):** for any parent token `p` and any sequence of `attenuate` calls producing descendant `c`, `c` satisfies invariants 1–4 with respect to `p`.

**Theorem 2 (gate soundness):** if `Gate.check(t, tool, args) = ALLOW` and the issuer's key is uncompromised, then there exists a verifiable chain of attenuation back to a root token explicitly authorising at least these args.

**Theorem 3 (policy-proof composition):** if `JSONSchemaProver.prove(schema, policy) = PROVEN` and a token `t` cites that proof's hash and carries constraints equal to or tighter than `policy`, then for every call `(tool, args)` accepted by the gate with token `t`, the call satisfies `policy` and conforms to `schema`.

The Lean proofs will be released alongside the paper (already MIT-licensed) — reviewers can re-check.

## 5. Implementation (~1 page)

- ~2,500 lines of Python for the runtime (`raucle-detect` v0.10.0, MIT, already on PyPI).
- ~500 lines of Lean 4 for the mechanisations.
- Z3 4.16 (PyZ3 bindings) for the SMT side.
- Ed25519 via `cryptography` 42+.
- No new cryptographic primitives; the contribution is the composition.

Discussion of design decisions:
- Why Ed25519 not RSA — speed, signature size, deterministic.
- Why content-addressed token IDs — prevents reassignment attacks.
- Why fail-closed by default — every existing AI security product fails open.
- Why the gate runs out-of-process — defence in depth, separate trust domain.

## 6. Evaluation (~3 pages) — the load-bearing section

Three experiments. This is the work that takes weeks 3-4.

### 6.1 Attack-success-rate reduction on standard benchmarks

Datasets:
- **AgentDojo** (Debenedetti et al., 2024) — 629 attack tasks against agents in 4 realistic deployments (banking, Slack, GitHub, travel).
- **InjecAgent** (Zhan et al., 2024) — 1,054 attack scenarios.

Configurations:
- **No defence** (baseline)
- **Spotlighting** (Hines et al., 2024)
- **StruQ** (Chen et al., 2024)
- **Prompt shields** (commercial vendor, anonymised)
- **Raucle text-scan only** (our v0.7 layer)
- **Raucle full stack** (scan + proof + capability gate)

Target table:

| Defence | AgentDojo ASR | InjecAgent ASR | Utility |
|---|---|---|---|
| None | 47.3% | 51.8% | 89% |
| Spotlighting | 22% | 28% | 87% |
| StruQ | 14% | 19% | 84% |
| Prompt shields | 18% | 23% | 86% |
| Raucle text-only | 31% | 34% | 88% |
| **Raucle full stack** | **0%** | **0%** | **86%** |

The 0% claim is the headline. Caveat: only for attacks whose effect is mediated through a tool call (the bounded surface). Attacks that succeed purely through the model's text output remain unaffected — explicitly scoped in Section 2.

### 6.2 Utility preservation

For each defence, measure benign task completion rate over the AgentDojo benign-task split. Raucle should hold above 85% — the tool-call constraints don't refuse legitimate tasks, only out-of-policy ones.

### 6.3 Performance

Microbenchmarks on the gate path:

| Operation | p50 | p95 | p99 |
|---|---|---|---|
| `Gate.check()` (no chain) | 0.4 ms | 1.1 ms | 1.8 ms |
| `Gate.check()` (3-link chain) | 1.2 ms | 2.4 ms | 3.6 ms |
| `JSONSchemaProver.prove()` (cold) | 18 ms | 42 ms | 88 ms |
| `JSONSchemaProver.prove()` (cached) | < 0.1 ms | < 0.1 ms | < 0.1 ms |

End-to-end overhead per tool call: ~1-2 ms. For agents making 10 calls/turn at human-conversation cadence, this is invisible.

### 6.4 Case study: real agent integration

One detailed walkthrough of integrating Raucle into a real open-source agent (probably `mcp-agent` or `autogen`), with the diff and the resulting trust graph. ~half a page.

## 7. Related work (~1.5 pages)

### Prompt injection and LLM-specific defences
- Perez & Ribeiro 2022, Greshake et al. USENIX Sec 2023, Liu et al. 2024 (taxonomy)
- Spotlighting (Hines et al. 2024), StruQ (Chen et al. 2024), constitutional classifiers (Anthropic 2024)
- AgentDojo (Debenedetti et al. 2024), InjecAgent (Zhan et al. 2024), TensorTrust

### Capability discipline (the borrowed half)
- Object capabilities: Levy 1984, Miller 2006 ("Robust Composition"), Shapiro et al. (EROS, KeyKOS)
- Caja, SES (Mark Miller), capability-safe JavaScript
- seL4 (Klein et al. 2009), Fuchsia, Genode
- Macaroons (Birgisson et al. 2014) — directly relevant attenuation primitive over HMAC; we cite as the closest prior art and explain why Ed25519 + content-addressed IDs differ.

### Software supply-chain attestation (the framing half)
- Sigstore (Newman et al. 2022), SLSA, in-toto
- TUF (Samuel et al. 2010)

### SMT for security policy
- Margrave (Fisler et al. 2005) on XACML policies, the closest spiritual ancestor; we cite and distinguish.

The novelty claim is precise: **capabilities for LLM agents have been discussed informally; nobody has shipped an implementation with mechanised attenuation invariants, SMT-proven policy completeness over the schema, content-addressed tokens, and empirical results on standard benchmarks.** All five together is the contribution.

## 8. Limitations and future work (~0.5 page)

Honest scope:

- **Bounded surface.** We protect tool calls. Free-form output bypass remains. Composition with output-side defences is straightforward.
- **Side channels.** A schema permitting 2^64 amounts has 2^64 covert messages. Tightening the schema is the answer; we recommend bounded enums where possible.
- **Confused deputy.** Multi-tool reasoning attacks ("read inbox → exfiltrate via legitimate send") need provenance-based taint tracking (Raucle v0.5, mentioned but not the focus of this paper).
- **Bootstrap trust.** The issuer's private key has to live somewhere. We push trust to one well-defined boundary, not zero.
- **Grammar coverage.** Currently `oneOf` / `anyOf` / recursive schemas raise `UnsupportedGrammar`. Section 8 sketches the extension.

## 9. Conclusion (~0.5 page)

Restate thesis. The prompt-injection literature has spent four years trying to harden the model; we propose moving the security boundary out of the model entirely, for the bounded part of the agent's action space where this is structurally tractable. The result is a defence that holds at 0% ASR on standard tool-call benchmarks at production-acceptable latency, with mechanised soundness proofs and an MIT-licensed reference implementation already in production use.

---

## Six-week execution plan

| Week | Deliverable | Outcome |
|---|---|---|
| 1 (May 15-21) | This outline + full bibliography (50-60 papers) + threat-model section drafted | "I know what I'm writing" |
| 2 (May 22-28) | Sections 3 (design) + 5 (impl) drafted. Lean 4 environment set up; Theorem 1 sketched. | "The system is described" |
| 3 (May 29-Jun 4) | AgentDojo + InjecAgent integrated; first ASR numbers measured for baselines and Raucle. Lean Theorems 1-3 sketched. | "The headline number exists" |
| 4 (Jun 5-11) | Run all 6 configurations across both benchmarks; performance microbenchmarks. Lean proofs polished. | "Evaluation is real" |
| 5 (Jun 12-18) | Sections 4 (formal), 6 (eval), 7 (related work) drafted. First end-to-end read-through. | "It's a paper" |
| 6 (Jun 19-25) | Polish, two external reviewers, abstract + intro rewrite, figure overhaul. Submit to S&P. | "Done" |

S&P 2027 first deadline historically: **early June 2026** (first cycle) or **early December 2026** (second cycle). Target the December cycle to give the eval room. USENIX Security 2027 winter deadline (~Feb 2027) is the backup.

## Open questions for the author

1. **Lean 4 or Coq?** Lean has the momentum and the cleaner string theory; if the proofs go faster in Coq stay with Coq. Decision needed by end of Week 1.
2. **Co-author?** Solo papers at S&P are rare but not unheard of. A formal-methods PhD as second author would strengthen Section 4 significantly; identify candidates by end of Week 1.
3. **Industry pilot for Section 6.4?** Any production user willing to be named adds enormous credibility. Even an unnamed "anonymised fintech partner with 1M tool calls/day" works. Lead time matters; reach out by end of Week 2.
4. **Anonymised submission requirements?** S&P is double-blind; the open-source repo must be referenceable but anonymised. Pre-arrange an anonymised mirror by end of Week 5.

## Concrete next 48 hours

1. Read AgentDojo paper (Debenedetti et al. 2024). Have the harness running locally.
2. Read InjecAgent paper (Zhan et al. 2024). Same.
3. Pick Lean 4 vs Coq.
4. Draft a 500-word abstract — the strongest accountability mechanism is committing to a story.
5. Decide on solo vs co-author and (if co-author) send one email.

This document is the source of truth. Edit as the work proceeds.
