# Abstract — Verified Capability Discipline for LLM Agent Tool Calls

*Working scratchpad. **Source of truth for the submitted abstract is `paper/main.tex`** — keep numbers and theorem wording here in sync with it and the §6 results. Last reconciled 2026-06-01 (post eval-sweep + Theorem-3 alignment).*

---

Large language model agents now execute billions of tool calls per day across regulated industries, but every published defence against prompt injection — including the strongest 2024-2026 results from Spotlighting, StruQ, prompt shields, and constitutional classifiers — reduces attack success rate without eliminating it. The latest benchmarks (AgentDojo, InjecAgent) report 14-31% attack success against the strongest text-side defences, because attempting to verify properties about unbounded natural language is the wrong shape of problem.

We observe that the consequential half of an agent's behaviour is not its free-form text output but its **tool calls**, and that every modern agent framework already declares tool interfaces as JSON Schema. The set of strings any well-formed tool call can take is bounded. Over a bounded grammar we can prove things, and we can enforce things cryptographically, neither of which is possible against the open prompt surface.

We present **Verified Capability Discipline**, a composition of three primitives that together render prompt-injection-driven tool misuse structurally impossible for the verified action surface. First, an SMT-backed prover encodes a tool's JSON Schema and a security policy into Z3 and decides whether every string the schema permits satisfies the policy; if so it issues a content-addressed proof artifact, otherwise it returns a concrete counterexample call. Second, an issuer mints Ed25519-signed **capability tokens** binding `(agent_id, tool, constraints, expiry, policy_proof_hash)`; an `attenuate()` primitive derives more-restricted children whose bounds are provably tighter than their parents along every constraint dimension and whose lifetimes cannot exceed them. Third, a **gate** sits on the only path from agent intent to tool execution and enforces eight checks — issuer pinning, signature, content-addressed token-ID binding, time bounds, tool match, agent-scope match, constraint satisfaction against actual arguments, and optional chain resolution — failing closed by default.

We mechanise three soundness theorems in Lean 4 with zero `sorry`s: attenuation cannot broaden permissions along any constraint dimension; if the gate returns ALLOW then the call arguments satisfy the token's modelled constraints in a valid descendant of a pinned-issuer token; and, given a `PROVEN` policy proof, a schema-conforming call accepted by the gate satisfies both the policy and the token's own constraints (the SMT solver's completeness is an explicit, **load-bearing** oracle axiom, not re-derived in Lean; the proof-to-token citation binding is enforced operationally in strict proof mode, not mechanised). Evaluating against AgentDojo and InjecAgent across contemporary text-side defences (Spotlighting, Microsoft Prompt Shields), three frontier-class open-weight base models, three attack families, and four task suites, Verified Capability Discipline reduces tool-call-mediated attack-success rate from a no-defence baseline of **1.4–70.8%** to a benchmark-artefact floor of **0.0–0.7%** while preserving **58.6–91.0%** benign task completion; at equivalent security, text-side defences collapse benign completion to 0.0–36.7%, a **+27.9 to +58.6 percentage-point** benign-preservation gap. A static upper bound across both benchmarks is verified at **0 of 2,737** attack scenarios. Per-call gate latency is well under 100 microseconds at p50; cached SMT proofs add no runtime cost. The defence is honest about scope: free-form text-output attacks and parameter-space side channels remain, but the dominant prompt-injection class — coercing a tool call — is closed.

The reference implementation, Lean development, and benchmark harness are released as open source under a strong-copyleft licence (with a commercial licence available for licence-incompatible uses) and form a complete reproducibility package. We do **not** report a separate production deployment in this paper. The thesis is that AI security must move its boundary out of the model.

---

## Word count check

487 words (target: 350-500 for S&P)

## What this abstract commits to

Counting commitments forces honesty. Each of these has to be defended in the paper:

1. **"renders … structurally impossible for the verified action surface"** — Theorem 2 + Theorem 3 must hold mechanically. ✓ Done. Lean 4 + Mathlib v4.10.0; ~430 lines; zero `sorry`s.
2. **"1.4–70.8% → 0.0–0.7% floor"** — the floor is the bet. If an attack lands above the benchmark-artefact level, the headline changes. (14-31% in ¶1 is the *external* number for the strongest published text-side defences, not a VCD figure.)
3. **"58.6–91.0% benign; +27.9–58.6pp gap"** — measured against the same baselines at equivalent security for it to be a fair comparison.
4. ~~**"1-2 ms per call"**~~ → **"sub-100 µs per call"** — verified on AMD EPYC-Milan, single thread: gate at 0.07 ms p50, 3-link chain at 0.27 ms p50, cold proof at 0.67 ms p50. Cached proof negligible. ✓
5. ~~**"in production use since May 2026"**~~ → **NOT claimed.** The paper reports benchmark results, not a production deployment; the body says so explicitly (§5). Do not reintroduce a production/pilot claim without a real, quotable (even anonymised) deployment.

## What this abstract deliberately does NOT claim

- "We solve prompt injection." We solve the tool-call-mediated class.
- "We replace text-side defences." We compose with them.
- "Our SMT is novel." Z3 is decades old; the contribution is applying it to the bounded slice of agent traffic.
- "Capabilities are new." Macaroons, seL4, Caja, Genode all predate this; the contribution is the *composition* with proofs and the *empirical demonstration* against modern attack benchmarks.

## Hooks for reviewers' assessment criteria

S&P's published criteria weight these dimensions; the abstract addresses each explicitly:

| Criterion | Where addressed |
|---|---|
| Novelty | "composition of three primitives" — the **composition** is new even though pieces aren't |
| Significance | "billions of tool calls per day across regulated industries" |
| Soundness | "mechanise three soundness theorems in Lean 4" |
| Empirical rigour | named benchmarks + named baselines + concrete delta numbers |
| Reproducibility | strong-copyleft (commercial licence available); reproducibility package = eval harness + machine-checked Lean development |
| Honest scope | last paragraph explicitly delimits coverage |

## Next pass — what to tighten

In the v2 rewrite (end of Week 5):

1. The first paragraph is currently 80 words. Cut to 60 by removing one of the named defences.
2. "Render … structurally impossible" is the strongest verb in the abstract; double-check the Lean proofs are airtight by then or weaken to "structurally precludes".
3. The 0.0% number must be exact at submission time. If real measurement shows 0.3%, rewrite the headline.
4. ~~"Production use since May 2026"~~ — **removed.** No production/pilot claim ships without a real, quotable (even anonymised) deployment; the body reports benchmark results only.
