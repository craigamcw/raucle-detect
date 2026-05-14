# Self-review — DRAFT v1

Read of `paper/DRAFT.md` as an S&P reviewer would. Issues recorded here for the v2 pass.

## Major (would cause reject or major revision)

1. **The 0% ASR claim is the entire paper. If it does not survive empirical measurement at sub-1%, the framing collapses.** Mitigations:
   - Make sure the AgentDojo harness is run on the *latest* version (the benchmark gets updated; reviewers will check).
   - Run with multiple base models (Claude Sonnet 4.6 + GPT-4o + Llama 3.1) so the result is not specific to one provider.
   - Pre-register the exact policy and schema for every tool in AgentDojo's deployments before measurement, so reviewers cannot accuse over-fitting.

2. **The "tool-call-mediated" caveat is doing enormous work.** Reviewers will probe: what fraction of AgentDojo attacks are tool-call-mediated, and what fraction are pure-output? If the answer is "most are tool-mediated", we have a strong paper. If it is closer to half, the 0% claim sounds less impressive and we need to be louder about it in the intro. Action: compute this fraction during eval and add a sentence in §1 or §6.

3. **Threat model is missing the gate-process integrity assumption.** Reviewers will ask: what if the model can RCE into the gate via a Python deserialisation bug? Section 2 says the gate is "out of scope" but doesn't articulate what the gate must do to maintain its trust boundary. Add a paragraph: gate runs in a separate process with no eval/exec on agent input, issuer key in HSM, audit log on append-only storage.

4. **No comparison to "tool authentication" baselines.** Spotlighting / StruQ are model-side defences; a fair comparison should include a *non-model-side* baseline such as "OpenAI's function-calling allowlist + parameter-type-checking." The honest framing is "we are not the first to add gate enforcement; we are the first to add provably-complete gate enforcement with attenuation invariants." Action: find a representative non-formal gate baseline (e.g., LangChain's `RestrictedPython` or LiteLLM's policy hooks) and benchmark it. Without this, reviewers will land on "this is just authn for tools."

5. ~~**Lean development is a structural skeleton, not a verified artefact.**~~ **Resolved (2026-05-14).** Full mechanisation lands in `paper/lean/`. 353 lines, zero `sorry`s, compiles under Lean 4.10.0 + Mathlib 4.10.0. All three theorems closed.

## Medium (would cause revision)

6. **Macaroons differentiation is underweighted.** §7.2 mentions Macaroons in one paragraph. Macaroons reviewers will ask: *exactly* what is the technical delta? Add a one-paragraph comparison table with: cryptographic substrate (Ed25519 vs HMAC-SHA256), discoverability (signatures verifiable without issuer secret vs require secret), revocation, content-addressed IDs, and the SMT-policy citation primitive (we have it; Macaroons don't).

7. **No ablation.** Reviewers want to know: which component contributes how much to the ASR delta? Add an ablation row:

   | Configuration | ASR |
   |---|---|
   | Capability gate only (no proof) | `[TBD]` |
   | Proof only (constraints checked at runtime, no capability) | `[TBD]` |
   | Both | `[TBD ≤ 0.5]%` |

   Ablation is one of the four things SoK reviewers always ask for. Cheap to add to the eval matrix.

8. **The "production use" claim must be substantiated.** Single sentence in §5 saying "in production use since May 2026" is not enough. Either:
   - Provide a real deployment quote (anonymised), or
   - Replace with "deployed in our reference test harness processing X tool calls during the evaluation window."
   The second is honest and adequate; the first is much stronger but requires a pilot.

9. **Performance numbers must be on multiple hardware.** Apple M-series only is suspicious. Add a Linux x86_64 row (cloud VM, e.g. AWS m7i.large) and an ARM server row. Same code, three rows; ten minutes of work if the harness is ready.

10. **Section 6.5 (Negative Results) is hidden too deep.** The honest scoping needs to be visible in the intro and at the start of the eval, not at the end. Promote a sentence to §1 and §6.1.

## Minor (copy-edit / clarity)

11. The phrase "structurally impossible" appears twice. S&P style prefers "structurally precluded" (more rigorous register). Apply throughout.

12. §3.4 is currently one paragraph; expand to a figure showing the four hashes and three signatures forming the trust graph. Reviewers love figures. Add a Tikz/Mermaid diagram.

13. §7's "the work conceptually closest to ours is Shi et al. [SLW+24]" — verify this citation exists and represents what I claim. Otherwise replace with a known-real citation.

14. The intro's third paragraph names "Claude Sonnet 4.6" — in the anonymised submission this could be model-fingerprinting. Either keep (S&P allows naming public models) or move to §5.

15. References missing publication years on a few entries. Pass through bibtex and audit.

## Structural

16. **No figures yet.** Target 4-5: (a) system architecture diagram, (b) trust-graph hashes/signatures diagram, (c) gate-decision flowchart, (d) ASR comparison bar chart, (e) latency CDF. Mermaid → PDF via puppeteer is sufficient for the camera-ready.

17. **No abstract committed in the draft itself** — currently lives in `paper/ABSTRACT.md`. Paste it in at the top of `DRAFT.md` before the next pass.

18. **No acknowledgments section.** S&P expects one even for solo papers (advisors, reviewers, anonymous shepherds). Hold blank until submission.

## What's actually strong

Worth recognising as not-to-touch:

- The thesis is tight and defensible.
- The threat model's explicit out-of-scope items will protect against reviewer overclaim accusations.
- The Lean theorems are real claims, not motte-and-bailey.
- The related-work section engages substantively with Macaroons, seL4, Margrave, Sigstore — reviewers will see this is a paper that has read its history.

## Priority for v2

1. Fix the gate-integrity gap in §2 (Major #3).
2. Add the tool-call-mediated fraction sentence in §1 and §6 (Major #2).
3. Add ablation row to §6 (Medium #7).
4. Strengthen the Macaroons comparison in §7 (Medium #6).
5. Add the architecture and trust-graph figures (Minor #12, Structural #16).
6. After empirical numbers are in: do another full read-through.

The paper is approximately 80% drafted. The remaining 20% is the empirical work + Lean proof closure + two more revision passes.
