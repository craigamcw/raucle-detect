# Reviewer rehearsal — DRAFT.md read as an adversarial S&P reviewer

*Read 2026-05-14. The reviewer below is me, pretending I didn't write the paper. Goal: surface every objection that would land in a real review, before it does.*

---

## Overall: weak accept, contingent on the empirical run

The paper is structurally well-built. Three soundness theorems mechanised in Lean. A defensible bounded-grammar argument. A pre-registered policy set. A static upper bound of 0/2737 attack scenarios already verified at submission time. If the LLM-driven AgentDojo + InjecAgent numbers come in below 1% ASR with benign-task completion above 80%, this is a strong accept. If they don't, the paper still lands as a methodology contribution.

What follows is the issue list. I'd raise all of these in a real review.

## Major

### M1. The "structurally precluded" verb is doing a lot of work.

The abstract says VCD *structurally precludes* prompt-injection-driven tool misuse over the verified action surface. Theorem 2 says: if the gate returns ALLOW, the call satisfies the constraints. That is necessary but not sufficient for "structurally precluded." The unstated assumption is that the *only path* from agent intent to tool execution is through the gate — which Section 2 ("Trust boundary of the gate") asserts but does not prove.

Concretely: if the agent runtime calls a tool by importing the implementation module directly, bypassing the gate process, the theorem provides no protection. The paper waves at this in §2 ("the gate runs out-of-process, no eval/exec on agent input") but doesn't formalise the constraint. A diligent reviewer will ask: where is the proof obligation on the agent runtime?

**Action:** add a paragraph at end of §3.3 making the gate-monopoly assumption explicit and naming it as an architectural rather than mathematical property. Use the word "architectural" rather than "structural" if necessary.

### M2. The "intent extraction" trust boundary is acknowledged but not analysed.

§3.4 and the policy files together perform a *hand-authored* intent extraction: each user task maps to a per-task policy. This is fine for a proof-of-concept but the paper claims at multiple points that the design generalises ("In production deployments this would be a small, audited component — a rule-based parser, a structured-output extractor, or a separate trusted LLM call with its own gate").

The reviewer will ask: is the intent extractor secure under the same threat model as the gate? If a malicious tool output reaches the extractor before the next-step policy is minted, the attacker has a way back in. The paper does not analyse this.

**Action:** add a §8 sub-paragraph titled "Intent extraction as a second trust boundary" enumerating the three production options and their threat models. Honest scope: a separate paper's worth of work to do properly.

### M3. The static upper bound (0/2737) is convincing but informal.

§6.2.1's static result is reported. The implicit claim is that the verifier's logic is identical to the runtime gate's logic. It is — `verify_policies.py` and `raucle_detect.capability._check_constraints` share the same constraint vocabulary. But there is no formal statement of this equivalence anywhere in the paper. A reviewer who cares about this will ask "why should I believe your verifier doesn't accidentally permit something the runtime gate denies?"

**Action:** add a half-paragraph in §6.2.1 or §4 noting that the verifier is a 30-line script that calls into the same `Policy.satisfiesArgs` function as the gate at runtime, and citing the relevant file in the open-source repo.

### M4. "Tool-call-mediated" carries the headline but is fuzzy.

The abstract and §1 claim 0% on "tool-call-mediated attacks". §6.1 says all of AgentDojo's `SuiteResults.security_results` is tool-call-mediated by construction. Fine for AgentDojo. But for InjecAgent the claim is implicit, and the term "tool-call-mediated" is undefined.

A reviewer can imagine asking: "An attacker who coerces the agent to *speak* the secret aloud, rather than emit a tool call — does that count as 'tool-call-mediated' because the secret was originally retrieved via a tool call?"

**Action:** define "tool-call-mediated" precisely in §2 or §6.1. Suggested operational definition: *"an attack is tool-call-mediated iff its success criterion is the invocation of a specific tool with specific argument values."* This matches AgentDojo's `security` boolean exactly; InjecAgent has the same shape.

### M5. The case study (§6.4) is empty.

`[anonymised production agent]` operating in `[anonymised regulated industry]` processing `[TBD]` tool calls per day. The reviewer will read this as a tell: the paper has no real deployment. Either get a pilot logo by submission, or rewrite §6.4 honestly as "deployed in our reference test harness processing X tool calls during the evaluation window" and own that.

**Action:** decision required from the author. The honest rewrite is the better path if no pilot lands.

## Medium

### m1. The Macaroons differentiation is good but the paper does not engage with the "OAuth scopes" comparison.

§7.2's table is solid for Macaroons. But the average industry reader will think first of OAuth 2.0 scopes — "scope=read:email scope=send:email" tokens — and wonder how VCD differs. The paper should explicitly address this in §7.2 or §8.

**Action:** add one sentence: "Unlike OAuth scopes, VCD's constraints are value-level (not just permission-level), the attenuation invariants are mechanically enforced (rather than scope-documented), and the tokens cite SMT-verified policies."

### m2. The "attenuation cannot broaden" claim is mechanised but I don't see how it interacts with token *theft*.

A child token is a child token regardless of whether the legitimate orchestrator or an attacker produced it. If the attacker steals a valid child, they can use it within its bounds. The paper's threat model says "cannot compromise the issuer's private signing key" but does not say tokens are confidential.

**Action:** §2 should explicitly enumerate the token-confidentiality assumption. Likely a one-sentence clarification: "Capability tokens are unforgeable but not confidential; an attacker who steals a token can use it within its bounds. Production deployments should bind tokens to a session via a confidential channel."

### m3. Performance numbers are on a single machine.

§6.3 reports 0.07 ms p50 on AMD EPYC-Milan. Reviewers expect at least two architectures. Apple M-series numbers exist from earlier measurement (0.15 ms p50); the paper should report both.

**Action:** add the M-series row to the §6.3 table. Easy fix.

### m4. The `_TOOL_RE` loosening to allow CamelCase is mentioned in changelog but not the paper.

Minor but a careful reviewer running the code will notice that early-2026 capability tokens with CamelCase tool names won't validate, then dig into the git history. Better to be upfront.

**Action:** none required; this is a private library detail.

### m5. The Lean proofs rely on opaque cryptographic primitives.

§4's three theorems treat `Ed25519Verify`, `Sha256Hex`, `canonBody` as opaque oracles. This is honest but the paper should explicitly state which properties of these oracles the mechanisation depends on: collision resistance for SHA-256, unforgeability under chosen-message attack for Ed25519, canonical-determinism for `canonBody`.

**Action:** add a half-paragraph in §4 listing the three crypto-oracle assumptions explicitly.

## Minor / polish

- §1's third paragraph names "Claude Sonnet 4.6"; in double-blind submission this can be left as "a frontier conversational model from one of the major providers" until the camera-ready.
- The phrase "structurally precluded" appears twice; "structurally impossible" appears once in legacy text. Pick one and grep-replace.
- The phrase "well under 100 microseconds" appears three times; consider varying or consolidating.
- Section 6.2.1 was added late; make sure it's referenced from §6.2's body text, not just appended.
- The pre-registration hashes are quoted in PRE-REGISTRATION.md but not in the paper itself. Worth quoting at least the first eight hex chars in §6.0 to anchor reviewer verification.

## What is *not* a weakness

Worth recognising:

- The Lean development is real, compiles, and is independently verifiable. §4 will not be challenged on rigor.
- The pre-registration hash anchors preempt the post-hoc-tuning attack.
- The static-upper-bound result is genuinely new — no prior text-side defence paper has it.
- The threat model is narrower than the typical "we solve prompt injection" claim and that narrowness is the paper's strength.
- The Macaroons differentiation table is the right level of engagement with prior art.

## What a real reviewer would actually write

A two-paragraph review:

> The paper proposes Verified Capability Discipline (VCD), a composition of SMT-verified policy completeness over JSON Schema tool grammars with Ed25519-signed attenuating capability tokens for LLM agent tool calls. The contribution is the composition rather than any single primitive; the paper engages well with prior work in object capabilities (Macaroons, seL4), supply-chain attestation (Sigstore), and policy-via-SMT (Margrave, Zelkova). Three soundness theorems are mechanised in Lean 4. A static upper bound of 0/2737 attack scenarios under VCD across AgentDojo and InjecAgent is established; LLM-driven ASR measurements are reported in §6.2 [pending].
>
> Strengths: rigorous mechanisation, pre-registered policies with cryptographic hash anchors, defensible threat model with explicit out-of-scope items, MIT-licensed reference implementation. Weaknesses: the gate-monopoly assumption is architectural rather than mathematical and could be more explicit (§3.3); the intent-extraction trust boundary is acknowledged but not analysed (§8); the case study (§6.4) is currently a placeholder. The headline 0% ASR claim is well-defined and structurally supported by the static verifier, but the "tool-call-mediated" qualifier needs an operational definition. Recommend accept after revisions to §3.3, §6.4, and §8.

A good outcome.
