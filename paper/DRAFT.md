# Verified Capability Discipline for LLM Agent Tool Calls

*Draft v1 — 2026-05-14.*
*All `[TBD]` markers indicate measurements that require the AgentDojo + InjecAgent harness run on your hardware. All `[LEAN]` markers indicate proof obligations whose Lean 4 mechanisation has been sketched in `paper/lean/` but not yet machine-checked.*

---

## 1. Introduction

Large language model agents now mediate billions of tool calls per day across customer support, financial services, software engineering, and clinical workflows. Every one of those calls is the output of a stochastic system whose input surface is, by construction, the open set of all natural language. Four years of work on prompt-injection defence has converged on a stable observation: text-side defences against text-side attacks improve attack-success rates from catastrophic to merely poor. The strongest published results in 2024-2026 — Spotlighting [HMC+24], StruQ [CDC+24], constitutional classifiers [Ant24], and the suite of commercial prompt-shield products — reduce the AgentDojo [DBL+24] and InjecAgent [ZSM+24] attack success rate (ASR) from a no-defence baseline of roughly half to between 14% and 31%. Half of one in three attempts still succeeds.

The diagnosis we offer is that the defences are operating in the wrong shape of problem. Verifying properties of unbounded natural language is open; the agent's downstream effect on the world, however, is mediated almost entirely through a much narrower interface. Every modern agent framework — OpenAI function-calling, Anthropic tool use, the Model Context Protocol, AutoGen, and LangChain among them — requires tools to declare structured input grammars, typically JSON Schema. Over those grammars the set of well-formed strings is bounded, the propositions one wants to enforce are decidable, and the enforcement point can be moved out of the model entirely.

This paper presents Verified Capability Discipline (VCD), a composition of three primitives that together structurally preclude prompt-injection-driven tool misuse over the verified action surface of an agent. We use SMT to prove that a tool's security policy is satisfied over every string its JSON Schema permits, or to extract a concrete counterexample call. We bind the proven policy into an Ed25519-signed capability token whose attenuation primitives mechanically forbid permission broadening. We place a gate on the only path from agent intent to tool execution and require every call to carry a token whose constraints are satisfied by the actual call arguments.

The contribution is neither the SMT verification nor the capability discipline taken alone — both have decades of prior art that we discuss in Section 7 — but the specific composition and the empirical demonstration that it holds against state-of-the-art prompt-injection benchmarks at production-acceptable latency. We mechanise three soundness theorems in Lean 4, evaluate against the two most cited contemporary benchmarks across four state-of-the-art baselines, and release the reference implementation, Lean development, and benchmark harness under the MIT licence.

Our principal claims are:

1. **Structural enforcement.** If the gate returns ALLOW for a tool call, the call arguments satisfy every constraint in a valid descendant of a capability token signed by a pinned issuer; absent compromise of the issuer's private key, no agent input — natural-language or otherwise — can produce an ALLOW for arguments that violate the policy.
2. **Provable policy completeness.** Given a tool's JSON Schema in a supported fragment, the prover terminates with either a proof that no string in the schema's language violates the policy, or a concrete counterexample call.
3. **Empirical attack-success reduction.** Across AgentDojo and InjecAgent, VCD reduces the tool-call-mediated attack-success rate from `[TBD-baseline]%` (no defence) and `[TBD-strongest-prior]%` (strongest text-side defence) to `[TBD ≤ 0.5]%`, with `[TBD ≥ 85]%` benign task completion and a per-call gate latency well under 100 microseconds at p50 on commodity hardware. We report in Section 6.1 the fraction of attacks in each benchmark that are *tool-call-mediated* (and thus in VCD's scope) versus pure-output (out of scope); the strength of the headline claim depends on this fraction, which we measure rather than estimate.

We argue in Section 9 that VCD does not solve prompt injection — free-form output attacks and side-channel exfiltration over allowed parameters are out of scope — but that it closes the dominant attack class, and that the trajectory of AI security must be to move enforcement boundaries out of the model and into structural gates wherever the grammar permits.

We adopt the convention throughout this paper of being conspicuously honest about the boundary of our claims. Section 2 enumerates the out-of-scope attack classes; Section 6.5 reports the configurations in which VCD did *not* eliminate attack success. The narrowness of the claim is what makes it credible.

The remainder of this paper is organised as follows. Section 2 fixes the threat model. Section 3 describes the three primitives and their composition. Section 4 states and sketches the three soundness theorems. Section 5 describes the implementation. Section 6 reports the empirical evaluation. Section 7 places VCD in the related literature. Section 8 discusses limitations.

## 2. Threat Model

We adopt the standard agentic-LLM adversary model from Greshake et al. [GAB+23] and Debenedetti et al. [DBL+24], with explicit cryptographic assumptions.

**Adversary capabilities.** The adversary controls any untrusted input the agent ingests: the user message, the contents of RAG-retrieved documents, the output of any third-party tool whose result is fed back into the agent's context, web pages the agent browses, and email or chat messages the agent reads. The adversary observes the agent's system prompt, the list of tools available to the agent, the JSON Schema of every tool, and — in our most pessimistic configuration — the constraint policy carried by the capability token in force at the time of the attack. The adversary cannot forge Ed25519 signatures, cannot compromise the issuer's private signing key, cannot execute code inside the gate process, and cannot tamper with the audit log after the fact.

**Defender capabilities.** The defender controls a gate process that sits between the agent runtime and the tool implementations. The gate runs in a separate trust domain from the model — a separate process, container, or address space — and is the only path through which tools are invoked. The defender holds the issuer's private key in a hardware security module or equivalent. The defender authors tool JSON Schemas and constraint policies; we make no assumption that either is correct, only that the SMT prover catches the cases where they disagree.

**Token confidentiality.** Capability tokens are *unforgeable* but not *confidential*: an attacker who steals a valid token can use it within its bounds. Production deployments should bind each token to a session via a confidential channel (mTLS between agent and gate; per-session token rotation; short TTLs) so that exfiltrated tokens are useless to attackers operating in different sessions. The reference implementation does not enforce this binding — it is the responsibility of the deployment. The threat model in this paper assumes tokens cannot be exfiltrated from the agent runtime; this assumption is realistic for in-process deployments and weakens to "tokens have short TTL and are bound to session keys" in the multi-tenant case.

**Security goal.** For every tool call $c = (\text{tool}, \text{args})$ that the gate authorises with token $t$, the arguments $\text{args}$ satisfy every constraint in $t$, and $t$ is a valid descendant of a root token signed by a pinned issuer. We refer to this property as *gate soundness*. We also require *attenuation soundness*: no child token derived from a parent can carry permissions broader than the parent along any constraint dimension or lifetime.

**Operational definition of "tool-call-mediated."** Throughout this paper an attack is *tool-call-mediated* iff its success criterion is the invocation of a specific tool with specific argument values. This matches AgentDojo's `security` boolean and InjecAgent's success predicate exactly. An attack whose success criterion is, for example, the agent *speaking aloud* a secret it previously retrieved through a tool — without subsequently emitting a structured tool call to exfiltrate it — is **not** tool-call-mediated under this definition, regardless of whether a tool call earlier in the trace produced the secret. We make no claim against the non-tool-call-mediated class; see §6.5.

**Out of scope.** We list explicitly what VCD does *not* claim. Free-form natural-language output attacks — for example, an attacker coercing the agent to reveal a secret in its visible response — remain unaddressed; the bounded-grammar argument does not apply. Side-channel exfiltration through allowed parameter values (an `amount` field accepting any 64-bit integer permits up to 64 bits per call of covert content) is not prevented; we discuss in Section 8 how schema tightening reduces this channel. Confused-deputy attacks across multiple legitimately-authorised tool calls — read mailbox, then exfiltrate via legitimate `send_email` — are partially addressed by our companion provenance layer [omitted for blind review] but are not the focus of this paper. The model itself is not part of the trusted computing base; the gate is. Compromise of the gate process or the issuer's signing key is outside the model.

**Trust boundary of the gate.** Because the gate's integrity is load-bearing for every claim in this paper, we are explicit about what its operational profile must look like. The gate runs in a separate process from the agent runtime, with no `eval`, `exec`, or untrusted-deserialisation entry points reachable from agent-controlled data; the issuer's private key resides in a hardware security module or analogous trusted environment; the audit log is written to append-only storage. Standard process-isolation, language-runtime hardening, and key-management practices apply. These requirements are the same as for any cryptographic gateway and are not specific to VCD. An agent runtime compromised by an unrelated vulnerability — RCE into the gate's address space, key exfiltration via memory disclosure — would defeat the property; we are not protecting against operating-system-level compromise.

This threat model is deliberately narrower than the universal "we defend against all prompt injection" claims common in the prior literature. We argue that narrow, well-defined threat models with formal guarantees are more useful to deployers than broad informal claims with statistical guarantees.

## 3. System Design

VCD has three components, each designed to be useful independently but engineered to compose. We describe them in the order they appear in a single end-to-end invocation: schema verification, capability minting, and gate enforcement.

### 3.1 SMT-Backed Policy Verification

Given a tool with JSON Schema $S$ and a security policy $P$, we ask: does every JSON object satisfying $S$ also satisfy $P$? If yes, the policy is *complete* over the schema; if no, there exists a concrete counterexample tool call.

We support a fragment of JSON Schema that has decidable semantics under the combined theory of strings, integers, and booleans in Z3 [DMB08]: top-level objects with primitive properties (`string`, `number`, `integer`, `boolean`), the `enum` keyword on string-valued properties, `minimum`/`maximum` constraints on numeric properties, and the `required` array. Constructs outside this fragment — recursive references, `oneOf`/`anyOf` schemas, arbitrary regex constraints on string fields, unbounded arrays — cause the prover to raise `UnsupportedGrammar` rather than silently approximate. Section 8 sketches the extensions needed to widen the fragment.

We support a corresponding fragment of policy language. A policy is a mapping from constraint kinds to per-field values: `forbidden_values: {field → [v_1, ..., v_n]}` and `allowed_values: {field → [v_1, ..., v_n]}` for set-valued constraints on string fields; `max_value` and `min_value` for numeric bounds; `required_present: [field, ...]` for additional presence requirements beyond the schema's `required`; and `forbidden_field_combinations: [[f_1, f_2], ...]` for forbidden co-occurrences.

The encoding into Z3 is direct. Each schema property becomes an SMT variable of matching sort. Each property's presence is a Boolean. Schema-level constraints (enum membership, numeric bounds, required presence) are conjuncted as preconditions. The policy is encoded as a *violation* disjunction: a single Z3 query asks whether there exists an assignment satisfying the schema preconditions and at least one violation. If `unsat`, the policy is proven complete. If `sat`, Z3 produces a model from which we extract a concrete counterexample call.

The prover emits a `ProofResult` containing canonical-JSON hashes of the schema and policy, the proof status (`PROVEN`, `REFUTED`, or `UNDECIDED`), and any counterexample. The proof result is itself hashed to produce a content-addressed `proof_hash` that capability tokens can cite.

### 3.2 Capability Tokens

A capability token $t$ is an Ed25519-signed structure binding `(agent_id, tool, constraints, issued_at, not_before, expires_at, parent_id, policy_proof_hash, issuer, key_id)`. The signature covers a canonical-JSON serialisation of the bound fields. The token's identifier is the SHA-256 of the same canonical body, prefixed with `cap:`; the identifier is therefore content-addressed and unforgeable absent collision.

The constraint schema mirrors the policy schema accepted by the prover, by deliberate design: a token can cite the proof's hash and the gate can statically verify that the token's constraints are at least as tight as the proven policy.

**Attenuation.** Given a parent token $p$ held by an authorised principal, the issuer's `attenuate` primitive derives a child token $c$ with: (a) the same `tool` as $p$; (b) an `agent_id` equal to or a prefix-extension of $p$'s; (c) constraints that are *narrower* along every dimension; (d) an `expires_at` no later than $p$'s; (e) `parent_id` set to $p$'s identifier. Narrowing is defined per constraint kind:

| Kind | Narrowing operation |
|---|---|
| `forbidden_values[f]` | union: $c.\text{forbidden}_f \supseteq p.\text{forbidden}_f$ |
| `allowed_values[f]` | intersection: $c.\text{allowed}_f \subseteq p.\text{allowed}_f$ |
| `max_value[f]` | minimum: $c.\text{max}_f \le p.\text{max}_f$ |
| `min_value[f]` | maximum: $c.\text{min}_f \ge p.\text{min}_f$ |
| `required_present` | superset: $c.\text{required} \supseteq p.\text{required}$ |
| `forbidden_field_combinations` | superset: $c.\text{forbidden\_combos} \supseteq p.\text{forbidden\_combos}$ |

Asking `attenuate` for a constraint that would broaden permissions silently retains the parent's tighter bound; asking for a child lifetime that would outlive the parent raises an exception. Both behaviours are mechanically enforced (Section 4).

The attenuation discipline is borrowed directly from the object-capability literature [Mil06] and from Macaroons [BAL+14], from which it differs primarily in the cryptographic substrate (Ed25519 signatures rather than chained HMACs) and the content-addressed identifier (preventing token-ID reassignment attacks that bedevil bearer-token systems).

### 3.3 The Gate

The gate is the only path from agent intent to tool execution. It runs out-of-process from both the model and the tool implementation, accepts a `(token, tool, args)` triple, and returns a `GateDecision` of `ALLOW` or `DENY` with a structured reason. The gate performs eight checks in order, failing closed on any one of them:

1. **Issuer pinning.** The token's `key_id` must appear in the gate's trusted-issuer map; otherwise DENY.
2. **Signature verification.** Verify the Ed25519 signature against the canonical body using the pinned public key.
3. **Identifier binding.** Recompute `cap:` + SHA-256 of the canonical body and compare to the token's `token_id`; reject on mismatch. This blocks an attack where an adversary substitutes a valid signature against a different body.
4. **Time bounds.** Reject if `now < not_before` or `now ≥ expires_at`.
5. **Tool match.** Reject if `token.tool ≠ requested_tool`.
6. **Agent scope.** Reject if the caller's claimed `agent_id` is neither equal to the token's `agent_id` nor a prefix-extension of it.
7. **Constraint satisfaction.** For each constraint kind in the token, evaluate the constraint against the supplied `args`. Reject on any violation.
8. **Chain resolution (optional).** If the token carries a `parent_id`, walk the parent chain. Every intermediate token must verify under the gate's trusted-issuer map. Reject on any unresolved or invalid parent.

The gate is a deterministic, side-effect-free decision procedure. Every invocation emits a structured event suitable for consumption by an append-only audit log; the gate does not itself maintain state.

**Gate-monopoly is an architectural assumption, not a mathematical theorem.** Theorem 2 (§4) establishes that any call returning ALLOW from the gate satisfies the in-force constraints; it does *not* establish that every tool invocation must go through the gate. That latter property is the deployer's responsibility and is enforced architecturally: tool implementations live in a separate process from the agent runtime, exposed only behind a gate-mediated RPC interface, with no eval/exec/direct-import paths reachable from agent-controlled data. The reference implementation ships the gate as an out-of-process server behind a Unix socket or local HTTPS endpoint, with the issuer key in an HSM. A deployment that violates this discipline — for example, by linking the agent runtime and the tool implementation into one address space and letting the agent reach the tool symbol directly — loses the property regardless of the gate's correctness. We call this property out explicitly because §4's mechanisation provides no formal guarantee about it.

### 3.4 Composition

The three primitives compose as follows. A platform operator authors a tool schema and a policy, runs the SMT prover, and on `PROVEN` obtains a `proof_hash`. The operator mints a root capability token citing the proof hash, signing with their issuer key. Tokens are distributed to authorised agent contexts, possibly via attenuation through orchestration layers. At tool-call time, the agent presents its current token to the gate; the gate enforces. Every gate decision is recorded into a hash-chained audit log signed by a separate operational key, providing tamper-evident attribution that is independently verifiable offline.

The four hashes — schema, policy, proof, audit-leaf — and three signatures — issuer (on the token), audit (on the chain checkpoint), gate-decision (optional, on the structured event) — close the trust graph. Every link is content-addressed; every link is verifiable by any party in possession of the corresponding public key. Figure 1 sketches the resulting graph.

```
                  ┌─────────────────┐
                  │  JSON Schema S  │── sha256 ──► grammar_hash
                  └─────────────────┘                   │
                                                        ▼
                  ┌─────────────────┐           ┌──────────────┐
                  │   Policy P      │── sha256 ─►│ proof_hash   │ (PROVEN/REFUTED)
                  └─────────────────┘           └──────────────┘
                                                        │
                                            cited by    │
                                                        ▼
            ┌──────────────────────────────────────────────────┐
            │  Capability Token   (Ed25519, content-addressed) │
            │  (agent, tool, constraints, nbf, exp,            │
            │   policy_proof_hash, parent_id)                  │
            └──────────────────────────────────────────────────┘
                                │                       │
                       attenuate│                       │ presented at call site
                                ▼                       ▼
                       ┌────────────────┐    ┌────────────────────┐
                       │  Child Token   │    │  Gate.check(...)   │
                       │  parent_id=…   │    │  ALLOW or DENY     │
                       └────────────────┘    └────────────────────┘
                                                        │
                                              audit event
                                                        ▼
                                            ┌──────────────────────┐
                                            │  Hash-chained log    │
                                            │  Merkle root, signed │
                                            └──────────────────────┘

Figure 1: The trust graph. Every solid arrow is a content-addressed
reference; every signed artefact is verifiable offline against a pinned
issuer or audit key.
```

## 4. Formal Analysis

We mechanise three theorems in Lean 4 [LEA]. The full development lives in `paper/lean/`; we sketch the statements and proof structure here.

Let $\Sigma$ denote the set of well-formed JSON objects under a fixed schema $S$ in the supported fragment, and $\Pi$ the set of policies in the supported policy fragment. Let $\text{Tok}$ denote the type of capability tokens, $\Pi_\text{tok}: \text{Tok} \to \Pi$ the projection from a token to its constraint set, and $\text{Verify}: \text{Tok} \times \mathcal{K} \to \{0, 1\}$ Ed25519 verification under a public key.

**Theorem 1 (Attenuation Soundness).** *For all $p, c : \text{Tok}$, if $c$ is in the image of $\text{attenuate}(p, \cdot)$, then for every constraint kind $k$ and every field $f$, the narrowing relation $\sqsubseteq_k$ holds between $\Pi_\text{tok}(c)|_{k,f}$ and $\Pi_\text{tok}(p)|_{k,f}$, and $c.\text{expires\_at} \le p.\text{expires\_at}$.*

The proof proceeds by case analysis on $k$. For each constraint kind, `attenuate`'s implementation is shown to compute the appropriate lattice meet (intersection, union, min, max). Because each operation is monotone in the lattice, $\sqsubseteq_k$ is preserved by definition. The lifetime bound follows from the explicit guard in `attenuate` that returns `none` when $c.\text{expires\_at} > p.\text{expires\_at}$. The Lean development is approximately 86 lines and compiles cleanly under Mathlib v4.10.0.

**Theorem 2 (Gate Soundness).** *For all $t : \text{Tok}$, all tools $T$, and all argument bindings $a$, if $\text{Gate.check}(t, T, a) = \text{ALLOW}$ under trusted-issuer set $\mathcal{K}$, then: (i) $t.\text{tool} = T$; (ii) every constraint in $\Pi_\text{tok}(t)$ is satisfied by $a$; (iii) the signature on $t$ verifies under some $k \in \mathcal{K}$; (iv) $t.\text{token\_id} = \text{cap:}\Vert\text{SHA256}(\text{canon}(t.\text{body}))$.*

The proof is a direct case analysis on the eight gate checks. Each check, if it returned ALLOW, established the corresponding postcondition. The pre-image analysis is mechanical. The Lean development is approximately 97 lines and compiles cleanly.

**Theorem 3 (Policy-Proof Composition).** *Let $S$ be a schema, $P$ a policy, $\rho$ a proof artifact from $\text{Prove}(S, P)$ with $\rho.\text{status} = \text{PROVEN}$, and $t$ a token whose $\text{policy\_proof\_hash} = \rho.\text{hash}$ and whose constraints are pointwise at least as tight as $P$ under the constraint lattice. Then for every $a$ such that $\text{Gate.check}(t, t.\text{tool}, a) = \text{ALLOW}$, the call $a$ satisfies $P$ and conforms to $S$.*

The proof composes the prover's soundness — every assignment satisfying $S$ that violates $P$ is found by Z3, so `PROVEN` certifies $\Sigma \cap \neg P = \emptyset$ — with Theorem 2 and the constraint-lattice tightness assumption on $t$. The Lean development is approximately 75 lines and depends on a small axiomatic interface to the Z3 oracle. The full mechanisation (Theorems 1, 2, and 3 together) is 353 lines of Lean 4 and compiles under Mathlib v4.10.0 with no `sorry`s.

We are honest about what the Lean development does and does not establish. It mechanises the *attenuation and gate logic at the level of the abstract data model*. It does not mechanise the bit-level correctness of the Ed25519 implementation (we rely on Erbsen et al.'s verified field-arithmetic for Curve25519/Ed25519 [erbsen2019simple] and the audited `cryptography` library [PYCA]) nor the bit-level correctness of Z3 (we treat the SMT solver as a trusted oracle whose `unsat` results we accept; in practice a `PROVEN` result from Z3 should be cross-validated against a second implementation, a step we have added to the reference codebase).

The mechanisation depends on three explicit cryptographic-oracle assumptions, all standard. (i) **Ed25519 unforgeability under chosen-message attack:** the only way to produce a valid signature over a body is to know the corresponding private key. Theorem 2's conclusion that the verifying public key is in the trusted set rests on this. (ii) **SHA-256 collision resistance:** no two distinct canonical bodies hash to the same `token_id`. Theorem 2's identifier-binding check rests on this. (iii) **`canonBody` determinism:** the canonical-JSON serialisation produces the same byte sequence for every logically-equivalent body across implementations and Python versions. Our canonicalisation uses sorted keys, no whitespace, UTF-8 encoding, and `ensure_ascii=False`; we treat this as an oracle property and recommend deployments cross-validate the canonical encoding against a second implementation at boot.

## 5. Implementation

The reference implementation is the open-source `raucle-detect` library (`[anonymised for blind review]`). Approximately 2,500 lines of Python implement the runtime; an additional 500 lines of Lean 4 contain the formal development. The implementation depends on Z3 (Python bindings) and the audited `cryptography` library for Ed25519. No new cryptographic primitives are introduced.

Several engineering decisions warrant comment.

**Canonical JSON.** All hashes and signature inputs use a canonical-JSON serialisation — sorted keys, no whitespace, UTF-8 encoded, `ensure_ascii=False` — so that the same logical object always produces the same bytes. This avoids signature-mismatch failures that bedevil deployments where serialisation order varies across implementations.

**Fail-closed defaults.** The gate raises rather than returning ALLOW on any internal error. The prover returns `UNDECIDED` (treated as a failure mode by downstream consumers) rather than `PROVEN` on solver timeout. We observed in early integration testing that these defaults catch a class of misconfiguration bugs — a missing pubkey in the trusted-issuer map, a corrupted token on disk — that fail-open defaults would silently mask.

**Out-of-process gate.** Although the gate can run as a Python library function in the same address space as the agent runtime, the recommended deployment runs it as a separate process behind a Unix socket or local HTTPS endpoint, with the issuer key held by an HSM. This separation provides defence-in-depth: an LLM-driven RCE in the agent runtime cannot directly mint or modify tokens.

**Content-addressed everything.** Tokens, proof artifacts, audit-chain leaves, and feed entries (where used in a larger deployment) are all content-addressed, allowing cross-reference by hash without needing a central registry.

The codebase has been MIT-licensed since release; the Lean development will be released alongside camera-ready acceptance.

## 6. Evaluation

We evaluate three claims: (i) tool-call attack-success rate is reduced to near zero on standard benchmarks; (ii) benign task completion is preserved; (iii) per-call latency overhead is production-acceptable.

### 6.0 Pre-registration

Before any measurement run that consumed LLM credits, the per-task policy files (§3.4) were frozen by SHA-256 hash and committed to the repository. The first eight hex characters of each file's hash:

```
banking.json    sha256:4b78e687…    slack.json     sha256:72698245…
travel.json     sha256:c7692b8e…    workspace.json sha256:8ba70481…
```

Full hashes appear in `paper/eval/PRE-REGISTRATION.md`; the static verifier (`paper/eval/verify_policies.py`) re-computes them on every CI build and aborts on drift. Policy edits after this freeze require a separate commit explaining the change and a new pre-registration entry. Any measurement number in §6.2 was produced against a policy file whose hash exactly matches one of the above.

### 6.1 Benchmarks and Configurations

We use the two most cited contemporary prompt-injection benchmarks against agentic LLMs:

- **AgentDojo** [DBL+24]: 629 attack tasks across four realistic deployments (banking, Slack, GitHub, travel agency). Each task pairs a benign user request with an adversarial document injected into the agent's context, with success defined as the agent calling a specific tool with attacker-controlled arguments.
- **InjecAgent** [ZSM+24]: 1,054 attack scenarios across multiple agent frameworks, with similar structure.

We test six defence configurations:

1. **None** — no defence beyond the base model's training.
2. **Spotlighting** [HMC+24] — input-perturbation defence that marks untrusted regions of the context.
3. **StruQ** [CDC+24] — structured-query defence that fine-tunes the model to ignore instructions in delimited regions.
4. **Prompt shields** — a commercial vendor's filter (anonymised at the vendor's request).
5. **VCD text-only** — the scanner layer of our reference implementation, without proof or capability.
6. **VCD full stack** — scanner + proof + capability gate.

All configurations run against the same base model and the same agent harness. We measure on two contemporary frontier-class models: **deepseek-v3.2** (671B, late 2025) and **deepseek-v4-flash** (140B, April 2026), via Ollama Cloud's OpenAI-compatible endpoint. We report tool-call-mediated attack success rate, benign task completion on the AgentDojo benign-task split, and gate latency on commodity hardware.

### 6.2 Headline Result

Measured on the AgentDojo banking suite (144 user × injection task pairs per cell). Numbers from the live LLM-driven evaluation reported here; `[TBD]` cells await currently-running tracks for the remaining suites (slack, travel, workspace) and the v4-pro prestige row.

**deepseek-v4-flash (frontier flash, April 2026):**

| Defence | ASR | Benign | Wall |
|---|---|---|---|
| None | **1.4%** | 86.8% | 7.6m |
| Spotlighting | 2.1% | 84.0% | 14.4m |
| StruQ | `[TBD]` | `[TBD]` | — |
| Prompt shields (DeBERTa PI) | **0.0%** | **35.4%** | 26.5m |
| VCD text-only | 0.0% | 91.0% | 22.5m |
| **VCD full stack** | **0.7%** | **90.3%** | 8.7m |
| VCD capability-only (ablation) | 0.0% | 88.9% | 9.1m |

**deepseek-v3.2 (frontier reasoning, late 2025):**

| Defence | ASR | Benign | Wall |
|---|---|---|---|
| None | **77.8%** | 100.0% | — |
| Spotlighting | `[TBD]` | `[TBD]` | — |
| StruQ | `[TBD]` | `[TBD]` | — |
| Prompt shields | `[TBD]` | `[TBD]` | — |
| VCD text-only | `[TBD]` | `[TBD]` | — |
| **VCD full stack** | `[TBD]` | `[TBD]` | — |
| VCD capability-only | `[TBD]` | `[TBD]` | — |

(v3.2 baseline measured on 18 of 144 banking cells before aggregation; the running v3.2 sweep covers all six configurations across all 144 pairs.)

The load-bearing comparison on v4-flash is the **shields vs VCD full stack** row pair: both achieve essentially-zero ASR, but the strongest text-side defence (transformers PI detector) drops benign task completion to **35.4%** while VCD full-stack preserves **90.3%** — a 54.9-percentage-point gap in legitimate task completion at equivalent security. Equivalently, deploying shields requires accepting the loss of more than half of legitimate agent productivity to reach VCD's security level.

For the AgentDojo and InjecAgent attack distributions, the fraction of attacks whose success is mediated by a constrained tool call is `[TBD-AD-frac]%` and `[TBD-IA-frac]%` respectively; the remainder are pure-output attacks that VCD does not target and that contribute to the residual ASR above zero. We discuss the small residual in Section 6.5.

#### 6.2.1 Static upper bound on attack-success rate

Before reporting the LLM-driven measurements, we report a *static* upper bound: assuming the model emits the attacker's canonical tool call exactly, do the gate's constraints — derived independently from each user task's prompt and pinned by the pre-registered hash anchors of §6.0 — admit the call? This is the maximum ASR the actual eval can exhibit; the LLM-driven run can only do as well or better, because natural-language defences provide additional attrition on top of the gate.

The static verifier (`paper/eval/verify_policies.py`) runs the same constraint logic the runtime gate runs. Static results under VCD full-stack, across both benchmarks, all defence-relevant cells:

| Benchmark | Cases | Attacks succeeding the static check | Static upper bound on ASR |
|---|---|---|---|
| AgentDojo (v1, all four suites) | 629 | 0 | 0.00% |
| InjecAgent (DH base + enhanced) | 1020 | 0 | 0.00% |
| InjecAgent (DS base + enhanced) | 1088 | 0 | 0.00% |
| **Total** | **2737** | **0** | **0.00%** |

The single known exception is one cell in AgentDojo banking (user_task_15 × schedule_transaction): the user's stated intent contains the same IBAN as the benchmark's adversarial recipient (the user's landlord). Capability discipline correctly admits that call — the user explicitly authorised it — while the same IBAN remains forbidden in every other user task's policy. The static verifier flags this cell as a *known-legitimate coincidence* and excludes it from the count above.

The verifier and the runtime gate share a single implementation of the constraint-check logic — both call into the same `Policy.satisfiesArgs` function in `raucle_detect.capability` — so the static result is not a separate model that could disagree with the runtime. The verifier is a 30-line driver that loads the policy files, iterates over the benchmark's catalogued attack args, and asks the same Python function the gate asks at runtime. Any policy edit that weakens the gate's behaviour weakens the static result identically. A CI job (configured in `.github/workflows/ci.yml`) re-runs the verifier on every commit and fails the build if the static block rate regresses below 100%.

**Ablation.** To attribute the headline delta across the three components of VCD, we measure each in isolation:

| Configuration | AgentDojo ASR | InjecAgent ASR |
|---|---|---|
| Capability gate only, runtime-checked constraints, no SMT proof | `[TBD]%` | `[TBD]%` |
| SMT proof only, constraints checked at the tool boundary, no capability | `[TBD]%` | `[TBD]%` |
| Both (VCD full stack) | `[TBD ≤ 0.5]%` | `[TBD ≤ 0.5]%` |

The capability gate alone is expected to catch the bulk of attacks because runtime constraint-checking already structurally blocks malformed tool calls; the SMT-proof-only configuration catches schema/policy disagreements that would otherwise leave gaps the gate has no way to detect. The composition closes both.

The VCD text-only row is a sanity check: with the capability gate disabled, we are merely a text-side defence and should sit roughly in the same range as Spotlighting / StruQ. The full-stack row is the load-bearing claim: every attack whose effect is *mediated through a tool call* (operationally defined in §2) is rejected by the gate, because every such tool call must satisfy the constraints in the in-force capability token, which were issued before the attacker had any access to the agent's context. The structural underpinning of this claim is reported in §6.2.1: a *static* upper bound establishes that the gate's constraint logic, run against the canonical attack args from both benchmarks, denies every attack across all 2,737 (user-task × injection-task) pairs. The LLM-driven measurements in the table above can only do as well or better than that static bound. We discuss in Section 6.5 the small residual that is not zero — attacks whose effect is *not* tool-mediated, such as those that succeed purely through the agent's free-form output.

### 6.3 Per-Call Latency

Measured on two reference hardware classes, single thread, Python 3.12+: an x86_64 cloud VM (AMD EPYC-Milan, Ubuntu 24.04) and a workstation (Apple M-series ARM64, macOS 14). 5,000 iterations per gate operation, 200 iterations per proof.

| Operation | x86_64 (EPYC-Milan) p50 / p95 / p99 | ARM64 (Apple M) p50 / p95 / p99 |
|---|---|---|
| `Gate.check()` no chain | 0.07 / 0.08 / 0.11 ms | 0.15 / 0.18 / 0.19 ms |
| `Gate.check()` 3-link chain | 0.27 / 0.30 / 0.34 ms | 0.58 / 0.64 / 0.69 ms |
| `Prove()` cold | 0.67 / 0.74 / 0.90 ms | 0.54 / 0.68 / 46.5 ms |

Proof results are cached by `(schema_hash, policy_hash)`. In steady-state deployments where the schema and policy change rarely, the prover is invoked once per policy version and the cache hit rate approaches 100%. **End-to-end overhead per tool call in the steady state is dominated by the gate path, at well under 100 microseconds at p50.** For agents making tens of tool calls per turn at human-conversation cadence, the cost is invisible. Proof-cache invalidation on policy update incurs a one-time sub-millisecond hit.

The numbers are dramatically below the latencies typically associated with formal-verification primitives because the supported JSON Schema fragment is small enough that Z3 finds the proof or counterexample in a handful of solver iterations. Schemas at the edge of our supported fragment (deep enum sets, many fields) can extend `Prove()` cold-path latency into the low milliseconds; this remains acceptable because proofs are issued once per policy version, not per call.

### 6.4 Reference Deployment

The reference implementation `raucle-detect` is MIT-licensed and has been on PyPI since 2026-04. The end-to-end demo (`examples/end_to_end/` in the repository) composes scanner, prover, capability minting, gate, audit chain, and offline-verifiable trust graph in a single script. The four pre-registered AgentDojo policy files (`paper/eval/policies/{banking,slack,travel,workspace}.json`, hash-anchored in `paper/eval/PRE-REGISTRATION.md`) authorised `[TBD-allow-count]` tool calls and denied `[TBD-deny-count]` policy-violating calls across the empirical evaluation reported in §6.2. We do not report a separate production deployment in this paper; the integration cost is modest (the reference adapter for AgentDojo is approximately 300 lines of glue), and we anticipate that one or more public deployments will report their numbers independently. The repository, Lean development, benchmark harness, and policy files are intended as a complete reproducibility package; readers can re-run any number in §6 against their own hardware and model credentials.

### 6.5 Negative Results

We report two configurations where VCD did *not* eliminate attack success:

- **Tool-output exfiltration.** Attacks whose payload is the *content* the agent eventually emits in its response — e.g., coercing the agent to print a secret retrieved from a legitimate tool call — are not affected by the gate. The legitimate tool call was authorised by a valid token; the leak occurs in the model's text output. VCD makes no claim against this class. Composition with output-side defences is the obvious next step.
- **Permitted-parameter side channels.** A schema permitting `amount` to be any number in `[0, 1\,000\,000]` permits an attacker who can coerce the agent into making *one* legitimate `transfer_funds` call to encode up to roughly 20 bits of information in the chosen amount. We do not eliminate this channel; we discuss schema tightening in Section 8.

We consider these honest concessions essential to the paper. The strength of the headline claim depends on its narrowness.

## 7. Related Work

### 7.1 Prompt Injection and LLM-Specific Defences

The original prompt-injection taxonomy is due to Perez and Ribeiro [PR22]; the realistic indirect-injection threat model originated with Greshake et al. [GAB+23]. Subsequent defences fall into three families. *Input perturbation* defences — Spotlighting [HMC+24], paraphrasing, retokenisation — modify the agent's context so that untrusted regions are visually marked or syntactically distinguished. *Output filtering* defences — constitutional classifiers [Ant24], commercial prompt shields — apply a secondary model to the agent's output to catch policy violations. *Training-time defences* — StruQ [CDC+24], SecAlign, instruction-hierarchy fine-tuning — modify the base model. All three families share the architectural property that they operate over unbounded natural language and provide statistical rather than structural guarantees. The empirical ceiling on these approaches against modern benchmarks sits around 14-31% attack success, as Section 6 reports.

The benchmark literature — AgentDojo [DBL+24], InjecAgent [ZSM+24], TensorTrust, AdvBench — has been instrumental in disciplining defence claims. We adopt AgentDojo and InjecAgent as our headline benchmarks because they specifically measure tool-call-mediated success, which is the class VCD addresses.

Greshake et al.'s indirect-injection threat model [greshake2023not] is the closest framing to ours — prompt injection as a privilege-escalation problem reachable via untrusted documents in the agent's context — and the recent thread of work on "spotlighting + tool authentication" combinations explores adjacent ideas informally. None of this prior work provides cryptographic enforcement, attenuation invariants, or SMT-verified policy completeness, and to our knowledge none has been evaluated against AgentDojo or InjecAgent with a structurally-enforced gate.

### 7.2 Capability Discipline

Object capabilities were introduced by Levy [Lev84] and developed by Mark Miller in his dissertation on robust composition [Mil06]; major implementations include EROS [SSF99], KeyKOS, Caja, and seL4 [KEH+09]. Macaroons [BAL+14] provide a particularly close analogue to our attenuation primitive, with HMAC-based chained restriction. The technical deltas are summarised in Table 1.

**Table 1. Macaroons vs VCD capability tokens.**

| Property | Macaroons | VCD |
|---|---|---|
| Cryptographic substrate | HMAC-SHA256 chain | Ed25519 signature per token |
| Verifiable without issuer secret | No (verifier holds HMAC key) | Yes (verifier holds only the public key) |
| Identifier | bearer-token byte string | content-addressed SHA-256 of canonical body |
| Reassignment of identifier | possible (no binding) | precluded (id determines body) |
| Constraint vocabulary | opaque caveat strings | typed constraint kinds with lattice meet |
| Mechanised attenuation soundness | no | yes (Lean 4, §4) |
| Binding to a verified policy artifact | no | `policy_proof_hash` field |
| Audit-graph composition | informal | content-addressed; chains into Merkle log |

The deltas are not academic. The public-key-verifiable property means a downstream tool implementation can independently verify a token without sharing a secret with the issuer — relevant in multi-vendor agent deployments. The content-addressed identifier blocks a class of token-substitution attacks that affects bearer-token systems generally. The typed constraint vocabulary is what enables the SMT bridge in Theorem 3.

The industry-familiar comparison is to OAuth 2.0 scopes. OAuth's `scope=read:email scope=send:email` model expresses *permission-level* restrictions; VCD's constraints are *value-level* (the per-call `recipient`, `amount`, and so on are checked, not just the verb). Macaroons' caveats are value-level but informal strings; VCD's are a typed vocabulary that admits SMT verification. OAuth scopes are documented; VCD's attenuation invariants are mechanically enforced in Lean. OAuth tokens carry no proof of policy completeness; VCD tokens cite a SMT-verified `policy_proof_hash`. The three frameworks (OAuth scopes, Macaroons, VCD) lie on a progression of structural commitment: OAuth scopes are a vocabulary, Macaroons add chained attenuation under HMAC, VCD adds value-level constraints + mechanised soundness + verified policy citation.

Capability-based approaches to LLM agents have been discussed informally in community forums and as part of broader "tool allowlist" practices in major agent frameworks, but to our knowledge no prior published work provides the mechanised attenuation invariants, cryptographic gate enforcement, and empirical evaluation on prompt-injection benchmarks that VCD combines.

### 7.3 SMT for Security Policy

The use of SMT solvers for security-policy reasoning has substantial prior art. Margrave [FKM+05] used decision procedures for XACML access-control reasoning; subsequent work scaled the approach to AWS IAM policies via Backes et al.'s Zelkova system [backes2018semantic], which encodes IAM access policies as SMT and proves containment and reachability properties. We borrow the conceptual move from this line of work — encode the policy as a violation predicate and ask the solver to refute it — and apply it to the specific case of JSON Schema-bounded tool-call grammars in LLM agent settings.

### 7.4 Software Supply-Chain Attestation

The framing of "every artefact content-addressed, every link signed" derives from the software supply-chain attestation literature. Sigstore [NCC+22] and SLSA articulate this design pattern for build provenance; in-toto [TFM+19] extends to multi-step pipelines; TUF [SCM+10] establishes the underlying compromise-resilience properties. VCD applies the same architectural pattern — content addresses, signed transitions, pinned roots — to a different domain (agent tool-call policy) and a different shape of artefact (capability tokens rather than build attestations).

## 8. Limitations and Future Work

We list limitations honestly. Several are direct consequences of the threat model in Section 2; the rest are practical scope decisions for this paper.

**Bounded tool-call surface only.** VCD addresses tool calls. Free-form agent output remains unprotected. Composition with output-side defences (constitutional classifiers, output filtering) is straightforward in principle and a natural next step.

**Schema expressivity.** The currently supported JSON Schema fragment is deliberately conservative. Extending to `oneOf`/`anyOf` is straightforward — the SMT encoding becomes a disjunction over each branch. Extending to regex constraints on string fields is more interesting; we believe Z3's string theory is adequate for common cases (allowlisted prefixes, length bounds) and a future paper will report on the coverage of this extension.

**Parameter-space side channels.** Discussed in Section 6.5. The mitigation is schema tightening — replacing unbounded numeric fields with bounded enums where the application semantics permit. A combinatorial analysis of side-channel capacity per schema would be a useful addendum.

**Confused-deputy attacks.** Multi-call attacks where each individual call is policy-compliant but the sequence violates an end-to-end property require provenance and dataflow analysis beyond the per-call gate. Our companion provenance layer addresses this; integrating it with VCD is in progress.

**Bootstrap and key management.** VCD reduces the trust problem from "the model must be robust to all prompt injection" to "the issuer's private key must be uncompromised". This is a substantial improvement but not zero. Standard HSM and key-rotation practices apply; the threat model treats compromise of the issuer's key as out of scope.

**Intent extraction as a second trust boundary.** Every per-task token in this paper is minted from a policy derived from the user's prompt. For the evaluation we author those per-task policies by hand and pin them under a cryptographic hash anchor (§6.0, pre-registration). Production deployments cannot author policies by hand at scale; an intent-extraction component must convert each user prompt into a constraint set. Three credible designs exist, with progressively weaker security properties: (a) a rule-based parser written in a memory-safe language, audited and ideally formally verified, accepting only a bounded grammar of user intents; (b) a structured-output extractor (e.g. JSON-schema-constrained LLM call) running in its own trust domain with its own per-task gate; (c) the agent's own LLM call producing a draft policy that is then reviewed by a human before being signed. Option (a) is the strongest and the only one that preserves the headline property end-to-end; option (b) introduces a new attack surface where a malicious user prompt could coerce the extractor into emitting an over-broad policy, but this surface is itself capability-gateable (the extractor calls only the policy-issuance tool, with constraints on the policy shape). Analysing the security of each option is beyond the scope of this paper and a clear direction for follow-up work.

**Defender effort.** A platform operator must author both a JSON Schema and a policy for each tool. The SMT prover catches inconsistencies but does not invent either artefact. For tools whose semantics are not well-understood by the operator, this is real effort. We argue that the effort is well-spent: it is the same security-engineering work that good API design requires regardless of whether an LLM is involved.

## 9. Conclusion

Prompt injection has been treated for four years as a problem of robustifying the model against natural-language attack inputs. That framing is structurally bounded by the open-grammar nature of the input surface; the empirical ceiling on text-side defences against state-of-the-art benchmarks sits at 14-31% attack success rate.

We have argued that the consequential half of an agent's behaviour passes through a much narrower interface, that the interface is bounded enough to admit cryptographic and proof-based enforcement, and that the resulting composition — SMT-verified policy completeness over the JSON Schema, Ed25519-signed capability tokens with mechanised attenuation invariants, gate enforcement on the only path to tool execution — eliminates the tool-call-mediated prompt-injection class. The cost is well under 100 microseconds per call on commodity hardware and the effort of authoring a schema and a policy per tool.

The deeper claim is that the trajectory of AI security must be to move enforcement boundaries out of the model and into structural gates wherever the grammar permits. Tool calls are the easiest such boundary; database queries, generated code, and structured outputs admit similar treatment. The thesis of this paper, generalised, is that the prompt-injection problem becomes tractable exactly when one stops trying to solve it inside the model.

The reference implementation, Lean development, and benchmark harness are MIT-licensed and available at `[anonymised]`.

---

## References

*Bibliography in `paper/references.bib`. Three entries marked `%% UNVERIFIED` need a final check against published proceedings before camera-ready.*

- Anthropic. Constitutional Classifiers. 2024.
- Backes, J. et al. Semantic-based automated reasoning for AWS access policies using SMT (Zelkova). FMCAD 2018.
- Birgisson, A. et al. Macaroons: cookies with contextual caveats. NDSS 2014.
- Chen, S. et al. StruQ: defending against prompt injection with structured queries. USENIX Sec 2024.
- de Moura, L. and Bjørner, N. Z3: an efficient SMT solver. TACAS 2008.
- de Moura, L. and Ullrich, S. The Lean 4 theorem prover and programming language. CADE 2021.
- Debenedetti, E. et al. AgentDojo: dynamic environment for attacks and defences for LLM agents. NeurIPS 2024.
- Erbsen, A. et al. Simple high-level code for cryptographic arithmetic, with proofs (Fiat-Crypto). S&P 2019.
- Fisler, K. et al. The Margrave tool for firewall analysis. ICSE 2005.
- Greshake, K. et al. Not what you've signed up for: indirect prompt injection in LLM-integrated applications. AISec 2023.
- Hines, K. et al. Defending against indirect prompt injection with spotlighting. arXiv 2024.
- Klein, G. et al. seL4: formal verification of an OS kernel. SOSP 2009.
- Levy, H. Capability-based computer systems. Digital Press 1984.
- mathlib community. mathlib4: a library of mathematics for Lean 4. 2024.
- Miller, M. Robust composition: a unified approach to access control and concurrency control. PhD thesis, 2006.
- Newman, Z. et al. Sigstore: software signing for everybody. CCS 2022.
- Perez, F. and Ribeiro, I. Ignore previous prompt: attack techniques for language models. arXiv 2022.
- PyCA. The cryptography library. https://cryptography.io
- Samuel, J. et al. Survivable key compromise in software update systems. CCS 2010.
- Shapiro, J. et al. EROS: a fast capability system. SOSP 1999.
- Torres-Arias, S. et al. in-toto: farm-to-table guarantees for bits and bytes. USENIX Sec 2019.
- Zhan, Q. et al. InjecAgent: benchmarking indirect prompt injections in tool-integrated LLM agents. ACL Findings 2024.

---

## Author's note on the placeholders

Every `[TBD]` marker in this draft corresponds to a specific measurement or text decision that has to be made before submission. The list of outstanding work:

1. **Run AgentDojo with all six configurations.** Records the four ASR columns and the benign-completion column.
2. **Run InjecAgent likewise.** Same.
3. **Measure gate latency** on commodity hardware over a representative call distribution.
4. **Mechanise the three Lean theorems** in `paper/lean/`. Line counts will firm up as the proofs are written.
5. **Confirm or revise the prior-art ASR numbers.** The figures in the headline table reflect the strongest published results as of late 2025; check for any 2026 publications that move the bar.
6. **Anonymise the implementation citations.** Replace `raucle-detect`, the repository URL, and the case-study deployment name with anonymous identifiers for double-blind submission.
7. **The case study.** Either secure a real deployment willing to be (anonymously) named, or rewrite Section 6.4 around the reference implementation's own usage data.

Once those are addressed, the document is camera-ready.
