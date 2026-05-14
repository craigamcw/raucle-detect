# OWASP AI Exchange — submission drafts

Three draft control patterns proposing the Raucle primitives as informational additions to the [OWASP AI Exchange](https://owaspai.org) threat-model and mitigations cluster on Indirect Prompt Injection.

| Profile | Document | What it standardises |
|---|---|---|
| `cap:v1` | [01-capability-token.md](01-capability-token.md) | Unforgeable, content-addressed, signed token authorising a single tool call under value-level constraints, with chained attenuation. |
| `proof:v1` | [02-verified-policy-proof.md](02-verified-policy-proof.md) | Verifier-independent artefact certifying that a policy is complete over a tool's declared JSON Schema. |
| `gate-decision:v1` | [03-gate-decision-profile.md](03-gate-decision-profile.md) | Standard format for the ALLOW/DENY decision events the gate emits, with chain integrity and SIEM-friendly fields. |

The three compose. A token references a proof hash. A gate consumes a token, optionally checks the proof, and emits a decision event. Each profile is independently useful and the wire formats interoperate.

## Submission process

OWASP AI Exchange accepts contributions via GitHub pull request against [github.com/OWASP/www-project-ai-security-and-privacy-guide](https://github.com/OWASP/www-project-ai-security-and-privacy-guide).

### Pre-submission checklist

- [ ] Cross-check each draft against the current OWASP AI Exchange threat-model taxonomy (link the `TT.*` identifiers we cite to the live taxonomy).
- [ ] Run the test vectors from the reference implementation and check they produce the documented values.
- [ ] Read the AI Exchange contributor guide and align our document structure to its expectations.
- [ ] Identify one or two existing AI Exchange maintainers who'd be receptive to a "new control pattern" PR. The list at [github.com/OWASP/www-project-ai-security-and-privacy-guide/blob/main/MAINTAINERS](https://github.com/OWASP/www-project-ai-security-and-privacy-guide/blob/main/MAINTAINERS) is the starting point.
- [ ] Draft a PR description summarising the three drafts as one cluster, not three independent submissions. Smaller surface for review.

### Submission timing

The right time to submit is after the empirical evaluation in §6.2 of the paper produces measured numbers, but **before** the paper itself is publicly posted. Reasoning:

- An OWASP submission with "we measured 0% ASR on AgentDojo and InjecAgent" is much stronger than one without empirical evidence.
- Submitting before the paper is public means OWASP's contributors can give feedback that improves the paper, not just respond to a finished artefact.
- 4-8 weeks from submission to merge with active engagement is the typical cadence; that timeline fits between the empirical run and an S&P submission window.

If the empirical numbers are not available before the S&P deadline, submit anyway with the static upper bound (0/2737) as the load-bearing result. The static bound is honest and substantial; the LLM-driven measurements add weight but are not strictly required for the protocol's informational status.

## Out of scope for these drafts

Each profile deliberately omits:

- **Implementation details.** No code, no SDK conventions, no language-specific bindings. The reference implementation is named; alternatives are welcome.
- **Threat-model expansion.** We address indirect prompt injection and tool misuse only. We do not propose new threat-model categories.
- **Cryptographic primitives.** Ed25519 + SHA-256 + canonical-JSON. No new crypto.
- **Trust roots.** No global CA, no central registry. Operators pin their own keys.

## What we are explicitly seeking

From the OWASP AI Exchange community:

1. Acceptance of the three profile identifiers (`cap:v1`, `proof:v1`, `gate-decision:v1`) as informational standards.
2. Listing under the Indirect Prompt Injection mitigation cluster, with the three documents linked from a single control entry.
3. Critique. Each draft has an "Open questions for review" section; we treat reviewer pushback as the primary value of the submission process. Better to be challenged here than at an enterprise procurement meeting.

## What this contributes to OWASP AI Exchange specifically

The current AI Exchange Indirect-Prompt-Injection section emphasises model-side defences (filtering, paraphrasing, training-time hardening). Our submission complements that with **enforcement-side** defences operating at the tool-invocation boundary. The two layers compose; neither obsoletes the other. We argue for an addition to the mitigation cluster, not a replacement.
