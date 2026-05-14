# Raucle — standards contributions

Submissions to standards bodies and community working groups, proposing the Raucle primitives as draft interoperable specifications. The Raucle library is the reference implementation; what lives here is the protocol-level definition that anyone could implement.

## Tracks

| Track | Where | What we propose |
|---|---|---|
| OWASP AI Exchange | [owaspai.org](https://owaspai.org) — open knowledge base on AI security | Three control-pattern contributions: capability tokens for agent tools, verified policy proofs, gate decision profile |
| NIST AI Risk Management Framework | [nist.gov/ai-rmf](https://www.nist.gov/itl/ai-risk-management-framework) | Map our primitives to specific Govern/Map/Measure/Manage controls; submit via public comment cycle |
| CNCF / OpenSSF | tentative | If a relevant SIG forms around AI supply-chain attestation, propose the receipt format |
| IETF | tentative | If the capability-token format stabilises and sees multi-vendor adoption, propose as Internet-Draft |

This directory ships the OWASP AI Exchange track. The other tracks are scoped but not yet drafted.

## Strategy

Three submissions, sequenced:

1. **Capability Token format** — most concrete, fastest path to adoption. The token is a JSON object with named, typed fields; the canonicalisation + Ed25519-signature scheme is mechanical to reimplement. Aim: a `cap:v1` profile that any agent framework can emit and any tool runtime can verify.
2. **Verified Policy Proof format** — defines the artefact produced by SMT-verifying a policy against a schema. A `proof:v1` profile that is independent of the prover (Z3, CVC5, Vampire — implementations may differ, the artefact format does not).
3. **Capability Gate decision profile** — defines the standard set of checks a gate must perform and the structured-event format it emits on decision. A `gate-decision:v1` profile suitable for SIEM ingestion.

The three compose. A token references a proof hash. A gate consumes a token, runs a proof-cached check, emits a decision event. Implementations of any one piece can interoperate with implementations of the others.

## Engagement cadence

OWASP AI Exchange accepts contributions via GitHub PR against [github.com/OWASP/www-project-ai-security-and-privacy-guide](https://github.com/OWASP/www-project-ai-security-and-privacy-guide). Initial submissions land as informational; mature ones become "controls" referenced from the threat model. Timeline: 4-8 weeks from submission to merge with active engagement.

NIST AI RMF accepts public comments during designated cycles. Calendar at [nist.gov/ai-rmf](https://www.nist.gov/itl/ai-risk-management-framework). Less interactive than OWASP; submissions are batched and reviewed in cohort.
