# Co-author outreach

A second author with formal-methods credentials makes §4 (the Lean
mechanisation) dramatically stronger and converts a solo paper into a
collaboration — both signals more attractive to FAANG hiring and acquihire
conversations than the paper alone.

## Target profile

Looking for one of:

- **PhD student or postdoc** working on formally-verified systems security
  (capability OS, language-based security, SMT for policy verification).
- **Industry researcher** at Galois, MITRE, JPL, or a national lab who has
  shipped Lean / Coq / F* mechanisations of security properties.
- **Faculty** with prior S&P / USENIX / CCS publications in the
  capability-discipline or policy-verification lineage who is currently
  taking on a junior co-author role on a focused project.

The candidate does *not* need prior LLM-security experience. The contribution
is the formal half of §4 plus a careful review of §3.3 and §3.4. Their
Lean fluency is the load-bearing skill.

## Where to find them

| Venue / list | Why |
|---|---|
| USENIX Security 2024-2026 PC, sub-area "formal methods" | Active, recognisably credentialed |
| IEEE S&P 2024-2026 authors of capability / policy-verification papers | Same |
| Lean Zulip — `#mathlib4 > security` and `#general > industry collab` | Strong filter for working Lean expertise |
| Coq-club mailing list | Same for Coq-fluent candidates |
| Galois "Cryptol / SAW" team | Industry side, security-focused |
| Felipe Bañados Schwerter, Jane Street, Tweag, Run-Time Verification Inc. | Industry contractors |

## Email template

Subject: **Co-author on a focused S&P submission — verified capabilities for LLM agents**

> Hi [name],
>
> I'm reaching out because of your work on [specific paper, e.g. "Verified IFC for Coq-Mtac" / "Mechanising capability discipline in Iris"], which is the closest published prior art to a system I've been building this year and now want to write up.
>
> Short version: I've shipped an open-source library (~2,500 LoC Python, MIT-licensed, currently on PyPI) that composes SMT-verified completeness of JSON Schema-bounded tool-call policies with Ed25519-signed capability tokens carrying mechanically-enforced attenuation invariants. The empirical claim is that this reduces AgentDojo and InjecAgent attack success to under 1% for tool-call-mediated attacks at production-acceptable latency.
>
> I have a complete prose draft and a Lean 4 skeleton of three soundness theorems (attenuation monotonicity, gate soundness, policy-proof composition). The proofs are sketched at the data-model level with about 600 lines of mechanical case analysis and lattice reasoning remaining. I'm targeting S&P's December 2026 cycle.
>
> I'm looking for a co-author who would own §4 (the Lean mechanisation) and review §3 (the formal data model). The empirical work and prose are mine. The draft, Lean skeleton, and review notes are public: [repo URL]/tree/main/paper.
>
> If this is interesting, I'd love a 30-minute call to walk you through the skeleton and see whether the workload feels right for the next six weeks. If it's not the right fit for you, a pointer to someone who might be is also enormously appreciated.
>
> Best,
> [your name]

## Notes on sending

1. **Personalise the first sentence.** A generic email gets deleted; a sentence that proves you read their work gets answered.
2. **Lead with the deadline.** Six weeks is short. Candidates who can commit need to know up front so they can decline if they can't.
3. **Send to three at once, not ten.** A 30% reply rate at this profile is realistic; three emails = roughly one reply. If none replies in five working days, send three more.
4. **Don't offer first authorship in the cold email.** Position the offer as "co-author owning §4". If a strong candidate counter-offers a different role, negotiate from there.
5. **Be ready with a real public repo link** when sending. The cold email's credibility depends entirely on the recipient being able to inspect the draft and the Lean skeleton in 60 seconds. The links must work.

## Candidates to consider

*(Placeholder — populate from the venues above before sending.)*

| Name | Affiliation | Why | Status |
|---|---|---|---|
| — | — | — | not contacted |
| — | — | — | not contacted |
| — | — | — | not contacted |

## Backup plan: no co-author

If three rounds of outreach yield no co-author by end of Week 2:

- Carry the Lean development solo. Plan: spend Week 3 on Lean rather than on
  the eval harness. Block out three full days; expect mid-week frustration.
- Weaken Theorem 3's statement to "we sketch the composition argument" if any
  proof refuses to close cleanly. The paper still lands; the contribution is
  marginally smaller.
- Add a third "external reviewer" pass in Week 5 by emailing one formal-methods
  acquaintance for read-through feedback only (no authorship), at the
  acknowledgments-line cost rather than the co-author cost.
