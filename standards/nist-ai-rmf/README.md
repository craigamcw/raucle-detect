# NIST AI Risk Management Framework — cross-walk

NIST AI 100-1 (the AI RMF) organises AI-system risk management into four functions: **Govern**, **Map**, **Measure**, **Manage**. Each function decomposes into Categories (e.g., GOVERN-1, MAP-2) and sub-Categories (GOVERN-1.1 …).

This cross-walk maps the Raucle primitives (`cap:v1`, `proof:v1`, `gate-decision:v1`) and the supporting controls (signed receipts, audit chain, formal verification) to specific NIST sub-Categories. The intent: any organisation already using or planning to align with AI RMF gets a defensible technical implementation path for the relevant Tool-Misuse and Indirect-Prompt-Injection subcategories.

## Files

- [crosswalk.md](crosswalk.md) — the main mapping. NIST sub-Category → Raucle primitive(s), evidence artefacts produced, what an auditor would check.
- [evidence-artefacts.md](evidence-artefacts.md) — for each Raucle primitive, the specific artefacts an audit team can request and how to verify them.

## Submission strategy

NIST publishes the AI RMF and accepts feedback via designated cycles documented at [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework). Unlike OWASP, NIST does not accept ad-hoc PRs — submissions are batched and reviewed in cohort.

The right submission is **not** a request that NIST add our control patterns as normative. NIST AI RMF is voluntary and intentionally implementation-agnostic; asking it to bless a specific protocol would be off-mission. The right submission is:

1. A **playbook companion** — a public document showing how Raucle primitives can be used to meet specific RMF sub-Categories. NIST has hosted similar playbooks for other domains; the AI RMF generative-AI profile launched in 2024 has community-contributed implementation playbooks.
2. Hosted at `raucle.com/nist-ai-rmf/` and linked from the README of the open-source library.
3. Submitted to the AI RMF GitHub at [github.com/usnistgov/AI-RMF-Playbook](https://github.com/usnistgov/AI-RMF-Playbook) as a third-party reference, not a normative change.

Timeline: post-paper-acceptance is fine. The NIST community is slow and patient. Optimising for "is this useful to a compliance team at a Fortune 500" beats optimising for "does NIST cite us".
