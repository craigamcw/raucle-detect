# AWS Cloud Credits for Open Source — application draft

Pre-filled draft for the [AWS Open Source Credits Program](https://aws.amazon.com/blogs/opensource/aws-promotional-credits-open-source-projects/)
(complete the official form and email `awsopen@amazon.com`; reviewed monthly).

---

**Project name:** raucle-detect

**Repository:** https://github.com/craigamcw/raucle-detect (public, Apache-2.0)

**One-line description:** Open-source, formally-grounded AI-agent security —
cryptographic provenance receipts, capability tokens, and a credential-custody
egress gate that produce portable, offline-verifiable evidence of what an agent
did and that it was authorised.

**What the project does (3–4 sentences):**
raucle-detect lets teams put an AI agent in production and *prove* to a regulator
or auditor what it did. An agent never holds downstream credentials; a custody
gate signs every action and emits an Ed25519 provenance receipt, which bundles
into a self-contained "audit pack" that anyone verifies offline against a public
key — no trust in, or contact with, the cloud provider required. The canonical
receipt format has five byte-identical reference implementations (Python, Go,
Rust, TypeScript, C#) and an A2A binding for verifiable inter-agent
authorisation. It is built to the evidentiary standard regulated industries
already demand — formal, mechanised, provable.

**Community value / traction:**
Public, actively developed (regular commits and releases), Apache-2.0. Standards
work in progress (OWASP AI Exchange control patterns, A2A per-skill-authorisation
binding, NIST AI RMF crosswalk). Reference implementations across five languages
with a cross-language conformance kit.

**How the credits will be used (CI / testing / demos):**
1. **Conformance & live validation** — run the egress gate against real AWS
   surfaces (DynamoDB, S3, SQS, Secrets Manager) in CI-adjacent test jobs, so the
   from-scratch SigV4 paths are continuously validated on the wire, not only
   against offline known-answer vectors.
2. **Public demo instances** — host the credential-custody gate + audit-pack
   verifier as a runnable demo so practitioners can see an agent gated and
   download a verifiable evidence pack.
3. **`raucle-bench`** — host the planned public adversarial benchmark
   leaderboard.
4. **Docs / artifact hosting.**

All workloads are scoped to least-privilege IAM and torn down after use; we
already run a NAT-free, ~$0 reference deployment design (see
`docs/proposals/aws-egress-nonbypass.md`).

**Estimated monthly usage:** modest — Fargate task-seconds, a small amount of
DynamoDB/S3/SQS/Secrets traffic, and interface-endpoint hours for demos; well
within Free-Tier for steady state, with credits covering demo/bench spikes.

**Contact:** awsaccount@epic28.com
