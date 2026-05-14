# Cross-walk: NIST AI RMF → Raucle controls

NIST AI 100-1 organises AI risk management into four functions: **Govern** (policies and oversight), **Map** (context and risk identification), **Measure** (assessment and tracking), **Manage** (response and mitigation). This document maps the Raucle primitives to the sub-Categories where they apply, identifies the evidence artefacts a Raucle deployment produces, and notes what an auditor would check.

Sub-category identifiers follow the NIST notation: `<FUNCTION>-<CATEGORY>.<SUB>`. Quoted wording is paraphrased from the AI RMF Core (AI 100-1) and the Generative AI Profile (AI 600-1) — the canonical text is authoritative.

## GOVERN

### GOVERN-1.4 — Mechanisms for documenting policies are established.

| | |
|---|---|
| **Raucle control** | `cap:v1` policy files (e.g. `paper/eval/policies/banking.json`) are version-controlled JSON documents with human-readable `_intent` and `_policy_notes` fields for every authorised tool. |
| **Evidence** | The policy files themselves; SHA-256 hashes committed to a pre-registration document; git history showing every edit with commit message rationale. |
| **Auditor check** | Pull the policy file. Verify the hash matches the pre-registration entry for the date of any decision under audit. Read the `_intent` field for a given user task; cross-reference with the user prompts the system actually received. |

### GOVERN-2.1 — Roles and responsibilities related to AI risks are documented.

| | |
|---|---|
| **Raucle control** | Token issuers (`cap:v1.issuer` field) name the principal responsible for authorising a class of tool calls. Multi-issuer deployments separate platform-operator authority (mints root tokens) from session-level authority (mints attenuated children). |
| **Evidence** | The set of `trusted_issuers` configured at each gate; documented procedures for issuer key rotation, HSM access, and emergency revocation. |
| **Auditor check** | Match the `key_id` on any token in the audit log to a named role in the organisation chart. |

### GOVERN-4.2 — Documented business justification for AI system deployment.

| | |
|---|---|
| **Raucle control** | Each tool's JSON Schema declares its intended interface; each `_intent` field in the policy declares which user requests the tool is authorised to serve. |
| **Evidence** | The schemas + policy files form a complete declaration of "what this agent is allowed to do, and why". |
| **Auditor check** | For any tool authorised in production, can the operator point to a user-prompt template that exercises it legitimately? |

## MAP

### MAP-2.3 — Scientific integrity and TEVV considerations are identified.

| | |
|---|---|
| **Raucle control** | `proof:v1` artefacts certify policy completeness over a tool's schema using independently-implemented SMT solvers (Z3 / CVC5). The Lean 4 mechanisation of the three soundness theorems is independently re-verifiable in 30 minutes. |
| **Evidence** | Proof artefacts (`paper/eval/`); Lean development (`paper/lean/`); cross-validation against second-implementation solver runs. |
| **Auditor check** | Reproduce the proofs locally. The Lean development should compile with zero `sorry`s under the pinned Mathlib version. |

### MAP-5.1 — Likelihood and magnitude of each identified risk is assessed.

| | |
|---|---|
| **Raucle control** | Static verifier (`paper/eval/verify_policies.py`) reports an *upper bound* on attack-success rate against catalogued benchmarks. End-to-end empirical numbers from AgentDojo + InjecAgent provide the lower bound. |
| **Evidence** | Static verifier output: 0/2737 attack scenarios across both benchmarks. Pre-registered policy hashes (PRE-REGISTRATION.md). CI job that re-runs the verifier on every commit. |
| **Auditor check** | Run the verifier locally. Confirm CI build status is green for every policy change. |

## MEASURE

### MEASURE-2.6 — AI system performance is regularly evaluated.

| | |
|---|---|
| **Raucle control** | `gate-decision:v1` events are hash-chained and (optionally) signed at periodic checkpoints. The event format supports SIEM ingestion for ongoing measurement of authorise/deny rates, deny-reason distributions, and per-tool deny-rate trending. |
| **Evidence** | Audit-chain files; SIEM dashboards; per-quarter denial-rate reports. |
| **Auditor check** | Walk a chain backwards from any reported metric. Verify the chain-integrity check passes. |

### MEASURE-2.7 — AI system security and resilience are evaluated.

| | |
|---|---|
| **Raucle control** | Pre-registered policy hashes anchor evaluation runs. AgentDojo + InjecAgent ASR measurements provide quantitative resilience metrics. Static verifier provides upper bound. |
| **Evidence** | Pre-registration document; AgentDojo / InjecAgent eval results; latency measurements; static verifier output. |
| **Auditor check** | The pre-registration document's hashes match the policy files at the time of measurement. The CI job's history shows the static verifier passed at every commit between pre-registration and the eval run. |

### MEASURE-2.9 — Privacy of training data and inputs is examined.

| | |
|---|---|
| **Raucle control** | `gate-decision:v1` events default to `args_hash` only, not full argument values. PII guidance in the gate-decision profile recommends per-deployment redaction policies. |
| **Evidence** | Configured redaction policy; sample audit-log entries showing hashed-only args; PII data-classification mapping. |
| **Auditor check** | Sample audit-log entries. Confirm sensitive argument values are hashed, not in plaintext. |

### MEASURE-2.10 — Provenance and lineage of AI inputs/outputs are tracked.

| | |
|---|---|
| **Raucle control** | Receipt-chain primitive (`raucle_detect.provenance`, shipped in v0.5) records signed receipts for every scan, model call, and tool invocation, linked by Merkle DAG. |
| **Evidence** | Receipt files; chain-of-custody report for any specific output. |
| **Auditor check** | Pick any agent output. Walk the receipt chain back to the user input that originated it. Verify every link's signature. |

## MANAGE

### MANAGE-2.3 — Mechanisms are in place to supersede, disengage, or deactivate AI systems.

| | |
|---|---|
| **Raucle control** | Token expiry + issuer-key rotation provide a fast disengage path: rotating the issuer key invalidates all outstanding tokens issued under it. Per-tool token revocation via short TTLs limits the blast radius of any compromised token. |
| **Evidence** | Documented key-rotation procedure; tested deactivation runbook. |
| **Auditor check** | Trigger an emergency-revocation drill. Time the propagation to all gate instances. |

### MANAGE-4.1 — Post-deployment AI system monitoring plan is implemented.

| | |
|---|---|
| **Raucle control** | `gate-decision:v1` events + checkpoint Merkle roots + signed audit chain provide tamper-evident monitoring. Standard SIEM tooling consumes the event stream. |
| **Evidence** | SIEM dashboards; alerting rules; quarterly chain-integrity verification report. |
| **Auditor check** | Sample a recent chain. Verify Merkle root at the latest checkpoint. Confirm SIEM alerts fired for any abnormal denial-rate spikes. |

### MANAGE-4.3 — Incidents and errors are communicated to relevant AI actors.

| | |
|---|---|
| **Raucle control** | The structured `deny_reason` and `deny_check` fields in every DENY event provide actionable information for triage. The fixed vocabulary (`issuer_pinning`, `signature`, `tool_match`, `constraint`, …) lets SIEM rules categorise without per-tool customisation. |
| **Evidence** | Incident-response playbooks keyed to `deny_check` values. |
| **Auditor check** | Pick a recent incident. Trace it from the original DENY event to the resolution. |

## Summary table

| NIST sub-Category | Primary Raucle artefact |
|---|---|
| GOVERN-1.4 | `cap:v1` policy files + pre-registration |
| GOVERN-2.1 | `trusted_issuers` map |
| GOVERN-4.2 | tool JSON Schemas + `_intent` fields |
| MAP-2.3 | `proof:v1` artefacts + Lean mechanisation |
| MAP-5.1 | Static verifier output |
| MEASURE-2.6 | `gate-decision:v1` chain |
| MEASURE-2.7 | Pre-registration + benchmark results |
| MEASURE-2.9 | `args_hash` + redaction policy |
| MEASURE-2.10 | Receipt chain (provenance) |
| MANAGE-2.3 | Key rotation + token expiry |
| MANAGE-4.1 | SIEM + Merkle checkpoints |
| MANAGE-4.3 | `deny_check` vocabulary |

12 sub-Categories with direct artefact support. We do not claim coverage of the entire AI RMF; we claim a defensible technical implementation path for the Tool-Misuse and Indirect-Prompt-Injection subcategories that overlap with our threat model.

## What this is NOT

- A claim that Raucle is "compliant" with AI RMF. Compliance with a voluntary framework is not a binary; this cross-walk is one possible implementation of a subset.
- A request that NIST cite or endorse Raucle. The library is implementation-agnostic; the framework is technology-agnostic. The cross-walk is offered as a community contribution.
- A replacement for any of: AI governance committees, model evaluation pipelines, red-team exercises, regulatory legal review. Those are organisational controls; Raucle is a technical primitive.
