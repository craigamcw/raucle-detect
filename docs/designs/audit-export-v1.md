# Audit-export artifact (v1)

The platform "magic moment": a CISO downloads a signed report, hands it to an
FCA/BaFin examiner, and the examiner accepts it because every claim is
independently re-verifiable offline. v1 is a CLI + library over the shipped
v0.17 primitives. It adds no new security primitives and runs nothing — it
verifies what already happened.

## Two layers
1. **Authoritative — signed JSON manifest.** Content-addressed, Ed25519-signed by
   the org's audit key. Carries every node, its status, evidence hashes, and the
   SHA-256 of every input (chain, pubkeys, proofs, tool version). The real
   artifact; the HTML is a view.
2. **Human — rendered HTML (print → PDF).** Exec summary, nodes, proof
   obligations, an input-hash appendix, and a "verify this yourself" appendix.

The report attests *reproducibility* ("these verdicts follow from these inputs"),
not certification. That is the credibility an examiner rewards.

## Inputs (all read-only)
- Provenance chain (JSONL, v0.17 minimal envelope).
- Trusted public keys (capability statements or PEMs).
- Proof artifacts (`ProofResult.to_dict()` JSON).
- The org's Ed25519 audit signing key (signs the manifest).

## Node + obligation status
- **GREEN** — chain verifies clean for this receipt; a `PROVEN` proof obligation
  with its certificate hash + the Lean theorem it rests on.
- **AMBER** — `UNDECIDED` proof, proof-mode informational, or a modelled-but-
  unproven kind; or the chain failed elsewhere but this node was not the flagged
  receipt.
- **RED** — `verify_chain` flagged this receipt (tamper/signature/taint/
  capability/unresolved-chain), or a `REFUTED` proof (with counterexample).

Obligation types: policy completeness (`ProofResult.hash`; rests on the
prover-soundness axiom), attenuation soundness (T1), gate soundness (T2),
composition (T3; the proof↔(schema,policy) binding is strict-mode-operational,
not mechanised). The honesty box stating mechanised-vs-operational ships **in**
the report.

## Verifiability
The manifest embeds the SHA-256 of every input. An examiner re-runs
`raucle-detect provenance verify` and recomputes proof hashes over the same
inputs and reproduces every status. A "Verify this report" appendix gives the
exact commands.

## CLI
`raucle-detect audit-export <chain.jsonl> --pubkeys <...> [--proofs <...>] --sign-key <pem> --out report.html`
(also writes `<out>.manifest.json`, signed).

## NOT in v1
- Not a live/multi-tenant dashboard (later platform graph UI).
- Not a "raucle certified" stamp — reproducible attestation only.
- Runs nothing; mutates nothing; no new security primitives.
