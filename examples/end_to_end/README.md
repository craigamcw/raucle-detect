# End-to-end demo — the whole trust graph in one script

One runnable scenario showing every primitive raucle-detect has shipped, composed:

```
user prompt
   │
   ▼
[1] Scanner.scan ─────────────► verdict receipt (Ed25519, v0.5)
   │                              │
   ▼                              │
[2] JSONSchemaProver.prove ────► proof_hash (v0.9)
   │                              │
   ▼                              │
[3] CapabilityIssuer.mint ─────► token bound to proof_hash (v0.10)
   │                              │
   ▼                              │
[4] CapabilityGate.check ──────► ALLOW / DENY decision (v0.10)
   │                              │
   ▼                              ▼
[5] HashChainSink ─────────► Merkle-rooted, signed audit chain (v0.4)
```

## Run

```bash
pip install 'raucle-detect[compliance,proof]'
python examples/end_to_end/demo.py
```

Artefacts land in `./demo-output/`. Every one of them is independently verifiable
offline:

```bash
raucle-detect audit verify demo-output/audit.jsonl --pubkey demo-output/audit.pub.pem
raucle-detect cap verify   demo-output/token.json   --pubkey demo-output/cap.pub.pem
```

## What each step proves

| Step | Primitive | What it answers |
|---|---|---|
| 1 | Scanner + VerdictSigner | "Was the input clean, at this ruleset version, signed by this verdict key?" |
| 2 | JSONSchemaProver | "Over every JSON object the tool's schema permits, is the policy violation-free?" |
| 3 | CapabilityIssuer.mint | "Was this token issued by a trusted key, binding (agent, tool, constraints, expiry) and citing the proof?" |
| 4 | CapabilityGate.check | "For these actual call args, does the token authorise execution?" |
| 5 | HashChainSink | "Is the full sequence of events tamper-evident and signed at the checkpoints?" |

The graph closes: every artefact references the previous by hash, every link is
Ed25519-signed by a pinned key, the audit chain binds them all into one
Merkle-rooted log.
