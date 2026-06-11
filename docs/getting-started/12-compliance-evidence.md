# 12. Compliance evidence packs

When a regulated buyer asks *"show me your agent-authorization evidence,"* one
command turns your signed receipt chain into a **control-mapped evidence map**
for a named framework — the artifact a CISO hands an auditor.

```bash
raucle compliance report receipts.jsonl --framework eu-ai-act
raucle compliance report receipts.jsonl --framework soc2 --format json --out soc2.json
```

Supported: `eu-ai-act`, `iso-42001`, `soc2`.

## What it produces

For each control the chain evidences, the report states the **status**
(SATISFIED / PARTIAL / OUT_OF_SCOPE) and the **concrete evidence** — real counts
pulled from the chain:

| Control | Status | Evidence |
|---|---|---|
| **Art.12** Record-keeping (automatic logging) | SATISFIED | 10 authorization decisions (7 ALLOW / 3 DENY) recorded as a tamper-evident, Ed25519-signed, timestamped hash chain with 1 signed checkpoint; independently verifiable offline. |
| **Art.14** Human oversight | PARTIAL | The gate is the enforcement point where a human-set policy is applied; interactive approval UX is out of scope. |

## Honest by construction

This is an **evidence map, not a conformance attestation.** Every report leads
with that disclaimer. raucle evidences the *subset* of each framework its
primitives genuinely address — record-keeping, capability access control, and
monitoring — and says plainly what is out of scope. A control is marked
SATISFIED only when the chain truly proves it: an **unsigned** chain downgrades
the logging controls to PARTIAL automatically, because integrity without
authentication is weaker evidence.

This honesty is the point. A regulated buyer can hand the map to their assessor
and trust it, which is worth more than an inflated "you are compliant" claim
that collapses under audit.

## Verify the underlying chain

The evidence map is only as good as the chain it reads. Verify and bundle it:

```bash
raucle audit verify receipts.jsonl        # signed-chain integrity
raucle audit-pack build receipts.jsonl    # offline-verifiable evidence pack
```

---

Generated from the same signed receipt chain the [capability gate](01-hello-receipt.md)
and [SIEM export](08-siem-and-live-view.md) produce. No new instrumentation —
the evidence was there; this names it against the controls a buyer asks about.
