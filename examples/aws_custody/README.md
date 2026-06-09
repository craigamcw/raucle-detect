# Portable, provable AWS custody — the anti-lock-in demo

One runnable scenario showing the whole custody → evidence wedge: an agent makes
two AWS calls through the raucle **AWS Egress Gate**, and the result is a
self-contained pack a regulator verifies **fully offline**.

```
pip install 'raucle-detect[compliance]'
python examples/aws_custody/demo.py
```

No AWS account or network needed — the transport is stubbed so the run is
deterministic. Evidence is written under `./demo-output/aws-custody/`.

## What it shows

1. **Credential custody.** raucle — not the agent — holds the AWS credentials and
   is the sole signer + egress path. The agent never sees a credential or the
   `Authorization` header.
2. **No receipt = no action.** An authorised DynamoDB read is gated, SigV4-signed,
   forwarded, and emits a per-action Ed25519 JWS provenance receipt *before*
   transport. The gate is constructed `require_durable_receipt=True`, so it
   refuses to run at all without somewhere durable to record.
3. **Denials are attested too.** An unauthorised read is refused *before* signing
   — and the refusal is itself a signed receipt.
4. **Offline-verifiable evidence.** Every action becomes a `raucle audit-pack`
   that verifies with no network, no AWS, and no trust in raucle: a signed index,
   member integrity, the manifest signature, the receipt chain against the
   bundled public key, reproducibility, and a pinned-custodian check.

## Why it matters

AWS Bedrock AgentCore Policy (GA March 2026) gates the same calls and logs
decisions to **CloudWatch** — evidence that is the cloud provider attesting to
itself, readable only by trusting AWS. The pack this demo produces is an Ed25519
chain a bank's FCA/BaFin examiner verifies against a public key **without the
cloud provider's cooperation**. That independent, offline verifiability is the
property a hyperscaler's internal log structurally cannot offer — and it is the
standard regulated industries already demand for everything else.

## The same flow from the CLI

```
raucle audit-pack build  <chain.jsonl> --pubkeys <broker.json> --sign-key <audit.pem> --out pack/
raucle audit-pack verify pack/ --signer <custodian-key-id>
```
