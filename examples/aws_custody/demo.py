"""Portable, provable AWS custody — the evidence a regulator verifies offline.

This is the end-to-end wedge in one runnable script. An agent tries two AWS
actions through the raucle AWS Egress Gate. raucle — not the agent — holds the
AWS credentials and is the sole signer + egress path, so:

1. an **authorised** DynamoDB read is gated, SigV4-signed with raucle-held creds,
   forwarded, and a per-action JWS provenance receipt is emitted;
2. an **unauthorised** read is denied *before* signing — and the refusal is
   cryptographically attested too;
3. the agent never holds a credential and never sees signed material;
4. every action becomes a self-contained ``audit-pack`` that a regulator
   verifies **fully offline** — no network, no AWS, no trust in raucle.

The point of contrast: AWS Bedrock AgentCore Policy (GA 2026) gates the same
calls and logs decisions to CloudWatch — but that evidence is the cloud
provider attesting to itself, readable only by trusting AWS. The pack this demo
produces is an Ed25519 chain a bank's FCA/BaFin examiner verifies against a
public key, *without the cloud provider's cooperation*. That is the property a
hyperscaler's internal log structurally cannot offer.

Run::

    pip install 'raucle-detect[compliance]'
    python examples/aws_custody/demo.py

No AWS account or network is needed — the transport is stubbed so the demo is
deterministic. It writes the evidence pack under ``./demo-output/aws-custody/``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle_detect.audit_pack import build_pack, verify_pack
from raucle_detect.broker import AWSEgressGate, CapabilityDenied
from raucle_detect.capability import CapabilityGate, CapabilityIssuer
from raucle_detect.provenance import AgentIdentity, ProvenanceLogger

OUT = Path("demo-output/aws-custody")
OUT.mkdir(parents=True, exist_ok=True)
FIXED_CLOCK = 1_700_000_000  # deterministic timestamps for a reproducible pack


class _StubAWS:
    """Stand-in for AWS: records the signed request, returns a canned response.
    Real deployments drop this and let the gate forward to AWS over HTTPS."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    def __call__(self, signed_request: object) -> tuple[int, bytes]:
        self.calls.append(signed_request)
        return 200, b'{"Item":{"customer_id":{"S":"C-123"},"kyc_status":{"S":"verified"}}}'


def _audit_key_pem() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def main() -> int:
    print("=" * 72)
    print("raucle — portable, provable AWS custody")
    print("=" * 72)

    # ── Setup: the bank's platform issues a narrow capability to the agent ──
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="dynamodb.GetItem",
        constraints={"allowed_values": {"TableName": ["customers"]}},
        ttl_seconds=300,
    )

    # raucle's broker identity signs the per-action provenance receipts; the
    # audit key signs the evidence pack. In production these live in a vault the
    # agent cannot reach.
    broker = AgentIdentity.generate(agent_id="agent:raucle-aws-egress-broker")
    chain_path = OUT / "custody-chain.jsonl"
    writer = ProvenanceLogger(broker, sink_path=chain_path)

    aws = _StubAWS()
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",  # raucle-held; never reaches the agent
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        provenance_writer=writer,
        require_durable_receipt=True,  # fail closed: no durable receipt → refuse
        transport=aws,
        clock=lambda: FIXED_CLOCK,
    )

    # ── 1. An AUTHORISED read — gated, signed, forwarded, receipted ──
    print("\n[1] agent → GetItem(customers, C-123)  [authorised]")
    result = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )
    print(f"    gate decision : {result.receipt['decision']}")
    print(f"    AWS response  : HTTP {result.status} (forwarded by raucle)")
    print(f"    receipt       : {result.receipt['provenance_receipt_hash']}")
    blob = repr(result).lower()
    leaked = any(s in blob for s in ("authorization", "akidexample", "wjalrxutnfemi"))
    print(f"    agent sees credentials/signature? {'YES (BUG)' if leaked else 'no'}")
    if leaked:
        print("    custody BROKEN: signed material leaked to the agent")
        return 1

    # ── 2. An UNAUTHORISED read — denied BEFORE signing, still attested ──
    print("\n[2] agent → GetItem(audit_logs, *)     [not in the capability]")
    try:
        egress.get_item(
            token,
            key={"id": {"S": "anything"}},
            table="audit_logs",
            agent_id="agent:kyc-prod",
        )
        print("    ERROR: the gate should have denied this")
        return 1
    except CapabilityDenied as exc:
        reached_aws = len(aws.calls) != 1  # only the one authorised call may forward
        print(f"    gate decision : DENY ({exc.reason})")
        print(f"    reached AWS?  : {'yes (BUG)' if reached_aws else 'no'}")
        if reached_aws:
            print("    custody BROKEN: a gated call reached AWS unexpectedly")
            return 1
    writer.close()

    # ── 3. Bundle the evidence into a self-contained, offline pack ──
    print("\n[3] building the regulator evidence pack…")
    index = build_pack(
        chain_path=chain_path,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key_pem(),
        out_dir=OUT / "pack",
        generated_at=FIXED_CLOCK,
    )
    custodian = index["audit_key_id"]
    print(f"    pack written  : {OUT / 'pack'}  ({len(index['members'])} members)")
    print(f"    custodian key : {custodian}")

    # ── 4. Verify it OFFLINE, the way an examiner would — pinning the custodian ──
    print("\n[4] regulator verifies the pack OFFLINE (no network, no AWS)…")
    verdict = verify_pack(OUT / "pack", expected_signer=custodian)
    for label, ok in (
        ("index signature", verdict.index_signature_ok),
        ("member integrity", verdict.integrity_ok),
        ("manifest signature", verdict.manifest_signature_ok),
        (f"receipt chain ({verdict.receipt_count} receipts)", verdict.chain_valid),
        ("reproducible", verdict.reproducible),
        ("signer is the pinned custodian", verdict.signer_trusted),
    ):
        print(f"    {'✓' if ok else '✗'} {label}")
    print(f"\n    RESULT: {'VERIFIED' if verdict.ok else 'REJECTED'}")

    print("\n" + "-" * 72)
    print("AgentCore Policy would log these decisions to CloudWatch — evidence you")
    print("must trust AWS to read. The pack above is an Ed25519 chain a regulator")
    print("verifies against a public key, without the cloud provider's cooperation.")
    print("-" * 72)
    return 0 if verdict.ok else 1


if __name__ == "__main__":
    sys.exit(main())
