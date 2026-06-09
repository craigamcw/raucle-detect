#!/usr/bin/env python3
"""Live-AWS smoke test for the raucle AWS Egress Gate (opt-in).

Proves the gate's from-scratch SigV4 works on the wire against REAL AWS — not
just the offline known-answer vectors — across every supported surface, then
proves the resulting receipt chain builds an audit-pack that verifies offline.

boto3 scaffolds throwaway ``<prefix>-*`` resources (a DynamoDB table, an S3
bucket, an SQS queue, a Secrets Manager secret); the **raucle gate** performs the
actual gated calls; everything is deleted in a ``finally``. It is gated behind
``RAUCLE_LIVE_AWS=1`` so it can never run by accident (and never in CI).

Usage::

    pip install boto3
    # credentials for a LEAST-PRIVILEGE IAM user scoped to <prefix>-* resources:
    export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...  AWS_DEFAULT_REGION=eu-west-2
    RAUCLE_LIVE_AWS=1 python scripts/live_aws_smoke.py

Cost is pennies (Free-Tier eligible). Never use root credentials.
"""

from __future__ import annotations

import io
import os
import pathlib
import sys
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raucle_detect.audit_pack import build_pack, verify_pack  # noqa: E402
from raucle_detect.broker import AWSEgressGate, CapabilityDenied  # noqa: E402
from raucle_detect.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle_detect.provenance import AgentIdentity, ProvenanceLogger  # noqa: E402

REGION = os.environ.get("AWS_DEFAULT_REGION", "eu-west-2")
PREFIX = os.environ.get("RAUCLE_SMOKE_PREFIX", "raucle-smoke")
SUF = uuid.uuid4().hex[:10]
TABLE = BUCKET = QUEUE = SECRET = f"{PREFIX}-{SUF}"

results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"  {'OK ' if ok else 'XX '} {name}{(' — ' + detail) if detail else ''}")


def main() -> int:
    import boto3

    ddb = boto3.client("dynamodb", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    sqs = boto3.client("sqs", region_name=REGION)
    sm = boto3.client("secretsmanager", region_name=REGION)
    ak = os.environ["AWS_ACCESS_KEY_ID"]
    sk = os.environ["AWS_SECRET_ACCESS_KEY"]

    def teardown() -> None:
        print(f"[teardown] deleting {PREFIX}-* resources")
        for fn in (
            lambda: ddb.delete_table(TableName=TABLE),
            lambda: [
                s3.delete_object(Bucket=BUCKET, Key=o["Key"])
                for o in s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])
            ],
            lambda: s3.delete_bucket(Bucket=BUCKET),
            lambda: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=QUEUE)["QueueUrl"]),
            lambda: sm.delete_secret(SecretId=SECRET, ForceDeleteWithoutRecovery=True),
        ):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup
                print(f"    (teardown warn: {type(exc).__name__})")

    try:
        print(f"[scaffold] region={REGION} suffix={SUF}")
        ddb.create_table(
            TableName=TABLE,
            AttributeDefinitions=[{"AttributeName": "customer_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "customer_id", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.get_waiter("table_exists").wait(TableName=TABLE)
        ddb.put_item(
            TableName=TABLE,
            Item={"customer_id": {"S": "C-123"}, "kyc_status": {"S": "verified"}},
        )
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        queue_url = sqs.create_queue(QueueName=QUEUE)["QueueUrl"]
        sm.create_secret(Name=SECRET, SecretString='{"api_key":"live-smoke-secret"}')
        time.sleep(2)

        issuer = CapabilityIssuer.generate(issuer="raucle.smoke")
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        broker = AgentIdentity.generate(agent_id="agent:raucle-smoke-broker")
        chain = io.StringIO()
        writer = ProvenanceLogger(broker, sink_file=chain)
        egress = AWSEgressGate(
            gate,
            region=REGION,
            access_key=ak,
            secret_key=sk,
            provenance_writer=writer,
            require_durable_receipt=True,
        )

        def tok(tool, constraints):
            return issuer.mint(
                agent_id="agent:kyc-prod", tool=tool, constraints=constraints, ttl_seconds=300
            )

        print("[gate] real AWS calls via raucle SigV4:")
        r = egress.get_item(
            tok("dynamodb.GetItem", {"allowed_values": {"TableName": [TABLE]}}),
            table=TABLE,
            key={"customer_id": {"S": "C-123"}},
            agent_id="agent:kyc-prod",
        )
        check(
            "dynamodb.GetItem",
            r.json().get("Item", {}).get("kyc_status", {}).get("S") == "verified",
        )
        r = egress.put_object(
            tok("s3.PutObject", {"allowed_values": {"Bucket": [BUCKET]}}),
            bucket=BUCKET,
            key="report.txt",
            body=b"hello-from-raucle",
            agent_id="agent:kyc-prod",
        )
        check("s3.PutObject", r.status in (200, 204))
        r = egress.get_object(
            tok("s3.GetObject", {"allowed_values": {"Bucket": [BUCKET]}}),
            bucket=BUCKET,
            key="report.txt",
            agent_id="agent:kyc-prod",
        )
        check("s3.GetObject", r.body == b"hello-from-raucle")
        r = egress.send_message(
            tok("sqs.SendMessage", {"allowed_values": {"QueueUrl": [queue_url]}}),
            queue_url=queue_url,
            message_body='{"event":"kyc.verified"}',
            agent_id="agent:kyc-prod",
        )
        check("sqs.SendMessage", r.status == 200 and "MessageId" in r.json())
        r = egress.get_secret_value(
            tok("secretsmanager.GetSecretValue", {"allowed_values": {"SecretId": [SECRET]}}),
            secret_id=SECRET,
            agent_id="agent:kyc-prod",
        )
        check(
            "secretsmanager.GetSecretValue", "live-smoke-secret" in r.json().get("SecretString", "")
        )

        denied = False
        try:
            egress.get_item(
                tok("dynamodb.GetItem", {"allowed_values": {"TableName": ["other-table"]}}),
                table=TABLE,
                key={"customer_id": {"S": "C-123"}},
                agent_id="agent:kyc-prod",
            )
        except CapabilityDenied:
            denied = True
        check("gate DENY blocks unauthorised call (never reaches AWS)", denied)
        writer.close()

        # Non-bypass / IAM-custody proof (optional): an AGENT principal holding
        # its OWN no-permission credentials must be DENIED by AWS itself on every
        # surface — proving the agent cannot act even with a key, while the broker
        # (gate) can. Set RAUCLE_AGENT_ACCESS_KEY_ID / _SECRET_ACCESS_KEY to a
        # second IAM user that has NO policy attached.
        agent_ak = os.environ.get("RAUCLE_AGENT_ACCESS_KEY_ID")
        agent_sk = os.environ.get("RAUCLE_AGENT_SECRET_ACCESS_KEY")
        if agent_ak and agent_sk:
            from botocore.exceptions import ClientError

            print("[non-bypass] AWS itself must DENY the no-permission agent principal:")
            ag = boto3.Session(
                aws_access_key_id=agent_ak, aws_secret_access_key=agent_sk, region_name=REGION
            )
            a_ddb, a_s3, a_sqs, a_sm = (
                ag.client("dynamodb"),
                ag.client("s3"),
                ag.client("sqs"),
                ag.client("secretsmanager"),
            )

            def must_deny(label, fn):
                try:
                    fn()
                    check(
                        f"AWS denies agent on {label}",
                        False,
                        "call SUCCEEDED — agent over-privileged",
                    )
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    check(
                        f"AWS denies agent on {label}",
                        code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"),
                        code,
                    )

            must_deny(
                "dynamodb.GetItem",
                lambda: a_ddb.get_item(TableName=TABLE, Key={"customer_id": {"S": "C-123"}}),
            )
            must_deny("s3.GetObject", lambda: a_s3.get_object(Bucket=BUCKET, Key="report.txt"))
            must_deny(
                "sqs.SendMessage", lambda: a_sqs.send_message(QueueUrl=queue_url, MessageBody="x")
            )
            must_deny(
                "secretsmanager.GetSecretValue", lambda: a_sm.get_secret_value(SecretId=SECRET)
            )

        # audit-pack + offline verify over the REAL receipt chain.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        d = pathlib.Path(tempfile.mkdtemp())
        (d / "chain.jsonl").write_text(chain.getvalue())
        audit_key = Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        idx = build_pack(
            chain_path=d / "chain.jsonl",
            public_keys={broker.key_id: broker.public_key_pem()},
            audit_key_pem=audit_key,
            out_dir=d / "pack",
            generated_at=1_700_000_000,
        )
        v = verify_pack(d / "pack", expected_signer=idx["audit_key_id"])
        check(f"audit-pack verifies offline ({v.receipt_count} real receipts)", v.ok)
    finally:
        teardown()

    ok = bool(results) and all(r[1] for r in results)
    print("\nRESULT:", "PASS — raucle gate works against real AWS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if os.environ.get("RAUCLE_LIVE_AWS") != "1":
        print(
            "Refusing to run: this creates and deletes REAL AWS resources.\n"
            "Set RAUCLE_LIVE_AWS=1 and provide least-privilege credentials. "
            "See the module docstring.",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(main())
