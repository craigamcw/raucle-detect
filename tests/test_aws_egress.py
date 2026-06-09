"""Tests for the AWS Egress Gate (raucle_detect.broker).

Covers: SigV4 correctness against the published AWS test vector, the gate
ALLOW/DENY paths, the receipt binding to the exact wire request, and the
custody invariant that the agent never receives signed material.
"""

from __future__ import annotations

import pytest

cryptography = pytest.importorskip("cryptography")

from raucle_detect.broker import AWSEgressGate, CapabilityDenied, sigv4
from raucle_detect.capability import CapabilityGate, CapabilityIssuer


# ---------------------------------------------------------------------------
# SigV4 — validate against the AWS aws-sig-v4-test-suite "get-vanilla" vector
# ---------------------------------------------------------------------------
def test_sigv4_matches_aws_get_vanilla_vector():
    """The canonical AWS SigV4 KAT: GET / with the example credentials must
    produce the published signature. Proves the signing algorithm is correct."""
    signed = sigv4.sign(
        method="GET",
        service="service",
        region="us-east-1",
        host="example.amazonaws.com",
        path="/",
        headers={},
        body=b"",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        amz_date="20150830T123600Z",
    )
    expected_sig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    assert f"Signature={expected_sig}" in signed.headers["authorization"]
    assert "SignedHeaders=host;x-amz-date" in signed.headers["authorization"]


def test_sigv4_binds_body_and_date():
    """Different body or date must change the signature — the receipt binding
    depends on this."""

    def _sig(body: bytes, date: str) -> str:
        return sigv4.sign(
            method="POST",
            service="dynamodb",
            region="us-east-1",
            host="dynamodb.us-east-1.amazonaws.com",
            path="/",
            headers={"content-type": "application/x-amz-json-1.0"},
            body=body,
            access_key="AKIDEXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            amz_date=date,
        ).canonical_hash

    base = _sig(b'{"TableName":"t"}', "20150830T123600Z")
    assert base != _sig(b'{"TableName":"u"}', "20150830T123600Z")  # body bound
    assert base != _sig(b'{"TableName":"t"}', "20150830T123601Z")  # date bound


# ---------------------------------------------------------------------------
# The gate: ALLOW / DENY / binding / no credential leak
# ---------------------------------------------------------------------------
class _FakeTransport:
    """Captures the signed request and returns a canned DynamoDB response."""

    def __init__(self):
        self.calls = []

    def __call__(self, req: sigv4.SignedRequest):
        self.calls.append(req)
        return 200, b'{"Item":{"customer_id":{"S":"C-123"}}}'


def _gate_and_token(constraints):
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="dynamodb.GetItem",
        constraints=constraints,
        ttl_seconds=300,
    )
    return gate, token


def _egress(gate, transport, *, clock=lambda: 1_700_000_000):
    return AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        transport=transport,
        clock=clock,
    )


def test_allow_signs_forwards_and_receipts():
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    tx = _FakeTransport()
    egress = _egress(gate, tx)

    result = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )

    assert result.status == 200
    assert result.response["Item"]["customer_id"]["S"] == "C-123"
    assert len(tx.calls) == 1  # exactly one wire request
    # Receipt is bound to the exact signed request.
    assert result.receipt["decision"] == "ALLOW"
    assert result.receipt["request_binding"]["canonical_request_hash"] == tx.calls[0].canonical_hash
    assert result.receipt["request_binding"]["service"] == "dynamodb"


def test_deny_never_signs_or_forwards():
    # Constrain to a different table; the requested one is not allowed.
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["other_table"]}})
    tx = _FakeTransport()
    egress = _egress(gate, tx)

    with pytest.raises(CapabilityDenied):
        egress.get_item(
            token,
            table="customers",
            key={"customer_id": {"S": "C-123"}},
            agent_id="agent:kyc-prod",
        )
    assert tx.calls == []  # never reached AWS


def test_agent_never_receives_signed_material():
    """The custody invariant: the EgressResult returned to the agent must carry
    NO Authorization header and NO credentials."""
    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    tx = _FakeTransport()
    egress = _egress(gate, tx)

    result = egress.get_item(
        token,
        table="customers",
        key={"customer_id": {"S": "C-123"}},
        agent_id="agent:kyc-prod",
    )

    blob = repr(result).lower()
    assert "authorization" not in blob
    assert "aws4-hmac-sha256" not in blob
    assert "akidexample" not in blob
    assert "wjalrxutnfemi" not in blob  # the secret key must never surface


def test_receipt_emitted_before_dispatch_survives_transport_failure():
    """no receipt = no action: a request that reaches the transport must already
    have a receipt, even if the transport then fails (timeout after AWS received
    it). The receipt is emitted to the sink BEFORE forwarding."""

    class _RecordingSink:
        def __init__(self):
            self.events = []

        def append(self, event):
            self.events.append(event)
            return event

    class _FailingTransport:
        def __call__(self, req):
            raise RuntimeError("connection reset after request was sent")

    gate, token = _gate_and_token({"allowed_values": {"TableName": ["customers"]}})
    sink = _RecordingSink()
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        sink=sink,
        transport=_FailingTransport(),
        clock=lambda: 1_700_000_000,
    )

    with pytest.raises(RuntimeError):
        egress.get_item(
            token,
            table="customers",
            key={"customer_id": {"S": "C-123"}},
            agent_id="agent:kyc-prod",
        )
    # The receipt for the signed, about-to-be-dispatched request was recorded
    # before the transport failed — the dispatch is never receipt-less.
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "ALLOW"
    assert sink.events[0]["request_binding"]["canonical_request_hash"].startswith("sha256:")
