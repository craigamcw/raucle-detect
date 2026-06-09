"""Tests for the raucle MCP server front-end (raucle_detect.broker.mcp_server).

Exercises the pure JSON-RPC handler: protocol handshake, tool listing, and
tool calls routed through the AWS Egress Gate (ALLOW returns content, DENY
returns an MCP tool error). No I/O.
"""

from __future__ import annotations

import base64
import json

import pytest

cryptography = pytest.importorskip("cryptography")

from raucle_detect.broker import AWSEgressGate, RaucleMCPServer
from raucle_detect.capability import CapabilityGate, CapabilityIssuer


class _FakeTransport:
    def __init__(self, status=200, body=b'{"Item":{"id":{"S":"C-1"}}}'):
        self.status = status
        self.body = body
        self.calls = []

    def __call__(self, req):
        self.calls.append(req)
        return self.status, self.body


def _server(constraints, tool, *, transport=None):
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod", tool=tool, constraints=constraints, ttl_seconds=300
    )
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        transport=transport or _FakeTransport(),
        clock=lambda: 1_700_000_000,
    )
    return RaucleMCPServer(egress, token_provider=lambda: token, agent_id="agent:kyc-prod")


def _req(method, params=None, msg_id=1):
    m = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        m["params"] = params
    return m


def test_initialize_handshake():
    srv = _server({"allowed_values": {"TableName": ["t"]}}, "dynamodb.GetItem")
    resp = srv.handle(_req("initialize"))
    assert resp["result"]["protocolVersion"]
    assert resp["result"]["serverInfo"]["name"] == "raucle-aws-egress"
    assert "tools" in resp["result"]["capabilities"]


def test_notification_gets_no_response():
    srv = _server({"allowed_values": {"TableName": ["t"]}}, "dynamodb.GetItem")
    # A notification has no id.
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_exposes_the_aws_tools():
    srv = _server({"allowed_values": {"TableName": ["t"]}}, "dynamodb.GetItem")
    resp = srv.handle(_req("tools/list"))
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"aws.dynamodb.get_item", "aws.s3.get_object", "aws.s3.put_object"}


def test_tools_call_dynamodb_allow_routes_through_gate():
    tx = _FakeTransport()
    srv = _server(
        {"allowed_values": {"TableName": ["customers"]}},
        "dynamodb.GetItem",
        transport=tx,
    )
    resp = srv.handle(
        _req(
            "tools/call",
            {
                "name": "aws.dynamodb.get_item",
                "arguments": {"table": "customers", "key": {"id": {"S": "C-1"}}},
            },
        )
    )
    assert "error" not in resp
    assert not resp["result"].get("isError")
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["Item"]["id"]["S"] == "C-1"
    assert len(tx.calls) == 1  # genuinely went through the gate + transport


def test_tools_call_denied_returns_mcp_tool_error():
    srv = _server({"allowed_values": {"TableName": ["other"]}}, "dynamodb.GetItem")
    resp = srv.handle(
        _req(
            "tools/call",
            {
                "name": "aws.dynamodb.get_item",
                "arguments": {"table": "customers", "key": {"id": {"S": "C-1"}}},
            },
        )
    )
    # Denial is a tool-level error (model sees it), not a JSON-RPC protocol error.
    assert "error" not in resp
    assert resp["result"]["isError"] is True
    assert "capability denied" in resp["result"]["content"][0]["text"]


def test_tools_call_s3_get_returns_base64_body():
    tx = _FakeTransport(body=b"\x00\x01\x02 binary")
    srv = _server({"allowed_values": {"Bucket": ["b"]}}, "s3.GetObject", transport=tx)
    resp = srv.handle(
        _req(
            "tools/call",
            {"name": "aws.s3.get_object", "arguments": {"bucket": "b", "key": "k"}},
        )
    )
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert base64.b64decode(payload["body_b64"]) == b"\x00\x01\x02 binary"


def test_unknown_method_is_protocol_error():
    srv = _server({"allowed_values": {"TableName": ["t"]}}, "dynamodb.GetItem")
    resp = srv.handle(_req("does/not/exist"))
    assert resp["error"]["code"] == -32601


def test_missing_argument_is_invalid_params():
    srv = _server({"allowed_values": {"TableName": ["t"]}}, "dynamodb.GetItem")
    resp = srv.handle(_req("tools/call", {"name": "aws.dynamodb.get_item", "arguments": {}}))
    assert resp["error"]["code"] == -32602


def test_egress_exception_text_is_not_leaked_to_host():
    """A lower-layer exception message could carry signed material/creds — the
    tool error must expose only the exception TYPE, never str(exc)."""

    class _LeakyTransport:
        def __call__(self, req):
            raise RuntimeError(
                "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE secret=hunter2"
            )

    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="dynamodb.GetItem",
        constraints={"allowed_values": {"TableName": ["customers"]}},
        ttl_seconds=300,
    )
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        transport=_LeakyTransport(),
        clock=lambda: 1_700_000_000,
    )
    srv = RaucleMCPServer(egress, token_provider=lambda: token)

    resp = srv.handle(
        _req(
            "tools/call",
            {
                "name": "aws.dynamodb.get_item",
                "arguments": {"table": "customers", "key": {"id": {"S": "C-1"}}},
            },
        )
    )
    text = resp["result"]["content"][0]["text"]
    assert resp["result"]["isError"] is True
    assert text == "egress error (RuntimeError)"  # only the type name
    assert "Authorization" not in text
    assert "AKIDEXAMPLE" not in text
    assert "hunter2" not in text


def test_bad_base64_body_is_invalid_params():
    srv = _server({"allowed_values": {"Bucket": ["b"]}}, "s3.PutObject")
    resp = srv.handle(
        _req(
            "tools/call",
            {
                "name": "aws.s3.put_object",
                "arguments": {"bucket": "b", "key": "k", "body_b64": "!!!not base64!!!"},
            },
        )
    )
    assert resp["error"]["code"] == -32602
