"""A minimal MCP server exposing the AWS Egress Gate as tools.

This is the front-end that lets a real MCP host (Claude Desktop, Cursor, an
agent runtime) reach AWS **only** through raucle's credential-custody gate. The
host calls MCP tools (``aws.dynamodb.get_item`` etc.); raucle holds the AWS
credentials, runs the :class:`~raucle_detect.broker.AWSEgressGate` (which gates,
SigV4-signs, forwards, and emits a receipt), and returns only the result. The
host/agent never holds an AWS credential or sees the ``Authorization`` header.

Because raucle *is* the MCP server here (not a transparent proxy of an arbitrary
upstream), only the small method set a host actually calls is implemented:
``initialize``, ``notifications/initialized``, ``tools/list``, ``tools/call``.
That keeps the protocol surface bounded and correct rather than re-implementing
the whole bidirectional MCP session. The JSON-RPC handling is a pure
``handle(message) -> response`` function so it is testable without any I/O; a
thin :meth:`serve_stdio` loop wires it to stdin/stdout.

Custody still depends on the deployment: the host must hold no AWS credentials
and have no direct AWS egress — only this server does.
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import Callable
from typing import Any

from .aws_egress import AWSEgressGate, CapabilityDenied, EgressResult

_PROTOCOL_VERSION = "2024-11-05"

# JSON-RPC error codes (subset of the spec).
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603

_TOOLS = [
    {
        "name": "aws.dynamodb.get_item",
        "description": "Read one item from a DynamoDB table through the raucle "
        "custody gate. Every call is capability-gated and produces a signed "
        "receipt.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "key": {
                    "type": "object",
                    "description": "DynamoDB key in attribute-value form, e.g. "
                    '{"customer_id": {"S": "C-123"}}.',
                },
            },
            "required": ["table", "key"],
        },
    },
    {
        "name": "aws.s3.get_object",
        "description": "Fetch an S3 object through the raucle custody gate. "
        "Returns the object bytes base64-encoded.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bucket": {"type": "string"},
                "key": {"type": "string"},
            },
            "required": ["bucket", "key"],
        },
    },
    {
        "name": "aws.s3.put_object",
        "description": "Write an S3 object (base64 body) through the raucle "
        "custody gate. Size can be capability-constrained.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bucket": {"type": "string"},
                "key": {"type": "string"},
                "body_b64": {"type": "string", "description": "base64 of the body"},
                "content_type": {"type": "string"},
            },
            "required": ["bucket", "key", "body_b64"],
        },
    },
]


class RaucleMCPServer:
    """MCP server wrapping an :class:`AWSEgressGate`.

    Parameters
    ----------
    gate
        The AWS egress gate (holds AWS credentials; the sole signer + egress).
    token_provider
        Returns the in-force capability token for the current call. A callable so
        a host can rotate the session token without rebuilding the server.
    agent_id
        Agent identity passed to the gate for each call.
    server_name, server_version
        Reported in the ``initialize`` response.
    """

    def __init__(
        self,
        gate: AWSEgressGate,
        *,
        token_provider: Callable[[], Any],
        agent_id: str | None = None,
        server_name: str = "raucle-aws-egress",
        server_version: str = "0.1.0",
    ) -> None:
        self._gate = gate
        self._token_provider = token_provider
        self._agent_id = agent_id
        self._server_name = server_name
        self._server_version = server_version

    # ── JSON-RPC dispatch (pure: message in, response-or-None out) ─────────
    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process one JSON-RPC message. Returns a response dict, or ``None`` for
        a notification (no id / no reply expected)."""
        method = message.get("method")
        msg_id = message.get("id")

        # Notifications (no id) get no response.
        if msg_id is None:
            return None

        if method == "initialize":
            return self._ok(
                msg_id,
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": self._server_name,
                        "version": self._server_version,
                    },
                },
            )
        if method == "tools/list":
            return self._ok(msg_id, {"tools": _TOOLS})
        if method == "tools/call":
            return self._tools_call(msg_id, message.get("params") or {})
        return self._err(msg_id, _METHOD_NOT_FOUND, f"method not found: {method}")

    def _tools_call(self, msg_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        args = params.get("arguments") or {}
        token = self._token_provider()
        try:
            if name == "aws.dynamodb.get_item":
                result = self._gate.get_item(
                    token,
                    table=args["table"],
                    key=args["key"],
                    agent_id=self._agent_id,
                )
                return self._tool_ok(msg_id, json.dumps(result.json()))
            if name == "aws.s3.get_object":
                result = self._gate.get_object(
                    token,
                    bucket=args["bucket"],
                    key=args["key"],
                    agent_id=self._agent_id,
                )
                return self._tool_ok(msg_id, self._s3_payload(result))
            if name == "aws.s3.put_object":
                try:
                    body = base64.b64decode(args["body_b64"], validate=True)
                except ValueError:  # binascii.Error subclasses ValueError
                    return self._err(msg_id, _INVALID_PARAMS, "body_b64 is not valid base64")
                result = self._gate.put_object(
                    token,
                    bucket=args["bucket"],
                    key=args["key"],
                    body=body,
                    content_type=args.get("content_type", "application/octet-stream"),
                    agent_id=self._agent_id,
                )
                return self._tool_ok(msg_id, json.dumps({"status": result.status}))
        except KeyError as exc:
            return self._err(msg_id, _INVALID_PARAMS, f"missing argument: {exc}")
        except CapabilityDenied as exc:
            # A gate denial is a tool-level error the model should see, not a
            # protocol error. The denial reason carries no signed material.
            return self._tool_error(msg_id, f"capability denied: {exc.reason}")
        except Exception as exc:  # noqa: BLE001 - fail safe; never leak exc text
            # Surface ONLY the exception type — a lower-layer message could carry
            # signed material (Authorization header, canonical request) or
            # credentials, which must never reach the host/model.
            return self._tool_error(msg_id, f"egress error ({type(exc).__name__})")
        return self._err(msg_id, _INVALID_PARAMS, f"unknown tool: {name}")

    @staticmethod
    def _s3_payload(result: EgressResult) -> str:
        return json.dumps(
            {"status": result.status, "body_b64": base64.b64encode(result.body).decode()}
        )

    # ── response builders ──────────────────────────────────────────────────
    @staticmethod
    def _ok(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def _tool_ok(self, msg_id: Any, text: str) -> dict[str, Any]:
        return self._ok(msg_id, {"content": [{"type": "text", "text": text}]})

    def _tool_error(self, msg_id: Any, text: str) -> dict[str, Any]:
        return self._ok(msg_id, {"content": [{"type": "text", "text": text}], "isError": True})

    # ── stdio loop ─────────────────────────────────────────────────────────
    def serve_stdio(self) -> None:  # pragma: no cover - thin I/O wrapper
        """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = self.handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
