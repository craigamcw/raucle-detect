"""raucle AWS Egress Gate — first credential-custody build.

The agent sends an *intended* AWS call (no credentials). raucle runs the
:class:`~raucle_detect.capability.CapabilityGate`, and only on ALLOW does it
SigV4-sign the exact request with raucle-held credentials, forward it to AWS, and
return the response. The agent never holds an AWS credential, never sees the
``Authorization`` header, and has no route to AWS except through this gate — so
"no receipt = no action" holds: it cannot act because it holds no key.

Scope (v1): DynamoDB ``GetItem`` only — a narrow, non-streaming, fixed-body
surface. Streaming, presigned URLs, multipart, redirects, and automatic retries
are intentionally out of scope (see docs/proposals/aws-egress-gate.md). Each
forwarded HTTP request gets its own receipt.

Custody requires an operational deployment guarantee: the agent's runtime must
have **no** AWS credentials and **no** direct AWS egress (allowlist to this gate
only). This module enforces the credential half (it never returns signed
material); the egress half is a deployment responsibility.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..capability import Capability, CapabilityGate
from ..provenance import _canonical_json, _sha256_hex
from . import sigv4

# A transport forwards a signed request and returns (status_code, body_bytes).
# Injectable so the gate is testable without live AWS.
Transport = Callable[[sigv4.SignedRequest], "tuple[int, bytes]"]

_DDB_TARGET_PREFIX = "DynamoDB_20120810"
_DDB_CONTENT_TYPE = "application/x-amz-json-1.0"


class CapabilityDenied(Exception):
    """Raised when the gate denies an AWS call. A DENY receipt is emitted before
    the raise; the request is never signed and never reaches AWS."""

    def __init__(self, action: str, reason: str) -> None:
        super().__init__(f"AWS egress denied for {action!r}: {reason}")
        self.action = action
        self.reason = reason


def _hash(obj: Any) -> str:
    return "sha256:" + _sha256_hex(_canonical_json(obj))


def _http_transport(req: sigv4.SignedRequest) -> tuple[int, bytes]:
    request = urllib.request.Request(  # noqa: S310 - https only, host from AWS
        req.url, data=req.body, headers=req.headers, method=req.method
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # AWS returns 4xx/5xx with a JSON body
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        # Timeout / connection reset / TLS failure. The request may already have
        # reached AWS, so the receipt (emitted before this call) correctly attests
        # the dispatch; we surface a transport-failure status to the agent without
        # leaking any signed material.
        return 0, json.dumps({"_transport_error": str(exc.reason)}).encode("utf-8")


@dataclass(frozen=True)
class EgressResult:
    """What the agent receives: the AWS response and the receipt that binds it.

    Deliberately contains **no** signed material (no ``Authorization`` header, no
    credentials) — only the response the gate chose to return.
    """

    status: int
    response: dict[str, Any]
    receipt: dict[str, Any]


class AWSEgressGate:
    """Holds AWS credentials and is the sole signer + egress path for AWS calls.

    Parameters
    ----------
    gate
        The :class:`CapabilityGate` that authorises each call.
    region, access_key, secret_key, session_token
        raucle-held AWS credentials. Never exposed to the agent.
    sink
        Audit sink with an ``append(event: dict) -> dict`` method that signs and
        hash-chains the receipt (e.g. ``HashChainSink``). Optional.
    lean_theorem_id
        Lean theorem identifier the receipt cites (carried through for parity
        with the other adapters).
    transport, clock
        Injectable for testing. ``transport`` forwards the signed request;
        ``clock`` returns epoch seconds.
    """

    def __init__(
        self,
        gate: CapabilityGate,
        *,
        region: str,
        access_key: str,
        secret_key: str,
        session_token: str | None = None,
        sink: Any | None = None,
        lean_theorem_id: str = "gate_allow_sound",
        transport: Transport | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._gate = gate
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token
        self._sink = sink
        self._lean_theorem_id = lean_theorem_id
        self._transport = transport or _http_transport
        self._clock = clock or time.time

    # ── DynamoDB GetItem (the v1 surface) ──────────────────────────────────
    def get_item(
        self,
        token: Capability,
        *,
        table: str,
        key: dict[str, Any],
        agent_id: str | None = None,
    ) -> EgressResult:
        """Gate, sign, forward, and receipt a DynamoDB ``GetItem`` call.

        ``key`` is the DynamoDB key in attribute-value form, e.g.
        ``{"customer_id": {"S": "C-123"}}``. Raises :class:`CapabilityDenied` if
        the gate denies the call (after emitting a DENY receipt).
        """
        # raucle tool namespace (dot-delimited; the capability `tool` field does
        # not permit the colon of the IAM action name "dynamodb:GetItem").
        action = "dynamodb.GetItem"
        args = {"TableName": table, "Key": key}

        decision = self._gate.check(token, tool=action, agent_id=agent_id, args=args)
        if not decision.allowed:
            self._emit(action, args, decision, request_binding=None)
            raise CapabilityDenied(action, decision.reason)

        body = json.dumps(args, separators=(",", ":")).encode("utf-8")
        host = f"dynamodb.{self._region}.amazonaws.com"
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self._clock()))
        signed = sigv4.sign(
            method="POST",
            service="dynamodb",
            region=self._region,
            host=host,
            path="/",
            headers={
                "content-type": _DDB_CONTENT_TYPE,
                "x-amz-target": f"{_DDB_TARGET_PREFIX}.GetItem",
            },
            body=body,
            access_key=self._access_key,
            secret_key=self._secret_key,
            amz_date=amz_date,
            session_token=self._session_token,
        )

        binding = {
            "method": "POST",
            "host": host,
            "path": "/",
            "region": self._region,
            "service": "dynamodb",
            "amz_date": amz_date,
            "canonical_request_hash": signed.canonical_hash,
        }
        # Emit the receipt for the signed request BEFORE forwarding. The receipt
        # attests "raucle authorised and signed THIS exact request and is
        # dispatching it"; emitting it first guarantees no request can reach AWS
        # without a durable receipt, even if the transport then times out after
        # the request was received ("no receipt = no action" holds on failure).
        receipt = self._emit(action, args, decision, request_binding=binding)
        status, raw = self._transport(signed)
        try:
            response = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            response = {"_raw": raw.decode("utf-8", "replace")}

        # Never return signed material (Authorization header / creds) to the agent.
        return EgressResult(status=status, response=response, receipt=receipt)

    # ── receipt construction ───────────────────────────────────────────────
    def _emit(
        self,
        action: str,
        args: dict[str, Any],
        decision: Any,
        *,
        request_binding: dict[str, Any] | None,
    ) -> dict[str, Any]:
        receipt = {
            "lean_theorem_id": self._lean_theorem_id,
            "attenuation_chain": list(getattr(decision, "chain", []) or []),
            "tool": action,
            "call_args_hash": _hash(args),
            "decision": "ALLOW" if decision.allowed else "DENY",
            "decision_reason": decision.reason,
            "request_binding": request_binding,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())),
        }
        if self._sink is not None:
            return self._sink.append(receipt)
        return receipt
