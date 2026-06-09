"""raucle AWS Egress Gate — first credential-custody build.

The agent sends an *intended* AWS call (no credentials). raucle runs the
:class:`~raucle_detect.capability.CapabilityGate`, and only on ALLOW does it
SigV4-sign the exact request with raucle-held credentials, forward it to AWS, and
return the response. The agent never holds an AWS credential, never sees the
``Authorization`` header, and has no route to AWS except through this gate — so
"no receipt = no action" holds: it cannot act because it holds no key.

Scope (v1): narrow, non-streaming, fixed-body surfaces — DynamoDB ``GetItem``,
S3 ``GetObject``/``PutObject``, SQS ``SendMessage`` (a gated
action/messaging surface), and Secrets Manager ``GetSecretValue`` (custody of
secrets). Streaming, presigned URLs, multipart, redirects, and automatic retries
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
from ..provenance import ProvenanceLogger, _canonical_json, _sha256_hex
from . import sigv4

# A transport forwards a signed request and returns (status_code, body_bytes).
# Injectable so the gate is testable without live AWS.
Transport = Callable[[sigv4.SignedRequest], "tuple[int, bytes]"]

_DDB_TARGET_PREFIX = "DynamoDB_20120810"
_DDB_CONTENT_TYPE = "application/x-amz-json-1.0"
_SQS_TARGET = "AmazonSQS.SendMessage"
_SQS_CONTENT_TYPE = "application/x-amz-json-1.0"
_SM_TARGET = "secretsmanager.GetSecretValue"
_SM_CONTENT_TYPE = "application/x-amz-json-1.1"


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
    # req.url is always https with an AWS-derived host (built by the gate), never
    # an agent-supplied scheme/host, so the dynamic-urlopen audit flag is moot.
    request = urllib.request.Request(  # noqa: S310
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
    """What the agent receives: the raw AWS response and the receipt that binds it.

    Deliberately contains **no** signed material (no ``Authorization`` header, no
    credentials) — only the response the gate chose to return. ``body`` is the
    raw response bytes (S3 object content is binary; DynamoDB is JSON); use
    :meth:`json` for JSON responses.

    Receipt semantics: ``receipt`` is emitted BEFORE transport (so no AWS request
    is ever dispatched receipt-less, even if the transport then fails). It
    therefore attests an *authorised, signed, dispatched* request — not a
    confirmed AWS-side outcome. The bound ``signed_request_hash`` pins the exact
    request raucle sent; the AWS *result* is whatever ``status``/``body`` report.
    """

    status: int
    body: bytes
    receipt: dict[str, Any]

    def json(self) -> dict[str, Any]:
        """Parse the response body as JSON (DynamoDB / AWS error documents)."""
        if not self.body:
            return {}
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Binary S3 object bytes (or a non-JSON document) — never crash on a
            # response the agent asked us to relay.
            return {"_raw": self.body.decode("utf-8", "replace")}


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
    provenance_writer
        Optional :class:`~raucle_detect.provenance.ProvenanceLogger`. When given,
        every gated action (ALLOW *and* DENY) additionally emits a per-action,
        Ed25519-signed JWS provenance receipt to the writer's chain — the
        portable, **offline-verifiable** custody evidence that ``raucle
        audit-export`` turns into a regulator-grade bundle. Unlike the
        hash-chained ``sink`` (tamper-evident, attributed only at checkpoints),
        each JWS receipt is independently verifiable from a public key without
        the cloud provider's cooperation. The returned receipt dict carries the
        signed receipt's ``provenance_receipt_hash`` so the two views link up.
    require_durable_receipt
        Fail-closed custody switch. When ``True``, construction raises unless a
        durable sink (``provenance_writer`` and/or ``sink``) is supplied, so the
        gate can never forward an AWS call while only able to return an in-memory
        receipt. Production custody deployments SHOULD set this.
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
        provenance_writer: ProvenanceLogger | None = None,
        require_durable_receipt: bool = False,
        lean_theorem_id: str = "gate_allow_sound",
        transport: Transport | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        # Fail-closed custody mode: a durable receipt requires a place to durably
        # record it. Refuse to construct a gate that would forward AWS calls while
        # only able to hand the agent an in-memory receipt dict (which a crash
        # before the agent persists it would lose) — that would break
        # "no DURABLE receipt = no action". Custody deployments MUST set this.
        if require_durable_receipt and sink is None and provenance_writer is None:
            raise ValueError(
                "require_durable_receipt=True needs a durable sink: pass "
                "`provenance_writer` (JWS receipts) and/or `sink` (hash chain). "
                "Refusing to build a custody gate that cannot durably record."
            )
        self._gate = gate
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token
        self._sink = sink
        self._prov_writer = provenance_writer
        self._lean_theorem_id = lean_theorem_id
        self._transport = transport or _http_transport
        self._clock = clock or time.time

    # ── DynamoDB ──────────────────────────────────────────────────────────
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
        args = {"TableName": table, "Key": key}
        body = json.dumps(args, separators=(",", ":")).encode("utf-8")
        return self._dispatch(
            token,
            action="dynamodb.GetItem",
            args=args,
            agent_id=agent_id,
            method="POST",
            service="dynamodb",
            host=f"dynamodb.{self._region}.amazonaws.com",
            path="/",
            body=body,
            headers={
                "content-type": _DDB_CONTENT_TYPE,
                "x-amz-target": f"{_DDB_TARGET_PREFIX}.GetItem",
            },
        )

    # ── S3 (fixed-body GET / PUT; no streaming/presign/multipart) ──────────
    def get_object(
        self,
        token: Capability,
        *,
        bucket: str,
        key: str,
        agent_id: str | None = None,
    ) -> EgressResult:
        """Gate, sign, forward, and receipt an S3 ``GetObject``. The response
        ``body`` is the raw object bytes. Raises :class:`CapabilityDenied` on
        deny (after a DENY receipt)."""
        body = b""
        return self._dispatch(
            token,
            action="s3.GetObject",
            args={"Bucket": bucket, "Key": key},
            agent_id=agent_id,
            method="GET",
            service="s3",
            host=f"{bucket}.s3.{self._region}.amazonaws.com",
            path="/" + key,
            body=body,
            headers={"x-amz-content-sha256": sigv4.payload_hash(body)},
        )

    def put_object(
        self,
        token: Capability,
        *,
        bucket: str,
        key: str,
        body: bytes,
        content_type: str = "application/octet-stream",
        agent_id: str | None = None,
    ) -> EgressResult:
        """Gate, sign, forward, and receipt an S3 ``PutObject`` with a fixed
        (fully-in-memory) body. The receipt's request hash binds the exact body
        written. Streaming/multipart uploads are out of scope (v1).

        ``ContentLength`` and ``ContentSha256`` are included in the gated args so
        a capability can *prevent* (not just audit) oversized or unexpected
        writes — e.g. ``{"max_value": {"ContentLength": 1048576}}``. The body
        itself is bound into the signed request and receipt via the payload hash.
        """
        content_hash = sigv4.payload_hash(body)
        return self._dispatch(
            token,
            action="s3.PutObject",
            args={
                "Bucket": bucket,
                "Key": key,
                "ContentLength": len(body),
                "ContentSha256": content_hash,
            },
            agent_id=agent_id,
            method="PUT",
            service="s3",
            host=f"{bucket}.s3.{self._region}.amazonaws.com",
            path="/" + key,
            body=body,
            headers={
                "x-amz-content-sha256": content_hash,
                "content-type": content_type,
            },
        )

    # ── SQS (JSON protocol; SendMessage only — a gated write/action surface) ─
    def send_message(
        self,
        token: Capability,
        *,
        queue_url: str,
        message_body: str,
        agent_id: str | None = None,
    ) -> EgressResult:
        """Gate, sign, forward, and receipt an SQS ``SendMessage``.

        Proves the custody model generalises past storage (DynamoDB/S3) to an
        action surface: a capability restricts *which queue* a message may go to
        and *how large* it may be, while the exact message is bound into the
        signed request and the JWS receipt. Gated args are ``QueueUrl`` and
        ``MessageBytes`` (the UTF-8 size), so a capability can both allowlist
        queues — ``{"allowed_values": {"QueueUrl": [...]}}`` — and cap size —
        ``{"max_value": {"MessageBytes": 262144}}`` (SQS's 256 KiB limit).
        """
        wire = {"QueueUrl": queue_url, "MessageBody": message_body}
        body = json.dumps(wire, separators=(",", ":")).encode("utf-8")
        return self._dispatch(
            token,
            action="sqs.SendMessage",
            args={"QueueUrl": queue_url, "MessageBytes": len(message_body.encode("utf-8"))},
            agent_id=agent_id,
            method="POST",
            service="sqs",
            host=f"sqs.{self._region}.amazonaws.com",
            path="/",
            body=body,
            headers={
                "content-type": _SQS_CONTENT_TYPE,
                "x-amz-target": _SQS_TARGET,
            },
        )

    # ── Secrets Manager (GetSecretValue — custody of secrets) ──────────────
    def get_secret_value(
        self,
        token: Capability,
        *,
        secret_id: str,
        agent_id: str | None = None,
    ) -> EgressResult:
        """Gate, sign, forward, and receipt a Secrets Manager ``GetSecretValue``.

        The purest custody case: raucle holds the AWS credential, so an agent can
        read a secret only for a ``SecretId`` its capability allows —
        ``{"allowed_values": {"SecretId": [...]}}`` — and never sees the AWS
        credential that fetched it. Each read is a per-action JWS receipt, so an
        auditor can prove exactly which secrets an agent accessed and under which
        authorisation. (The secret *value* is returned to the caller; gating
        which secrets are reachable is the v1 control.)
        """
        wire = {"SecretId": secret_id}
        body = json.dumps(wire, separators=(",", ":")).encode("utf-8")
        return self._dispatch(
            token,
            action="secretsmanager.GetSecretValue",
            args={"SecretId": secret_id},
            agent_id=agent_id,
            method="POST",
            service="secretsmanager",
            host=f"secretsmanager.{self._region}.amazonaws.com",
            path="/",
            body=body,
            headers={
                "content-type": _SM_CONTENT_TYPE,
                "x-amz-target": _SM_TARGET,
            },
        )

    # ── shared dispatch: gate → sign → receipt → forward ───────────────────
    def _dispatch(
        self,
        token: Capability,
        *,
        action: str,
        args: dict[str, Any],
        agent_id: str | None,
        method: str,
        service: str,
        host: str,
        path: str,
        body: bytes,
        headers: dict[str, str],
    ) -> EgressResult:
        decision = self._gate.check(token, tool=action, agent_id=agent_id, args=args)
        if not decision.allowed:
            self._emit(action, args, decision, request_binding=None)
            raise CapabilityDenied(action, decision.reason)

        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self._clock()))
        signed = sigv4.sign(
            method=method,
            service=service,
            region=self._region,
            host=host,
            path=path,
            headers=headers,
            body=body,
            access_key=self._access_key,
            secret_key=self._secret_key,
            amz_date=amz_date,
            session_token=self._session_token,
        )
        binding = {
            "method": method,
            "host": host,
            "path": path,
            "region": self._region,
            "service": service,
            "amz_date": amz_date,
            "canonical_request_hash": signed.canonical_hash,
            # The canonical-request hash alone does NOT pin the signer: a
            # different principal/signature over the same canonical request would
            # match it. Bind a hash of the EXACT signed wire request — including
            # the Authorization header (the actual SigV4 signature) — so the
            # receipt attests the precise request raucle dispatched. It is a hash,
            # so no credential or signature is leaked into the receipt.
            "signed_request_hash": _hash(
                {
                    "method": signed.method,
                    "url": signed.url,
                    "headers": {k.lower(): v for k, v in sorted(signed.headers.items())},
                    "payload_hash": sigv4.payload_hash(body),
                }
            ),
        }
        # Emit the receipt for the signed request BEFORE forwarding, so no request
        # can reach AWS without a durable receipt even if the transport then fails
        # after the request was received ("no receipt = no action" holds).
        receipt = self._emit(action, args, decision, request_binding=binding)
        status, raw = self._transport(signed)
        # Never return signed material (Authorization header / creds) to the agent.
        return EgressResult(status=status, body=raw, receipt=receipt)

    # ── receipt construction ───────────────────────────────────────────────
    def _emit(
        self,
        action: str,
        args: dict[str, Any],
        decision: Any,
        *,
        request_binding: dict[str, Any] | None,
    ) -> dict[str, Any]:
        decision_str = "ALLOW" if decision.allowed else "DENY"
        receipt = {
            "lean_theorem_id": self._lean_theorem_id,
            "attenuation_chain": list(getattr(decision, "chain", []) or []),
            "tool": action,
            "call_args_hash": _hash(args),
            "decision": decision_str,
            "decision_reason": decision.reason,
            "request_binding": request_binding,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())),
        }
        # Per-action JWS provenance receipts: the portable, offline-verifiable
        # custody artifacts `raucle audit-export` consumes. Each gated action is a
        # mini-chain rooted at the gate DECISION (a guardrail_scan — the only
        # operation, besides user_input, permitted to root a chain) so the audit
        # graph reads "gate scanned the requested action → verdict → [if allowed]
        # AWS call performed". Emitted BEFORE any transport, so every action —
        # permitted or refused — is cryptographically attested. The whole chain
        # verifies offline from the broker's public key, with no AWS cooperation.
        if self._prov_writer is not None:
            # ruleset_hash binds the policy identity (cited Lean theorem +
            # attenuation chain) into the signed decision receipt.
            ruleset_hash = _hash(
                {
                    "lean_theorem_id": self._lean_theorem_id,
                    "attenuation_chain": receipt["attenuation_chain"],
                }
            )
            scan_hash = self._prov_writer.record_guardrail_scan(
                parents=[],
                scanned_text=_canonical_json({"action": action, "args": args}).decode("utf-8"),
                verdict=decision_str,
                ruleset_hash=ruleset_hash,
                scan_target="aws-egress",
            )
            if request_binding is not None:
                # ALLOW: the actual AWS call, descending from the decision, with
                # the exact signed request bound into its output hash.
                receipt["provenance_receipt_hash"] = self._prov_writer.record_tool_call(
                    parents=[scan_hash],
                    tool=action,
                    input_args=args,
                    output=request_binding,
                    extra_taint={"gate:allow"},
                )
            else:
                # DENY: no AWS action was performed; the decision receipt is the
                # attestation that the gate refused the call.
                receipt["provenance_receipt_hash"] = scan_hash
        if self._sink is not None:
            return self._sink.append(receipt)
        return receipt
