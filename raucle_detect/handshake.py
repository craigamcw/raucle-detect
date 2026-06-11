"""Cross-organisation agent handshake (P2) — trust resolved from the registry.

P1 (the :mod:`~raucle_detect.trust_registry`) made issuer keys *resolvable* across
orgs. P2 is the protocol that uses it: two agents from different organisations
establish a verifiable, capability-gated call and exchange signed receipts —
**without any prior key exchange between them.** Each side resolves the other's
key from the shared Trust Registry.

The flow (org A's agent calls org B's agent):

    org A                         shared registry                      org B
    -----                         ---------------                      -----
    mint capability token  --------- publish kA -------->  (kA resolvable)
    present (token, tool, args)  ----------------------------------->  accept_call()
                                       resolve kA  <------------------    │
                                  (fail-closed if unknown/revoked)        │
                                                                gate.check(token, args)
    verify B's ack  <----------- publish kB ------------- emit signed ack receipt
    (resolve kB)                                                          │

Org B never held org A's key beforehand; it resolves ``token.key_id`` from the
registry, checks revocation, runs the capability gate, and answers with a signed
acknowledgement that org A verifies the same way (resolving B's key). The result
is a cross-org receipt pair anchored in the registry — the interop primitive for
multi-agent ecosystems.

Fail-closed throughout: an initiator key that is unknown or revoked in the
registry is rejected before the gate ever runs.
"""

from __future__ import annotations

import base64 as _base64
import datetime as _dt
import logging
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Any

from raucle_detect.audit import Ed25519Signer, _canonical_json, _sha256_hex
from raucle_detect.capability import Capability, CapabilityGate, GateDecision
from raucle_detect.trust_registry import TrustRegistry

logger = logging.getLogger(__name__)


def _b64(data: bytes) -> str:
    return _base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return _base64.urlsafe_b64decode(data + padding)


#: Handshake protocol identifier (carried in the ack receipt).
HANDSHAKE_VERSION = "raucle-handshake/v1"


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


@dataclass
class HandshakeRequest:
    """What an initiator (org A) presents to a responder (org B).

    Carries the capability token (which names ``key_id`` — the trust anchor the
    responder resolves from the registry), the concrete call, and the caller's
    agent id. No public key is included: the responder resolves it.
    """

    capability_token: dict[str, Any]
    tool: str
    args: dict[str, Any]
    caller_agent_id: str
    nonce: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_token": self.capability_token,
            "tool": self.tool,
            "args": self.args,
            "caller_agent_id": self.caller_agent_id,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HandshakeRequest:
        return cls(
            capability_token=d["capability_token"],
            tool=d["tool"],
            args=d.get("args") or {},
            caller_agent_id=d.get("caller_agent_id", ""),
            nonce=d.get("nonce", ""),
        )


@dataclass
class HandshakeResult:
    """The responder's verified verdict + a signed acknowledgement receipt."""

    accepted: bool
    reason: str
    initiator_key_id: str
    ack_receipt: dict[str, Any] = field(default_factory=dict)


def build_request(
    token: Capability,
    *,
    tool: str,
    args: dict[str, Any],
    nonce: str = "",
) -> HandshakeRequest:
    """Initiator side: package a minted capability token + the concrete call.

    The token already carries ``key_id`` (the trust anchor) and is Ed25519-signed
    by the initiator's issuer, so nothing else needs signing here — the responder
    resolves and verifies it. A fresh random ``nonce`` is generated when none is
    given, so every handshake is uniquely bound (anti-replay).
    """
    return HandshakeRequest(
        capability_token=token.to_dict(),
        tool=tool,
        args=dict(args),
        caller_agent_id=token.agent_id,
        nonce=nonce or _secrets.token_hex(16),
    )


def accept_call(
    request: HandshakeRequest,
    *,
    registry: TrustRegistry,
    responder_signer: Ed25519Signer,
    responder_id: str,
    require_unrevoked: bool = True,
) -> HandshakeResult:
    """Responder side (org B): resolve the initiator's key from the **registry**,
    capability-gate the call, and return a signed acknowledgement.

    Steps (fail-closed):

    1. Parse the presented token; read its ``key_id``.
    2. Resolve ``key_id`` from the shared registry. Unknown or revoked → REJECT
       (no gate runs). This is the cross-org trust decision, made with no prior
       key exchange.
    3. Build a gate anchored on the resolved key and check the call.
    4. Emit a signed ack receipt (the responder's own key, also registry-
       published) stating ACCEPT/REJECT, so the initiator can verify the outcome.
    """
    try:
        token = Capability.from_dict(request.capability_token)
    except Exception as exc:
        return _ack(
            responder_signer,
            responder_id,
            accepted=False,
            reason=f"malformed capability token: {type(exc).__name__}",
            initiator_key_id="",
            request=request,
        )

    key_id = token.key_id
    record = registry.resolve(key_id)  # fail-closed: None for unknown
    if record is None or record.revoked:
        revoked = record is not None and record.revoked
        reason = (
            f"initiator key_id {key_id} is revoked in the registry"
            if revoked
            else f"initiator key_id {key_id} is not in the registry (untrusted issuer)"
        )
        return _ack(
            responder_signer,
            responder_id,
            accepted=False,
            reason=reason,
            initiator_key_id=key_id,
            request=request,
            token=token,
        )

    # Anti-impersonation: the token's claimed issuer must match the registry's
    # authoritative record for this key (codex #2). A registered org cannot
    # present a token claiming to be a DIFFERENT org.
    if token.issuer != record.issuer:
        return _ack(
            responder_signer,
            responder_id,
            accepted=False,
            reason=(
                f"issuer mismatch: token claims {token.issuer!r} but key {key_id} "
                f"is registered to {record.issuer!r}"
            ),
            initiator_key_id=key_id,
            request=request,
            token=token,
        )

    gate = CapabilityGate(trusted_issuers={key_id: record.public_key_pem})
    decision: GateDecision = gate.check(
        token, tool=request.tool, args=request.args, agent_id=request.caller_agent_id
    )
    return _ack(
        responder_signer,
        responder_id,
        accepted=decision.allowed,
        reason=decision.reason or ("authorised" if decision.allowed else "denied"),
        initiator_key_id=key_id,
        request=request,
        token=token,
    )


def _ack(
    signer: Ed25519Signer,
    responder_id: str,
    *,
    accepted: bool,
    reason: str,
    initiator_key_id: str,
    request: HandshakeRequest,
    token: Capability | None = None,
) -> HandshakeResult:
    """Build and sign the responder's acknowledgement receipt.

    The signed body binds the FULL request (``request_hash``) and the
    capability ``token_id``, so a signed ACCEPT cannot be replayed into a
    different call or capability context (codex #3).
    """
    body = {
        "version": HANDSHAKE_VERSION,
        "responder": responder_id,
        "responder_key_id": _sha256_hex(signer.public_key_pem())[:16],
        "initiator_key_id": initiator_key_id,
        "caller_agent_id": request.caller_agent_id,
        "tool": request.tool,
        "args_hash": _sha256_hex(_canonical_json(request.args)),
        "request_hash": _sha256_hex(_canonical_json(request.to_dict())),
        "token_id": token.token_id if token is not None else "",
        "decision": "ACCEPT" if accepted else "REJECT",
        "reason": reason,
        "nonce": request.nonce,
        "issued_at": _now(),
    }
    sig = signer.sign(_canonical_json(body))
    receipt = {"body": body, "signature": _b64(sig)}
    return HandshakeResult(
        accepted=accepted,
        reason=reason,
        initiator_key_id=initiator_key_id,
        ack_receipt=receipt,
    )


def verify_ack(
    ack_receipt: dict[str, Any],
    *,
    registry: TrustRegistry,
    expected_nonce: str | None = None,
    expected_token_id: str | None = None,
    expected_request: HandshakeRequest | None = None,
    expected_decision: str | None = None,
) -> tuple[bool, str]:
    """Initiator side: verify the responder's ack, resolving the responder's
    key from the **same registry** (no prior key exchange with org B either).

    Returns ``(ok, reason)``. Always: the responder's key resolves to an active
    registry key and the signature verifies. Anti-replay/substitution (pass the
    ones you can): ``expected_nonce``, ``expected_token_id``, and
    ``expected_request`` (its ``request_hash`` must match the signed body) bind
    the ack to *this* handshake. ``ok=True`` means the ack is AUTHENTIC and bound
    — it does NOT by itself mean ACCEPT; pass ``expected_decision="ACCEPT"`` to
    require acceptance, or read ``body['decision']``.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    body = ack_receipt.get("body")
    sig = ack_receipt.get("signature")
    if not isinstance(body, dict) or not isinstance(sig, str):
        return False, "malformed ack receipt"
    if body.get("version") != HANDSHAKE_VERSION:
        return False, f"unknown handshake version {body.get('version')!r}"

    responder_key_id = body.get("responder_key_id", "")
    pem = registry.public_key(responder_key_id)  # fail-closed
    if pem is None:
        return False, f"responder key_id {responder_key_id} unknown/revoked in registry"

    try:
        loaded = serialization.load_pem_public_key(pem.encode())
        if not isinstance(loaded, Ed25519PublicKey):
            return False, "responder key is not Ed25519"
        loaded.verify(_b64d(sig), _canonical_json(body))
    except (InvalidSignature, ValueError, TypeError):
        return False, "ack signature did not verify against responder key"

    if expected_nonce is not None and body.get("nonce") != expected_nonce:
        return False, "ack nonce mismatch (possible replay)"
    if expected_token_id is not None and body.get("token_id") != expected_token_id:
        return False, "ack token_id mismatch (bound to a different capability)"
    if expected_request is not None:
        want = _sha256_hex(_canonical_json(expected_request.to_dict()))
        if body.get("request_hash") != want:
            return False, "ack request_hash mismatch (bound to a different request)"
    if expected_decision is not None and body.get("decision") != expected_decision:
        return False, f"decision is {body.get('decision')}, expected {expected_decision}"

    return True, f"ack verified: {body.get('decision')}"


__all__ = [
    "HANDSHAKE_VERSION",
    "HandshakeRequest",
    "HandshakeResult",
    "build_request",
    "accept_call",
    "verify_ack",
]
