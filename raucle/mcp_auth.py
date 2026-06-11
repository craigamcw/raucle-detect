"""MCP capability-binding helpers — `mcp-cap:v1`.

The Model Context Protocol (MCP) has no built-in authorization model for tool
calls: a `tools/list` entry advertises a tool, and a `tools/call` invokes it,
but nothing in the protocol says *which principal may call it with which
arguments*, nor produces verifiable evidence of the decision. This module
implements the **`mcp-cap:v1` binding**: a small, additive convention that
carries a `cap:v1` capability requirement on each gated tool and a signed
decision receipt on each tool result, both inside MCP's reserved ``_meta``
field (so non-aware clients ignore them and aware clients can enforce/verify).

See the normative profile: ``standards/mcp/01-capability-binding.md``.

Two pure helpers:

- :func:`tool_capability_annotation` — the ``_meta.raucle`` block an MCP server
  attaches to a gated tool in ``tools/list``, declaring the trust anchor
  (issuer ``key_id``) and the constraint keys the in-force token must satisfy.
- :func:`receipt_meta` — the ``_meta.raucle`` block an MCP server attaches to a
  ``tools/call`` result, carrying the ALLOW/DENY decision and a reference to
  the signed receipt recorded in the server's audit chain.

Plus :func:`verify_tool_annotation`, a client-side fail-closed check that a
listed gated tool names a trust anchor the client actually trusts.
"""

from __future__ import annotations

from typing import Any

#: Binding profile identifier, stamped on every annotation/receipt block.
MCP_CAP_VERSION = "mcp-cap:v1"

#: The constraint keys an `mcp-cap:v1` annotation may require, mirroring the
#: cap:v1 constraint vocabulary (standards/owasp-ai-exchange/01-capability-token.md).
_CONSTRAINT_KEYS = frozenset(
    {
        "forbidden_values",
        "allowed_values",
        "max_value",
        "min_value",
        "required_present",
        "forbidden_present",
        "forbidden_field_combinations",
    }
)


def tool_capability_annotation(
    *,
    issuer_key_id: str,
    required_constraints: list[str],
    policy_proof_hash: str | None = None,
) -> dict[str, Any]:
    """Build the ``_meta.raucle`` annotation for a gated tool in ``tools/list``.

    Parameters
    ----------
    issuer_key_id : str
        The ``key_id`` (first 16 hex of SHA-256 over the issuer Ed25519 public
        PEM) the in-force capability token MUST be signed by. This is the trust
        anchor the client checks before presenting a token.
    required_constraints : list[str]
        Constraint keys (from the cap:v1 vocabulary) the token MUST carry —
        e.g. ``["allowed_values", "max_value"]``. Advertised so a client can
        reject a tool whose authorisation surface is weaker than it requires.
    policy_proof_hash : str | None
        If the tool's constraints are backed by a ``proof:v1`` artefact, its
        SHA-256; lets a verifier confirm the constraints are complete over the
        tool's declared schema.

    Returns the block to place at ``tool["_meta"]["raucle"]``. Raises
    ``ValueError`` on an unknown constraint key (fail-closed authoring).
    """
    unknown = sorted(set(required_constraints) - _CONSTRAINT_KEYS)
    if unknown:
        raise ValueError(f"unknown cap:v1 constraint key(s): {unknown}")
    block: dict[str, Any] = {
        "version": MCP_CAP_VERSION,
        "gated": True,
        "issuer_key_id": issuer_key_id,
        "required_constraints": sorted(set(required_constraints)),
    }
    if policy_proof_hash is not None:
        block["policy_proof_hash"] = policy_proof_hash
    return block


def receipt_meta(
    *,
    decision: str,
    receipt_id: str,
    token_id: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Build the ``_meta.raucle`` block for a ``tools/call`` result.

    Parameters
    ----------
    decision : str
        ``"ALLOW"`` or ``"DENY"``.
    receipt_id : str
        Reference to the signed receipt the server recorded in its audit chain
        (e.g. a content-addressed ``sha256:…`` id or chain index). The decision
        in ``_meta`` is a convenience copy; the *authoritative* record is the
        signed receipt, verifiable offline.
    token_id : str | None
        The presented capability token's ``token_id``, for correlation.
    reason : str
        Human-readable reason (denials only). MUST NOT carry signed material.

    Raises ``ValueError`` if ``decision`` is not ALLOW/DENY.
    """
    if decision not in ("ALLOW", "DENY"):
        raise ValueError(f"decision must be 'ALLOW' or 'DENY', got {decision!r}")
    block: dict[str, Any] = {
        "version": MCP_CAP_VERSION,
        "decision": decision,
        "receipt_id": receipt_id,
    }
    if token_id is not None:
        block["token_id"] = token_id
    if decision == "DENY" and reason:
        block["reason"] = reason
    return block


def verify_tool_annotation(tool: dict[str, Any], *, trusted_key_ids: set[str]) -> tuple[bool, str]:
    """Client-side fail-closed check of a gated tool's annotation.

    Returns ``(ok, reason)``. A tool is acceptable to call if it is either
    **not** gated, or gated by an ``issuer_key_id`` the client trusts. An
    annotation that claims to be gated but is malformed, or names an untrusted
    anchor, is rejected — never silently treated as ungated.
    """
    meta = (tool.get("_meta") or {}).get("raucle")
    if meta is None:
        return True, "ungated tool"
    if meta.get("version") != MCP_CAP_VERSION:
        return False, f"unknown binding version {meta.get('version')!r}"
    if not meta.get("gated"):
        return True, "annotation present but not gated"
    key_id = meta.get("issuer_key_id")
    if not isinstance(key_id, str) or not key_id:
        return False, "gated tool missing issuer_key_id"
    if key_id not in trusted_key_ids:
        return False, f"gated by untrusted issuer key_id {key_id!r}"
    return True, "gated by a trusted issuer"


__all__ = [
    "MCP_CAP_VERSION",
    "tool_capability_annotation",
    "receipt_meta",
    "verify_tool_annotation",
]
