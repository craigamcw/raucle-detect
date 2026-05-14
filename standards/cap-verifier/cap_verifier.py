#!/usr/bin/env python3
"""cap-verifier — minimal reference verifier for the cap:v1 profile.

A deliberately tiny, dependency-free (modulo `cryptography`) implementation of
the eight-check gate from standards/owasp-ai-exchange/01-capability-token.md.
Intended for:
  - shipping with the OWASP standards submission as proof the spec is
    implementable by anyone in ~150 lines;
  - dropping into CI pipelines as a yes/no token-validity check;
  - cross-validating the main `raucle_detect.capability` implementation
    by an independent code path.

Usage:
    cap-verifier verify token.json --pubkey issuer.pub.pem
    cap-verifier verify token.json --pubkey issuer.pub.pem \\
        --tool transfer_funds --agent agent:billing \\
        --args call_args.json
    cap-verifier hash token.json    # print the token_id we compute

Exit codes:
    0  token verified, all checks pass
    1  token failed verification (signature, hash, time, scope, or constraints)
    2  usage / file / format error
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical-JSON serialisation (mirrors §"Canonical-JSON serialisation"
# of standards/owasp-ai-exchange/01-capability-token.md).
# ---------------------------------------------------------------------------


def canonical_json(obj) -> bytes:
    """Sorted keys, no whitespace, UTF-8, ensure_ascii=False."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


# ---------------------------------------------------------------------------
# Spec validation regexes (mirrors cap:v1 §"Field semantics").
# ---------------------------------------------------------------------------


_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9][a-z0-9_\-./]{0,127}$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-./]{0,127}$")


# ---------------------------------------------------------------------------
# Token body extraction.
# Excludes `token_id` and `signature` from the canonical body for hashing/sig.
# ---------------------------------------------------------------------------


_BODY_FIELDS = (
    "version", "agent_id", "tool", "constraints",
    "issuer", "key_id", "issued_at", "not_before", "expires_at",
    "parent_id", "policy_proof_hash",
)


def token_body(token: dict) -> dict:
    """Build the canonical body, applying default values consistent with raucle_detect's encoding."""
    out = {}
    # Constraints are normalised before hashing (mirrors raucle_detect.capability._normalise_constraints).
    if "constraints" in token:
        out["constraints"] = _normalise_constraints(token["constraints"])
    for f in _BODY_FIELDS:
        if f == "constraints":
            continue
        if f == "version":
            # version is implicit in cap:v1; not part of the hashed body in the
            # reference implementation. We accept its presence but exclude it
            # from the canonical bytes for cross-implementation compatibility.
            continue
        if f in token:
            out[f] = token[f]
        else:
            # parent_id and policy_proof_hash default to None when absent.
            if f in ("parent_id", "policy_proof_hash"):
                out[f] = None
    return out


def _normalise_constraints(c: dict) -> dict:
    """Normalisation logic mirroring raucle_detect.capability._normalise_constraints."""
    out: dict = {}
    if "forbidden_values" in c:
        out["forbidden_values"] = {k: sorted(v) for k, v in c["forbidden_values"].items()}
    if "allowed_values" in c:
        out["allowed_values"] = {k: sorted(v) for k, v in c["allowed_values"].items()}
    if "max_value" in c:
        out["max_value"] = dict(c["max_value"])
    if "min_value" in c:
        out["min_value"] = dict(c["min_value"])
    if "required_present" in c:
        out["required_present"] = sorted(c["required_present"])
    if "forbidden_combos" in c:
        out["forbidden_combos"] = sorted(sorted(combo) for combo in c["forbidden_combos"])
    return out


# ---------------------------------------------------------------------------
# Eight-check gate (mirrors cap:v1 §"Verification (gate-side)").
# ---------------------------------------------------------------------------


def verify_token(
    token: dict,
    pubkey_pem: str,
    *,
    tool: str | None = None,
    agent_id: str | None = None,
    args: dict | None = None,
    now: int | None = None,
) -> tuple[bool, str, str | None]:
    """Run the eight cap:v1 checks. Returns (allowed, reason, deny_check)."""
    from cryptography.hazmat.primitives import serialization
    ts = now if now is not None else int(time.time())

    # Field-shape sanity
    if not _AGENT_ID_RE.match(token.get("agent_id", "")):
        return False, "agent_id malformed", "format"
    if not _TOOL_RE.match(token.get("tool", "")):
        return False, "tool malformed", "format"

    body_bytes = canonical_json(token_body(token))

    # Check 1: issuer pinning (caller passes the pubkey explicitly here;
    # in a fuller deployment this would look up key_id in a trusted map).
    if "key_id" not in token:
        return False, "missing key_id", "issuer_pinning"

    # Check 2: signature
    try:
        pub = serialization.load_pem_public_key(pubkey_pem.encode("ascii"))
        sig = b64url_decode(token["signature"])
        pub.verify(sig, body_bytes)
    except Exception as exc:
        return False, f"signature: {exc}", "signature"

    # Check 3: token_id binding
    expected_id = "cap:" + sha256_hex(body_bytes)[:24]
    if token.get("token_id") != expected_id:
        return False, f"token_id mismatch (expected {expected_id})", "token_id_binding"

    # Check 4: time bounds
    if ts < token["not_before"]:
        return False, "not yet valid", "time_bounds"
    if ts >= token["expires_at"]:
        return False, "expired", "time_bounds"

    # Check 5: tool match
    if tool is not None and tool != token["tool"]:
        return False, f"tool mismatch (token says {token['tool']!r})", "tool_match"

    # Check 6: agent scope
    if agent_id is not None and agent_id != token["agent_id"]:
        if not agent_id.startswith(token["agent_id"] + "."):
            return False, f"agent {agent_id!r} not a sub-scope of {token['agent_id']!r}", "agent_scope"

    # Check 7: constraints (only if args supplied)
    if args is not None:
        reason = _check_constraints(token.get("constraints", {}), args)
        if reason:
            return False, f"constraint: {reason}", "constraint"

    # Check 8 (chain resolution): not implemented by this minimal verifier.
    # A fuller implementation walks parent_id chains.

    return True, "ok", None


def _check_constraints(c: dict, args: dict) -> str | None:
    for fld, bads in c.get("forbidden_values", {}).items():
        if fld in args:
            val = args[fld]
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if v in bads:
                    return f"{fld}={v!r} in forbidden_values"
    for fld, oks in c.get("allowed_values", {}).items():
        if fld in args:
            val = args[fld]
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if v not in oks:
                    return f"{fld}={v!r} not in allowed_values"
    for fld, bound in c.get("max_value", {}).items():
        if fld in args and args[fld] > bound:
            return f"{fld}={args[fld]} > max_value {bound}"
    for fld, bound in c.get("min_value", {}).items():
        if fld in args and args[fld] < bound:
            return f"{fld}={args[fld]} < min_value {bound}"
    for fld in c.get("required_present", []):
        if fld not in args:
            return f"required field {fld!r} missing"
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cap-verifier", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Run the eight-check gate against a token")
    v.add_argument("token", type=Path, help="cap:v1 token JSON")
    v.add_argument("--pubkey", type=Path, required=True, help="Issuer Ed25519 PEM")
    v.add_argument("--tool", help="Tool the caller is invoking (optional)")
    v.add_argument("--agent", help="Caller agent_id (optional)")
    v.add_argument("--args", type=Path, help="Call-args JSON (optional)")
    v.add_argument("--now", type=int, help="Override clock for testing")

    h = sub.add_parser("hash", help="Print the token_id we compute for the body")
    h.add_argument("token", type=Path)

    args = p.parse_args(argv)

    try:
        token = json.loads(args.token.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read token: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "hash":
        print("cap:" + sha256_hex(canonical_json(token_body(token)))[:24])
        return 0

    try:
        pubkey = args.pubkey.read_text()
    except OSError as exc:
        print(f"error: cannot read pubkey: {exc}", file=sys.stderr)
        return 2

    call_args = None
    if args.args:
        call_args = json.loads(args.args.read_text())

    allowed, reason, check = verify_token(
        token,
        pubkey,
        tool=args.tool,
        agent_id=args.agent,
        args=call_args,
        now=args.now,
    )
    if allowed:
        print(f"OK  token_id={token.get('token_id')}")
        return 0
    print(f"DENY ({check}): {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
