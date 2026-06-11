"""Regression tests for the post-relicense hygiene pass.

1. Gate constraint-evaluation errors must DENY with a *generic* reason — the
   raw exception text is logged server-side, never returned to the caller.
2. ``Scanner(require_receipts=True)`` fails loud when a receipt/audit side
   effect cannot be produced (default behaviour stays warn-and-continue).
3. Conformance: a token minted by ``CapabilityIssuer`` must verify (and deny
   identically) through the standalone OWASP ``cap_verifier`` — byte-identical
   canonicalisation across both code paths.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

from raucle import capability as cap_mod
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.scanner import ReceiptEmissionError, Scanner

# ---------------------------------------------------------------------------
# 1) Generic deny reason on constraint-evaluation error
# ---------------------------------------------------------------------------


def test_constraint_eval_error_denies_with_generic_reason(monkeypatch):
    issuer = CapabilityIssuer.generate("issuer:test")
    token = issuer.mint(agent_id="agent:t", tool="search", constraints={"max_value": {"n": 5}})
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

    secret = "SECRET-INTERNAL-PATH-/etc/raucle"

    def boom(constraints, args):
        raise RuntimeError(secret)

    monkeypatch.setattr(cap_mod, "_check_constraints", boom)
    decision = gate.check(token, agent_id="agent:t", tool="search", args={"n": 1})
    assert decision.allowed is False
    assert secret not in decision.reason
    assert "constraint evaluation error" in decision.reason


# ---------------------------------------------------------------------------
# 2) require_receipts fail-loud mode
# ---------------------------------------------------------------------------


class _BrokenSink:
    def append(self, record):
        raise OSError("disk full")


class _BrokenSigner:
    def issue(self, **kwargs):
        raise OSError("hsm unavailable")


def test_default_mode_warns_and_continues():
    scanner = Scanner(audit_sink=_BrokenSink(), verdict_signer=_BrokenSigner())
    result = scanner.scan("hello world")  # must not raise
    assert result.verdict in {"MALICIOUS", "SUSPICIOUS", "CLEAN"}
    assert not result.receipt  # default is empty string


def test_require_receipts_raises_on_signer_failure():
    scanner = Scanner(verdict_signer=_BrokenSigner(), require_receipts=True)
    with pytest.raises(ReceiptEmissionError):
        scanner.scan("hello world")


def test_require_receipts_raises_on_audit_failure():
    scanner = Scanner(audit_sink=_BrokenSink(), require_receipts=True)
    with pytest.raises(ReceiptEmissionError):
        scanner.scan("hello world")


def test_require_receipts_noop_when_no_sinks_configured():
    scanner = Scanner(require_receipts=True)
    assert scanner.scan("hello world").verdict in {"MALICIOUS", "SUSPICIOUS", "CLEAN"}


# ---------------------------------------------------------------------------
# 3) Issuer ↔ standalone cap_verifier conformance round-trip
# ---------------------------------------------------------------------------


def _load_cap_verifier():
    path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "standards"
        / "cap-verifier"
        / "cap_verifier.py"
    )
    spec = importlib.util.spec_from_file_location("cap_verifier_roundtrip", path)
    cv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cv)
    return cv


def test_minted_token_verifies_through_standalone_verifier():
    cv = _load_cap_verifier()
    issuer = CapabilityIssuer.generate("issuer:conformance")
    token = issuer.mint(
        agent_id="agent:conf",
        tool="payments.transfer",
        constraints={
            "max_value": {"amount": 1000},
            "allowed_values": {"currency": ["EUR", "GBP"]},
        },
    )
    token_dict = token.to_dict()

    allowed, reason, deny_check = cv.verify_token(
        token_dict,
        issuer.public_key_pem,
        tool="payments.transfer",
        agent_id="agent:conf",
        args={"amount": 500, "currency": "EUR"},
    )
    assert allowed is True, f"standalone verifier denied a valid call: {reason}"


def test_constraint_violation_denied_by_both_paths():
    cv = _load_cap_verifier()
    issuer = CapabilityIssuer.generate("issuer:conformance")
    token = issuer.mint(
        agent_id="agent:conf",
        tool="payments.transfer",
        constraints={"max_value": {"amount": 1000}},
    )
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    bad_args = {"amount": 99999}

    gate_decision = gate.check(
        token, agent_id="agent:conf", tool="payments.transfer", args=bad_args
    )
    cv_allowed, _, _ = cv.verify_token(
        token.to_dict(),
        issuer.public_key_pem,
        tool="payments.transfer",
        agent_id="agent:conf",
        args=bad_args,
    )
    assert gate_decision.allowed is False
    assert cv_allowed is False


def test_tampered_token_denied_by_standalone_verifier():
    cv = _load_cap_verifier()
    issuer = CapabilityIssuer.generate("issuer:conformance")
    token = issuer.mint(agent_id="agent:conf", tool="search", constraints={})
    tampered = token.to_dict()
    tampered["tool"] = "payments.transfer"  # signature no longer covers this

    allowed, _, _ = cv.verify_token(
        tampered,
        issuer.public_key_pem,
        tool="payments.transfer",
        agent_id="agent:conf",
        args={},
    )
    assert allowed is False
