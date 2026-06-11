"""Security regression tests for the capability gate.

Covers the five hardening fixes:
  GATE-NaN, AGENT-ID-REGEX, REVOKE-DEPTH, KEY-PERMS, TTL guard.
"""

import os
import stat

import pytest

from raucle.capability import (
    _AGENT_ID_RE,
    CapabilityGate,
    CapabilityIssuer,
    _is_number,
)


def _gate(issuer, **kw):
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem}, **kw)


# --------------------------------------------------------------------------
# 1) GATE-NaN
# --------------------------------------------------------------------------


def test_is_number_rejects_non_finite():
    assert _is_number(5) is True
    assert _is_number(5.0) is True
    assert _is_number(float("nan")) is False
    assert _is_number(float("inf")) is False
    assert _is_number(float("-inf")) is False
    assert _is_number(True) is False
    assert _is_number("5") is False


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_gate_denies_non_finite_amount(bad):
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    tok = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}, "min_value": {"amount": 0}},
        ttl_seconds=3600,
    )
    gate = _gate(issuer)
    d = gate.check(tok, tool="transfer_funds", args={"amount": bad})
    assert d.denied
    assert "not a number" in d.reason


def test_gate_allows_finite_within_bounds():
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    tok = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}, "min_value": {"amount": 0}},
        ttl_seconds=3600,
    )
    gate = _gate(issuer)
    assert gate.check(tok, tool="transfer_funds", args={"amount": 50}).allowed


# --------------------------------------------------------------------------
# 2) AGENT-ID-REGEX
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good",
    [
        "agent:billing",
        "agent:billing.invoice",
        "agent:a",
        "agent:b1",
        "agent:billing.invoice.sub",
        "agent:my-agent_v2.task",
    ],
)
def test_agent_id_accepts_valid(good):
    assert _AGENT_ID_RE.match(good)


@pytest.mark.parametrize(
    "bad",
    [
        "agent:billing.",  # trailing dot
        "agent:billing..evil",  # consecutive dots
        "agent:.billing",  # leading dot in tail
        "agent:billing.evil.",  # trailing dot deeper
        "agent:",  # empty tail
        "agent:Billing",  # uppercase
        "agent:billing-",  # we still allow trailing '-'? -> see note
    ][:6],  # exclude the trailing-dash debate
)
def test_agent_id_rejects_invalid(bad):
    assert not _AGENT_ID_RE.match(bad)


def test_mint_rejects_trailing_and_double_dot():
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    for bad in ("agent:billing.", "agent:billing..evil"):
        with pytest.raises(ValueError):
            issuer.mint(agent_id=bad, tool="t", ttl_seconds=60)


# --------------------------------------------------------------------------
# 3) REVOKE-DEPTH (3-level chain + resolver)
# --------------------------------------------------------------------------


def test_revoke_ancestor_denies_descendant_with_resolver():
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    root = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=3600,
    )
    child = issuer.attenuate(root, extra_constraints={"max_value": {"amount": 50}})
    grandchild = issuer.attenuate(child, extra_constraints={"max_value": {"amount": 10}})

    store = {root.token_id: root, child.token_id: child, grandchild.token_id: grandchild}
    gate = _gate(issuer, parent_resolver=store.get)

    # Baseline: grandchild allowed.
    assert gate.check(grandchild, tool="transfer_funds", args={"amount": 5}).allowed

    # Revoke the ROOT (an ancestor two levels up, NOT the direct parent).
    gate.revoke(root.token_id)
    d = gate.check(grandchild, tool="transfer_funds", args={"amount": 5})
    assert d.denied
    assert "revoked" in d.reason
    assert root.token_id in d.reason


def test_revoke_direct_parent_still_denies():
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    root = issuer.mint(
        agent_id="agent:billing",
        tool="t",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=3600,
    )
    child = issuer.attenuate(root, extra_constraints={"max_value": {"amount": 50}})
    store = {root.token_id: root, child.token_id: child}
    gate = _gate(issuer, parent_resolver=store.get)
    gate.revoke(root.token_id)
    assert gate.check(child, tool="t", args={"amount": 5}).denied


# --------------------------------------------------------------------------
# 4) KEY-PERMS
# --------------------------------------------------------------------------


def test_save_private_key_is_0600(tmp_path):
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    p = tmp_path / "issuer.key.pem"
    issuer.save_private_key(p)
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, oct(mode)


def test_save_private_key_overwrite_tightens(tmp_path):
    p = tmp_path / "issuer.key.pem"
    p.write_text("preexisting world-readable junk")
    os.chmod(p, 0o644)
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    issuer.save_private_key(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


# --------------------------------------------------------------------------
# 5) TTL guard
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_ttl", [0, -1, -3600, 10**12])
def test_mint_rejects_absurd_ttl(bad_ttl):
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    with pytest.raises(ValueError):
        issuer.mint(agent_id="agent:billing", tool="t", ttl_seconds=bad_ttl)


def test_mint_accepts_sane_ttl():
    issuer = CapabilityIssuer.generate(issuer="platform.test")
    tok = issuer.mint(agent_id="agent:billing", tool="t", ttl_seconds=3600)
    assert tok.expires_at > tok.issued_at
