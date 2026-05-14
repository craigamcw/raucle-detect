"""Tests for capability-based agent permissions (v0.10.0)."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("cryptography")

from raucle_detect.capability import (
    Capability,
    CapabilityGate,
    CapabilityIssuer,
)


def _issuer(name: str = "platform.example") -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer=name)


def _gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


# ---------------------------------------------------------------------------
# Minting + verification
# ---------------------------------------------------------------------------


def test_mint_produces_valid_token():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    assert cap.token_id.startswith("cap:")
    assert cap.signature
    assert cap.expires_at > cap.issued_at


def test_gate_allows_call_satisfying_constraints():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    decision = _gate(iss).check(
        cap, tool="transfer_funds", args={"to": "alice@example", "amount": 50}
    )
    assert decision.allowed, decision.reason


def test_gate_denies_call_violating_max_value():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    decision = _gate(iss).check(cap, tool="transfer_funds", args={"amount": 500})
    assert decision.denied
    assert "max_value" in decision.reason


def test_gate_denies_forbidden_recipient():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:billing",
        tool="send_email",
        constraints={"forbidden_values": {"to": ["attacker@evil.example"]}},
    )
    decision = _gate(iss).check(
        cap, tool="send_email", args={"to": "attacker@evil.example", "body": "hi"}
    )
    assert decision.denied


def test_gate_denies_wrong_tool():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:billing", tool="transfer_funds")
    decision = _gate(iss).check(cap, tool="delete_user", args={})
    assert decision.denied
    assert "tool" in decision.reason


def test_gate_denies_expired_token():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t", ttl_seconds=1)
    time.sleep(1.1)
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.denied
    assert "expired" in decision.reason


def test_gate_denies_not_yet_valid_token():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t", not_before_offset=120)
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.denied
    assert "not yet valid" in decision.reason


def test_gate_denies_unknown_issuer():
    iss_a = _issuer("a.example")
    iss_b = _issuer("b.example")
    cap = iss_a.mint(agent_id="agent:x", tool="t")
    gate = CapabilityGate(trusted_issuers={iss_b.key_id: iss_b.public_key_pem})
    decision = gate.check(cap, tool="t", args={})
    assert decision.denied
    assert "unknown key_id" in decision.reason


def test_gate_denies_tampered_signature():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t", constraints={"max_value": {"amount": 100}})
    # Mutate the constraints after signing.
    cap.constraints = {"max_value": {"amount": 999_999}}
    decision = _gate(iss).check(cap, tool="t", args={"amount": 500})
    assert decision.denied


def test_gate_denies_tampered_token_id():
    iss = _issuer()
    cap = iss.mint(agent_id="agent:x", tool="t")
    cap.token_id = "cap:" + "f" * 24
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.denied


# ---------------------------------------------------------------------------
# Attenuation
# ---------------------------------------------------------------------------


def test_attenuation_narrows_max_value():
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 1000}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 50}})
    assert child.parent_id == parent.token_id
    assert child.constraints["max_value"]["amount"] == 50
    # Parent's bound stays intact on the original token.
    assert parent.constraints["max_value"]["amount"] == 1000


def test_attenuation_cannot_broaden_max_value():
    """Asking for a higher bound silently keeps the tighter parent bound."""
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"max_value": {"amount": 100}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 1000}})
    # Merge picks the smaller bound — broadening is impossible.
    assert child.constraints["max_value"]["amount"] == 100


def test_attenuation_cannot_outlive_parent():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:x", tool="t", ttl_seconds=10)
    with pytest.raises(ValueError, match="outlive"):
        iss.attenuate(parent, narrower_ttl_seconds=10_000)


def test_attenuation_narrower_agent_id_must_be_subscope():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:billing", tool="t")
    # Valid sub-scope:
    child = iss.attenuate(parent, narrower_agent_id="agent:billing.invoice")
    assert child.agent_id == "agent:billing.invoice"
    # Invalid (sibling, not sub-scope):
    with pytest.raises(ValueError, match="sub-scope"):
        iss.attenuate(parent, narrower_agent_id="agent:auth")


def test_attenuated_child_gate_check_inherits_parent_constraints():
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:x",
        tool="transfer_funds",
        constraints={"forbidden_values": {"to": ["attacker@evil.example"]}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 100}})
    decision = _gate(iss).check(
        child,
        tool="transfer_funds",
        args={"to": "attacker@evil.example", "amount": 50},
    )
    assert decision.denied
    assert "forbidden_values" in decision.reason


def test_attenuation_intersects_allowed_values():
    iss = _issuer()
    parent = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"allowed_values": {"currency": ["USD", "EUR", "GBP"]}},
    )
    child = iss.attenuate(
        parent, extra_constraints={"allowed_values": {"currency": ["EUR", "JPY"]}}
    )
    # Intersection only — JPY drops out, USD/GBP drop out.
    assert child.constraints["allowed_values"]["currency"] == ["EUR"]


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def test_gate_verifies_full_chain_when_resolver_supplied():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:x", tool="t")
    child = iss.attenuate(parent)

    by_id = {parent.token_id: parent, child.token_id: child}
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        parent_resolver=by_id.get,
    )
    decision = gate.check(child, tool="t", args={})
    assert decision.allowed
    assert parent.token_id in decision.chain


def test_chain_verification_rejects_missing_parent():
    iss = _issuer()
    parent = iss.mint(agent_id="agent:x", tool="t")
    child = iss.attenuate(parent)
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        parent_resolver=lambda _id: None,
    )
    decision = gate.check(child, tool="t", args={})
    assert decision.denied
    assert "unresolved parent" in decision.reason


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_token_roundtrips_through_disk(tmp_path):
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:x",
        tool="t",
        constraints={"forbidden_values": {"to": ["bad@example"]}},
    )
    path = tmp_path / "tok.json"
    cap.save(path)
    loaded = Capability.load(path)
    assert loaded.token_id == cap.token_id
    assert loaded.signature == cap.signature
    decision = _gate(iss).check(loaded, tool="t", args={"to": "good@example"})
    assert decision.allowed


def test_policy_proof_hash_round_trips():
    iss = _issuer()
    cap = iss.mint(
        agent_id="agent:x",
        tool="t",
        policy_proof_hash="sha256:" + "a" * 64,
    )
    decision = _gate(iss).check(cap, tool="t", args={})
    assert decision.allowed
    assert cap.policy_proof_hash == "sha256:" + "a" * 64
