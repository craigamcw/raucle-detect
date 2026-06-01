"""Regression tests for the fail-closed redesign live bugs.

Pins the behaviours fixed under docs/proposals/fail-closed-redesign.md:
  - §8.2 live bug #1: prover must not certify a policy whose keys it ignores.
  - §8.7 live bug #4: a token citing a parent_id must DENY when the gate has no
    parent_resolver to verify the chain.

These complement tests/test_registry_drift.py (which pins the registry as the
source of truth) by exercising the runtime paths the registry now governs.
"""

from __future__ import annotations

import pytest

pytest.importorskip("z3")
pytest.importorskip("cryptography")

from raucle_detect.capability import CapabilityGate, CapabilityIssuer
from raucle_detect.prove import JSONSchemaProver


def _txfer_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "amount": {"type": "number", "minimum": 0, "maximum": 1_000_000},
        },
        "required": ["to", "amount"],
    }


# ---------------------------------------------------------------------------
# Live bug #1 — decorative proof inputs (§8.2)
# ---------------------------------------------------------------------------


def test_prover_undecided_on_allowed_values():
    """allowed_values is a gate-enforced kind the prover does NOT model. A policy
    carrying it must NOT be PROVEN (would silently ignore the whitelist)."""
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"allowed_values": {"to": ["alice@example.com"]}},
    )
    assert p.status == "UNDECIDED", p.status
    assert any("does not model" in n for n in p.notes)


def test_prover_undecided_on_starts_with():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"starts_with": {"to": "alice@"}},
    )
    assert p.status == "UNDECIDED", p.status


def test_prover_undecided_when_modelled_key_mixed_with_unmodelled():
    """A satisfiable modelled constraint must still NOT come back PROVEN if an
    unmodelled key rode along — the proof would have ignored that key."""
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {
            "max_value": {"amount": 1_000_000},  # modelled, would be PROVEN alone
            "allowed_values": {"to": ["alice@example.com"]},  # unmodelled
        },
    )
    assert p.status == "UNDECIDED", p.status


def test_prover_still_refutes_with_unmodelled_key_present():
    """A REFUTED counterexample stays valid even alongside an unmodelled key —
    only would-be PROVEN is downgraded, never a refutation suppressed."""
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {
            "max_value": {"amount": 100},  # violatable → REFUTED
            "starts_with": {"to": "alice@"},  # unmodelled
        },
    )
    assert p.status == "REFUTED", p.status
    assert p.counterexample is not None


def test_prover_proven_with_only_modelled_keys():
    """Sanity: the whitelist does not break the happy path."""
    p = JSONSchemaProver().prove(_txfer_schema(), {"max_value": {"amount": 1_000_000}})
    assert p.status == "PROVEN", p.status


# ---------------------------------------------------------------------------
# Live bug #4 — unresolved attenuation chain must DENY (§8.7)
# ---------------------------------------------------------------------------


def test_child_with_parent_id_denied_without_resolver():
    iss = CapabilityIssuer.generate(issuer="platform.example")
    parent = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 50}})
    assert child.parent_id == parent.token_id

    # Gate with NO parent_resolver configured.
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    decision = gate.check(child, tool="transfer_funds", args={"to": "a", "amount": 10})
    assert decision.denied, "unresolved chain must fail closed"
    assert "no parent_resolver" in decision.reason or "parent" in decision.reason


def test_root_token_still_allowed_without_resolver():
    """A token with no parent_id is unaffected by the unresolved-chain rule."""
    iss = CapabilityIssuer.generate(issuer="platform.example")
    cap = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    assert cap.parent_id is None
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    decision = gate.check(cap, tool="transfer_funds", args={"to": "a", "amount": 10})
    assert decision.allowed, decision.reason


def test_child_allowed_when_resolver_present():
    """With a resolver wired, a valid child still passes (the fix only closes the
    no-resolver hole, it does not break resolvable chains)."""
    iss = CapabilityIssuer.generate(issuer="platform.example")
    parent = iss.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
    )
    child = iss.attenuate(parent, extra_constraints={"max_value": {"amount": 50}})
    store = {parent.token_id: parent, child.token_id: child}
    gate = CapabilityGate(
        trusted_issuers={iss.key_id: iss.public_key_pem},
        parent_resolver=store.get,
    )
    decision = gate.check(child, tool="transfer_funds", args={"to": "a", "amount": 10})
    assert decision.allowed, decision.reason
