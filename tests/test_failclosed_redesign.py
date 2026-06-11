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

from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.prove import JSONSchemaProver


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


def test_allowed_values_forall_collection_semantics():
    """§8.6 FORALL_ALLOW: a list is allowed iff every element is in the allowed
    set; one disallowed element (or an empty collection) DENIES."""
    iss = CapabilityIssuer.generate(issuer="platform.example")
    cap = iss.mint(
        agent_id="agent:billing",
        tool="t",
        constraints={"allowed_values": {"region": ["us", "eu"]}},
    )
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    assert gate.check(cap, tool="t", args={"region": "us"}).allowed
    assert gate.check(cap, tool="t", args={"region": ["us", "eu"]}).allowed
    assert not gate.check(cap, tool="t", args={"region": ["us", "apac"]}).allowed
    assert not gate.check(cap, tool="t", args={"region": []}).allowed
    assert not gate.check(cap, tool="t", args={}).allowed  # absent → deny


def test_starts_with_collection_denied():
    """§8.6 STRING_ONLY: a collection value can never satisfy starts_with."""
    iss = CapabilityIssuer.generate(issuer="platform.example")
    cap = iss.mint(
        agent_id="agent:billing",
        tool="t",
        constraints={"starts_with": {"path": "/safe/"}},
    )
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    assert gate.check(cap, tool="t", args={"path": "/safe/x"}).allowed
    assert not gate.check(cap, tool="t", args={"path": ["/safe/x"]}).allowed


def test_mint_rejects_bool_and_float_numeric_bounds():
    """§8.5: numeric bounds must be real integers — bool (an int subclass) and
    float are rejected at mint, not silently signed."""
    import pytest

    iss = CapabilityIssuer.generate(issuer="platform.example")
    for bad in (True, 1.5, "100", None):
        with pytest.raises(ValueError, match="bound must be an integer"):
            iss.mint(agent_id="agent:a", tool="t", constraints={"max_value": {"amount": bad}})


def test_mint_rejects_non_string_starts_with_prefix():
    """§8.5: a starts_with prefix must be a string."""
    import pytest

    iss = CapabilityIssuer.generate(issuer="platform.example")
    for bad in (123, ["/x"], None):
        with pytest.raises(ValueError, match="prefix must be a string"):
            iss.mint(agent_id="agent:a", tool="t", constraints={"starts_with": {"path": bad}})


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


def test_mint_rejects_non_list_value_collections():
    """§8.5: forbidden_values/allowed_values members must be a JSON list — a
    set/tuple/frozenset (non-JSON / unordered) is rejected at mint."""
    import pytest

    iss = CapabilityIssuer.generate(issuer="platform.example")
    for bad in ({"admin"}, ("admin",), frozenset({"admin"})):
        with pytest.raises(ValueError, match="list"):
            iss.mint(agent_id="agent:a", tool="t", constraints={"forbidden_values": {"role": bad}})


def test_mint_rejects_non_scalar_value_members():
    """§8.5: value-list members must be JSON scalars (str/int/bool)."""
    import pytest

    iss = CapabilityIssuer.generate(issuer="platform.example")
    for bad in (1.5, None, b"x", ["nested"]):
        with pytest.raises(ValueError, match="scalar|float|None|bytes|container"):
            iss.mint(agent_id="agent:a", tool="t", constraints={"allowed_values": {"r": [bad]}})


def test_mint_rejects_unicode_colliding_field_names():
    """§8.5: field names that collide under Unicode NFC are rejected at mint."""
    import pytest

    iss = CapabilityIssuer.generate(issuer="platform.example")
    # U+00C5 (Å precomposed) vs U+0041 U+030A (A + combining ring) — NFC-equal.
    precomposed = "Åfield"
    decomposed = "Åfield"
    assert precomposed != decomposed
    with pytest.raises(ValueError, match="NFC"):
        iss.mint(
            agent_id="agent:a",
            tool="t",
            constraints={"forbidden_values": {precomposed: ["x"], decomposed: ["y"]}},
        )
