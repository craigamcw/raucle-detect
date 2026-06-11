"""Tests for raucle's AGT ``ExternalPolicyBackend`` implementation.

Skipped automatically when ``agent_os`` (Microsoft Agent Governance
Toolkit's Python package) is not installed. Exercises the post-merge
integration path for `microsoft/agent-governance-toolkit#2610`_.

.. _microsoft/agent-governance-toolkit#2610:
   https://github.com/microsoft/agent-governance-toolkit/pull/2610
"""

from __future__ import annotations

import pytest

agent_os = pytest.importorskip("agent_os")
pytest.importorskip("agent_os.policies.backends")
pytest.importorskip("agent_os.policies.evaluator")

from agent_os.policies.backends import ExternalPolicyBackend  # noqa: E402
from agent_os.policies.evaluator import PolicyEvaluator  # noqa: E402

from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.agent_framework import set_in_force_token  # noqa: E402
from raucle.integrations.agt_backend import RauclePolicyBackend  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def issuer() -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer="acme.test.kyc")


@pytest.fixture
def gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


@pytest.fixture
def backend(gate: CapabilityGate) -> RauclePolicyBackend:
    return RauclePolicyBackend(
        gate=gate,
        verification_base_url="https://acme.test",
        lean_development_path="/.well-known/raucle-lean/",
    )


# ─── Protocol shape ────────────────────────────────────────────────────


def test_backend_satisfies_protocol(backend):
    """RauclePolicyBackend duck-types ExternalPolicyBackend."""
    assert isinstance(backend, ExternalPolicyBackend)


def test_backend_name_is_versioned(backend):
    assert backend.name.startswith("raucle.vcd@")


# ─── Verdicts ──────────────────────────────────────────────────────────


def test_no_token_denies(backend):
    """Absent capability token must produce a fail-closed deny."""
    set_in_force_token(None)
    d = backend.evaluate({"tool_name": "lookup_customer", "agent_id": "agent:x"})
    assert d.allowed is False
    assert d.action == "deny"
    assert "no capability token" in d.reason


def test_token_for_wrong_tool_denies(backend, issuer):
    set_in_force_token(
        issuer.mint(agent_id="agent:x", tool="lookup_customer", constraints={}, ttl_seconds=60)
    )
    d = backend.evaluate({"tool_name": "transfer_funds", "agent_id": "agent:x"})
    assert d.allowed is False


def test_allow_path_carries_assurance_fields_when_supported(backend, issuer):
    """When the installed AGT supports the new fields (PR #2610 merged),
    an ALLOW decision carries proof_artefact and verification_pointers."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    d = backend.evaluate(
        {
            "tool_name": "lookup_customer",
            "agent_id": "agent:kyc-prod",
            "arguments": {"customer_id": "C-1042"},
        }
    )

    assert d.allowed is True
    if backend._supports_assurance_fields:
        # The token didn't cite a proof_hash here, so proof_artefact may
        # be None; verification_pointers are always populated.
        assert d.verification_pointers["issuer_pubkey"].startswith("https://")
        assert d.verification_pointers["policy_registry"].endswith("/")


# ─── End-to-end with PolicyEvaluator ───────────────────────────────────


def test_end_to_end_through_policy_evaluator(backend, issuer):
    """The full chain: register backend with evaluator, evaluate
    context, observe propagated audit_entry."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    ev = PolicyEvaluator()
    ev.add_backend(backend)

    decision = ev.evaluate(
        {
            "tool_name": "lookup_customer",
            "agent_id": "agent:kyc-prod",
            "arguments": {"customer_id": "C-1042"},
        }
    )

    assert decision.allowed is True
    audit = decision.audit_entry
    assert audit["backend"].startswith("raucle.vcd@")
    if backend._supports_assurance_fields:
        # Post-merge AGT propagates these:
        assert "verification_pointers" in audit
        assert audit["verification_pointers"]["issuer_pubkey"].startswith("https://")


def test_hierarchical_agent_id(backend, issuer):
    """A token minted for ``agent:x`` covers ``agent:x.region-eu-west-1``."""
    set_in_force_token(
        issuer.mint(agent_id="agent:x", tool="lookup_customer", constraints={}, ttl_seconds=60)
    )
    d = backend.evaluate(
        {
            "tool_name": "lookup_customer",
            "agent_id": "agent:x.region-eu-west-1",
            "arguments": {},
        }
    )
    assert d.allowed is True
