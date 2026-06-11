"""Unit tests for raucle.integrations.agt.RauclePolicyProvider.

Exercises the four contract paths of the proposed AGT PDP interface
(see docs/proposals/agt-pdp-contract.md) against the real raucle
CapabilityGate / CapabilityIssuer primitives.

No external dependencies. The IPolicyProvider stub lives in raucle's
own integration module until Microsoft lands the upstream contract.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.integrations.agent_framework import set_in_force_token  # noqa: E402
from raucle.integrations.agt import (  # noqa: E402
    RAUCLE_PROVIDER_VERSION,
    PolicyDecision,
    RauclePolicyProvider,
)

# ---------------------------------------------------------------------------
# Fixtures


@pytest.fixture
def issuer() -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer="acme.test.kyc")


@pytest.fixture
def gate(issuer: CapabilityIssuer) -> CapabilityGate:
    return CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})


@pytest.fixture
def provider(gate: CapabilityGate) -> RauclePolicyProvider:
    return RauclePolicyProvider(
        gate=gate,
        verification_base_url="https://acme.bank",
        lean_development_path="/raucle-proofs",
    )


# ---------------------------------------------------------------------------
# Tests


def test_name_is_versioned(provider: RauclePolicyProvider):
    """The provider name embeds the contract version for audit-record
    legibility."""
    assert provider.name() == f"raucle.vcd@{RAUCLE_PROVIDER_VERSION}"


def test_supports_returns_false_without_token(provider):
    """No token in force → provider declines to handle."""
    set_in_force_token(None)
    assert not provider.supports("any_tool", "agent:any")


def test_supports_matches_token_tool(issuer, provider):
    """Provider handles only the tool the in-force token authorises."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)
    assert provider.supports("lookup_customer", "agent:kyc-prod")
    assert not provider.supports("transfer_funds", "agent:kyc-prod")


def test_supports_allows_sub_agent_extension(issuer, provider):
    """Hierarchical agent ids: a provider scoped to agent:kyc-prod
    handles agent:kyc-prod.region-eu-west-1 too."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)
    assert provider.supports("lookup_customer", "agent:kyc-prod.region-eu-west-1")


def test_decide_returns_allow_when_constraints_satisfied(issuer, provider):
    """Token + correct tool + satisfying args → ALLOW + policy_proof_hash
    in proof_artefact (when token carries one)."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
        policy_proof_hash="sha256:4b78e687a3f1deadbeef203f",
    )
    set_in_force_token(token)

    decision = provider.decide(
        tool="lookup_customer",
        agent_id="agent:kyc-prod",
        arguments={"customer_id": "C-1042"},
    )

    assert isinstance(decision, PolicyDecision)
    assert decision.allowed
    assert decision.reason  # non-empty
    assert decision.proof_artefact == "sha256:4b78e687a3f1deadbeef203f"


def test_decide_returns_deny_for_wrong_tool(issuer, provider):
    """Calling the provider with a tool the token doesn't cover →
    DENY (the gate enforces this even though supports() also returns
    False; AGT may still ask for a decision)."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    decision = provider.decide(
        tool="transfer_funds",
        agent_id="agent:kyc-prod",
        arguments={"to": "GB29NWBK60161331926819", "amount": 4.00},
    )

    assert not decision.allowed
    assert "tool" in decision.reason.lower()


def test_decide_returns_deny_when_no_token(provider):
    """No token bound → DENY with explanatory reason."""
    set_in_force_token(None)
    decision = provider.decide(
        tool="lookup_customer",
        agent_id="agent:kyc-prod",
        arguments={"customer_id": "C-1042"},
    )
    assert not decision.allowed
    assert "no capability token in force" in decision.reason


def test_verification_pointers_use_base_url(issuer, provider):
    """All pointer URLs are rooted at the configured base URL."""
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    decision = provider.decide(
        tool="lookup_customer",
        agent_id="agent:kyc-prod",
        arguments={"customer_id": "C-1042"},
    )

    pointers = decision.verification_pointers
    assert pointers["issuer_pubkey"].startswith("https://acme.bank/")
    assert pointers["policy_registry"].startswith("https://acme.bank/")
    assert pointers["lean_development"] == "https://acme.bank/raucle-proofs"


def test_verification_pointers_omit_lean_when_unset(gate, issuer):
    """A provider configured without lean_development_path omits the
    field rather than emitting an empty string."""
    provider = RauclePolicyProvider(
        gate=gate,
        verification_base_url="https://example.com",
        # no lean_development_path
    )
    token = issuer.mint(
        agent_id="agent:test",
        tool="any_tool",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    decision = provider.decide(
        tool="any_tool",
        agent_id="agent:test",
        arguments={},
    )
    assert "lean_development" not in decision.verification_pointers


def test_decision_is_immutable(issuer, provider):
    """PolicyDecision is a frozen dataclass — guards against
    accidental mutation by downstream code."""
    token = issuer.mint(
        agent_id="agent:test",
        tool="lookup_customer",
        constraints={},
        ttl_seconds=60,
    )
    set_in_force_token(token)

    decision = provider.decide(
        tool="lookup_customer",
        agent_id="agent:test",
        arguments={},
    )
    with pytest.raises((AttributeError, Exception)):  # FrozenInstanceError
        decision.allowed = False  # type: ignore[misc]
