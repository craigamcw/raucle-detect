"""raucle reference Policy Decision Point for the Microsoft Agent Governance Toolkit.

Implements the `IPolicyProvider` contract proposed in
``docs/proposals/agt-pdp-contract.md``. Since AGT does not yet ship a
documented PDP plug-in interface, this module defines a *proposal-shape*
stub (`IPolicyProvider`, `PolicyDecision`) that mirrors what we are
asking Microsoft to land upstream, and provides `RauclePolicyProvider`
as the canonical reference implementation against that shape.

When AGT lands the contract, `IPolicyProvider` and `PolicyDecision` here
become thin re-exports of the upstream symbols; `RauclePolicyProvider`
keeps its public surface unchanged. Consumers who want to wire raucle
into AGT today can use the stub interface directly — every public
attribute is documented and stable.

Quick start
-----------

.. code-block:: python

    from raucle.audit import HashChainSink, Ed25519Signer
    from raucle.capability import CapabilityGate, CapabilityIssuer
    from raucle.integrations.agent_framework import set_in_force_token
    from raucle.integrations.agt import RauclePolicyProvider

    issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc-platform")
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

    token = issuer.mint(
        agent_id="agent:kyc-prod", tool="lookup_customer",
        constraints={}, ttl_seconds=60,
    )
    set_in_force_token(token)

    provider = RauclePolicyProvider(
        gate=gate,
        verification_base_url="https://acme.bank",
    )

    # AGT's Agent OS would call these — until the upstream contract
    # lands, you can wire them from a custom AGT policy adapter:
    assert provider.supports("lookup_customer", "agent:kyc-prod")
    decision = provider.decide(
        tool="lookup_customer",
        agent_id="agent:kyc-prod",
        arguments={"customer_id": "C-1042"},
    )
    assert decision.allowed
    assert decision.proof_artefact   # sha256:... policy_proof_hash if minted with one
    assert decision.verification_pointers["issuer_pubkey"].startswith("https://")

Status
------

This module is the **M2 deliverable** for ``docs/proposals/agt-pdp-contract.md``
— a working `RauclePolicyProvider` against the proposed (not-yet-
shipped) `IPolicyProvider` contract, with unit tests that pin the
behaviour. M3 ships the upstream PR to ``microsoft/agent-governance-
toolkit``; until that lands, the stub interface here is the canonical
shape we are asking for.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from raucle.capability import CapabilityGate
from raucle.integrations.agent_framework import get_in_force_token

# ---------------------------------------------------------------------------
# Proposal-shape stubs.
#
# These mirror what `docs/proposals/agt-pdp-contract.md` asks Microsoft to
# accept upstream. They are deliberately minimal — when AGT lands its own
# `IPolicyProvider`, the only change here is to re-export the upstream
# symbols.


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of an external PDP consultation.

    Mirrors the dataclass in the proposal. ``proof_artefact`` and
    ``verification_pointers`` are the two fields that distinguish a
    raucle-style verifiable decision from an opaque allow/deny.
    """

    allowed: bool
    reason: str
    proof_artefact: str | None = None
    verification_pointers: Mapping[str, str] = field(default_factory=dict)


class IPolicyProvider(ABC):
    """Abstract Policy Decision Point.

    AGT's Agent OS (after the upstream contract lands) calls
    ``supports`` to decide which provider handles a given tool-call,
    then ``decide`` to render the verdict. Providers that don't have
    proof artefacts simply leave ``PolicyDecision.proof_artefact`` as
    ``None``.
    """

    @abstractmethod
    def name(self) -> str:
        """Stable identifier for this provider; appears in audit records."""

    @abstractmethod
    def supports(self, tool: str, agent_id: str) -> bool:
        """Return True if this provider handles (tool, agent_id)."""

    @abstractmethod
    def decide(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        """Render a policy decision for this specific tool call."""


# ---------------------------------------------------------------------------
# The raucle implementation.

# Module-level version pinned for the receipt's policy_provider field.
# Bumped explicitly when the contract shape changes; not tied to the
# raucle package version because the contract is independent.
RAUCLE_PROVIDER_VERSION = "0.1.0"


class RauclePolicyProvider(IPolicyProvider):
    """raucle's reference PDP for the proposed AGT contract.

    Each ``decide()`` call consults the in-force capability token (via
    the same asyncio-ContextVar mechanism the Agent Framework
    middleware uses), runs the gate, and returns a structured
    `PolicyDecision` carrying the policy-proof hash and the deploying
    organisation's published verification URLs.

    Parameters
    ----------
    gate
        The :class:`~raucle.capability.CapabilityGate` to consult.
    verification_base_url
        Base URL where the deploying organisation publishes its issuer
        public key, policy registry, and (optionally) Lean development
        URL. Used to populate
        :attr:`PolicyDecision.verification_pointers` so AGT's audit
        chain can record a self-describing record an external verifier
        can re-check offline.
    issuer_pubkey_path
        Relative path under ``verification_base_url`` to the issuer
        public key (defaults to ``/.well-known/raucle-issuer.pub``).
    policy_registry_path
        Relative path to the policy-proof registry
        (defaults to ``/.well-known/raucle-policies/``).
    lean_development_path
        Optional relative path to the published Lean 4 mechanisation.
        ``None`` if the deploying organisation does not publish their
        own Lean development.
    """

    def __init__(
        self,
        *,
        gate: CapabilityGate,
        verification_base_url: str,
        issuer_pubkey_path: str = "/.well-known/raucle-issuer.pub",
        policy_registry_path: str = "/.well-known/raucle-policies/",
        lean_development_path: str | None = None,
    ) -> None:
        self._gate = gate
        self._base = verification_base_url.rstrip("/")
        self._issuer_pubkey_path = issuer_pubkey_path
        self._policy_registry_path = policy_registry_path
        self._lean_development_path = lean_development_path

    def name(self) -> str:
        return f"raucle.vcd@{RAUCLE_PROVIDER_VERSION}"

    def supports(self, tool: str, agent_id: str) -> bool:
        """Handle decisions for any (tool, agent_id) pair that the
        in-force capability token covers.

        Multi-tool tokens are supported by AGT's first-match-wins
        resolution: if a different provider supports this tool, AGT
        consults that one first.
        """
        token = get_in_force_token()
        if token is None:
            return False
        if token.tool != tool:
            return False
        return token.agent_id == agent_id or agent_id.startswith(token.agent_id + ".")

    def decide(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        token = get_in_force_token()
        if token is None:
            return PolicyDecision(
                allowed=False,
                reason="no capability token in force",
                verification_pointers=self._pointers(),
            )

        gate_decision = self._gate.check(
            token,
            tool=tool,
            agent_id=agent_id,
            args=dict(arguments),
        )

        return PolicyDecision(
            allowed=gate_decision.allowed,
            reason=gate_decision.reason,
            proof_artefact=token.policy_proof_hash,
            verification_pointers=self._pointers(),
        )

    # ------------------------------------------------------------------

    def _pointers(self) -> dict[str, str]:
        """Compose the verification-pointers dict; omits the Lean
        development URL when the deploying organisation does not
        publish one."""
        pointers = {
            "issuer_pubkey": self._base + self._issuer_pubkey_path,
            "policy_registry": self._base + self._policy_registry_path,
        }
        if self._lean_development_path:
            pointers["lean_development"] = self._base + self._lean_development_path
        return pointers


__all__ = [
    "IPolicyProvider",
    "PolicyDecision",
    "RAUCLE_PROVIDER_VERSION",
    "RauclePolicyProvider",
]
