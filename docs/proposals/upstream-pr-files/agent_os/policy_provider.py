"""Policy Decision Point plug-in contract for Agent OS.

This module defines an abstract Policy Decision Point (PDP) interface
that Agent OS's PolicyEngine consults for tool-call authorisation
decisions delegated to external providers.

Motivation
----------

Agent OS today supports YAML, OPA/Rego, and Cedar policies interpreted
in-process. Some deployments — particularly in regulated industries —
require policy decisions whose soundness is established by formal
methods (SMT verification over JSON Schema, mechanised theorems in
proof assistants, or hardware-attested execution) that do not fit
naturally inside the in-process interpreter loop.

Rather than embedding those mechanisms in Agent OS itself, we expose a
plug-in seam: any conforming ``IPolicyProvider`` can register with the
PolicyEngine and AGT will route the relevant tool-call decisions to it.

Design constraints
------------------

The contract is deliberately minimal:

1. **Synchronous by default.** ``decide()`` is a sync call. Providers
   whose decision requires I/O can implement ``decide_async()`` instead
   and AGT's engine will route async-capable callers through that path.
2. **Self-describing decisions.** ``PolicyDecision`` carries an optional
   ``proof_artefact`` (the content-address of the underlying proof, if
   any) and ``verification_pointers`` (URLs at which a third-party
   verifier can fetch the issuer's published material to re-check the
   decision offline). Providers that don't have proofs simply leave
   these fields empty.
3. **Frozen decisions.** ``PolicyDecision`` is an immutable dataclass;
   the engine and audit layer can pass it around without defensive
   copies.
4. **Provider scoping.** ``supports(tool, agent_id)`` lets multiple
   providers coexist; the engine consults each in registration order
   and routes to the first match.

Composition with the existing in-process engine
-----------------------------------------------

The in-process YAML/OPA/Cedar engine remains the default. External
providers compose alongside via this contract:

- ``engine.register_provider(provider)`` adds the provider to the
  resolution chain. The in-process engine is always tried first; if it
  defers (returns ``None`` from its internal ``check``), the chain of
  external providers is consulted.
- An external provider's ALLOW does not override an in-process DENY:
  the engine is fail-closed across the chain. This matches Agent OS's
  existing semantics.
- The PolicyDecision's ``verification_pointers`` and
  ``proof_artefact`` are recorded in the audit chain under three new
  optional fields (see ``agent_hypervisor/audit_record.py``).

See ``docs/adr/0042-policy-decision-point-plugin.md`` for the
architectural rationale.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of a Policy Decision Point consultation.

    Returned by ``IPolicyProvider.decide()``. Immutable.

    Attributes
    ----------
    allowed
        Whether the call is admitted. ``False`` short-circuits the
        execution chain immediately.
    reason
        Human-readable explanation of the decision, suitable for both
        operator logs and end-user-facing refusal messages.
    proof_artefact
        Optional content-address (typically ``sha256:...``) of the
        underlying proof artefact, if the provider's decision is
        derived from one. Recorded in the audit chain alongside the
        decision so verifiers can re-check the proof offline.
    verification_pointers
        Optional dict of named URLs at which a third-party verifier can
        fetch the deploying organisation's published material — issuer
        public key, policy registry, theorem development, attestation
        chain — to re-verify this decision without contacting the
        operator. Recorded in the audit chain.
    """

    allowed: bool
    reason: str
    proof_artefact: str | None = None
    verification_pointers: Mapping[str, str] = field(default_factory=dict)


class IPolicyProvider(ABC):
    """Abstract Policy Decision Point.

    Implementations are registered with Agent OS's PolicyEngine via
    ``engine.register_provider(...)``. The engine routes tool-call
    authorisation decisions to the first provider whose
    ``supports(tool, agent_id)`` returns True.

    Providers that perform network I/O or other latency-sensitive work
    should additionally implement ``decide_async()``; the engine
    prefers the async variant when an async caller is present.
    """

    @abstractmethod
    def name(self) -> str:
        """Stable identifier for this provider.

        Used by the audit layer as the ``policy_provider`` field on
        emitted audit records. Convention: ``<vendor>.<technique>@<version>``,
        e.g. ``acme.smt-verified@1.2.0``. The version is part of the
        identifier so audit records remain unambiguous across provider
        upgrades.
        """

    @abstractmethod
    def supports(self, tool: str, agent_id: str) -> bool:
        """Whether this provider handles decisions for (tool, agent_id).

        The engine calls this once per tool-call to select which
        provider should render the decision; first-match-wins. A
        provider may handle any subset of an agent's tools (e.g.
        formally-verified providers for sensitive tools, the in-process
        engine for the rest).
        """

    @abstractmethod
    def decide(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        """Render a synchronous policy decision for this tool call.

        Parameters
        ----------
        tool
            The tool being invoked.
        agent_id
            The (resolved) agent identity making the call. Format
            matches Agent OS's existing convention (SPIFFE ID, Entra
            principal id, or ``agent:<name>`` for raw identifiers).
        arguments
            The tool-call arguments, already validated against the
            tool's JSON Schema. A Mapping rather than a dict so
            providers can be passed views over read-only state.
        context
            Optional engine-provided context dict (session id,
            correlation id, deployer-defined extras). Providers may
            ignore.

        Returns
        -------
        A frozen ``PolicyDecision``. The engine records it verbatim
        in the audit chain.
        """

    # Async variant; default implementation delegates to the sync one
    # so subclasses are not forced to implement both.
    async def decide_async(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        """Render an async policy decision.

        Providers that perform I/O should override this method directly
        and not delegate to the sync variant. The engine prefers this
        path when an async caller is present.
        """
        return self.decide(
            tool=tool,
            agent_id=agent_id,
            arguments=arguments,
            context=context,
        )


__all__ = ["IPolicyProvider", "PolicyDecision"]
