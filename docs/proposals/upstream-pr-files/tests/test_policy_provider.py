"""Tests for the Policy Decision Point plug-in contract.

These tests exercise the abstract contract surface — they do not
require an external provider to be installed. They prove:

  1. ``IPolicyProvider`` is correctly defined as an ABC (cannot be
     instantiated directly; all three abstract methods enforced).
  2. ``PolicyDecision`` is frozen (cannot be mutated after creation).
  3. A minimal in-tree stub provider can be constructed and round-trips
     through the contract correctly.
  4. The async ``decide_async()`` default delegates to the sync
     ``decide()`` so subclasses are not forced to implement both.

The intent of these tests is for the AGT engine team to drop into
``tests/agent_os/`` unchanged; they assert the contract shape, not any
particular implementation behaviour.
"""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from agent_os.policy_provider import IPolicyProvider, PolicyDecision


class _StubProvider(IPolicyProvider):
    """Minimal in-tree provider used by the contract tests below."""

    def __init__(self, default_allow: bool = True) -> None:
        self._default_allow = default_allow
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def name(self) -> str:
        return "stub.test@0.0.1"

    def supports(self, tool: str, agent_id: str) -> bool:
        return True

    def decide(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        self.calls.append((tool, agent_id, dict(arguments)))
        return PolicyDecision(
            allowed=self._default_allow,
            reason="stub decision",
            proof_artefact="sha256:" + "0" * 64,
            verification_pointers={"issuer_pubkey": "https://example.test/.well-known/k"},
        )


# ---------------------------------------------------------------------------
# Contract shape


def test_ipolicyprovider_is_abstract():
    """Direct instantiation must raise; the contract is abstract."""
    with pytest.raises(TypeError):
        IPolicyProvider()  # type: ignore[abstract]


def test_ipolicyprovider_requires_name():
    """A subclass that omits ``name`` cannot be instantiated."""

    class _NoName(IPolicyProvider):
        def supports(self, tool, agent_id):
            return True

        def decide(self, *, tool, agent_id, arguments, context=None):
            return PolicyDecision(allowed=True, reason="")

    with pytest.raises(TypeError):
        _NoName()  # type: ignore[abstract]


def test_ipolicyprovider_requires_supports():
    """A subclass that omits ``supports`` cannot be instantiated."""

    class _NoSupports(IPolicyProvider):
        def name(self):
            return "x"

        def decide(self, *, tool, agent_id, arguments, context=None):
            return PolicyDecision(allowed=True, reason="")

    with pytest.raises(TypeError):
        _NoSupports()  # type: ignore[abstract]


def test_ipolicyprovider_requires_decide():
    """A subclass that omits ``decide`` cannot be instantiated."""

    class _NoDecide(IPolicyProvider):
        def name(self):
            return "x"

        def supports(self, tool, agent_id):
            return True

    with pytest.raises(TypeError):
        _NoDecide()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# PolicyDecision shape


def test_policy_decision_is_frozen():
    """PolicyDecision is immutable; the engine relies on this for safe
    audit-chain passthrough."""
    d = PolicyDecision(allowed=True, reason="ok")
    with pytest.raises(Exception):  # FrozenInstanceError
        d.allowed = False  # type: ignore[misc]


def test_policy_decision_defaults():
    """proof_artefact defaults to None; verification_pointers defaults
    to an empty mapping (not None) to simplify downstream consumers."""
    d = PolicyDecision(allowed=False, reason="denied")
    assert d.proof_artefact is None
    assert d.verification_pointers == {}


def test_policy_decision_carries_proof_artefact_and_pointers():
    """End-to-end: a decision can carry the optional fields and they
    round-trip without coercion."""
    d = PolicyDecision(
        allowed=True,
        reason="constraints satisfied",
        proof_artefact="sha256:4b78e687a3f1deadbeef203f",
        verification_pointers={
            "issuer_pubkey": "https://acme.bank/.well-known/raucle-issuer.pub",
            "policy_registry": "https://acme.bank/.well-known/raucle-policies/",
        },
    )
    assert d.proof_artefact == "sha256:4b78e687a3f1deadbeef203f"
    assert d.verification_pointers["issuer_pubkey"].startswith("https://")
    assert d.verification_pointers["policy_registry"].endswith("/")


# ---------------------------------------------------------------------------
# Provider round-trip


def test_stub_provider_round_trip():
    """A conforming provider runs through the full contract surface."""
    p = _StubProvider(default_allow=True)
    assert p.name() == "stub.test@0.0.1"
    assert p.supports("any_tool", "agent:any")

    d = p.decide(
        tool="lookup_customer",
        agent_id="agent:kyc-prod",
        arguments={"customer_id": "C-1042"},
    )
    assert d.allowed is True
    assert d.reason == "stub decision"
    assert d.proof_artefact == "sha256:" + "0" * 64

    # Provider observed the call
    assert p.calls == [("lookup_customer", "agent:kyc-prod", {"customer_id": "C-1042"})]


def test_async_default_delegates_to_sync():
    """A provider that only implements ``decide`` still works via the
    async path — the default ``decide_async`` delegates."""
    p = _StubProvider(default_allow=False)

    async def _run() -> PolicyDecision:
        return await p.decide_async(
            tool="t",
            agent_id="agent:x",
            arguments={},
        )

    d = asyncio.run(_run())
    assert d.allowed is False
    assert len(p.calls) == 1, "async path must route through sync decide() by default"


def test_async_override_is_preferred(monkeypatch):
    """Providers that override ``decide_async`` keep their implementation;
    the engine prefers it when both are present."""
    sync_called = []
    async_called = []

    class _AsyncProvider(_StubProvider):
        def decide(self, *, tool, agent_id, arguments, context=None):
            sync_called.append(True)
            return super().decide(
                tool=tool, agent_id=agent_id, arguments=arguments, context=context
            )

        async def decide_async(self, *, tool, agent_id, arguments, context=None):
            async_called.append(True)
            return PolicyDecision(allowed=True, reason="async path")

    p = _AsyncProvider()

    async def _run() -> PolicyDecision:
        return await p.decide_async(
            tool="t",
            agent_id="agent:x",
            arguments={},
        )

    d = asyncio.run(_run())
    assert d.reason == "async path"
    assert async_called == [True]
    assert sync_called == [], "engine must not fall back to sync when async is overridden"
