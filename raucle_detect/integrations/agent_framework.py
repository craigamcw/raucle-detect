"""raucle middleware for the Microsoft Agent Framework (≥ 1.0, GA 2026-04-03).

Drop-in ``FunctionMiddleware`` that produces a signed capability receipt for
every tool call an Agent Framework agent makes. See the design proposal at
``docs/proposals/agent-framework-middleware.md`` for the full rationale,
threat-model deltas, and milestone plan.

Quick start
-----------

.. code-block:: python

    from agent_framework import ChatAgent
    from raucle_detect.capability import CapabilityGate, CapabilityIssuer
    from raucle_detect.audit import HashChainSink, Ed25519Signer
    from raucle_detect.integrations.agent_framework import (
        RaucleFunctionMiddleware,
        set_in_force_token,
    )

    issuer = CapabilityIssuer(...)
    gate   = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink   = HashChainSink("./receipts.log", signer=Ed25519Signer.generate())

    agent = ChatAgent(chat_client=..., tools=[...])
    agent.middleware.add(RaucleFunctionMiddleware(gate=gate, sink=sink))

    # Per-session token wiring — call this when a session opens
    token = issuer.mint(agent_id="agent-1", tool="...", constraints={...}, ttl_seconds=60)
    set_in_force_token(token)

The middleware short-circuits any tool call whose arguments fail the in-force
token's gate check, emitting a signed denial receipt either way.

Status
------

This module is a **working skeleton** as of raucle-detect v0.11.0a. The
public surface (the ``RaucleFunctionMiddleware`` class, the ``TokenResolver``
typedef, and the ``set_in_force_token`` / ``get_in_force_token`` helpers) is
intended to be stable. Two known limitations are tracked as M4 in the design
proposal: streaming-response receipts and downstream-middleware result
mutation. Pull requests welcome.

The integration depends on ``agent-framework>=1.0``; install with
``pip install 'raucle-detect[agent-framework]'``.
"""
from __future__ import annotations

import contextvars
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from raucle_detect.audit import (
    Ed25519Signer,
    HashChainSink,
    NullSink,
    _canonical_json,
    _sha256_hex,
)
from raucle_detect.capability import (
    Capability,
    CapabilityGate,
    GateDecision,
)

logger = logging.getLogger(__name__)

# --- Lazy host-framework import --------------------------------------------
# We refuse to fail at import-time if `agent_framework` isn't installed; users
# who installed `raucle-detect` without the extra should still be able to
# `from raucle_detect.integrations import agent_framework` and get a clear
# RuntimeError only when they try to instantiate the middleware.

try:  # pragma: no cover - import-time check, not exercised in unit tests
    from agent_framework import FunctionMiddleware  # type: ignore[import-not-found]

    _HAS_AGENT_FRAMEWORK = True
except ImportError:  # pragma: no cover
    _HAS_AGENT_FRAMEWORK = False

    class FunctionMiddleware:  # type: ignore[no-redef]
        """Stub used when ``agent-framework`` is not installed.

        Subclassing this class outside of an Agent Framework deployment is a
        no-op; instantiating ``RaucleFunctionMiddleware`` will raise a clear
        RuntimeError directing the user to install the extra.
        """


# --- In-force token resolution ---------------------------------------------
# Agents emit tool calls under a session's in-force capability token. We
# resolve via an asyncio-safe ContextVar by default; deployers can override
# with a custom callable for more sophisticated scoping (per-tenant,
# per-agent, distributed-cache-backed, etc.).

TokenResolver = Callable[["FunctionInvocationContext"], Capability | None]  # noqa: F821

_in_force_token: contextvars.ContextVar[Capability | None] = contextvars.ContextVar(
    "raucle_in_force_token", default=None
)


def set_in_force_token(token: Capability | None) -> None:
    """Bind a capability token to the current async context.

    Call this when a session begins (e.g. when handling the first message of a
    user conversation). The token remains in force for the lifetime of the
    asyncio context — concurrent sessions get independent token bindings.
    """
    _in_force_token.set(token)


def get_in_force_token() -> Capability | None:
    """Return the capability token bound to the current async context, if any."""
    return _in_force_token.get()


def _default_resolver(_context: Any) -> Capability | None:
    """Default resolver: read the in-force token from the asyncio context.

    Deployers can substitute a custom resolver by passing
    ``token_resolver=...`` to ``RaucleFunctionMiddleware``.
    """
    return get_in_force_token()


# --- Receipt construction ---------------------------------------------------


@dataclass(frozen=True)
class CapabilityReceipt:
    """A signed, content-addressed record of a single gate decision.

    Matches the receipt format documented in ``docs/spec/provenance/v1.md``
    and in the ``Anatomy of a receipt`` section of raucle.com. The signature
    is produced by the configured sink's ``Ed25519Signer``; everything else
    is content-addressed and self-describing.
    """

    issuer: str
    issuer_pubkey: str
    schema_hash: str | None
    policy_proof_hash: str | None
    lean_theorem_id: str
    attenuation_chain: list[str]
    agent_id: str
    tool: str
    call_args_hash: str
    decision: str  # "ALLOW" or "DENY"
    decision_reason: str
    timestamp: str  # ISO 8601 with millisecond precision
    signature: str | None  # populated by the sink

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "issuer_pubkey": self.issuer_pubkey,
            "schema_hash": self.schema_hash,
            "policy_proof_hash": self.policy_proof_hash,
            "lean_theorem_id": self.lean_theorem_id,
            "attenuation_chain": self.attenuation_chain,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "call_args_hash": self.call_args_hash,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }


def _hash_args(args: dict[str, Any]) -> str:
    """SHA-256 of canonical-JSON-serialised tool-call arguments."""
    return "sha256:" + _sha256_hex(_canonical_json(args))


def _iso_now() -> str:
    """ISO 8601 timestamp with millisecond precision and explicit Z suffix."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + (
        f".{int((time.time() % 1) * 1000):03d}Z"
    )


# --- The middleware ---------------------------------------------------------


class RaucleFunctionMiddleware(FunctionMiddleware):
    """``FunctionMiddleware`` that gates tool calls and emits capability receipts.

    Wire into an Agent Framework agent with::

        agent.middleware.add(RaucleFunctionMiddleware(gate=..., sink=...))

    On each tool invocation:

      * Look up the in-force capability token (via ``token_resolver``).
      * If no token is bound, emit a DENY receipt with reason ``"no token in
        force"`` and refuse the call.
      * Else, call ``gate.check(token, tool=..., args=...)``.
      * On ``decision.allowed``: invoke ``call_next()`` so the tool runs;
        emit an ALLOW receipt.
      * On ``decision.denied``: short-circuit (do *not* call ``call_next()``);
        set ``context.result`` to a structured refusal; emit a DENY receipt.

    Parameters
    ----------
    gate
        The :class:`~raucle_detect.capability.CapabilityGate` instance the
        middleware will check tool calls against.
    sink
        An audit sink that writes receipts. Defaults to a :class:`NullSink`
        (receipts are still constructed but not persisted); production
        deployments should pass a :class:`~raucle_detect.audit.HashChainSink`.
    token_resolver
        Callable that, given the Agent Framework invocation context, returns
        the in-force ``Capability`` token or ``None``. Defaults to the
        asyncio ContextVar populated by :func:`set_in_force_token`.
    lean_theorem_id
        The Lean 4 theorem identifier the receipts should cite as the
        soundness anchor. Defaults to ``"vcd.gate_soundness"`` (the gate-
        soundness theorem in ``paper/lean/``).
    """

    def __init__(
        self,
        *,
        gate: CapabilityGate,
        sink: HashChainSink | NullSink | None = None,
        token_resolver: TokenResolver | None = None,
        lean_theorem_id: str = "vcd.gate_soundness",
    ) -> None:
        if not _HAS_AGENT_FRAMEWORK:
            raise RuntimeError(
                "RaucleFunctionMiddleware requires the 'agent-framework' "
                "Python package. Install with `pip install "
                "'raucle-detect[agent-framework]'`."
            )
        self._gate = gate
        self._sink: HashChainSink | NullSink = sink if sink is not None else NullSink()
        self._token_resolver: TokenResolver = token_resolver or _default_resolver
        self._lean_theorem_id = lean_theorem_id

    async def process(
        self,
        context: Any,  # agent_framework.FunctionInvocationContext at runtime
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        """The hook the Agent Framework calls for every tool invocation."""
        token = self._token_resolver(context)
        tool_name = self._extract_tool_name(context)
        call_args = self._extract_args(context)
        agent_id = self._extract_agent_id(context)

        # No token bound? Fail-closed.
        if token is None:
            receipt = self._build_receipt(
                token=None,
                agent_id=agent_id,
                tool=tool_name,
                args=call_args,
                decision=GateDecision(
                    allowed=False, reason="no capability token in force"
                ),
            )
            self._emit(receipt)
            self._set_refusal(context, "no capability token in force")
            return

        # Gate check.
        decision = self._gate.check(token, tool=tool_name, agent_id=agent_id, args=call_args)
        receipt = self._build_receipt(
            token=token, agent_id=agent_id, tool=tool_name, args=call_args, decision=decision
        )

        if decision.allowed:
            try:
                await call_next()
            finally:
                # Emit the receipt regardless of whether the tool itself
                # raised — the gate's decision was ALLOW and the audit record
                # should reflect that.
                self._emit(receipt)
        else:
            self._set_refusal(context, decision.reason)
            self._emit(receipt)

    # --- Helpers --------------------------------------------------------

    def _build_receipt(
        self,
        *,
        token: Capability | None,
        agent_id: str | None,
        tool: str,
        args: dict[str, Any],
        decision: GateDecision,
    ) -> CapabilityReceipt:
        return CapabilityReceipt(
            issuer=(token.issuer if token else "<unknown>"),
            issuer_pubkey=(token.key_id if token else "<unknown>"),
            schema_hash=None,  # populated when policy_proof_hash is wired in
            policy_proof_hash=(token.policy_proof_hash if token else None),
            lean_theorem_id=self._lean_theorem_id,
            attenuation_chain=(decision.chain or ([] if token is None else [token.token_id])),
            agent_id=agent_id or "<unknown>",
            tool=tool,
            call_args_hash=_hash_args(args),
            decision=("ALLOW" if decision.allowed else "DENY"),
            decision_reason=decision.reason,
            timestamp=_iso_now(),
            signature=None,  # populated by sink.write below
        )

    def _emit(self, receipt: CapabilityReceipt) -> None:
        """Hand the receipt to the audit sink for signing + persistence."""
        try:
            # HashChainSink wraps each event in a hash-chain entry and
            # signs periodically; NullSink discards.
            self._sink.append(
                {"kind": "capability_receipt", "receipt": receipt.to_dict()}
            )
        except Exception:  # pragma: no cover
            # Never let receipt emission break the agent's main path —
            # but log loudly. A deployment that silently drops receipts is a
            # broken deployment; the deployer needs to know.
            logger.exception("raucle: failed to emit capability receipt")

    # --- Context extraction (defensive against schema variation) ---------
    # The exact shape of `FunctionInvocationContext` is stable as of Agent
    # Framework 1.0 but we keep these as named helpers so future Microsoft
    # API tweaks land in one place.

    @staticmethod
    def _extract_tool_name(context: Any) -> str:
        # AF docs name this `context.function.name`.
        try:
            return str(context.function.name)
        except AttributeError:  # pragma: no cover
            return "<unknown_tool>"

    @staticmethod
    def _extract_args(context: Any) -> dict[str, Any]:
        # AF docs name this `context.arguments` (a Mapping[str, Any]).
        try:
            args = context.arguments
        except AttributeError:  # pragma: no cover
            return {}
        if args is None:
            return {}
        if isinstance(args, dict):
            return dict(args)
        # Other Mapping types — coerce.
        try:
            return dict(args)
        except (TypeError, ValueError):  # pragma: no cover
            return {}

    @staticmethod
    def _extract_agent_id(context: Any) -> str | None:
        # AF docs: `context.agent.id` populated from agent construction.
        try:
            return str(context.agent.id)
        except AttributeError:  # pragma: no cover
            return None

    @staticmethod
    def _set_refusal(context: Any, reason: str) -> None:
        """Replace ``context.result`` with a structured refusal payload.

        The downstream tool runner sees a normal `FunctionResult` carrying
        the refusal text; the agent observes a tool that "ran" and returned
        the refusal. Per AF middleware semantics, not calling ``call_next``
        means the actual tool implementation is never invoked.
        """
        refusal = {
            "raucle": {
                "decision": "DENY",
                "reason": reason,
                "advice": "request a token with broader scope, or revise the call args",
            }
        }
        # Try the Agent Framework's expected `FunctionResult` shape first,
        # falling back to a plain assignment if the host version differs.
        try:
            from agent_framework import FunctionResult  # type: ignore[import-not-found]

            context.result = FunctionResult(value=json.dumps(refusal))
        except Exception:  # pragma: no cover
            try:
                context.result = json.dumps(refusal)
            except Exception:
                logger.exception("raucle: could not set refusal on context")


__all__ = [
    "CapabilityReceipt",
    "RaucleFunctionMiddleware",
    "TokenResolver",
    "get_in_force_token",
    "set_in_force_token",
]
