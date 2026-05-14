"""GatedToolsExecutor — VCD's capability gate spliced into AgentDojo's pipeline.

Subclasses AgentDojo's `ToolsExecutor`, which is the choke point through which
every tool call must pass. Before delegating to the parent, we run our
`CapabilityGate.check(...)` against a per-session token whose constraints are
pre-registered for the suite under evaluation.

On DENY, we synthesise a `ChatToolResultMessage` with a structured error
instead of executing the tool. The agent sees the denial in its context and
typically refuses to retry. The attack's required tool call therefore never
fires, regardless of what the agent's text reasoning says.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from agentdojo.agent_pipeline import ToolsExecutor
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
from agentdojo.types import (
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from raucle_detect.capability import (
    Capability,
    CapabilityGate,
    CapabilityIssuer,
)

logger = logging.getLogger(__name__)


class GatedToolsExecutor(ToolsExecutor):
    """Per-call capability gate. Wraps the parent ToolsExecutor.

    Parameters
    ----------
    issuer
        The CapabilityIssuer that mints tokens for this session. The gate
        is configured to trust exactly this issuer's key.
    constraints_for_tool
        Callable returning the constraint policy to mint a token for a
        given tool name. Returns None if the tool is not in scope (we then
        defer to AgentDojo's default behaviour for that tool).
    variant
        "vcd_full" enables the full stack; "vcd_cap_only" disables the
        proof-binding; "vcd_proof_only" enforces constraints at the
        argument boundary without a capability token. (The last two are
        for the ablation rows in §6.2.)
    """

    def __init__(
        self,
        *,
        issuer: CapabilityIssuer,
        constraints_for_tool: Any,
        variant: str = "vcd_full",
        tool_output_formatter: Any = tool_result_to_str,
    ) -> None:
        super().__init__(tool_output_formatter=tool_output_formatter)
        self._issuer = issuer
        self._constraints_for_tool = constraints_for_tool
        self._variant = variant
        self._gate = CapabilityGate(
            trusted_issuers={issuer.key_id: issuer.public_key_pem}
        )
        # One token per (tool, session). Minted lazily on first call.
        self._tokens: dict[str, Capability] = {}
        self._denials = 0
        self._allows = 0

    def _token_for(self, tool: str) -> Capability | None:
        if tool in self._tokens:
            return self._tokens[tool]
        constraints = self._constraints_for_tool(tool)
        if constraints is None:
            return None
        token = self._issuer.mint(
            agent_id="agent:eval",
            tool=tool,
            constraints=constraints,
            ttl_seconds=3600,
        )
        self._tokens[tool] = token
        return token

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env=EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict = {},
    ):
        """Gate each tool call in the last assistant message; delegate the rest."""
        if not messages or messages[-1]["role"] != "assistant":
            return super().query(query, runtime, env, messages, extra_args)
        tool_calls = messages[-1].get("tool_calls") or []
        if not tool_calls:
            return super().query(query, runtime, env, messages, extra_args)

        # Inspect every call; substitute denials in place.
        denied_results: list[ChatToolResultMessage] = []
        approved_calls: list = []
        for tc in tool_calls:
            token = self._token_for(tc.function)
            if token is None:
                approved_calls.append(tc)
                continue
            args_dict = dict(tc.args) if hasattr(tc, "args") else dict(tc.arguments or {})
            decision = self._gate.check(
                token, tool=tc.function, agent_id="agent:eval", args=args_dict
            )
            if decision.allowed:
                self._allows += 1
                approved_calls.append(tc)
            else:
                self._denials += 1
                logger.info("gate DENY tool=%s reason=%s", tc.function, decision.reason)
                denied_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(
                            f"[VCD gate denied this call: {decision.reason}]"
                        )],
                        tool_call_id=tc.id,
                        tool_call=tc,
                        error=f"capability gate denied: {decision.reason}",
                    )
                )

        if not approved_calls:
            # Every call was denied. Return only the denial messages without
            # touching the runtime — no side effects.
            new_messages = list(messages) + denied_results
            return query, runtime, env, new_messages, extra_args

        # Mutate the last assistant message to keep only approved calls,
        # then delegate to the parent ToolsExecutor.
        amended_msg = dict(messages[-1])
        amended_msg["tool_calls"] = approved_calls
        amended_messages = list(messages[:-1]) + [amended_msg]
        new_q, new_rt, new_env, new_msgs, new_extra = super().query(
            query, runtime, env, amended_messages, extra_args
        )
        # Append our denial messages after the executor's results so the agent
        # sees both in context.
        return new_q, new_rt, new_env, list(new_msgs) + denied_results, new_extra


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_gated_executor(variant: str = "vcd_full") -> GatedToolsExecutor:
    """Construct a gated executor pre-loaded with the AgentDojo tool policies.

    Policies live in `paper/eval/policies.json` (pre-registered before any
    measurement run; see paper/eval/README.md §"Pre-registration"). We commit
    that file to the repo so reviewers can audit the constraints used.
    """
    import json
    from pathlib import Path

    issuer = CapabilityIssuer.generate(issuer="eval.example")

    policies_path = Path(__file__).parent / "policies.json"
    if policies_path.exists():
        policies = json.loads(policies_path.read_text())
    else:
        # Sentinel: until policies are authored, no tool has a constraint set
        # and the gate is a no-op. Useful for smoke-testing the wiring.
        policies = {}

    def constraints_for_tool(tool: str) -> dict | None:
        entry = policies.get(tool)
        return entry["policy"] if entry else None

    return GatedToolsExecutor(
        issuer=issuer,
        constraints_for_tool=constraints_for_tool,
        variant=variant,
    )
