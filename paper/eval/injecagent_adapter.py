"""InjecAgent adapter. Same shape as the AgentDojo adapter.

InjecAgent [ZSM+24] ships 1,054 attack scenarios in two modes:
- DH (direct harm): the injection asks the agent to perform a harmful action;
- DS (data steal): the injection asks the agent to exfiltrate data through a
  benign-looking tool call.

Upstream: https://github.com/uiuc-kang-lab/InjecAgent
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class TaskResult:
    case_id: str
    mode: str                  # "dh" or "ds"
    attack_success: bool
    is_tool_mediated: bool


@dataclass
class ModeResult:
    mode: str
    total_cases: int
    attack_successes: int
    tool_mediated_attacks: int

    @property
    def asr(self) -> float:
        return self.attack_successes / self.total_cases if self.total_cases else 0.0


def run(defence_factory: Callable, *, model: str, modes: list[str]) -> list[ModeResult]:
    """TODO: pin a specific InjecAgent version and import its evaluator.
    Bind the defence wrapper to the agent harness as in agentdojo_adapter."""
    raise NotImplementedError(
        "Pin InjecAgent version and integrate its evaluator. See README."
    )
