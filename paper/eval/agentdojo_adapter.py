"""AgentDojo adapter. Two TODOs.

AgentDojo [DBL+24] ships a suite of agent deployments (banking, Slack, GitHub,
travel) plus an attack-task corpus. Each task pairs a benign user instruction
with one or more adversarial documents injected into the agent's context;
success is measured by whether the agent calls a designated tool with
attacker-controlled arguments.

Upstream: https://github.com/ethz-spylab/agentdojo

This adapter:
- iterates over AgentDojo's attack tasks for a given suite,
- wraps the agent in the defence under test,
- runs each task and records (tool_call_attack_succeeded, task_completed_benignly),
- returns aggregate ASR + utility metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class TaskResult:
    task_id: str
    suite: str
    attack_success: bool       # the adversarial outcome was triggered
    benign_success: bool       # the benign half of the task also completed
    is_tool_mediated: bool     # success required a constrained tool call


@dataclass
class SuiteResult:
    suite: str                       # "banking" / "slack" / "github" / "travel"
    total_tasks: int
    attack_successes: int
    benign_successes: int
    tool_mediated_attacks: int
    per_task: list[TaskResult]

    @property
    def asr(self) -> float:
        return self.attack_successes / self.total_tasks if self.total_tasks else 0.0

    @property
    def benign_completion(self) -> float:
        return self.benign_successes / self.total_tasks if self.total_tasks else 0.0

    @property
    def tool_mediated_fraction(self) -> float:
        return (
            self.tool_mediated_attacks / max(self.attack_successes, 1)
            if self.attack_successes
            else 0.0
        )


def run(defence_factory: Callable, *, model: str, suites: list[str]) -> list[SuiteResult]:
    """Run every AgentDojo task in `suites` under `defence_factory`.

    TODO #1: pin a specific AgentDojo version (commit SHA) and import its
    benchmark runner. Avoid depending on the package's "latest" release.

    TODO #2: bind the harness's per-step hooks ("agent emits tool call",
    "tool returns to agent") to the defence wrapper so the gate sees every
    call. The exact hook shape is described in AgentDojo's `docs/extending.md`.

    Returns one SuiteResult per suite.
    """
    raise NotImplementedError(
        "Pin AgentDojo version and integrate its runner. See README."
    )
