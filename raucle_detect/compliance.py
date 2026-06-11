"""Compliance evidence packs (P4) — map the receipt chain to named controls.

A regulated buyer's recurring question is *"show me your agent-authorization
evidence."* raucle already produces a signed, offline-verifiable receipt chain;
this module turns that chain into a **control-mapped compliance report**: for a
named framework (EU AI Act, ISO/IEC 42001, SOC 2), which controls the chain
*evidences*, with the concrete counts/receipts that satisfy each, and an honest
statement of what is out of scope.

This is deliberately an **evidence map, not a conformance attestation.** raucle
evidences a *subset* of each framework — the record-keeping, access-control, and
monitoring controls its primitives genuinely address. Full compliance needs
other artifacts and an assessor. Every control below states exactly what the
chain proves and what it does not, in the same honest posture as the
[OWASP](../docs/standards/owasp-agentic-top10-mapping.md) and
[NIST](../docs/standards/nist-ai-agent-standards-alignment.md) mappings.

Usage::

    from raucle_detect.compliance import build_report, render_markdown
    report = build_report("receipts.jsonl", framework="eu-ai-act")
    print(render_markdown(report))

CLI: ``raucle-detect compliance report receipts.jsonl --framework eu-ai-act``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ControlStatus(str, Enum):
    SATISFIED = "SATISFIED"  # the chain provides the evidence this control asks for
    PARTIAL = "PARTIAL"  # the chain provides part; named gaps remain
    OUT_OF_SCOPE = "OUT_OF_SCOPE"  # raucle does not address this control


@dataclass
class ChainEvidence:
    """Facts extracted from a receipt chain, the raw material for control checks."""

    total_events: int = 0
    decisions: int = 0
    allow: int = 0
    deny: int = 0
    scans: int = 0
    flagged_scans: int = 0
    signed: bool = False
    checkpoints: int = 0
    distinct_agents: int = 0
    distinct_tools: int = 0


def extract_evidence(chain_path: str | Path) -> ChainEvidence:
    """Read a receipt chain (JSONL) and tally the facts controls are checked against."""
    ev = ChainEvidence()
    agents: set[str] = set()
    tools: set[str] = set()
    for line in Path(chain_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("chain_meta"):
            ev.signed = bool(rec.get("signed"))
            continue
        if rec.get("checkpoint"):
            ev.checkpoints += 1
            continue
        event = rec.get("event") if isinstance(rec.get("event"), dict) else rec
        ev.total_events += 1
        if "decision" in event:
            ev.decisions += 1
            if event["decision"] == "ALLOW":
                ev.allow += 1
            else:
                ev.deny += 1
            if event.get("agent_id"):
                agents.add(event["agent_id"])
            if event.get("tool"):
                tools.add(event["tool"])
        elif "verdict" in event:
            ev.scans += 1
            if event["verdict"] != "CLEAN":
                ev.flagged_scans += 1
    ev.distinct_agents = len(agents)
    ev.distinct_tools = len(tools)
    return ev


@dataclass
class Control:
    """One framework control and how raucle evidence maps to it."""

    id: str
    title: str
    requirement: str
    status_fn: Callable[[ChainEvidence], tuple[ControlStatus, str]]


@dataclass
class ControlResult:
    id: str
    title: str
    requirement: str
    status: ControlStatus
    evidence: str


@dataclass
class ComplianceReport:
    framework: str
    framework_title: str
    chain_path: str
    chain_signed: bool
    controls: list[ControlResult] = field(default_factory=list)
    evidence: ChainEvidence | None = None

    def summary(self) -> dict[str, int]:
        out = {s.value: 0 for s in ControlStatus}
        for c in self.controls:
            out[c.status.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "framework_title": self.framework_title,
            "chain_path": self.chain_path,
            "chain_signed": self.chain_signed,
            "disclaimer": _DISCLAIMER,
            "summary": self.summary(),
            "controls": [
                {
                    "id": c.id,
                    "title": c.title,
                    "requirement": c.requirement,
                    "status": c.status.value,
                    "evidence": c.evidence,
                }
                for c in self.controls
            ],
        }


_DISCLAIMER = (
    "This is an EVIDENCE MAP, not a conformance attestation. raucle evidences the "
    "subset of controls its primitives address (signed authorization decisions, "
    "tamper-evident logging, capability access control). Full compliance requires "
    "additional controls, artifacts, and an accredited assessor."
)


# ---------------------------------------------------------------------------
# Control-status helpers (honest: SATISFIED only when the chain truly evidences it)
# ---------------------------------------------------------------------------


def _signed_log(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    if ev.signed and ev.decisions > 0:
        return ControlStatus.SATISFIED, (
            f"{ev.decisions} authorization decisions ({ev.allow} ALLOW / {ev.deny} DENY) "
            f"recorded as a tamper-evident, Ed25519-signed, timestamped hash chain "
            f"with {ev.checkpoints} signed checkpoint(s); independently verifiable offline."
        )
    if ev.decisions > 0:
        return ControlStatus.PARTIAL, (
            f"{ev.decisions} decisions logged but the chain is UNSIGNED — integrity is "
            "hash-chained but not authenticated. Sign the chain (audit signer) for full evidence."
        )
    return ControlStatus.PARTIAL, "no authorization decisions found in this chain."


def _access_control(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    if ev.decisions > 0:
        return ControlStatus.PARTIAL, (
            f"Capability tokens enforce per-call tool authorization at the gate "
            f"({ev.deny} call(s) denied across {ev.distinct_tools} tool(s), "
            f"{ev.distinct_agents} agent identit(y/ies)). This is the tool-call access-control "
            "layer; identity provisioning, human IAM, and network access are out of scope."
        )
    return ControlStatus.OUT_OF_SCOPE, "no gated tool calls in this chain."


def _monitoring(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    signals = ev.deny + ev.flagged_scans
    if signals > 0 or ev.scans > 0:
        return ControlStatus.SATISFIED, (
            f"{ev.deny} denied call(s) and {ev.flagged_scans} flagged scan(s) of {ev.scans} "
            "recorded as signed anomaly signals — a continuous, attributable detection record "
            "of policy-violating and adversarial activity."
        )
    return (
        ControlStatus.PARTIAL,
        "no denial or scan signals recorded yet (monitoring active, no events).",
    )


def _human_oversight(_ev: ChainEvidence) -> tuple[ControlStatus, str]:
    return ControlStatus.PARTIAL, (
        "The gate is the enforcement point where a human-set authorization policy is applied; "
        "DENY decisions are the structural oversight mechanism. Interactive human-in-the-loop "
        "approval UX is out of scope (pair with an approval workflow)."
    )


def _robustness(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    return ControlStatus.PARTIAL, (
        "Structural prompt-injection resistance on the tool-call surface (a call outside the "
        f"signed capability cannot execute; {ev.deny} blocked here) plus signed-integrity of the "
        "record. Not a full robustness/accuracy regime for model outputs."
    )


def _not_addressed(_ev: ChainEvidence) -> tuple[ControlStatus, str]:
    return ControlStatus.OUT_OF_SCOPE, "raucle does not address this control."


# ---------------------------------------------------------------------------
# Framework control maps (the honest subset raucle evidences)
# ---------------------------------------------------------------------------

_FRAMEWORKS: dict[str, tuple[str, list[Control]]] = {
    "eu-ai-act": (
        "EU AI Act (Regulation 2024/1689) — high-risk AI obligations",
        [
            Control(
                "Art.12",
                "Record-keeping (automatic logging)",
                "High-risk AI systems shall technically allow for the automatic recording of "
                "events (logs) over the system's lifetime.",
                _signed_log,
            ),
            Control(
                "Art.14",
                "Human oversight",
                "High-risk AI systems shall be designed to be effectively overseen by natural "
                "persons.",
                _human_oversight,
            ),
            Control(
                "Art.15",
                "Accuracy, robustness and cybersecurity",
                "High-risk AI systems shall be resilient to attempts to alter their use or "
                "behaviour by exploiting vulnerabilities.",
                _robustness,
            ),
        ],
    ),
    "iso-42001": (
        "ISO/IEC 42001:2023 — AI management system",
        [
            Control(
                "A.6.2.6",
                "AI system operation and monitoring",
                "The organization shall log and monitor the operation of AI systems.",
                _monitoring,
            ),
            Control(
                "A.6.2.8",
                "AI system recording of event logs",
                "The organization shall determine the event logs needed and retain them.",
                _signed_log,
            ),
            Control(
                "A.8.3",
                "Information for interested parties / auditability",
                "The organization shall provide information enabling assessment of the AI system.",
                lambda ev: (
                    (
                        ControlStatus.SATISFIED,
                        "Every decision is independently verifiable offline "
                        "via the signed chain + bundled keys (audit-pack), needing no trust in the "
                        "producing party.",
                    )
                    if ev.signed
                    else (
                        ControlStatus.PARTIAL,
                        "chain is unsigned; bundle a signed chain for independent auditability.",
                    )
                ),
            ),
        ],
    ),
    "soc2": (
        "SOC 2 (AICPA Trust Services Criteria)",
        [
            Control(
                "CC6.1",
                "Logical access controls",
                "The entity implements logical access security measures to protect against "
                "unauthorized access.",
                _access_control,
            ),
            Control(
                "CC7.2",
                "Monitoring for anomalies",
                "The entity monitors system components for anomalies indicative of malicious "
                "acts or errors.",
                _monitoring,
            ),
            Control(
                "CC7.3",
                "Evaluation of security events (evidence)",
                "The entity evaluates security events and maintains evidence of its response.",
                _signed_log,
            ),
        ],
    ),
}


def supported_frameworks() -> list[str]:
    return sorted(_FRAMEWORKS)


def build_report(chain_path: str | Path, *, framework: str) -> ComplianceReport:
    """Map a receipt chain to a framework's controls and produce the evidence report."""
    key = framework.lower()
    if key not in _FRAMEWORKS:
        raise ValueError(
            f"unknown framework {framework!r}; choose from {', '.join(supported_frameworks())}"
        )
    title, controls = _FRAMEWORKS[key]
    ev = extract_evidence(chain_path)
    results: list[ControlResult] = []
    for c in controls:
        status, evidence = c.status_fn(ev)
        results.append(
            ControlResult(
                id=c.id,
                title=c.title,
                requirement=c.requirement,
                status=status,
                evidence=evidence,
            )
        )
    return ComplianceReport(
        framework=key,
        framework_title=title,
        chain_path=str(chain_path),
        chain_signed=ev.signed,
        controls=results,
        evidence=ev,
    )


def render_markdown(report: ComplianceReport) -> str:
    """Render a report as a Markdown evidence map (the artifact for a CISO/auditor)."""
    s = report.summary()
    lines = [
        f"# Compliance evidence map — {report.framework_title}",
        "",
        f"**Source:** `{report.chain_path}` "
        f"({'signed' if report.chain_signed else 'UNSIGNED'} receipt chain)",
        "",
        f"> {_DISCLAIMER}",
        "",
        f"**Summary:** {s['SATISFIED']} satisfied · {s['PARTIAL']} partial · "
        f"{s['OUT_OF_SCOPE']} out of scope.",
        "",
        "| Control | Status | Evidence |",
        "|---|---|---|",
    ]
    for c in report.controls:
        ev = c.evidence.replace("|", "\\|")
        lines.append(f"| **{c.id}** {c.title} | {c.status.value} | {ev} |")
    lines += [
        "",
        "*Generated by `raucle-detect compliance report`. Verify the underlying chain "
        "with `raucle-detect audit verify` (and bundle it with `raucle-detect audit-pack "
        "build` for an offline-verifiable evidence pack).*",
    ]
    return "\n".join(lines)


__all__ = [
    "ControlStatus",
    "ChainEvidence",
    "ComplianceReport",
    "ControlResult",
    "extract_evidence",
    "build_report",
    "render_markdown",
    "supported_frameworks",
]
