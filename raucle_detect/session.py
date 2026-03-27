"""Session-aware scanning for multi-turn attack detection.

Tracks conversation state across turns to detect escalation patterns,
accumulated risk, and multi-turn injection attempts that look benign
individually.

    from raucle_detect import Scanner
    from raucle_detect.session import SessionScanner

    session = SessionScanner()
    result = session.scan_message("Hello", role="user")
    print(result.session_risk)       # 0.0
    print(result.session_action)     # "ALLOW"
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from raucle_detect.scanner import Scanner, ScanResult


@dataclass
class SessionScanResult:
    """Result of a session-aware scan."""

    message_result: ScanResult
    """Individual message scan result."""

    session_risk: float
    """Cumulative session risk score, 0.0 -- 1.0."""

    escalation_detected: bool
    """True if scores are trending upward across recent turns."""

    turn_number: int
    """1-based turn index within this session."""

    risk_trend: str
    """One of ``stable``, ``rising``, or ``declining``."""

    session_action: str
    """Recommended session-level action: ``ALLOW``, ``ALERT``, or ``BLOCK``."""

    notes: list[str] = field(default_factory=list)
    """Informational notes about session-level observations."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary (JSON-friendly)."""
        return {
            "message_result": self.message_result.to_dict(),
            "session_risk": self.session_risk,
            "escalation_detected": self.escalation_detected,
            "turn_number": self.turn_number,
            "risk_trend": self.risk_trend,
            "session_action": self.session_action,
            "notes": self.notes,
        }


class SessionScanner:
    """Tracks conversation state for multi-turn attack detection.

    Maintains a rolling window of scan results to detect:
    - Escalation patterns (scores trending upward)
    - Accumulated risk across turns
    - Multi-turn injection attempts that look benign individually

    Parameters
    ----------
    scanner : Scanner, optional
        An existing scanner instance.  If ``None``, a new one is created.
    window_size : int
        Maximum number of turns to keep in the rolling window.
    escalation_threshold : float
        Minimum increase between recent and previous average scores to
        flag escalation.
    cumulative_threshold : float
        Session risk level that triggers a BLOCK action.
    mode : str
        Detection mode passed to the scanner if one is created internally.
    rules_dir : str, optional
        Rules directory passed to the scanner if one is created internally.
    """

    def __init__(
        self,
        scanner: Scanner | None = None,
        window_size: int = 20,
        escalation_threshold: float = 0.15,
        cumulative_threshold: float = 0.6,
        mode: str = "standard",
        rules_dir: str | None = None,
    ) -> None:
        self._scanner = scanner or Scanner(mode=mode, rules_dir=rules_dir)
        self._window_size = window_size
        self._escalation_threshold = escalation_threshold
        self._cumulative_threshold = cumulative_threshold
        self._history: deque[ScanResult] = deque(maxlen=window_size)
        self._turn: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_message(
        self,
        message: str,
        role: str = "user",
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
    ) -> SessionScanResult:
        """Scan a message within session context.

        Parameters
        ----------
        message : str
            The message text.
        role : str
            One of ``user``, ``assistant``, or ``tool_result``.
        tool_name : str, optional
            If provided, also run a tool-call scan.
        tool_args : dict, optional
            Arguments for the tool call scan.
        """
        self._turn += 1

        # Pick the right scan method based on role
        if role == "assistant":
            result = self._scanner.scan_output(message)
        else:
            result = self._scanner.scan(message)

        # If tool info is provided, also scan the tool call and merge
        if tool_name is not None and tool_args is not None:
            tool_result = self._scanner.scan_tool_call(tool_name, tool_args)
            # Take the worse of the two results
            if tool_result.confidence > result.confidence:
                result = tool_result

        self._history.append(result)

        # Calculate session-level metrics
        session_risk = self._calculate_session_risk()
        escalation_detected = self._detect_escalation()
        risk_trend = self._calculate_trend()

        # Determine session action
        notes: list[str] = []
        if session_risk > self._cumulative_threshold:
            session_action = "BLOCK"
            notes.append(
                f"Session risk ({session_risk:.2f}) exceeds "
                f"cumulative threshold ({self._cumulative_threshold:.2f})."
            )
        elif escalation_detected or session_risk > self._cumulative_threshold * 0.6:
            session_action = "ALERT"
            if escalation_detected:
                notes.append("Escalation detected: recent scores trending upward.")
            if session_risk > self._cumulative_threshold * 0.6:
                notes.append(
                    f"Session risk ({session_risk:.2f}) approaching "
                    f"cumulative threshold ({self._cumulative_threshold:.2f})."
                )
        else:
            session_action = "ALLOW"

        return SessionScanResult(
            message_result=result,
            session_risk=round(session_risk, 4),
            escalation_detected=escalation_detected,
            turn_number=self._turn,
            risk_trend=risk_trend,
            session_action=session_action,
            notes=notes,
        )

    def get_session_risk(self) -> dict[str, Any]:
        """Return current session risk assessment."""
        return {
            "session_risk": round(self._calculate_session_risk(), 4),
            "escalation_detected": self._detect_escalation(),
            "risk_trend": self._calculate_trend(),
            "turn_count": self._turn,
            "window_size": len(self._history),
        }

    def reset(self) -> None:
        """Clear session history."""
        self._history.clear()
        self._turn = 0

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _calculate_session_risk(self) -> float:
        """Calculate session risk with exponential decay weighting."""
        if not self._history:
            return 0.0

        scores = [r.confidence for r in self._history]
        n = len(scores)

        # Exponential decay: recent turns weighted more heavily
        decay = 0.85
        weighted_sum = 0.0
        weight_total = 0.0
        for i, score in enumerate(scores):
            w = math.pow(decay, n - 1 - i)
            weighted_sum += score * w
            weight_total += w

        risk = weighted_sum / weight_total if weight_total > 0 else 0.0

        # Boost if any single message was MALICIOUS
        if any(r.verdict == "MALICIOUS" for r in self._history):
            risk = min(1.0, risk + 0.3)

        return min(1.0, risk)

    def _detect_escalation(self) -> bool:
        """Check if recent scores are trending upward."""
        if len(self._history) < 6:
            return False

        scores = [r.confidence for r in self._history]
        recent_3 = scores[-3:]
        previous_3 = scores[-6:-3]

        avg_recent = sum(recent_3) / len(recent_3)
        avg_previous = sum(previous_3) / len(previous_3)

        return (avg_recent - avg_previous) > self._escalation_threshold

    def _calculate_trend(self) -> str:
        """Determine the risk trend based on recent vs overall average."""
        if len(self._history) < 3:
            return "stable"

        scores = [r.confidence for r in self._history]
        overall_avg = sum(scores) / len(scores)
        last_3_avg = sum(scores[-3:]) / 3

        if last_3_avg > overall_avg + 0.05:
            return "rising"
        elif last_3_avg < overall_avg - 0.05:
            return "declining"
        return "stable"
