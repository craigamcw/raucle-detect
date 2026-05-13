"""Framework-agnostic middleware for integrating raucle-detect into LLM pipelines.

Provides pre/post processing hooks and event callbacks for scanning user
inputs, LLM outputs, and tool calls.

    from raucle_detect.middleware import RaucleMiddleware

    mw = RaucleMiddleware(on_block=lambda r, phase: print(f"Blocked in {phase}"))
    prompt, result = mw.pre_process("Ignore all previous instructions", session_id="s1")
    output, result = mw.post_process("Here is the answer", session_id="s1")
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from raucle_detect.scanner import Scanner, ScanResult
from raucle_detect.session import SessionScanner, SessionScanResult

_DEFAULT_SESSION_TTL = 3600  # seconds — idle sessions older than this are evicted


class RaucleMiddleware:
    """Framework-agnostic middleware for integrating raucle-detect into LLM pipelines.

    Provides pre/post processing hooks and event callbacks.

    Parameters
    ----------
    mode : str
        Detection sensitivity mode.
    rules_dir : str, optional
        Path to custom YAML rules directory.
    on_alert : callable, optional
        Callback fired when a scan produces an ALERT verdict.
        Signature: ``(result, phase) -> None`` where *phase* is
        ``"pre_process"``, ``"post_process"``, or ``"pre_tool_call"``.
    on_block : callable, optional
        Callback fired when a scan produces a BLOCK verdict.
        Same signature as *on_alert*.
    session_enabled : bool
        Whether to track session state across calls.
    window_size : int
        Rolling window size for session tracking.
    session_ttl : int
        Seconds of inactivity after which a session is automatically evicted.
        Defaults to 3600 (1 hour).  Set to 0 to disable TTL eviction.
    """

    def __init__(
        self,
        mode: str = "standard",
        rules_dir: str | None = None,
        on_alert: Callable[[ScanResult | SessionScanResult, str], None] | None = None,
        on_block: Callable[[ScanResult | SessionScanResult, str], None] | None = None,
        session_enabled: bool = True,
        window_size: int = 20,
        session_ttl: int = _DEFAULT_SESSION_TTL,
    ) -> None:
        self.scanner = Scanner(mode=mode, rules_dir=rules_dir)
        self.on_alert = on_alert
        self.on_block = on_block
        self._sessions: dict[str, SessionScanner] = {}
        self._session_last_seen: dict[str, float] = {}
        self._session_enabled = session_enabled
        self._window_size = window_size
        self._mode = mode
        self._session_ttl = session_ttl

    def get_session(self, session_id: str) -> SessionScanner:
        """Get or create a session scanner for the given ID.

        Evicts stale sessions on each access when TTL is enabled.
        """
        self._evict_stale_sessions()
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionScanner(
                scanner=self.scanner,
                window_size=self._window_size,
                mode=self._mode,
            )
        self._session_last_seen[session_id] = time.monotonic()
        return self._sessions[session_id]

    def active_session_count(self) -> int:
        """Return the number of currently tracked sessions."""
        return len(self._sessions)

    def _evict_stale_sessions(self) -> None:
        """Remove sessions that have been idle longer than *session_ttl* seconds."""
        if not self._session_ttl:
            return
        now = time.monotonic()
        stale = [
            sid
            for sid, last in self._session_last_seen.items()
            if now - last > self._session_ttl
        ]
        for sid in stale:
            self._sessions.pop(sid, None)
            self._session_last_seen.pop(sid, None)

    def pre_process(
        self,
        prompt: str,
        session_id: str | None = None,
    ) -> tuple[str, ScanResult | SessionScanResult]:
        """Scan user input before it reaches the LLM.

        Returns the (unchanged) prompt and the scan result.
        Fires on_alert/on_block callbacks as appropriate.
        """
        if self._session_enabled and session_id is not None:
            session = self.get_session(session_id)
            result: ScanResult | SessionScanResult = session.scan_message(prompt, role="user")
            action = result.session_action
        else:
            scan_result = self.scanner.scan(prompt)
            result = scan_result
            action = scan_result.action

        self._fire_callbacks(result, action, "pre_process")
        return prompt, result

    def post_process(
        self,
        output: str,
        original_prompt: str | None = None,
        session_id: str | None = None,
    ) -> tuple[str, ScanResult | SessionScanResult]:
        """Scan LLM output before it's returned to the user.

        Returns the (unchanged) output and the scan result.
        """
        if self._session_enabled and session_id is not None:
            session = self.get_session(session_id)
            result: ScanResult | SessionScanResult = session.scan_message(output, role="assistant")
            action = result.session_action
        else:
            scan_result = self.scanner.scan_output(output, original_prompt=original_prompt)
            result = scan_result
            action = scan_result.action

        self._fire_callbacks(result, action, "post_process")
        return output, result

    def pre_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[bool, ScanResult]:
        """Scan tool call before execution.

        Returns ``(allowed, result)`` where *allowed* is ``False`` when the
        scan produces a BLOCK action.
        """
        result = self.scanner.scan_tool_call(tool_name, arguments)

        # If session tracking, also record in session
        if self._session_enabled and session_id is not None:
            session = self.get_session(session_id)
            # Serialize args for session tracking
            arg_text = " ".join(f"{k}={v}" for k, v in arguments.items())
            session.scan_message(
                arg_text,
                role="user",
                tool_name=tool_name,
                tool_args=arguments,
            )

        self._fire_callbacks(result, result.action, "pre_tool_call")
        allowed = result.action != "BLOCK"
        return allowed, result

    def drop_session(self, session_id: str) -> None:
        """Remove a session from tracking."""
        self._sessions.pop(session_id, None)
        self._session_last_seen.pop(session_id, None)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fire_callbacks(
        self,
        result: ScanResult | SessionScanResult,
        action: str,
        phase: str,
    ) -> None:
        """Fire on_alert or on_block callbacks based on the action."""
        if action == "BLOCK" and self.on_block is not None:
            self.on_block(result, phase)
        elif action == "ALERT" and self.on_alert is not None:
            self.on_alert(result, phase)
