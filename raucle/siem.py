"""SIEM-friendly event export — ECS-normalised JSON Lines + tee sink.

raucle's signed hash-chain (``HashChainSink``) is the *evidence* log: append-only,
Ed25519-checkpointed, offline-verifiable. SIEMs, however, want flat, normalised,
greppable events. This module bridges the two without weakening either:

- :func:`to_ecs` maps a raucle audit event (gate decision, scan verdict, …) to an
  `Elastic Common Schema <https://www.elastic.co/guide/en/ecs/current/index.html>`_-style
  document that Splunk / Microsoft Sentinel / Elastic / QRadar ingest natively
  from a file or syslog input. The original event is carried verbatim under the
  ``raucle.*`` namespace so no information is lost in mapping.
- :class:`SIEMSink` is a drop-in ``audit_sink`` (same ``append(event)`` contract)
  that writes one ECS JSON line per event — and can **tee** into an inner
  ``HashChainSink``, so one ``append`` feeds both the operational SIEM stream
  and the tamper-evident signed chain::

      from raucle.audit import Ed25519Signer, HashChainSink
      from raucle.siem import SIEMSink

      sink = SIEMSink(
          "raucle-siem.jsonl",                       # SIEM picks this up
          inner=HashChainSink("receipts.jsonl",       # signed evidence chain
                              signer=Ed25519Signer.generate()),
      )
      scanner = Scanner(audit_sink=sink)             # or RaucleCallbackHandler(sink=sink)

  Point a Splunk universal forwarder / Sentinel AMA / Filebeat at
  ``raucle-siem.jsonl`` and every gate decision and scan verdict streams in as
  structured JSON. Optionally mirror to syslog (RFC 5424 over UDP/TCP) with
  ``syslog_address=("siem.example", 514)``.

The SIEM file is an *operational copy*: convenient, but not tamper-evident on
its own. For disputes, verify the inner signed chain — that is the artefact a
third party can check offline.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import socket
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Schema tag stamped on every exported document.
ECS_VERSION = "8.11"


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def to_ecs(event: dict[str, Any]) -> dict[str, Any]:
    """Map one raucle audit event to an ECS-style document.

    Handles the two event families raucle emits today — capability gate
    decisions (``decision`` field) and scanner verdicts (``verdict`` field) —
    and degrades gracefully for anything else (generic ``raucle.event``).
    The source event is preserved verbatim under ``raucle``.
    """
    doc: dict[str, Any] = {
        "@timestamp": str(event.get("timestamp") or _utc_now_iso()),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "module": "raucle",
            "kind": "event",
            "provider": "raucle",
        },
        "raucle": event,
    }

    if "decision" in event:  # capability gate receipt
        allowed = event.get("decision") == "ALLOW"
        doc["event"].update(
            {
                "category": ["iam"],
                "type": ["allowed" if allowed else "denied"],
                "action": "capability-gate-decision",
                "outcome": "success" if allowed else "failure",
                "reason": event.get("decision_reason") or event.get("reason") or "",
            }
        )
        doc["user"] = {"id": event.get("agent_id", "")}
        doc["rule"] = {
            "name": event.get("tool", ""),
            "id": (event.get("attenuation_chain") or [""])[-1],
        }
    elif "verdict" in event:  # scanner verdict
        verdict = event.get("verdict", "")
        doc["event"].update(
            {
                "category": ["intrusion_detection"],
                "type": ["info" if verdict == "CLEAN" else "indicator"],
                "action": event.get("kind", "scan"),
                "outcome": "success" if verdict == "CLEAN" else "failure",
                "severity": {"CLEAN": 1, "SUSPICIOUS": 5, "MALICIOUS": 9}.get(verdict, 3),
            }
        )
        doc["rule"] = {
            "name": ",".join(event.get("matched_rules") or []),
            "ruleset": event.get("ruleset_hash", ""),
        }
    else:
        doc["event"]["action"] = str(event.get("kind", "raucle.event"))

    return doc


class SIEMSink:
    """Tee audit events to an ECS JSON-lines file (and optionally syslog).

    Implements the same ``append(event)`` contract as ``HashChainSink`` /
    ``NullSink``, so it slots in anywhere an ``audit_sink`` is accepted.

    Parameters
    ----------
    path : str | Path | None
        File to append ECS JSON lines to (one event per line, flushed per
        line so a tailing forwarder sees events immediately). ``None`` to
        skip file output (syslog only).
    inner : Any | None
        Optional wrapped sink (typically a ``HashChainSink``). Events are
        forwarded **first** — the signed evidence chain is authoritative, so
        its failure modes (and ``require_receipts``-style fail-loud wrappers)
        must see the event even if SIEM export breaks.
    syslog_address : tuple[str, int] | None
        Optional ``(host, port)`` to also emit each document as an RFC 5424
        syslog datagram (UDP).
    """

    def __init__(
        self,
        path: str | Path | None,
        *,
        inner: Any | None = None,
        syslog_address: tuple[str, int] | None = None,
    ) -> None:
        if path is None and syslog_address is None:
            raise ValueError("SIEMSink needs a file path, a syslog address, or both")
        self._inner = inner
        self._lock = threading.Lock()
        # Long-lived append handle for the sink's lifetime (closed in close());
        # a context manager per append would defeat per-line flushing.
        self._fh = (
            open(path, "a", encoding="utf-8") if path is not None else None  # noqa: SIM115
        )
        self._syslog_address = syslog_address
        self._sock = (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if syslog_address is not None else None
        )
        self._hostname = socket.gethostname()

    def append(self, event: dict[str, Any]) -> None:
        # Evidence chain first: it is the authoritative record and its
        # exceptions must propagate to fail-loud callers untouched.
        if self._inner is not None:
            self._inner.append(event)

        try:
            doc = to_ecs(event)
            line = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
            with self._lock:
                if self._fh is not None:
                    self._fh.write(line + "\n")
                    self._fh.flush()
                if self._sock is not None and self._syslog_address is not None:
                    # RFC 5424: <PRI>1 TIMESTAMP HOST APP - - - MSG  (PRI 134 = local0.info)
                    msg = f"<134>1 {doc['@timestamp']} {self._hostname} raucle - - - {line}"
                    self._sock.sendto(msg.encode("utf-8"), self._syslog_address)
        except Exception:
            # SIEM export is the operational copy; never let it take down the
            # gate or scan path that already recorded to the signed chain.
            logger.exception("SIEM export failed (signed chain unaffected)")

    def close(self) -> None:
        if self._inner is not None and hasattr(self._inner, "close"):
            self._inner.close()
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
            if self._sock is not None:
                self._sock.close()
                self._sock = None
