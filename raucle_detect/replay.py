"""Counterfactual replay — re-run any provenance chain with a different policy.

Given a chain produced by :mod:`raucle_detect.provenance` and an input store
mapping ``input_hash`` to the original prompt text, this module re-runs every
``guardrail_scan`` receipt against an alternate :class:`Scanner` configuration
and reports the diff in verdicts.

The killer SOC question this answers: *"If we'd had this stricter rule on
last Tuesday, would we have caught the incident?"* Today the answer is "we'll
check the logs and guess." With a replay you get a cryptographically-anchored
yes/no.

Architecture
------------

Three primitives:

- :class:`InputStore` — JSONL of ``{"hash": ..., "text": ..., ...}`` records
  with verified integrity on lookup. Keep this alongside (not inside) the
  provenance chain so receipts stay privacy-by-default.
- :class:`Replayer` — given a :class:`~raucle_detect.scanner.Scanner` and an
  :class:`InputStore`, walks a chain JSONL and produces a :class:`ReplayResult`.
- :class:`ReplayResult` — typed diff: new BLOCKs, new ALLOWs, missing inputs,
  unchanged scans.

The CLI surfaces this as ``raucle-detect provenance replay``.

Usage
-----

::

    from raucle_detect.replay import InputStore, Replayer
    from raucle_detect.scanner import Scanner

    store = InputStore.open("audit/inputs.jsonl")
    scanner = Scanner(mode="strict")   # the counterfactual policy
    replayer = Replayer(scanner, store)
    result = replayer.replay_chain("audit/chain.jsonl")
    print(result.summary())
    for change in result.newly_blocked:
        print(f"{change.receipt_hash[:18]}… would now BLOCK ({change.explanation})")
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from raucle_detect.scanner import Scanner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input store — hash-verified JSONL companion to the provenance chain
# ---------------------------------------------------------------------------


def _hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StoredInput:
    """One record in the input store."""

    hash: str
    text: str
    tenant: str | None = None
    created_at: int = 0
    metadata: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "hash": self.hash,
            "text": self.text,
            "created_at": self.created_at,
        }
        if self.tenant is not None:
            out["tenant"] = self.tenant
        if self.metadata:
            out["metadata"] = self.metadata
        return out


class InputStore:
    """JSONL-backed, append-only store mapping ``input_hash`` to original text.

    Keep this file *alongside* the provenance chain. Receipts continue to
    carry only hashes — privacy-by-default. The replay layer reads from the
    store only when it needs to actually re-run the scanner.

    The store verifies hash consistency on every lookup so a tampered
    ``text`` value is detected as a missing entry rather than silently
    returning the wrong prompt.

    Concurrency: callers serialise access; the file is opened in append
    mode so multiple writers won't interleave at byte level but won't
    coordinate across processes either. Use one writer per process and
    let the OS append-write guarantee handle the rest.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        file: IO[str] | None = None,
    ) -> None:
        if (path is None) == (file is None):
            raise ValueError("exactly one of path or file must be provided")
        self._records: dict[str, StoredInput] = {}
        if path is not None:
            self._path = Path(path)
            if self._path.exists():
                self._load_existing(self._path)
            self._file = open(self._path, "a", encoding="utf-8")  # noqa: SIM115
            self._owns_file = True
        else:
            self._path = None
            self._file = file
            self._owns_file = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def open(cls, path: str | Path) -> InputStore:
        """Open or create a JSONL input store at *path*."""
        return cls(path=path)

    def close(self) -> None:
        if self._owns_file:
            self._file.close()

    def __enter__(self) -> InputStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(
        self,
        text: str,
        tenant: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Add *text* to the store. Idempotent: existing hash returns its hash."""
        h = _hash_text(text)
        if h in self._records:
            return h
        record = StoredInput(
            hash=h,
            text=text,
            tenant=tenant,
            created_at=int(dt.datetime.now(dt.timezone.utc).timestamp()),
            metadata=metadata or {},
        )
        self._records[h] = record
        self._file.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
        self._file.flush()
        return h

    def get(self, input_hash: str) -> StoredInput | None:
        """Return the stored input, or None if absent or tampered."""
        record = self._records.get(input_hash)
        if record is None:
            return None
        recomputed = _hash_text(record.text)
        if recomputed != record.hash:
            logger.warning(
                "InputStore: stored hash %s does not match recomputed %s — "
                "record will be treated as missing",
                record.hash,
                recomputed,
            )
            return None
        return record

    def __contains__(self, input_hash: str) -> bool:
        return self.get(input_hash) is not None

    def __len__(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_existing(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    record = StoredInput(
                        hash=obj["hash"],
                        text=obj["text"],
                        tenant=obj.get("tenant"),
                        created_at=obj.get("created_at", 0),
                        metadata=obj.get("metadata", {}),
                    )
                except (json.JSONDecodeError, KeyError) as exc:
                    logger.warning(
                        "InputStore: skipping malformed record at %s:%d (%s)",
                        path,
                        line_no,
                        exc,
                    )
                    continue
                self._records[record.hash] = record


# ---------------------------------------------------------------------------
# Replay result types
# ---------------------------------------------------------------------------


@dataclass
class ReplayChange:
    """One receipt whose verdict differs between the original and replayed run."""

    receipt_hash: str
    """The original receipt's hash."""

    operation: str
    """The operation type — typically ``guardrail_scan``."""

    input_hash: str
    """Hash of the input that was scanned."""

    original_verdict: str
    """``CLEAN`` / ``SUSPICIOUS`` / ``MALICIOUS`` as recorded in the original receipt."""

    counterfactual_verdict: str
    """What the alternate scanner would have emitted."""

    original_action: str
    """``ALLOW`` / ``ALERT`` / ``BLOCK`` derived from the original verdict."""

    counterfactual_action: str
    """Action derived from the counterfactual verdict."""

    explanation: str
    """Human-readable summary — matched rule, category, or 'unchanged'."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_hash": self.receipt_hash,
            "operation": self.operation,
            "input_hash": self.input_hash,
            "original_verdict": self.original_verdict,
            "counterfactual_verdict": self.counterfactual_verdict,
            "original_action": self.original_action,
            "counterfactual_action": self.counterfactual_action,
            "explanation": self.explanation,
        }


@dataclass
class ReplayResult:
    """Aggregate output of a counterfactual replay."""

    chain_path: str
    counterfactual_policy: str
    """Free-form label for the policy under test (e.g. ``"strict mode + extra-rules.yaml"``)."""

    total_receipts: int = 0
    """Total receipts in the chain."""

    replayed_receipts: int = 0
    """Guardrail-scan receipts where the input was found in the store and re-run."""

    missing_inputs: list[str] = field(default_factory=list)
    """Hashes of receipts whose inputs were absent from the store."""

    unchanged: list[ReplayChange] = field(default_factory=list)
    """Receipts whose verdict was identical under both policies."""

    changes: list[ReplayChange] = field(default_factory=list)
    """Receipts whose verdict differed."""

    # ------------------------------------------------------------------
    # Convenience views
    # ------------------------------------------------------------------

    @property
    def newly_blocked(self) -> list[ReplayChange]:
        """Receipts that were CLEAN/SUSPICIOUS originally but would be BLOCKed now."""
        return [
            c
            for c in self.changes
            if c.counterfactual_action == "BLOCK" and c.original_action != "BLOCK"
        ]

    @property
    def newly_allowed(self) -> list[ReplayChange]:
        """Receipts that were BLOCKED/ALERTed originally but would be ALLOWed now."""
        return [
            c
            for c in self.changes
            if c.counterfactual_action == "ALLOW" and c.original_action != "ALLOW"
        ]

    @property
    def newly_alerted(self) -> list[ReplayChange]:
        """Receipts that flipped to ALERT (from either ALLOW or BLOCK)."""
        return [
            c
            for c in self.changes
            if c.counterfactual_action == "ALERT" and c.original_action != "ALERT"
        ]

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, int]:
        """Compact stats for printing or programmatic consumption."""
        return {
            "total_receipts": self.total_receipts,
            "replayed": self.replayed_receipts,
            "missing_inputs": len(self.missing_inputs),
            "unchanged": len(self.unchanged),
            "changed": len(self.changes),
            "newly_blocked": len(self.newly_blocked),
            "newly_allowed": len(self.newly_allowed),
            "newly_alerted": len(self.newly_alerted),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_path": self.chain_path,
            "counterfactual_policy": self.counterfactual_policy,
            "summary": self.summary(),
            "missing_inputs": list(self.missing_inputs),
            "changes": [c.to_dict() for c in self.changes],
            "unchanged_count": len(self.unchanged),
        }


# ---------------------------------------------------------------------------
# Replayer
# ---------------------------------------------------------------------------


_VERDICT_TO_ACTION = {
    "CLEAN": "ALLOW",
    "SUSPICIOUS": "ALERT",
    "MALICIOUS": "BLOCK",
}


class Replayer:
    """Re-run a provenance chain against an alternate :class:`Scanner` policy."""

    def __init__(
        self,
        scanner: Scanner,
        input_store: InputStore,
        *,
        policy_label: str = "",
    ) -> None:
        self._scanner = scanner
        self._store = input_store
        self._policy_label = policy_label or f"mode={scanner.mode}"

    def replay_chain(self, chain_path: str | Path) -> ReplayResult:
        """Walk every receipt in *chain_path* and produce a :class:`ReplayResult`."""
        result = ReplayResult(
            chain_path=str(chain_path),
            counterfactual_policy=self._policy_label,
            total_receipts=0,
        )

        with open(chain_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                result.total_receipts += 1
                self._process_receipt(raw, result)

        return result

    def _process_receipt(self, raw: dict[str, Any], result: ReplayResult) -> None:
        # Only `guardrail_scan` receipts are replayable. Every other operation
        # describes an event (a model call, a tool call) whose outcome is not a
        # function of the scanner — replaying them would be meaningless.
        if raw.get("operation") != "guardrail_scan":
            return

        input_hash = raw.get("input_hash", "")
        receipt_hash = raw.get("receipt_hash", "")
        original_verdict = raw.get("guardrail_verdict", "")
        if not input_hash or not original_verdict:
            return

        stored = self._store.get(input_hash)
        if stored is None:
            result.missing_inputs.append(receipt_hash)
            return

        counterfactual = self._scanner.scan(stored.text)
        result.replayed_receipts += 1

        original_action = _VERDICT_TO_ACTION.get(original_verdict, "ALLOW")
        change = ReplayChange(
            receipt_hash=receipt_hash,
            operation="guardrail_scan",
            input_hash=input_hash,
            original_verdict=original_verdict,
            counterfactual_verdict=counterfactual.verdict,
            original_action=original_action,
            counterfactual_action=counterfactual.action,
            explanation=self._explain(counterfactual),
        )

        if original_verdict == counterfactual.verdict:
            result.unchanged.append(change)
        else:
            result.changes.append(change)

    @staticmethod
    def _explain(scan_result: Any) -> str:
        """Build a one-line rationale from a ScanResult."""
        parts: list[str] = []
        if scan_result.attack_technique:
            parts.append(f"technique={scan_result.attack_technique}")
        if scan_result.matched_rules:
            parts.append("rules=" + ",".join(scan_result.matched_rules[:3]))
            if len(scan_result.matched_rules) > 3:
                parts.append(f"+{len(scan_result.matched_rules) - 3} more")
        parts.append(f"confidence={scan_result.confidence:.2f}")
        return " ".join(parts) if parts else "no signal"
