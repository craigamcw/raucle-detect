"""Core Scanner -- the main developer-facing API for Raucle Detect.

Usage::

    from raucle_detect import Scanner

    scanner = Scanner()
    result = scanner.scan("Ignore all previous instructions")
    if result.injection_detected:
        print(f"Blocked: {result.verdict} ({result.confidence:.0%})")

The scanner combines a fast regex pattern layer with a heuristic (or optional
ML) semantic classifier, producing a single :class:`ScanResult` per prompt.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle_detect.classifier import HeuristicClassifier, MLClassifier
from raucle_detect.patterns import PatternLayer
from raucle_detect.rules import load_rules_dir, load_yaml_file

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input size limits
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 1_048_576  # 1 MB
MAX_INPUT_LENGTH = 100_000   # characters

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Immutable result of scanning a single prompt."""

    verdict: str
    """One of ``CLEAN``, ``SUSPICIOUS``, or ``MALICIOUS``."""

    confidence: float
    """Combined score from all layers, between 0.0 and 1.0."""

    injection_detected: bool
    """``True`` when the combined score meets the detection threshold."""

    categories: list[str] = field(default_factory=list)
    """Threat categories that matched (e.g. ``direct_injection``, ``jailbreak``)."""

    attack_technique: str = ""
    """Most specific attack technique identified."""

    layer_scores: dict[str, float] = field(default_factory=dict)
    """Per-layer breakdown: ``pattern``, ``semantic``."""

    matched_rules: list[str] = field(default_factory=list)
    """IDs of pattern rules that fired."""

    action: str = "ALLOW"
    """Recommended action: ``ALLOW``, ``ALERT``, or ``BLOCK``."""

    notes: list[str] = field(default_factory=list)
    """Informational notes (e.g. input was truncated)."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary (JSON-friendly)."""
        d: dict[str, Any] = {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "injection_detected": self.injection_detected,
            "categories": self.categories,
            "attack_technique": self.attack_technique,
            "layer_scores": self.layer_scores,
            "matched_rules": self.matched_rules,
            "action": self.action,
        }
        if self.notes:
            d["notes"] = self.notes
        return d


# ---------------------------------------------------------------------------
# Mode thresholds
# ---------------------------------------------------------------------------

_MODE_THRESHOLDS: dict[str, dict[str, float]] = {
    "strict": {"block": 0.4, "alert": 0.2},
    "standard": {"block": 0.7, "alert": 0.4},
    "permissive": {"block": 0.85, "alert": 0.6},
}

# Layer weights: pattern 30 %, semantic 70 %
_PATTERN_WEIGHT = 0.35
_SEMANTIC_WEIGHT = 0.65


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """High-level prompt-injection scanner.

    Parameters
    ----------
    mode : str
        Detection sensitivity -- ``"strict"``, ``"standard"`` (default), or
        ``"permissive"``.
    rules_dir : str | Path | None
        Path to a directory of YAML rule files.  If ``None`` (default), only
        built-in patterns are used.
    use_ml : bool
        When ``True``, attempt to load a local transformer model for the
        semantic layer.  Defaults to ``False`` (heuristic classifier).
    model_path : str | None
        Path to the directory containing the ``semantic-classifier/`` model
        checkpoint.  Only relevant when *use_ml* is ``True``.
    """

    def __init__(
        self,
        mode: str = "standard",
        rules_dir: str | Path | None = None,
        use_ml: bool = False,
        model_path: str | None = None,
    ) -> None:
        if mode not in _MODE_THRESHOLDS:
            raise ValueError(f"Unknown mode {mode!r}. Choose from: strict, standard, permissive")

        self._mode = mode
        self._thresholds = _MODE_THRESHOLDS[mode]

        # Pattern layer
        self._pattern_layer = PatternLayer()
        self._pattern_layer.load_builtin()

        # Load custom rules
        if rules_dir is not None:
            extra = load_rules_dir(rules_dir)
            if extra:
                self._pattern_layer.add_rules(extra)

        # Semantic layer
        self._heuristic = HeuristicClassifier()
        self._ml: MLClassifier | None = None
        if use_ml:
            ml = MLClassifier()
            if ml.load(model_path):
                self._ml = ml

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self._mode

    def load_rules(self, path: str | Path) -> int:
        """Load additional rules from a YAML file or directory.

        Returns the number of rules added.
        """
        path = Path(path)
        if path.is_dir():
            rules = load_rules_dir(path)
        elif path.is_file():
            rules = load_yaml_file(path)
        else:
            return 0
        if rules:
            self._pattern_layer.add_rules(rules)
        return len(rules)

    def list_rules(self) -> list[dict[str, Any]]:
        """Return a summary of all loaded rules."""
        return self._pattern_layer.list_rules()

    def scan(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
        mode: str | None = None,
    ) -> ScanResult:
        """Scan a single prompt and return a :class:`ScanResult`.

        Parameters
        ----------
        prompt : str
            The text to scan.
        context : dict, optional
            Unused in the open-source edition but reserved for future
            contextual scoring (user role, data classification, etc.).
        mode : str, optional
            Override the scanner-level mode for this single call.
        """
        thresholds = _MODE_THRESHOLDS.get(mode, self._thresholds) if mode else self._thresholds

        # Input size guard
        notes: list[str] = []
        if len(prompt) > MAX_INPUT_LENGTH:
            logger.warning(
                "Input truncated from %d to %d characters", len(prompt), MAX_INPUT_LENGTH
            )
            prompt = prompt[:MAX_INPUT_LENGTH]
            notes.append(
                f"Input was truncated to {MAX_INPUT_LENGTH:,} characters. "
                "Detection covers the truncated text only."
            )

        # Layer 1: Pattern matching
        pat = self._pattern_layer.scan(prompt)

        # Layer 2: Semantic classification
        if self._ml is not None:
            sem = self._ml.classify(prompt)
        else:
            sem = self._heuristic.classify(prompt)

        # Combine scores
        combined = pat["score"] * _PATTERN_WEIGHT + sem["score"] * _SEMANTIC_WEIGHT

        # Merge categories
        categories = list(set(pat.get("categories", []) + sem.get("categories", [])))

        # Pick most specific technique
        technique = pat.get("technique", "") or sem.get("technique", "")

        # Determine verdict
        if combined >= thresholds["block"]:
            verdict = "MALICIOUS"
            action = "BLOCK"
        elif combined >= thresholds["alert"]:
            verdict = "SUSPICIOUS"
            action = "ALERT"
        else:
            verdict = "CLEAN"
            action = "ALLOW"

        return ScanResult(
            verdict=verdict,
            confidence=round(combined, 4),
            injection_detected=combined >= thresholds["alert"],
            categories=categories,
            attack_technique=technique,
            layer_scores={
                "pattern": round(pat["score"], 4),
                "semantic": round(sem["score"], 4),
            },
            matched_rules=pat.get("matched_rules", []),
            action=action,
            notes=notes,
        )

    def scan_batch(
        self,
        prompts: list[str],
        workers: int = 4,
        mode: str | None = None,
    ) -> list[ScanResult]:
        """Scan multiple prompts concurrently.

        Parameters
        ----------
        prompts : list[str]
            Prompts to scan.
        workers : int
            Maximum number of threads.
        mode : str, optional
            Override the scanner-level mode for this batch.

        Returns
        -------
        list[ScanResult]
            Results in the same order as the input prompts.
        """
        max_workers = max(1, min(workers, os.cpu_count() or 4))
        if max_workers != workers:
            logger.warning(
                "Worker count adjusted from %d to %d (clamped to CPU count)", workers, max_workers
            )

        results: list[ScanResult | None] = [None] * len(prompts)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_idx = {
                pool.submit(self.scan, p, mode=mode): i for i, p in enumerate(prompts)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                results[idx] = future.result()
        return results  # type: ignore[return-value]
