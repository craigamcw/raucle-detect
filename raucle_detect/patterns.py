"""Pattern matching layer -- fast regex-based detection of known injection techniques.

This module provides the first line of defence, scanning prompts against a library
of compiled regular expressions that match known attack signatures. Target latency
is under 1 ms for a typical prompt.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ReDoS protection constants
# ---------------------------------------------------------------------------

MAX_INPUT_LENGTH = 100_000  # characters -- inputs longer than this are truncated

# Patterns that can cause exponential backtracking on long inputs.
# These get a tighter per-pattern input length limit.
_REDOS_RISKY_PATTERNS: set[str] = {
    r"(.)\1{50,}",
    r"(\b\w+\b)\s+\1(\s+\1){10,}",
}

_REDOS_PATTERN_MAX_LENGTH = 10_000

# ---------------------------------------------------------------------------
# Built-in pattern library
# ---------------------------------------------------------------------------
# Each rule has an id, human-readable name, threat category, MITRE-like
# technique label, severity, a list of regex strings, and a base score
# (0.0-1.0) indicating how confident a single match makes us.
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: list[dict[str, Any]] = [
    # -- Direct injection: instruction override --------------------------------
    {
        "id": "PI-001",
        "name": "instruction_override",
        "category": "direct_injection",
        "technique": "instruction_override",
        "severity": "HIGH",
        "patterns": [
            r"(?i)ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)",
            r"(?i)disregard\s+(all\s+)?prior\s+(instructions|context|rules)",
            r"(?i)forget\s+(all\s+)?(your|previous)\s+(instructions|rules|training)",
            r"(?i)override\s+(your\s+)?(system|previous)\s+(prompt|instructions|rules)",
            r"(?i)you\s+are\s+now\s+(a|an)\s+",
            r"(?i)new\s+instructions?:\s+",
            r"(?i)system\s*:\s*you\s+are",
        ],
        "score": 0.85,
    },
    # -- Direct injection: role hijacking --------------------------------------
    {
        "id": "PI-002",
        "name": "role_hijacking",
        "category": "direct_injection",
        "technique": "role_hijacking",
        "severity": "HIGH",
        "patterns": [
            r"(?i)pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+",
            r"(?i)act\s+as\s+(if\s+you\s+are\s+)?(a|an)\s+",
            r"(?i)roleplay\s+as\s+",
            r"(?i)you\s+are\s+DAN",
            r"(?i)jailbreak\s+mode",
            r"(?i)developer\s+mode\s+(enabled|activated|on)",
            r"(?i)enable\s+(unrestricted|unlimited|god)\s+mode",
        ],
        "score": 0.75,
    },
    # -- Jailbreak: DAN and variants -------------------------------------------
    {
        "id": "PI-003",
        "name": "dan_jailbreak",
        "category": "jailbreak",
        "technique": "dan_jailbreak",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)\bDAN\b.*\bdo\s+anything\s+now\b",
            r"(?i)from\s+now\s+on.*two\s+responses",
            r"(?i)simulate\s+.*\bunfiltered\b",
            r"(?i)maximum\s+mode",
            r"(?i)opposite\s+mode",
            r"(?i)anti-?ai\s+mode",
            r"(?i)DUDE\s+mode",
            r"(?i)AIM\s+mode",
        ],
        "score": 0.90,
    },
    # -- Data exfiltration -----------------------------------------------------
    {
        "id": "PI-004",
        "name": "data_exfiltration",
        "category": "data_exfiltration",
        "technique": "data_exfiltration",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)output\s+(all|the|your)\s+system\s+prompt",
            r"(?i)reveal\s+(your|the)\s+(system|initial)\s+(prompt|instructions)",
            r"(?i)print\s+(your|the)\s+instructions",
            r"(?i)show\s+me\s+(your|the)\s+(hidden|secret)\s+(instructions|prompt|rules)",
            r"(?i)what\s+(are|were)\s+your\s+(original|initial|system)\s+(instructions|prompt)",
            r"(?i)repeat\s+(everything|all)\s+(above|before)\s+this",
            r"(?i)display\s+(the\s+)?(full|complete|entire)\s+(system\s+)?prompt",
        ],
        "score": 0.80,
    },
    # -- Indirect injection: context manipulation ------------------------------
    {
        "id": "PI-005",
        "name": "context_stuffing",
        "category": "indirect_injection",
        "technique": "context_stuffing",
        "severity": "HIGH",
        "patterns": [
            r"(?i)<\|im_start\|>system",
            r"(?i)\[INST\].*\[/INST\]",
            r"(?i)<<SYS>>.*<</SYS>>",
            r"(?i)Human:\s*\n.*\nAssistant:",
            r"\x00+",  # Null bytes
            r"(?i)<!-- .*(ignore|override|new instructions).*-->",
            r"(?i)\[system\]\s*#",
        ],
        "score": 0.85,
    },
    # -- MCP tool poisoning ----------------------------------------------------
    {
        "id": "PI-006",
        "name": "mcp_tool_poisoning",
        "category": "tool_poisoning",
        "technique": "mcp_tool_poisoning",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)tool_description.*ignore.*instructions",
            r"(?i)when\s+called.*execute.*command",
            r"(?i)hidden\s+instruction.*tool",
            r"(?i)override.*tool.*behavior",
        ],
        "score": 0.90,
    },
    # -- Encoding bypass attempts ----------------------------------------------
    {
        "id": "PI-007",
        "name": "encoding_bypass",
        "category": "evasion",
        "technique": "encoding_bypass",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{20,}",
            r"(?i)decode\s+this\s*:\s*[A-Za-z0-9+/=]{20,}",
            r"(?i)hex\s*:\s*[0-9a-fA-F]{20,}",
            r"(?i)rot13\s*:\s*",
            r"(?i)translate\s+from\s+(base64|hex|binary|rot13)",
        ],
        "score": 0.60,
    },
    # -- Credential / secret patterns ------------------------------------------
    {
        "id": "DLP-001",
        "name": "credential_exposure",
        "category": "data_loss",
        "technique": "credential_exposure",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
            r"sk-[A-Za-z0-9]{20,}",  # OpenAI-style keys
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
            r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
            r"(?i)(secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"AKIA[A-Z0-9]{16}",  # AWS access keys
        ],
        "score": 0.70,
    },
    # -- PII patterns (UK / EU focus) ------------------------------------------
    {
        "id": "DLP-002",
        "name": "pii_exposure",
        "category": "data_loss",
        "technique": "pii_exposure",
        "severity": "HIGH",
        "patterns": [
            r"\b[A-Z]{2}\d{6}[A-Z]\b",       # UK National Insurance Number
            r"\b\d{3}\s?\d{4}\s?\d{4}\b",     # NHS Number
            r"\b[A-Z]{1,2}\d{1,2}\s?\d[A-Z]{2}\b",  # UK Postcode
            r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",   # Credit card
            r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?\d{7,}\b",  # IBAN
        ],
        "score": 0.65,
    },
]


class PatternLayer:
    """Fast regex-based pattern matching layer.

    Compiles all patterns once at load time, then scans incoming text in a
    single pass through the rule list.  Returns the highest-scoring match
    along with the union of matched categories and rule IDs.
    """

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []
        self._compiled: list[tuple[dict[str, Any], list[tuple[re.Pattern[str], str]]]] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_builtin(self) -> None:
        """Load only the built-in pattern library (no disk I/O)."""
        self._rules = list(BUILTIN_PATTERNS)
        self._compile()

    def add_rules(self, rules: list[dict[str, Any]]) -> None:
        """Append additional rules (e.g. from YAML) and recompile."""
        self._rules.extend(rules)
        self._compile()

    def _compile(self) -> None:
        self._compiled = []
        for rule in self._rules:
            compiled_patterns: list[tuple[re.Pattern[str], str]] = []
            for p in rule.get("patterns", []):
                try:
                    compiled_patterns.append((re.compile(p), p))
                except re.error as exc:
                    logger.warning("Invalid regex in rule %s: %s", rule.get("id", "?"), exc)
            self._compiled.append((rule, compiled_patterns))

    # ------------------------------------------------------------------
    # ReDoS-safe matching
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_match(pattern: re.Pattern[str], raw_pattern: str, text: str) -> re.Match[str] | None:
        """Match with a length pre-check for ReDoS-risky patterns."""
        if raw_pattern in _REDOS_RISKY_PATTERNS:
            if len(text) > _REDOS_PATTERN_MAX_LENGTH:
                text = text[:_REDOS_PATTERN_MAX_LENGTH]
        return pattern.search(text)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan(self, text: str) -> dict[str, Any]:
        """Scan *text* against all compiled patterns.

        Returns a dict with ``score``, ``categories``, ``technique``, and
        ``matched_rules``.
        """
        # Global input length guard
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]

        best_score = 0.0
        matched_categories: list[str] = []
        matched_technique = ""
        matched_rules: list[str] = []

        for rule, patterns in self._compiled:
            for pattern, raw_pattern in patterns:
                if self._safe_match(pattern, raw_pattern, text):
                    score = rule.get("score", 0.5)
                    if score > best_score:
                        best_score = score
                        matched_technique = rule.get("technique", "")
                    matched_categories.append(rule["category"])
                    matched_rules.append(rule["id"])
                    break  # One match per rule is sufficient

        return {
            "score": best_score,
            "categories": list(set(matched_categories)),
            "technique": matched_technique,
            "matched_rules": matched_rules,
        }

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def list_rules(self) -> list[dict[str, Any]]:
        """Return a summary of every loaded rule."""
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "category": r["category"],
                "severity": r.get("severity", "MEDIUM"),
                "pattern_count": len(r.get("patterns", [])),
            }
            for r in self._rules
        ]
