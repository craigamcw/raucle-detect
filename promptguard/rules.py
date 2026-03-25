"""YAML rule loader for PromptGuard.

Rule files follow the Raucle rule-pack format:

    rules:
      - id: PI-100
        name: markdown_image_exfil
        category: indirect_injection
        technique: markdown_exfiltration
        severity: HIGH
        patterns:
          - '(?i)...'
        score: 0.80

Files can also be a bare YAML list (without the ``rules:`` wrapper key).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def _require_yaml() -> None:
    if not _YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required to load rule files.  "
            "Install it with:  pip install promptguard[rules]  or  pip install pyyaml"
        )


def load_yaml_file(path: str | Path) -> list[dict[str, Any]]:
    """Load rules from a single YAML file and return a list of rule dicts."""
    _require_yaml()
    path = Path(path)

    with open(path) as fh:
        data = yaml.safe_load(fh)

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "rules" in data:
        return data["rules"]

    raise ValueError(f"Unrecognised rule file format in {path}")


def load_rules_dir(directory: str | Path) -> list[dict[str, Any]]:
    """Load all ``*.yaml`` and ``*.yml`` files from *directory*.

    Returns the concatenated list of rules.  Files are loaded in sorted order
    so that rule precedence is deterministic.
    """
    _require_yaml()
    directory = Path(directory)
    rules: list[dict[str, Any]] = []

    if not directory.is_dir():
        logger.warning("Rules directory does not exist: %s", directory)
        return rules

    for rule_file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        try:
            rules.extend(load_yaml_file(rule_file))
            logger.info("Loaded %s", rule_file.name)
        except Exception as exc:
            logger.error("Failed to load %s: %s", rule_file, exc)

    return rules


def list_loaded_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a compact summary suitable for display or serialisation."""
    return [
        {
            "id": r.get("id", "?"),
            "name": r.get("name", "unnamed"),
            "category": r.get("category", ""),
            "severity": r.get("severity", "MEDIUM"),
            "pattern_count": len(r.get("patterns", [])),
            "score": r.get("score", 0.5),
        }
        for r in rules
    ]
