"""Patch AgentDojo at import time to support Claude Sonnet 4.6.

AgentDojo 0.1.35's `ModelsEnum` was frozen in Feb 2025 and does not include
the 2026-model-generation entries we want for the paper's headline runs.
Rather than fork the package, we extend the enum's internal maps and the
`MODEL_PROVIDERS` lookup so `AgentPipeline.from_config(llm='claude-sonnet-4-6')`
works without modification.

Import this module **before** constructing any AgentDojo pipeline. The
agentdojo_adapter does so automatically.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# (value, provider) — extend as new models land.
_EXTRA_MODELS = [
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-opus-4-7", "anthropic"),
]


def _add_enum_member(enum_cls, name: str, value: str) -> None:
    """Append a new member to a closed Python StrEnum.

    StrEnum doesn't expose a public API for runtime extension, but the
    underlying machinery is just two maps on the class: `_member_map_` and
    `_value2member_map_`. Mutating both adds a member that behaves identically
    to a statically-declared one.
    """
    if name in enum_cls._member_map_:
        return
    member = str.__new__(enum_cls, value)
    member._name_ = name
    member._value_ = value
    enum_cls._member_map_[name] = member
    enum_cls._value2member_map_[value] = member
    # Attribute access goes through EnumMeta.__getattr__ → _member_map_, so we
    # don't need setattr (which the EnumMeta blocks anyway).


def apply() -> None:
    """Add the extra models to AgentDojo's registries. Idempotent."""
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum

    for value, provider in _EXTRA_MODELS:
        name = value.upper().replace("-", "_").replace(".", "_")
        _add_enum_member(ModelsEnum, name, value)
        member = ModelsEnum._value2member_map_[value]
        MODEL_PROVIDERS[member] = provider
        logger.debug("registered %s -> %s", value, provider)


# Apply at import.
apply()
