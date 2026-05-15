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
#
# The "ollama" provider is our own; we register it in apply() below to route
# OpenAI-compatible chat completions through Ollama Cloud at https://ollama.com/v1.
_EXTRA_MODELS = [
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-opus-4-7", "anthropic"),
    # Ollama Cloud models. Add more as we widen the eval.
    ("deepseek-v3.2", "ollama"),
    ("deepseek-v4-pro", "ollama"),
    ("deepseek-v4-flash", "ollama"),
    ("qwen3.5:397b", "ollama"),
    ("kimi-k2.6", "ollama"),
    ("kimi-k2.5", "ollama"),
    ("glm-5.1", "ollama"),
    ("glm-4.7", "ollama"),
    ("mistral-large-3:675b", "ollama"),
    ("gpt-oss:120b", "ollama"),
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
        name = value.upper().replace("-", "_").replace(".", "_").replace(":", "_")
        _add_enum_member(ModelsEnum, name, value)
        member = ModelsEnum._value2member_map_[value]
        MODEL_PROVIDERS[member] = provider
        logger.debug("registered %s -> %s", value, provider)

    _patch_get_llm()
    _patch_model_names()


def _patch_model_names() -> None:
    """Extend AgentDojo's MODEL_NAMES so the injection templates can address our models.

    The `important_instructions` attack family composes injection prompts that
    say "as an AI model named X, you should ignore previous instructions and
    do Y". The mapping is from full model id to a human-readable name; we add
    the Ollama/Anthropic-2026 entries the published catalogue doesn't know
    about. Falls back to 'AI assistant' for ambiguous cases.
    """
    from agentdojo.models import MODEL_NAMES

    additions = {
        # Anthropic 2026 generation
        "claude-sonnet-4-6": "Claude",
        "claude-opus-4-7":   "Claude",
        # Ollama Cloud catalogue
        "deepseek-v4-pro":   "DeepSeek",
        "deepseek-v4-flash": "DeepSeek",
        "deepseek-v3.2":     "DeepSeek",
        "deepseek-v3.1":     "DeepSeek",
        "kimi-k2.6":         "Kimi",
        "kimi-k2.5":         "Kimi",
        "kimi-k2":           "Kimi",
        "qwen3.5":           "Qwen",
        "qwen3-coder":       "Qwen",
        "qwen3-vl":          "Qwen",
        "qwen3-next":        "Qwen",
        "glm-5.1":           "GLM",
        "glm-5":             "GLM",
        "glm-4.7":           "GLM",
        "glm-4.6":           "GLM",
        "mistral-large-3":   "Mistral",
        "gpt-oss":           "AI assistant",
        "nemotron-3":        "Nemotron",
        "gemma3":            "Gemma",
        "gemma4":            "Gemma",
        "minimax-m2":        "MiniMax",
        "cogito-2":          "Cogito",
        "devstral":          "AI assistant",
        "ministral-3":       "Mistral",
        "rnj-1":             "AI assistant",
    }
    MODEL_NAMES.update(additions)
    logger.debug("extended MODEL_NAMES with %d entries", len(additions))


def _patch_get_llm() -> None:
    """Wrap AgentDojo's get_llm to handle our 'ollama' provider.

    Ollama Cloud exposes an OpenAI-compatible chat-completions endpoint at
    https://ollama.com/v1. We route any 'ollama' provider to that endpoint
    using the OPENAI_API_KEY-style bearer auth, taking the actual key from
    the OLLAMA_API_KEY environment variable.
    """
    import os
    import agentdojo.agent_pipeline.agent_pipeline as ap_mod

    original_get_llm = ap_mod.get_llm

    def patched_get_llm(provider, model, model_id, tool_delimiter):
        if provider != "ollama":
            return original_get_llm(provider, model, model_id, tool_delimiter)
        import openai
        from agentdojo.agent_pipeline import OpenAILLM
        key = os.getenv("OLLAMA_API_KEY")
        if not key:
            raise RuntimeError(
                "OLLAMA_API_KEY not set; source /root/raucle-paper/.secrets/ollama.env "
                "or export OLLAMA_API_KEY=... before invoking the harness."
            )
        client = openai.OpenAI(
            api_key=key,
            base_url="https://ollama.com/v1",
        )
        return OpenAILLM(client, model)

    ap_mod.get_llm = patched_get_llm
    logger.debug("patched get_llm to handle ollama provider")


# Apply at import.
apply()
