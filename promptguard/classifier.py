"""Heuristic and optional ML classifier for semantic prompt-injection detection.

When ``transformers`` and ``torch`` are installed and a local model checkpoint
exists, the classifier will use a fine-tuned DeBERTa-v3-small (or compatible)
model.  Otherwise it falls back to a lightweight keyword-density heuristic that
works without any external dependencies.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal word lists
# ---------------------------------------------------------------------------

INJECTION_SIGNALS: list[str] = [
    # Instruction manipulation
    "ignore", "disregard", "forget", "override", "bypass",
    "new instructions", "updated instructions", "real instructions",
    # Role play / identity
    "pretend", "roleplay", "act as", "you are now", "simulate",
    # System prompt extraction
    "system prompt", "initial prompt", "hidden instructions",
    "reveal", "display", "output", "repeat everything",
    # Jailbreak keywords
    "jailbreak", "unrestricted", "unfiltered", "uncensored",
    "no restrictions", "no limits", "no rules", "anything goes",
    "DAN", "developer mode", "god mode",
    # Encoding / evasion
    "base64", "decode this", "translate from",
    # Harmful intent
    "malicious", "exploit", "hack", "inject", "exfiltrate",
]

BENIGN_SIGNALS: list[str] = [
    "please help", "can you explain", "summarize",
    "write a", "create a", "generate a",
    "how do I", "what is", "tell me about",
    "review this", "check this", "analyze",
]


class HeuristicClassifier:
    """Lightweight keyword-density classifier that requires zero dependencies.

    Scores text by counting injection-related and benign signal phrases, then
    produces a 0-1 confidence score.  Useful as a standalone fallback or as a
    secondary signal alongside the pattern layer.
    """

    def classify(self, text: str) -> dict[str, Any]:
        text_lower = text.lower()
        words = text_lower.split()
        total_words = max(len(words), 1)

        injection_hits = sum(1 for s in INJECTION_SIGNALS if s in text_lower)
        benign_hits = sum(1 for s in BENIGN_SIGNALS if s in text_lower)

        injection_density = (injection_hits / total_words) * 100
        raw_score = min(1.0, (injection_hits * 0.12) + (injection_density * 0.05))
        benign_reduction = min(0.3, benign_hits * 0.08)
        score = max(0.0, raw_score - benign_reduction)

        categories: list[str] = []
        technique = ""
        if score > 0.5:
            categories = ["heuristic_injection"]
            technique = "heuristic_detection"

        return {
            "score": round(score, 4),
            "categories": categories,
            "technique": technique,
        }


class MLClassifier:
    """Transformer-based classifier (optional -- requires ``transformers`` and ``torch``)."""

    def __init__(self) -> None:
        self._model: Any = None
        self._tokenizer: Any = None
        self._available = False

    def load(self, model_path: str | None = None) -> bool:
        """Attempt to load a local model checkpoint.

        Returns ``True`` if the model was loaded successfully.
        """
        model_path = model_path or os.environ.get("PROMPTGUARD_MODEL_PATH", "./models")
        local_dir = os.path.join(model_path, "semantic-classifier")

        if not os.path.isdir(local_dir):
            logger.debug("No local model at %s -- ML classifier not available", local_dir)
            return False

        try:
            from transformers import (  # type: ignore[import-untyped]
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            self._tokenizer = AutoTokenizer.from_pretrained(local_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(local_dir)
            self._model.eval()
            self._available = True
            logger.info("Loaded semantic model from %s", local_dir)
            return True
        except ImportError:
            logger.info("transformers package not installed -- ML classifier disabled")
            return False
        except Exception as exc:
            logger.warning("Failed to load ML model: %s", exc)
            return False

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, text: str) -> dict[str, Any]:
        """Run text through the transformer and return a score dict."""
        if not self._available or self._model is None:
            raise RuntimeError("ML classifier is not loaded")

        import torch  # type: ignore[import-untyped]

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)
            injection_prob: float = probs[0][1].item()

        categories: list[str] = []
        technique = ""
        if injection_prob > 0.7:
            categories = ["semantic_injection"]
            technique = "semantic_detection"

        return {
            "score": round(injection_prob, 4),
            "categories": categories,
            "technique": technique,
        }
