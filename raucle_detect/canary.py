"""Canary watermarking for system prompt leak detection.

Embeds invisible watermark tokens into a system prompt.  When the LLM
produces output that contains those tokens, the scanner knows the model
was manipulated into leaking its instructions.

Usage::

    from raucle_detect.canary import CanaryManager

    cm = CanaryManager()

    # Embed canaries into your system prompt before sending to the LLM
    protected_prompt, token = cm.embed("You are a helpful assistant.")

    # After getting the LLM response, check for leakage
    result = cm.check_output(response_text, token)
    if result.leaked:
        print(f"System prompt leaked! Confidence: {result.confidence:.0%}")
        print(f"Evidence: {result.evidence}")

How it works
------------
1.  A cryptographically random token is generated (configurable length).
2.  The token is embedded into the system prompt using one of several
    concealment strategies (zero-width Unicode characters, semantic
    sentence injection, or an explicit marker comment).
3.  ``check_output`` scans the LLM response for any trace of the token.
4.  Because the token was never given to the user, its appearance in the
    output is strong evidence of prompt extraction.

The ``CanaryManager`` maintains a registry of active tokens so you can
reuse it across a session and detect leakage from any of them.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Concealment strategies
# ---------------------------------------------------------------------------

class EmbedStrategy(str, Enum):
    ZERO_WIDTH = "zero_width"
    """Encode the token as a sequence of zero-width Unicode characters
    (U+200B ZERO WIDTH SPACE and U+200C ZERO WIDTH NON-JOINER).
    Invisible to readers but preserved in most model contexts."""

    SEMANTIC = "semantic"
    """Append a natural-language sentence containing the token disguised
    as a random instruction ID.  Slightly visible but survives heavy
    tokenisation."""

    COMMENT = "comment"
    """Embed the token inside an HTML comment.  Works well for prompts
    that are rendered or processed as markup."""


# Zero-width characters used for binary encoding
_ZW_ZERO = "​"   # ZERO WIDTH SPACE  → 0
_ZW_ONE  = "‌"   # ZERO WIDTH NON-JOINER → 1
_ZW_SEP  = "‍"   # ZERO WIDTH JOINER  → byte separator


def _token_to_zw(token: str) -> str:
    """Encode *token* as a zero-width character sequence."""
    parts: list[str] = []
    for byte in token.encode():
        bits = format(byte, "08b").replace("0", _ZW_ZERO).replace("1", _ZW_ONE)
        parts.append(bits)
    return _ZW_SEP.join(parts)


def _zw_to_token(text: str) -> str | None:
    """Extract and decode a zero-width token from *text*. Returns None on failure."""
    # Collect contiguous runs of zero-width chars
    zw_chars = {_ZW_ZERO, _ZW_ONE, _ZW_SEP}
    runs: list[str] = []
    current: list[str] = []
    for ch in text:
        if ch in zw_chars:
            current.append(ch)
        else:
            if current:
                runs.append("".join(current))
                current = []
    if current:
        runs.append("".join(current))

    # Try to decode the longest run
    for run in sorted(runs, key=len, reverse=True):
        try:
            byte_strs = run.split(_ZW_SEP)
            decoded = bytes(
                int(bs.replace(_ZW_ZERO, "0").replace(_ZW_ONE, "1"), 2)
                for bs in byte_strs
                if len(bs) == 8
            )
            return decoded.decode("utf-8")
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CanaryToken:
    """A single canary token embedded in a system prompt."""

    value: str
    """The raw random token string."""

    strategy: EmbedStrategy
    """How the token was concealed."""

    created_at: float = field(default_factory=time.time)
    """Unix timestamp of token creation."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Optional caller-supplied metadata (session ID, user ID, etc.)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "strategy": self.strategy.value,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass
class CanaryCheckResult:
    """Result of checking LLM output for canary token leakage."""

    leaked: bool
    """True when a canary token was found in the output."""

    confidence: float
    """0.0 – 1.0 confidence that the leak is genuine."""

    token_value: str
    """The specific token that leaked (empty string if no leak)."""

    strategy: EmbedStrategy | None
    """The concealment strategy used for the leaked token."""

    evidence: str
    """Human-readable description of how the leak was detected."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "leaked": self.leaked,
            "confidence": self.confidence,
            "token_value": self.token_value,
            "strategy": self.strategy.value if self.strategy else None,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class CanaryManager:
    """Create, embed, and check canary tokens for system prompt leak detection.

    Parameters
    ----------
    token_length : int
        Number of random bytes to use for each canary token.
        Longer tokens are harder to guess but take more space.
    default_strategy : EmbedStrategy
        Default concealment strategy for :meth:`embed`.
    secret : bytes | None
        Optional HMAC secret for token signing.  When set, tokens include
        an HMAC digest that can be verified independently of the registry,
        making offline verification possible.
    max_tokens : int
        Maximum number of active tokens to keep in the registry before
        oldest tokens are evicted.  Prevents unbounded memory growth.
    """

    def __init__(
        self,
        token_length: int = 16,
        default_strategy: EmbedStrategy = EmbedStrategy.ZERO_WIDTH,
        secret: bytes | None = None,
        max_tokens: int = 10_000,
    ) -> None:
        self._token_length = token_length
        self._default_strategy = default_strategy
        self._secret = secret
        self._max_tokens = max_tokens
        self._registry: dict[str, CanaryToken] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_token(self, metadata: dict[str, Any] | None = None) -> CanaryToken:
        """Generate a new canary token without embedding it.

        Useful when you want to store the token separately and embed later.
        """
        raw = secrets.token_hex(self._token_length)
        if self._secret:
            sig = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()[:8]
            value = f"{raw}.{sig}"
        else:
            value = raw

        token = CanaryToken(
            value=value,
            strategy=self._default_strategy,
            metadata=metadata or {},
        )
        self._register(token)
        return token

    def embed(
        self,
        system_prompt: str,
        strategy: EmbedStrategy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, CanaryToken]:
        """Embed a canary token into *system_prompt*.

        Returns
        -------
        tuple[str, CanaryToken]
            The watermarked prompt and the token that was embedded.
            Store the token; you will need it for :meth:`check_output`.
        """
        strategy = strategy or self._default_strategy
        token = CanaryToken(
            value=self._generate_value(),
            strategy=strategy,
            metadata=metadata or {},
        )
        self._register(token)

        if strategy == EmbedStrategy.ZERO_WIDTH:
            watermark = _token_to_zw(token.value)
            # Insert after the first sentence boundary if possible, else append
            idx = system_prompt.find(". ")
            if idx != -1:
                watermarked = system_prompt[: idx + 1] + watermark + system_prompt[idx + 1 :]
            else:
                watermarked = system_prompt + watermark

        elif strategy == EmbedStrategy.SEMANTIC:
            watermarked = (
                system_prompt.rstrip()
                + f"\n\n[Ref: session-token={token.value}]"
            )

        else:  # COMMENT
            watermarked = (
                system_prompt.rstrip()
                + f"\n<!-- canary:{token.value} -->"
            )

        return watermarked, token

    def check_output(
        self,
        output: str,
        token: CanaryToken | None = None,
    ) -> CanaryCheckResult:
        """Scan *output* for evidence of canary token leakage.

        Parameters
        ----------
        output : str
            The LLM-generated text to inspect.
        token : CanaryToken | None
            A specific token to look for.  If ``None``, all registered
            tokens are checked (useful for session-level detection).

        Returns
        -------
        CanaryCheckResult
            Describes whether and how leakage was detected.
        """
        targets = [token] if token else list(self._registry.values())

        for t in targets:
            result = self._check_single(output, t)
            if result.leaked:
                return result

        return CanaryCheckResult(
            leaked=False,
            confidence=0.0,
            token_value="",
            strategy=None,
            evidence="No canary tokens found in output.",
        )

    def check_output_all(self, output: str) -> list[CanaryCheckResult]:
        """Check output against every registered token; returns all matches."""
        results = []
        for t in self._registry.values():
            r = self._check_single(output, t)
            if r.leaked:
                results.append(r)
        return results

    def revoke_token(self, token_value: str) -> bool:
        """Remove a token from the registry. Returns True if it existed."""
        return self._registry.pop(token_value, None) is not None

    def active_token_count(self) -> int:
        """Return the number of tokens currently in the registry."""
        return len(self._registry)

    def verify_token(self, token_value: str) -> bool:
        """Verify an HMAC-signed token without the registry.

        Only meaningful when a *secret* was provided at construction time.
        Returns True if the signature is valid, False otherwise.
        """
        if not self._secret:
            return True  # no signing configured
        if "." not in token_value:
            return False
        raw, provided_sig = token_value.rsplit(".", 1)
        expected_sig = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()[:8]
        return hmac.compare_digest(provided_sig, expected_sig)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _generate_value(self) -> str:
        raw = secrets.token_hex(self._token_length)
        if self._secret:
            sig = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()[:8]
            return f"{raw}.{sig}"
        return raw

    def _register(self, token: CanaryToken) -> None:
        if len(self._registry) >= self._max_tokens:
            # Evict oldest token
            oldest_key = min(self._registry, key=lambda k: self._registry[k].created_at)
            del self._registry[oldest_key]
        self._registry[token.value] = token

    def _check_single(self, output: str, token: CanaryToken) -> CanaryCheckResult:
        """Check output for a specific token using its original strategy."""
        value = token.value

        if token.strategy == EmbedStrategy.ZERO_WIDTH:
            # Reconstruct the zero-width encoding and check
            zw_encoded = _token_to_zw(value)
            if zw_encoded in output:
                return CanaryCheckResult(
                    leaked=True,
                    confidence=0.99,
                    token_value=value,
                    strategy=token.strategy,
                    evidence="Zero-width encoded canary token reproduced verbatim in output.",
                )
            # Also try recovering via decode (token may be partially reformed)
            recovered = _zw_to_token(output)
            if recovered and recovered == value:
                return CanaryCheckResult(
                    leaked=True,
                    confidence=0.95,
                    token_value=value,
                    strategy=token.strategy,
                    evidence="Zero-width canary token decoded from output.",
                )

        # For SEMANTIC and COMMENT strategies (and as fallback for ZERO_WIDTH):
        # check if the raw token value appears literally in the output
        if value in output:
            confidence = 0.98 if token.strategy == EmbedStrategy.SEMANTIC else 0.95
            return CanaryCheckResult(
                leaked=True,
                confidence=confidence,
                token_value=value,
                strategy=token.strategy,
                evidence=f"Canary token value ({value[:8]}…) found verbatim in output.",
            )

        # Partial match: first 12 chars of token found (weaker signal)
        if len(value) > 12 and value[:12] in output:
            return CanaryCheckResult(
                leaked=True,
                confidence=0.70,
                token_value=value,
                strategy=token.strategy,
                evidence=f"Partial canary token prefix ({value[:8]}…) found in output.",
            )

        return CanaryCheckResult(
            leaked=False,
            confidence=0.0,
            token_value="",
            strategy=None,
            evidence="",
        )
