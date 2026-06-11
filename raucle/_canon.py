"""Shared canonical-ordering helpers for signed/hashed material.

Historically several modules (provenance, capability, prove, audit, feed,
verdicts) each carried their own ``_canonical_json`` with ``sort_keys=True``,
i.e. Python's native Unicode **code-point** key ordering. That diverges from
JavaScript / .NET ordinal ordering — and from RFC 8785 (JCS §3.2.3) — for
non-BMP (astral) object keys, breaking cross-language and cross-component
byte-identity of signed material. These helpers centralise the correct
**UTF-16 code-unit** ordering so every canonicaliser agrees.

For BMP characters UTF-16 order == code-point order, so this is byte-neutral
for all existing ASCII/BMP material.
"""

from __future__ import annotations

from typing import Any


def reject_lone_surrogates(s: str) -> None:
    """Raise ``ValueError`` if *s* contains an unpaired UTF-16 surrogate.

    In a Python ``str`` a valid non-BMP character is stored as a single code
    point (e.g. U+1F511), so any code point in U+D800..U+DFFF is necessarily an
    unpaired (lone) surrogate. Such a string cannot be encoded to UTF-8 and the
    five reference implementations disagree on it: Python and Rust reject it,
    Go and .NET silently substitute U+FFFD, and a JS ``JSON.stringify`` emits a
    ``\\udXXX`` escape. Rejecting at sign/verify keeps signed material byte-
    identical across all implementations — the R8 invariant of the Raucle
    Canonical JSON Profile. This is the shared, *explicit* enforcement point so
    every signer/verifier rejects on the same clean error rather than relying on
    the incidental ``UnicodeEncodeError`` from a later ``.encode("utf-8")``.
    """
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError(
                "canonical JSON: lone surrogate "
                f"U+{ord(ch):04X} is not permitted in v1 signed/hashed material "
                "(unpaired surrogates are not cross-implementation stable)"
            )


def utf16_key(s: str) -> bytes:
    """Sort key giving RFC 8785 / JCS §3.2.3 ordering: by UTF-16 code unit.
    UTF-16 big-endian byte comparison == unsigned-16-bit code-unit comparison,
    matching JavaScript ``a < b`` and .NET ``StringComparer.Ordinal``.

    Rejects lone surrogates explicitly first (R8): ``encode("utf-16-be")`` would
    itself raise ``UnicodeEncodeError`` on a lone surrogate, but routing it
    through the explicit rejector means every sort path — including the
    constraint-normalisation pre-sort that runs before ``_canonical_json`` — fails
    on the same clean ``ValueError`` rather than an incidental encode error."""
    reject_lone_surrogates(s)
    return s.encode("utf-16-be")


def value_sort_key(v: Any):
    """Deterministic sort key for allow/deny LIST values (strings or integers).
    Strings sort by UTF-16 code unit; non-strings are ranked by type name first
    (so ``bool`` — an ``int`` subclass — never collides with an equal ``int``,
    e.g. ``True`` vs ``1``) and then by value within the same type."""
    # Uniform 3-tuple shape (rank, type-name, comparable): strings compare by
    # their UTF-16 bytes, non-strings by value; the leading rank keeps the two
    # groups apart so cross-type members never compare. Ordering is unchanged
    # from the prior 2-/3-tuple form (byte-neutral).
    if isinstance(v, str):
        reject_lone_surrogates(v)  # R8: clean ValueError on any sort path
        return (0, "str", v.encode("utf-16-be"))
    return (1, type(v).__name__, v)


def reorder_keys_utf16(obj: Any) -> Any:
    """Recursively reorder object keys by UTF-16 code unit, preserving array
    order. Tuples are treated as arrays (parity with float-rejection traversal).
    Returns a structurally equal value to serialise with ``sort_keys=False``."""
    if isinstance(obj, dict):
        return {k: reorder_keys_utf16(obj[k]) for k in sorted(obj, key=utf16_key)}
    if isinstance(obj, (list, tuple)):
        return [reorder_keys_utf16(v) for v in obj]
    return obj


def make_duplicate_key_rejecter(context: str = "JSON object"):
    """Return a ``json.loads`` ``object_pairs_hook`` that rejects duplicate keys.

    Duplicate keys are valid per the JSON grammar but their handling is
    implementation-defined (Python keeps the last value; a first-key parser
    sees the other), so a signed payload could verify here while presenting
    different content elsewhere — encoding malleability. We refuse them.
    ``context`` names the payload kind in the error message.
    """

    def _hook(pairs: list) -> dict:
        seen: dict = {}
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate key {key!r} in {context}")
            seen[key] = value
        return seen

    return _hook
