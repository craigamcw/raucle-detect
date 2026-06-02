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


def utf16_key(s: str) -> bytes:
    """Sort key giving RFC 8785 / JCS §3.2.3 ordering: by UTF-16 code unit.
    UTF-16 big-endian byte comparison == unsigned-16-bit code-unit comparison,
    matching JavaScript ``a < b`` and .NET ``StringComparer.Ordinal``."""
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
