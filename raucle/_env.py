"""Environment variable lookup with legacy-name fallback.

The project was renamed from raucle-detect to raucle in v0.22.0. New
configuration uses ``RAUCLE_<NAME>``; the legacy ``RAUCLE_DETECT_<NAME>``
names remain supported indefinitely so existing deployments keep working.
"""

from __future__ import annotations

import os


def env(name: str, default: str | None = None) -> str | None:
    """Return ``RAUCLE_<name>``, falling back to legacy ``RAUCLE_DETECT_<name>``."""
    value = os.environ.get(f"RAUCLE_{name}")
    if value is not None:
        return value
    return os.environ.get(f"RAUCLE_DETECT_{name}", default)


__all__ = ["env"]
