"""Deprecated compatibility shim: ``raucle_detect`` is now ``raucle``.

The package was renamed in v0.22.0. This shim keeps existing code working
(``import raucle_detect`` and ``from raucle_detect.scanner import ...``) by
aliasing the old name to the new package. It will be removed in a future
major release — migrate imports to ``raucle``.
"""

import sys
import warnings

import raucle as _raucle

warnings.warn(
    "the 'raucle_detect' package has been renamed to 'raucle'; "
    "update imports (this shim will be removed in a future release)",
    DeprecationWarning,
    stacklevel=2,
)

# Alias the package so `import raucle_detect.<submodule>` resolves inside the
# renamed package. Submodules imported via the old name share raucle's __path__.
sys.modules[__name__] = _raucle
