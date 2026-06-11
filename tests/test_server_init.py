"""Tests for the FastAPI server's compliance-init fail-loud behaviour.

FIX 1.1 of the HOLD SCOPE review — ``_init_compliance()`` must:

  * refuse to start when an explicit env var is set but the resource
    cannot be loaded (e.g. unparseable PEM);
  * warn loudly (not silently) when no key is configured and continue
    in unsigned mode.

These tests import ``raucle.server`` ONCE at module load (with
clean env), then exercise ``_init_compliance()`` directly under various
monkeypatched environments. The module-level call runs once during
import; the function-level calls do not re-execute it.
"""

from __future__ import annotations

import logging

import pytest

cryptography = pytest.importorskip("cryptography")
fastapi = pytest.importorskip("fastapi")

# Import ONCE while env is clean. The module-level ``_init_compliance()``
# call runs here; subsequent test-level invocations are explicit and
# isolated from this side-effect.
import raucle.server as srv  # noqa: E402


def test_server_refuses_start_with_bad_verdict_key_pem(monkeypatch):
    """A set-but-malformed RAUCLE_DETECT_VERDICT_KEY_PEM must surface
    as a ConfigurationError, NOT a silent fallback to no signer."""
    from raucle.errors import ConfigurationError

    monkeypatch.setenv("RAUCLE_DETECT_VERDICT_KEY_PEM", "not a real PEM")
    monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PATH", raising=False)
    monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM", raising=False)

    with pytest.raises(ConfigurationError, match="verdict signer"):
        srv._init_compliance()


def test_server_refuses_start_with_bad_audit_key_pem(monkeypatch, tmp_path):
    """A set-but-malformed RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM must
    surface as a ConfigurationError."""
    from raucle.errors import ConfigurationError

    monkeypatch.setenv("RAUCLE_DETECT_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM", "still not a PEM")
    monkeypatch.delenv("RAUCLE_DETECT_VERDICT_KEY_PEM", raising=False)

    with pytest.raises(ConfigurationError, match="audit signer"):
        srv._init_compliance()


def test_server_warns_when_no_keys_configured(monkeypatch, caplog):
    """No key env vars at all → loud WARNING, return (None, None).
    Never a silent pass."""
    monkeypatch.delenv("RAUCLE_DETECT_VERDICT_KEY_PEM", raising=False)
    monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PATH", raising=False)
    monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM", raising=False)

    with caplog.at_level(logging.WARNING):
        sink, signer = srv._init_compliance()

    assert sink is None
    assert signer is None
    assert "UNSIGNED" in caplog.text or "not include signed receipts" in caplog.text


def test_server_succeeds_with_valid_verdict_key(monkeypatch):
    """A valid PEM → returns a signer, no exception."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    monkeypatch.setenv("RAUCLE_DETECT_VERDICT_KEY_PEM", pem)
    monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PATH", raising=False)
    monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM", raising=False)

    sink, signer = srv._init_compliance()
    assert sink is None  # no audit path
    assert signer is not None
    assert signer.public_key_pem()  # non-empty
