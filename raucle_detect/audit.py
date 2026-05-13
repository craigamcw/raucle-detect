"""Tamper-evident audit chain for compliance evidence (EU AI Act Article 12).

Every detection event is appended to a hash-chained, append-only log.  Each
record's hash links to its predecessor, and the chain is periodically anchored
with an Ed25519-signed checkpoint.  Any modification to past records breaks
the chain and can be detected by ``AuditVerifier.verify_chain``.

This module ships only stdlib + ``cryptography`` (already pulled in by FastAPI)
so it does not expand the mandatory dependency surface.

Usage::

    from raucle_detect.audit import HashChainSink, Ed25519Signer

    signer = Ed25519Signer.generate()
    sink = HashChainSink("audit.jsonl", signer=signer, checkpoint_every=100)
    scanner = Scanner(audit_sink=sink)

    # Later — verify
    from raucle_detect.audit import AuditVerifier
    report = AuditVerifier(public_key=signer.public_key_pem).verify_chain("audit.jsonl")
    print(report.valid, report.first_invalid_index)

The format is plain JSON Lines so it streams to S3/GCS/Splunk without buffering.
Each line is one event::

    {
      "index": 42,
      "timestamp": "2026-05-13T18:23:04.123456Z",
      "prev_hash": "<hex sha256 of previous record's canonical bytes>",
      "event": {...},                       # caller-supplied payload
      "hash": "<hex sha256 of this record's canonical bytes>"
    }

Checkpoints (every ``checkpoint_every`` events, plus on close) are written as::

    {
      "checkpoint": true,
      "index": 100,
      "merkle_root": "<hex sha256 of all leaf hashes 0..99>",
      "signature": "<base64 ed25519 sig over canonical(index, merkle_root)>",
      "key_id": "<sha256(pubkey)[:16]>"
    }
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ed25519 signing (optional — falls back to unsigned chain if unavailable)
# ---------------------------------------------------------------------------


class Ed25519Signer:
    """Wraps an Ed25519 keypair for signing audit checkpoints.

    Uses the ``cryptography`` library which is already a transitive dependency
    of FastAPI/Pydantic.  If not available, ``HashChainSink`` still produces a
    hash-chained log but skips signed checkpoints.
    """

    def __init__(self, private_key: Any) -> None:
        self._private_key = private_key
        try:
            from cryptography.hazmat.primitives import serialization

            self._public_key = private_key.public_key()
            self._public_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            self._public_key = None
            self._public_pem = b""

    @classmethod
    def generate(cls) -> Ed25519Signer:
        """Generate a fresh Ed25519 keypair."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem_bytes: bytes, password: bytes | None = None) -> Ed25519Signer:
        """Load a signer from PEM-encoded private key bytes."""
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(pem_bytes, password=password)
        return cls(key)

    def sign(self, data: bytes) -> bytes:
        """Sign *data* and return the raw signature bytes."""
        return self._private_key.sign(data)

    def public_key_pem(self) -> bytes:
        return self._public_pem

    def key_id(self) -> str:
        """Stable short identifier derived from the public key (first 16 hex)."""
        if not self._public_pem:
            return "unsigned"
        return hashlib.sha256(self._public_pem).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Canonical JSON serialisation — required for deterministic hashing
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    """Serialise *obj* as canonical JSON for hashing (sorted keys, no spaces, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Hash-chain sink
# ---------------------------------------------------------------------------


class HashChainSink:
    """Append-only, hash-chained sink for audit events.

    Thread-safe.  Each call to :meth:`append` writes one JSON line containing
    the canonical hash of the event plus the previous record's hash.

    Parameters
    ----------
    path : str | Path
        File path or pre-opened file object.  When a path is given, the file
        is opened in append mode; existing chains are extended seamlessly.
    signer : Ed25519Signer | None
        Optional signer for periodic checkpoints.
    checkpoint_every : int
        Emit a signed checkpoint every N events.  Set to 0 to disable
        intermediate checkpoints (only emit on ``close``).
    """

    _GENESIS_HASH = "0" * 64

    def __init__(
        self,
        path: str | Path | IO[str],
        signer: Ed25519Signer | None = None,
        checkpoint_every: int = 1000,
    ) -> None:
        self._signer = signer
        self._checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        self._leaf_hashes: list[str] = []
        self._next_index = 0
        self._prev_hash = self._GENESIS_HASH

        if hasattr(path, "write"):
            self._file: IO[str] = path  # type: ignore[assignment]
            self._owns_file = False
        else:
            path = Path(path)
            if path.exists():
                # Resume an existing chain
                self._resume(path)
            self._file = open(path, "a", encoding="utf-8")  # noqa: SIM115 — held for sink lifetime
            self._owns_file = True

    def _resume(self, path: Path) -> None:
        """Read an existing chain and recover the tail hash + index."""
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("checkpoint"):
                    continue
                self._prev_hash = rec.get("hash", self._prev_hash)
                self._next_index = rec.get("index", -1) + 1
                self._leaf_hashes.append(rec.get("hash", ""))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append a single event to the chain.

        Returns the full record (with ``index``, ``prev_hash``, ``hash``,
        ``timestamp``) so callers can use it as a receipt.
        """
        with self._lock:
            record = {
                "index": self._next_index,
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "prev_hash": self._prev_hash,
                "event": event,
            }
            record_hash = _sha256_hex(_canonical_json(record))
            record["hash"] = record_hash

            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()

            self._leaf_hashes.append(record_hash)
            self._prev_hash = record_hash
            self._next_index += 1

            if (
                self._signer
                and self._checkpoint_every > 0
                and self._next_index % self._checkpoint_every == 0
            ):
                self._emit_checkpoint_locked()

            return record

    def emit_checkpoint(self) -> dict[str, Any] | None:
        """Force-write a checkpoint now.  Returns the checkpoint record (or None
        if no signer configured)."""
        with self._lock:
            return self._emit_checkpoint_locked()

    def close(self) -> None:
        """Flush a final checkpoint and close the underlying file."""
        with self._lock:
            if self._signer:
                self._emit_checkpoint_locked()
            if self._owns_file:
                self._file.close()

    def __enter__(self) -> HashChainSink:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def event_count(self) -> int:
        return self._next_index

    @property
    def tail_hash(self) -> str:
        return self._prev_hash

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_checkpoint_locked(self) -> dict[str, Any] | None:
        if not self._signer or not self._leaf_hashes:
            return None

        merkle_root = _merkle_root(self._leaf_hashes)
        body = {
            "index": self._next_index,
            "merkle_root": merkle_root,
            "key_id": self._signer.key_id(),
        }
        sig = self._signer.sign(_canonical_json(body))
        checkpoint = {
            "checkpoint": True,
            **body,
            "signature": base64.b64encode(sig).decode("ascii"),
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        self._file.write(json.dumps(checkpoint, ensure_ascii=False) + "\n")
        self._file.flush()
        return checkpoint


# ---------------------------------------------------------------------------
# Merkle helpers
# ---------------------------------------------------------------------------


def _merkle_root(leaf_hashes: list[str]) -> str:
    """Compute the Merkle root over a list of hex-encoded leaf hashes."""
    if not leaf_hashes:
        return _sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left  # duplicate last on odd count
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


@dataclass
class VerificationReport:
    """Outcome of verifying an audit chain file."""

    valid: bool
    event_count: int
    checkpoint_count: int
    valid_signatures: int
    invalid_signatures: int
    first_invalid_index: int | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "event_count": self.event_count,
            "checkpoint_count": self.checkpoint_count,
            "valid_signatures": self.valid_signatures,
            "invalid_signatures": self.invalid_signatures,
            "first_invalid_index": self.first_invalid_index,
            "errors": self.errors,
        }


class AuditVerifier:
    """Verify the integrity of a hash-chained audit log.

    Parameters
    ----------
    public_key_pem : bytes | None
        Ed25519 public key in PEM format.  When provided, checkpoint
        signatures are also verified.  When None, only the hash chain itself
        is verified (still detects tampering with event content).
    """

    def __init__(self, public_key_pem: bytes | None = None) -> None:
        self._public_pem = public_key_pem
        self._public_key: Any = None
        if public_key_pem:
            from cryptography.hazmat.primitives import serialization

            self._public_key = serialization.load_pem_public_key(public_key_pem)

    def verify_chain(self, path: str | Path) -> VerificationReport:
        """Verify the chain at *path*.  Returns a :class:`VerificationReport`."""
        report = VerificationReport(
            valid=True,
            event_count=0,
            checkpoint_count=0,
            valid_signatures=0,
            invalid_signatures=0,
        )

        prev_hash = HashChainSink._GENESIS_HASH
        expected_index = 0
        leaf_hashes: list[str] = []

        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    report.errors.append(f"line {line_no}: invalid JSON: {exc}")
                    report.valid = False
                    continue

                if rec.get("checkpoint"):
                    self._verify_checkpoint(rec, leaf_hashes, expected_index, report)
                    continue

                # Verify event record
                if rec.get("index") != expected_index:
                    report.errors.append(
                        f"line {line_no}: index mismatch (expected {expected_index}, "
                        f"got {rec.get('index')})"
                    )
                    if report.first_invalid_index is None:
                        report.first_invalid_index = rec.get("index", expected_index)
                    report.valid = False

                if rec.get("prev_hash") != prev_hash:
                    report.errors.append(
                        f"line {line_no}: prev_hash mismatch — chain broken at "
                        f"index {expected_index}"
                    )
                    if report.first_invalid_index is None:
                        report.first_invalid_index = expected_index
                    report.valid = False

                # Recompute hash without the hash field
                stored_hash = rec.pop("hash", None)
                recomputed = _sha256_hex(_canonical_json(rec))
                rec["hash"] = stored_hash  # restore for any downstream readers
                if stored_hash != recomputed:
                    report.errors.append(
                        f"line {line_no}: hash mismatch at index {expected_index} "
                        f"(stored != recomputed) — record tampered"
                    )
                    if report.first_invalid_index is None:
                        report.first_invalid_index = expected_index
                    report.valid = False

                leaf_hashes.append(stored_hash or "")
                prev_hash = stored_hash or prev_hash
                expected_index += 1
                report.event_count += 1

        return report

    def _verify_checkpoint(
        self,
        rec: dict[str, Any],
        leaf_hashes: list[str],
        expected_index: int,
        report: VerificationReport,
    ) -> None:
        report.checkpoint_count += 1

        ckpt_index = rec.get("index", -1)
        if ckpt_index != expected_index:
            report.errors.append(
                f"checkpoint at index {ckpt_index} does not match chain head ({expected_index})"
            )
            report.valid = False
            return

        expected_root = _merkle_root(leaf_hashes)
        if rec.get("merkle_root") != expected_root:
            report.errors.append(
                f"checkpoint at index {ckpt_index}: merkle_root mismatch — chain tampered"
            )
            report.valid = False
            return

        if not self._public_key:
            # Hash matches but we can't verify signature without a key
            return

        try:
            sig = base64.b64decode(rec["signature"])
            body = {
                "index": ckpt_index,
                "merkle_root": rec["merkle_root"],
                "key_id": rec.get("key_id", ""),
            }
            self._public_key.verify(sig, _canonical_json(body))
            report.valid_signatures += 1
        except Exception as exc:
            report.invalid_signatures += 1
            report.errors.append(
                f"checkpoint at index {ckpt_index}: signature verification failed: {exc}"
            )
            report.valid = False


# ---------------------------------------------------------------------------
# Convenience: a no-op sink used when audit logging is disabled
# ---------------------------------------------------------------------------


class NullSink:
    """A no-op sink.  Use this as the default when audit logging is disabled."""

    def append(self, event: dict[str, Any]) -> dict[str, Any]:  # noqa: D401
        return {}

    def close(self) -> None:
        pass

    @property
    def event_count(self) -> int:
        return 0

    @property
    def tail_hash(self) -> str:
        return ""


# Export the env-var name so the CLI and server can both reference it.
ENV_AUDIT_PATH = "RAUCLE_DETECT_AUDIT_PATH"
ENV_AUDIT_KEY = "RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM"


def sink_from_env() -> HashChainSink | None:
    """Build a HashChainSink from environment variables, or None if not configured.

    - ``RAUCLE_DETECT_AUDIT_PATH`` — file path for the chain log
    - ``RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM`` — PEM private key (optional)
    """
    path = os.environ.get(ENV_AUDIT_PATH)
    if not path:
        return None
    signer: Ed25519Signer | None = None
    key_pem = os.environ.get(ENV_AUDIT_KEY)
    if key_pem:
        try:
            signer = Ed25519Signer.from_pem(key_pem.encode())
        except Exception as exc:
            logger.warning("Failed to load audit signer key: %s", exc)
    return HashChainSink(path, signer=signer)
