r"""Federated signed-IOC feed -- the AI-security equivalent of a CT log.

Every Indicator of Compromise (IOC) is content-addressed and Ed25519-signed
by its publisher. Feeds are Merkle-rooted manifests that consumers fetch,
verify against a pinned issuer pubkey, and merge into the local Scanner.

There is no central authority: each consumer maintains a small
``trusted_issuers`` allowlist. Multiple feeds can be subscribed
simultaneously. A compromised feed cannot mutate prior IOCs silently --
every IOC carries its own signature, verifiable offline.

Usage (publisher)::

    from raucle_detect.feed import IOCSigner, SignedIOC
    signer = IOCSigner.generate(issuer="raucle.io")
    signer.save_private_key("issuer.pem")
    ioc = signer.sign_ioc(
        kind="regex",
        pattern=r"(?i)ignore\s+all\s+previous",
        severity="high",
        categories=["direct_injection"],
        description="Classic instruction-override jailbreak",
    )
    feed = signer.build_feed([ioc], feed_id="raucle/core")
    feed.save("feed.json")

Usage (consumer)::

    from raucle_detect.feed import Feed, FeedStore
    feed = Feed.load("feed.json")
    feed.verify(pubkey_pem=trusted_pem)  # raises if signature/root invalid
    store = FeedStore.open("~/.raucle/feeds")
    store.merge(feed)
    rules = store.as_pattern_rules()  # feed into Scanner(extra_patterns=...)

Design
------
- IOC kinds: ``regex``, ``substring``, ``unicode_signature``. Future:
  ``embedding`` (cosine), ``ast`` (tool-call shape).
- Canonical JSON for hashing; Ed25519 over the canonical bytes.
- Feed manifest carries a Merkle root over sorted IOC content hashes,
  signed once. Adding/removing IOCs requires re-signing.
- Revocation: publish a feed entry with ``revokes=[<content_hash>]``.
  Consumers honour revocations from the same issuer only.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonicalisation primitives (mirrors provenance.py for consistency)
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _now() -> int:
    return int(dt.datetime.now(dt.timezone.utc).timestamp())


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


IOC_KINDS = frozenset({"regex", "substring", "unicode_signature"})
SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass
class SignedIOC:
    """A single signed Indicator of Compromise.

    The ``content_hash`` is the canonical identifier and binds every
    field below the signature. The ``signature`` covers the canonical
    JSON of :meth:`body`.
    """

    kind: str
    pattern: str
    severity: str
    categories: list[str]
    description: str
    issuer: str
    key_id: str
    issued_at: int
    revokes: list[str] = field(default_factory=list)
    expires_at: int | None = None
    content_hash: str = ""
    signature: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "pattern": self.pattern,
            "severity": self.severity,
            "categories": sorted(self.categories),
            "description": self.description,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "issued_at": self.issued_at,
            "revokes": sorted(self.revokes),
            "expires_at": self.expires_at,
        }

    def compute_content_hash(self) -> str:
        return "sha256:" + _sha256_hex(_canonical_json(self.body()))

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["content_hash"] = self.content_hash
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedIOC:
        return cls(
            kind=d["kind"],
            pattern=d["pattern"],
            severity=d["severity"],
            categories=list(d.get("categories", [])),
            description=d.get("description", ""),
            issuer=d["issuer"],
            key_id=d["key_id"],
            issued_at=int(d["issued_at"]),
            revokes=list(d.get("revokes", [])),
            expires_at=d.get("expires_at"),
            content_hash=d.get("content_hash", ""),
            signature=d.get("signature", ""),
        )

    def validate_shape(self) -> None:
        if self.kind not in IOC_KINDS:
            raise ValueError(f"unknown ioc kind: {self.kind!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")
        if not self.pattern:
            raise ValueError("pattern must not be empty")
        if not self.issuer:
            raise ValueError("issuer must not be empty")


@dataclass
class Feed:
    """A signed bundle of IOCs from a single issuer.

    The feed manifest carries a Merkle root over the sorted content
    hashes of its IOCs and a single signature over the manifest body.
    Every IOC inside is *also* individually signed -- the feed
    signature is a convenience for batch verification, not a
    substitute.
    """

    feed_id: str
    issuer: str
    key_id: str
    public_key_pem: str
    issued_at: int
    iocs: list[SignedIOC] = field(default_factory=list)
    merkle_root: str = ""
    signature: str = ""
    version: str = "raucle-feed/v1"

    def compute_merkle_root(self) -> str:
        hashes = sorted(i.content_hash for i in self.iocs)
        if not hashes:
            return "sha256:" + _sha256_hex(b"")
        return "sha256:" + _sha256_hex(_canonical_json(hashes))

    def manifest_body(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "feed_id": self.feed_id,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "issued_at": self.issued_at,
            "merkle_root": self.merkle_root,
            "ioc_count": len(self.iocs),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.manifest_body(),
            "signature": self.signature,
            "iocs": [i.to_dict() for i in self.iocs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Feed:
        return cls(
            feed_id=d["feed_id"],
            issuer=d["issuer"],
            key_id=d["key_id"],
            public_key_pem=d["public_key_pem"],
            issued_at=int(d["issued_at"]),
            iocs=[SignedIOC.from_dict(i) for i in d.get("iocs", [])],
            merkle_root=d.get("merkle_root", ""),
            signature=d.get("signature", ""),
            version=d.get("version", "raucle-feed/v1"),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls, path: str | Path) -> Feed:
        return cls.from_dict(json.loads(Path(path).read_text()))

    def verify(self, *, pubkey_pem: str | None = None) -> None:
        """Verify Merkle root, manifest signature, and every IOC signature.

        Raises ``ValueError`` on any mismatch. If ``pubkey_pem`` is
        provided, it must match the feed's embedded key; this is the
        consumer's pinning check.
        """
        if pubkey_pem is not None and pubkey_pem.strip() != self.public_key_pem.strip():
            raise ValueError("pinned pubkey does not match feed's embedded public key")

        expected_root = self.compute_merkle_root()
        if expected_root != self.merkle_root:
            raise ValueError(
                f"merkle root mismatch: feed declares {self.merkle_root}, computed {expected_root}"
            )

        pub = _load_pubkey(self.public_key_pem)
        _ed25519_verify(pub, _canonical_json(self.manifest_body()), _b64d(self.signature))

        for ioc in self.iocs:
            expected_h = ioc.compute_content_hash()
            if expected_h != ioc.content_hash:
                raise ValueError(
                    f"ioc content_hash mismatch: declared {ioc.content_hash}, "
                    f"computed {expected_h}"
                )
            _ed25519_verify(pub, _canonical_json(ioc.body()), _b64d(ioc.signature))


# ---------------------------------------------------------------------------
# Crypto helpers (lazy-import cryptography)
# ---------------------------------------------------------------------------


def _require_crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "raucle_detect.feed requires the [compliance] extra: "
            "pip install 'raucle-detect[compliance]'"
        ) from exc
    return serialization, ed25519


def _load_pubkey(pem: str) -> Any:
    serialization, _ = _require_crypto()
    return serialization.load_pem_public_key(pem.encode("ascii"))


def _ed25519_verify(pub: Any, data: bytes, sig: bytes) -> None:
    try:
        pub.verify(sig, data)
    except Exception as exc:
        raise ValueError(f"signature verification failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------


class IOCSigner:
    """Holds an Ed25519 private key and signs IOCs / feeds."""

    def __init__(self, issuer: str, private_key: Any) -> None:
        if not issuer:
            raise ValueError("issuer must not be empty")
        self.issuer = issuer
        self._priv = private_key
        serialization, _ = _require_crypto()
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = pub_pem.decode("ascii")
        self.key_id = _sha256_hex(pub_pem)[:16]

    @classmethod
    def generate(cls, issuer: str) -> IOCSigner:
        _, ed25519 = _require_crypto()
        return cls(issuer=issuer, private_key=ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def load_private_key(cls, issuer: str, path: str | Path) -> IOCSigner:
        serialization, _ = _require_crypto()
        priv = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        return cls(issuer=issuer, private_key=priv)

    def save_private_key(self, path: str | Path) -> None:
        serialization, _ = _require_crypto()
        pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        Path(path).write_bytes(pem)

    def sign_ioc(
        self,
        *,
        kind: str,
        pattern: str,
        severity: str,
        categories: list[str],
        description: str = "",
        revokes: list[str] | None = None,
        expires_at: int | None = None,
    ) -> SignedIOC:
        ioc = SignedIOC(
            kind=kind,
            pattern=pattern,
            severity=severity,
            categories=list(categories),
            description=description,
            issuer=self.issuer,
            key_id=self.key_id,
            issued_at=_now(),
            revokes=list(revokes or []),
            expires_at=expires_at,
        )
        ioc.validate_shape()
        ioc.content_hash = ioc.compute_content_hash()
        ioc.signature = _b64(self._priv.sign(_canonical_json(ioc.body())))
        return ioc

    def build_feed(self, iocs: list[SignedIOC], *, feed_id: str) -> Feed:
        for ioc in iocs:
            if ioc.issuer != self.issuer or ioc.key_id != self.key_id:
                raise ValueError(
                    f"ioc {ioc.content_hash} was signed by a different issuer/key"
                )
        feed = Feed(
            feed_id=feed_id,
            issuer=self.issuer,
            key_id=self.key_id,
            public_key_pem=self.public_key_pem,
            issued_at=_now(),
            iocs=list(iocs),
        )
        feed.merkle_root = feed.compute_merkle_root()
        feed.signature = _b64(self._priv.sign(_canonical_json(feed.manifest_body())))
        return feed


# ---------------------------------------------------------------------------
# Consumer: persistent store + scanner integration
# ---------------------------------------------------------------------------


class FeedStore:
    """A directory-backed store of verified feeds.

    Each subscribed feed is saved as ``<feed_id>.json``. Calling
    :meth:`merge` re-verifies and atomically replaces the on-disk
    copy. Revocations from the same issuer are honoured when
    rendering pattern rules.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @classmethod
    def open(cls, path: str | Path) -> FeedStore:
        return cls(Path(path).expanduser())

    def _feed_path(self, feed_id: str) -> Path:
        safe = feed_id.replace("/", "__").replace("..", "_")
        return self.root / f"{safe}.json"

    def merge(self, feed: Feed, *, pubkey_pem: str | None = None) -> None:
        feed.verify(pubkey_pem=pubkey_pem)
        path = self._feed_path(feed.feed_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(feed.to_dict(), indent=2, ensure_ascii=False))
        tmp.replace(path)

    def list_feeds(self) -> list[Feed]:
        feeds: list[Feed] = []
        for p in sorted(self.root.glob("*.json")):
            try:
                feeds.append(Feed.load(p))
            except Exception as exc:
                logger.warning("skipping unreadable feed %s: %s", p, exc)
        return feeds

    def all_iocs(self) -> list[SignedIOC]:
        """Return all non-revoked, non-expired IOCs across all subscribed feeds."""
        now = _now()
        # Collect revocations per-issuer first; an issuer can only revoke its own IOCs.
        revocations: dict[str, set[str]] = {}
        all_iocs: list[SignedIOC] = []
        for feed in self.list_feeds():
            for ioc in feed.iocs:
                revocations.setdefault(ioc.issuer, set()).update(ioc.revokes)
                all_iocs.append(ioc)
        result: list[SignedIOC] = []
        for ioc in all_iocs:
            if ioc.content_hash in revocations.get(ioc.issuer, set()):
                continue
            if ioc.expires_at is not None and now >= ioc.expires_at:
                continue
            result.append(ioc)
        return result

    def as_pattern_rules(self) -> list[dict[str, Any]]:
        """Render the live IOC set as Scanner-compatible pattern rules."""
        rules: list[dict[str, Any]] = []
        for ioc in self.all_iocs():
            if ioc.kind == "regex":
                pattern = ioc.pattern
            elif ioc.kind == "substring":
                import re

                pattern = re.escape(ioc.pattern)
            elif ioc.kind == "unicode_signature":
                # pattern is a hex codepoint list, e.g. "200B,202E"; match any.
                cps = [c.strip() for c in ioc.pattern.split(",") if c.strip()]
                pattern = "|".join(f"\\u{c.zfill(4)}" for c in cps)
            else:
                continue
            cats = list(ioc.categories) or ["feed_ioc"]
            rules.append(
                {
                    "id": f"feed:{ioc.issuer}:{ioc.content_hash[7:23]}",
                    "patterns": [pattern],
                    "category": cats[0],
                    "severity": ioc.severity,
                    "score": _severity_to_score(ioc.severity),
                    "technique": ioc.description[:120] or "signed_ioc",
                    "source": f"feed:{ioc.issuer}",
                }
            )
        return rules


def _severity_to_score(severity: str) -> float:
    return {"low": 0.4, "medium": 0.65, "high": 0.85, "critical": 0.95}.get(severity, 0.5)


# ---------------------------------------------------------------------------
# Fetcher (stdlib only, optional)
# ---------------------------------------------------------------------------


def fetch_feed(url: str, *, timeout: float = 10.0) -> Feed:
    """Fetch a feed over HTTPS. The caller MUST then verify against a pinned pubkey."""
    from urllib.request import Request, urlopen

    req = Request(url, headers={"User-Agent": "raucle-detect-feed/1"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https expected, caller verifies
        data = resp.read()
    return Feed.from_dict(json.loads(data))
