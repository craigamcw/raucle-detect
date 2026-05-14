"""Tests for federated signed-IOC feeds (v0.8.0)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from raucle_detect.feed import Feed, FeedStore, IOCSigner, SignedIOC
from raucle_detect.scanner import Scanner


def _make_signer(issuer: str = "test.example") -> IOCSigner:
    return IOCSigner.generate(issuer=issuer)


def test_ioc_roundtrip_and_signature():
    s = _make_signer()
    ioc = s.sign_ioc(
        kind="regex",
        pattern=r"(?i)ignore\s+all\s+previous",
        severity="high",
        categories=["direct_injection"],
        description="classic override",
    )
    assert ioc.content_hash.startswith("sha256:")
    assert ioc.content_hash == ioc.compute_content_hash()
    # Roundtrip through dict
    d = ioc.to_dict()
    ioc2 = SignedIOC.from_dict(d)
    assert ioc2.content_hash == ioc.content_hash
    assert ioc2.signature == ioc.signature


def test_feed_verifies_with_correct_pubkey(tmp_path: Path):
    s = _make_signer()
    iocs = [
        s.sign_ioc(
            kind="regex",
            pattern=r"(?i)ignore",
            severity="high",
            categories=["direct_injection"],
        ),
        s.sign_ioc(
            kind="substring",
            pattern="DROP TABLE",
            severity="critical",
            categories=["sql_injection"],
        ),
    ]
    feed = s.build_feed(iocs, feed_id="test/core")
    feed_path = tmp_path / "feed.json"
    feed.save(feed_path)

    loaded = Feed.load(feed_path)
    loaded.verify(pubkey_pem=s.public_key_pem)


def test_feed_rejects_pinned_pubkey_mismatch(tmp_path: Path):
    s1 = _make_signer()
    s2 = _make_signer()
    feed = s1.build_feed(
        [s1.sign_ioc(kind="substring", pattern="bad", severity="low", categories=["x"])],
        feed_id="test/x",
    )
    with pytest.raises(ValueError, match="pinned pubkey"):
        feed.verify(pubkey_pem=s2.public_key_pem)


def test_feed_rejects_tampered_pattern(tmp_path: Path):
    s = _make_signer()
    feed = s.build_feed(
        [s.sign_ioc(kind="substring", pattern="orig", severity="low", categories=["x"])],
        feed_id="t/x",
    )
    d = feed.to_dict()
    d["iocs"][0]["pattern"] = "tampered"
    tampered = Feed.from_dict(d)
    with pytest.raises(ValueError):
        tampered.verify(pubkey_pem=s.public_key_pem)


def test_feed_rejects_merkle_root_mutation(tmp_path: Path):
    s = _make_signer()
    feed = s.build_feed(
        [s.sign_ioc(kind="substring", pattern="x", severity="low", categories=["x"])],
        feed_id="t/x",
    )
    d = feed.to_dict()
    d["merkle_root"] = "sha256:" + "0" * 64
    bad = Feed.from_dict(d)
    with pytest.raises(ValueError, match="merkle root"):
        bad.verify(pubkey_pem=s.public_key_pem)


def test_feed_store_merge_and_pattern_render(tmp_path: Path):
    s = _make_signer(issuer="raucle.io")
    feed = s.build_feed(
        [
            s.sign_ioc(
                kind="regex",
                pattern=r"(?i)ignore\s+all\s+previous",
                severity="high",
                categories=["direct_injection"],
                description="classic",
            )
        ],
        feed_id="raucle/core",
    )
    store = FeedStore.open(tmp_path / "feeds")
    store.merge(feed, pubkey_pem=s.public_key_pem)

    rules = store.as_pattern_rules()
    assert len(rules) == 1
    assert rules[0]["category"] == "direct_injection"
    assert rules[0]["severity"] == "high"
    assert rules[0]["source"] == "feed:raucle.io"


def test_revocation_drops_ioc(tmp_path: Path):
    s = _make_signer()
    ioc = s.sign_ioc(kind="substring", pattern="bad", severity="low", categories=["x"])
    feed_v1 = s.build_feed([ioc], feed_id="t/v1")
    revoker = s.sign_ioc(
        kind="substring",
        pattern="_revocation_",
        severity="low",
        categories=["meta"],
        revokes=[ioc.content_hash],
    )
    feed_v2 = s.build_feed([revoker], feed_id="t/v2")

    store = FeedStore.open(tmp_path / "store")
    store.merge(feed_v1, pubkey_pem=s.public_key_pem)
    store.merge(feed_v2, pubkey_pem=s.public_key_pem)

    live = {i.content_hash for i in store.all_iocs()}
    assert ioc.content_hash not in live
    assert revoker.content_hash in live


def test_cross_issuer_revocation_ignored(tmp_path: Path):
    s1 = _make_signer(issuer="a.example")
    s2 = _make_signer(issuer="b.example")
    target = s1.sign_ioc(kind="substring", pattern="x", severity="low", categories=["y"])
    hostile = s2.sign_ioc(
        kind="substring",
        pattern="_rev_",
        severity="low",
        categories=["y"],
        revokes=[target.content_hash],
    )
    store = FeedStore.open(tmp_path / "s")
    store.merge(s1.build_feed([target], feed_id="a/x"), pubkey_pem=s1.public_key_pem)
    store.merge(s2.build_feed([hostile], feed_id="b/x"), pubkey_pem=s2.public_key_pem)

    live = {i.content_hash for i in store.all_iocs()}
    # s2 cannot revoke s1's IOC.
    assert target.content_hash in live


def test_scanner_picks_up_feed_iocs(tmp_path: Path):
    s = _make_signer(issuer="raucle.io")
    feed = s.build_feed(
        [
            s.sign_ioc(
                kind="substring",
                pattern="QUANTUM_BACKDOOR_TOKEN",
                severity="critical",
                categories=["direct_injection"],
                description="novel attack",
            )
        ],
        feed_id="raucle/novel",
    )
    store = FeedStore.open(tmp_path / "feeds")
    store.merge(feed, pubkey_pem=s.public_key_pem)

    scanner = Scanner(mode="strict", feed_store=store)
    result = scanner.scan("Please call QUANTUM_BACKDOOR_TOKEN now")
    assert any("feed:raucle.io" in r for r in result.matched_rules)
    assert result.verdict in {"SUSPICIOUS", "MALICIOUS"}


def test_persisted_feed_survives_reload(tmp_path: Path):
    s = _make_signer()
    feed = s.build_feed(
        [s.sign_ioc(kind="substring", pattern="x", severity="low", categories=["y"])],
        feed_id="t/p",
    )
    root = tmp_path / "feeds"
    FeedStore.open(root).merge(feed, pubkey_pem=s.public_key_pem)
    # Re-open from disk
    store2 = FeedStore.open(root)
    assert len(store2.list_feeds()) == 1
    assert len(store2.all_iocs()) == 1


def test_drafts_to_signed_feed_pipeline(tmp_path: Path):
    """Mirrors the `raucle-detect feed sign` flow end-to-end."""
    s = _make_signer()
    drafts = [
        {
            "kind": "regex",
            "pattern": r"(?i)reveal\s+system\s+prompt",
            "severity": "high",
            "categories": ["prompt_extraction"],
            "description": "system-prompt extraction",
        }
    ]
    iocs = [
        s.sign_ioc(
            kind=d["kind"],
            pattern=d["pattern"],
            severity=d["severity"],
            categories=d["categories"],
            description=d["description"],
        )
        for d in drafts
    ]
    feed = s.build_feed(iocs, feed_id="t/drafts")
    out = tmp_path / "feed.json"
    feed.save(out)

    on_disk = json.loads(out.read_text())
    assert on_disk["ioc_count"] == 1
    Feed.load(out).verify(pubkey_pem=s.public_key_pem)
