"""Tests for the tamper-evident audit chain."""

from __future__ import annotations

import json

import pytest

cryptography = pytest.importorskip("cryptography")

from raucle_detect.audit import (
    AuditVerifier,
    Ed25519Signer,
    HashChainSink,
    _merkle_root,
)


class TestHashChainSink:
    def test_basic_append(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"verdict": "CLEAN"})
            sink.append({"verdict": "MALICIOUS"})
        # Two event records (no checkpoints — no signer)
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_chain_links_records(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            r1 = sink.append({"verdict": "CLEAN"})
            r2 = sink.append({"verdict": "SUSPICIOUS"})
        assert r2["prev_hash"] == r1["hash"]
        assert r1["index"] == 0
        assert r2["index"] == 1

    def test_resume_existing_chain(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            r1 = sink.append({"verdict": "CLEAN"})

        # Reopen and append
        with HashChainSink(path) as sink:
            r2 = sink.append({"verdict": "MALICIOUS"})

        assert r2["index"] == 1
        assert r2["prev_hash"] == r1["hash"]

    def test_signed_checkpoint_emitted(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=2) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})  # triggers checkpoint at index 2
            sink.append({"v": "c"})

        lines = path.read_text().strip().split("\n")
        records = [json.loads(line) for line in lines]
        checkpoints = [r for r in records if r.get("checkpoint")]
        assert len(checkpoints) >= 1
        assert "merkle_root" in checkpoints[0]
        assert "signature" in checkpoints[0]


class TestAuditVerifier:
    def test_clean_chain_verifies(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is True
        assert report.event_count == 2
        assert report.invalid_signatures == 0

    def test_tampered_record_detected(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "original"})
            sink.append({"v": "second"})

        # Tamper with the first record
        lines = path.read_text().strip().split("\n")
        first = json.loads(lines[0])
        first["event"]["v"] = "modified"
        lines[0] = json.dumps(first)
        path.write_text("\n".join(lines) + "\n")

        report = AuditVerifier().verify_chain(path)
        assert report.valid is False
        assert report.first_invalid_index == 0

    def test_invalid_signature_detected(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
            sink.append({"v": "a"})

        # Verify with a DIFFERENT key
        wrong_signer = Ed25519Signer.generate()
        report = AuditVerifier(public_key_pem=wrong_signer.public_key_pem()).verify_chain(path)
        assert report.valid is False
        assert report.invalid_signatures >= 1


class TestMerkleRoot:
    def test_empty_list(self):
        # Should return sha256 of empty bytes
        assert _merkle_root([]) == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_single_leaf(self):
        h = "a" * 64
        assert _merkle_root([h]) == h

    def test_two_leaves_deterministic(self):
        r1 = _merkle_root(["a" * 64, "b" * 64])
        r2 = _merkle_root(["a" * 64, "b" * 64])
        assert r1 == r2 and len(r1) == 64

    def test_odd_leaves_duplicates_last(self):
        # Three leaves should hash without error (last is duplicated at each odd level)
        r = _merkle_root(["a" * 64, "b" * 64, "c" * 64])
        assert len(r) == 64
