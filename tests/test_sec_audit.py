"""Security regression tests for the tamper-evident audit chain.

Covers two findings:

* AUDIT-DOWNGRADE (HIGH): a verifier constructed *with* a public key must
  reject any chain that is not provably signed (signature stripping).
* AUDIT-TRUNC (CRITICAL): trailing-record truncation must be detectable —
  via a required head signed-checkpoint, and via an externally-anchored
  ``expected_head`` high-water mark.
"""

from __future__ import annotations

import json

from raucle.audit import (
    AuditVerifier,
    Ed25519Signer,
    HashChainSink,
)


def _read(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _write(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")


# ---------------------------------------------------------------------------
# AUDIT-DOWNGRADE
# ---------------------------------------------------------------------------


class TestAuditDowngrade:
    def test_unsigned_chain_with_key_supplied_is_invalid(self, tmp_path):
        """An unsigned chain verified WITH a public key is a signature-stripping
        downgrade and must be rejected."""
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:  # no signer => unsigned
            sink.append({"v": "a"})
            sink.append({"v": "b"})

        signer = Ed25519Signer.generate()
        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is False
        assert report.signed_mode == "unsigned"
        assert any("AUDIT-DOWNGRADE" in e for e in report.errors)

    def test_legacy_headerless_chain_with_key_supplied_is_invalid(self, tmp_path):
        """A legacy chain with no chain_meta header (signed_mode unknown) is
        rejected when a key is supplied."""
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})

        # Strip the chain_meta header to simulate a legacy chain.
        records = [r for r in _read(path) if not r.get("chain_meta")]
        _write(path, records)

        signer = Ed25519Signer.generate()
        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is False
        assert report.signed_mode == "unknown"
        assert any("AUDIT-DOWNGRADE" in e for e in report.errors)

    def test_unsigned_chain_without_key_still_best_effort_valid(self, tmp_path):
        """When NO key is supplied, an unsigned chain is still accepted on a
        best-effort hash-chain basis (behaviour preserved)."""
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})

        report = AuditVerifier().verify_chain(path)
        assert report.valid is True
        assert report.signed_mode == "unsigned"

    def test_properly_signed_closed_chain_with_key_is_valid(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=0) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is True
        assert report.signed_mode == "signed"


# ---------------------------------------------------------------------------
# AUDIT-TRUNC
# ---------------------------------------------------------------------------


class TestAuditTruncation:
    def test_truncating_signed_closed_chain_is_detected(self, tmp_path):
        """Dropping trailing event records from a signed, cleanly-closed chain
        must be detected (valid=False)."""
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=0) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})
            sink.append({"v": "c"})

        # Baseline: intact chain verifies.
        ok = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert ok.valid is True

        # Truncate: drop the final event record (index 2). The head checkpoint
        # now claims index 3 over leaves it can no longer see.
        records = _read(path)
        events = [r for r in records if not r.get("checkpoint") and not r.get("chain_meta")]
        last_event_idx = max(r["index"] for r in events)
        kept = [
            r
            for r in records
            if not (
                not r.get("checkpoint")
                and not r.get("chain_meta")
                and r.get("index") == last_event_idx
            )
        ]
        _write(path, kept)

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is False

    def test_truncating_tail_and_checkpoint_caught_by_required_head_checkpoint(self, tmp_path):
        """Dropping BOTH the final events AND the head checkpoint leaves a
        valid-looking prefix, but the verifier requires a signed checkpoint
        covering the final index — so the unverifiable tail is rejected."""
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=0) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})
            sink.append({"v": "c"})

        # Adversary drops the head checkpoint and the last event. The
        # remaining prefix (chain_meta + events 0,1) is internally consistent.
        records = _read(path)
        kept = [r for r in records if not r.get("checkpoint")]
        kept = [r for r in kept if not (not r.get("chain_meta") and r.get("index") == 2)]
        _write(path, kept)

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is False
        assert any("unverifiable tail" in e for e in report.errors)

    def test_expected_head_index_detects_truncation(self, tmp_path):
        """An externally-anchored expected final index catches truncation even
        with no key supplied (the only way past-checkpoint truncation is
        detectable)."""
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})
            sink.append({"v": "c"})  # final index = 2

        # Truncate: drop the last event.
        records = _read(path)
        kept = [r for r in records if not (not r.get("chain_meta") and r.get("index") == 2)]
        _write(path, kept)

        # No key, but we anchor the expected head externally.
        report = AuditVerifier().verify_chain(path, expected_head={"index": 2})
        assert report.valid is False
        assert any("AUDIT-TRUNC" in e for e in report.errors)

    def test_expected_head_hash_detects_truncation(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})
            rec_b = sink.append({"v": "b"})

        expected_hash = rec_b["hash"]

        # Truncate the last event.
        records = _read(path)
        kept = [r for r in records if not (not r.get("chain_meta") and r.get("index") == 1)]
        _write(path, kept)

        report = AuditVerifier().verify_chain(path, expected_head={"hash": expected_hash})
        assert report.valid is False
        assert any("AUDIT-TRUNC" in e for e in report.errors)

    def test_expected_head_matches_intact_chain(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})
            rec = sink.append({"v": "b"})

        report = AuditVerifier().verify_chain(path, expected_head={"index": 1, "hash": rec["hash"]})
        assert report.valid is True

    def test_close_emits_head_checkpoint(self, tmp_path):
        """A cleanly-closed signed chain has a head checkpoint at the final
        index, so it verifies with a key supplied."""
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=0) as sink:
            sink.append({"v": "a"})

        records = _read(path)
        checkpoints = [r for r in records if r.get("checkpoint")]
        assert checkpoints, "close() must emit a final checkpoint"
        assert checkpoints[-1]["index"] == 1  # covers the single event (idx 0)

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is True
