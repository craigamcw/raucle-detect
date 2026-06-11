"""Tests for the Agent Trust Registry (P1) — the cross-org trust-anchor layer."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from raucle_detect.audit import Ed25519Signer  # noqa: E402
from raucle_detect.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle_detect.trust_registry import (  # noqa: E402
    REGISTRY_VERSION,
    RegistryIntegrityError,
    TrustRegistry,
)


def _issuer(name: str) -> CapabilityIssuer:
    return CapabilityIssuer.generate(issuer=name)


class TestPublishResolve:
    def test_publish_returns_canonical_key_id(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        assert kid == iss.key_id  # matches cap:v1 key_id derivation

    def test_resolve_active_key(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        rec = reg.resolve(kid)
        assert rec is not None and rec.issuer == "Org A" and not rec.revoked
        assert reg.public_key(kid) == iss.public_key_pem

    def test_unknown_key_is_none_fail_closed(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        assert reg.public_key("deadbeefdeadbeef") is None
        assert reg.resolve("deadbeefdeadbeef") is None


class TestRevocation:
    def test_revoke_fails_closed(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        reg.revoke(kid, reason="compromised")
        assert reg.public_key(kid) is None  # fail-closed
        assert reg.is_revoked(kid)
        # history preserved: the record is still resolvable, marked revoked
        rec = reg.resolve(kid)
        assert rec.revoked and rec.revoked_reason == "compromised"

    def test_republish_reactivates(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("org-a")
        kid = reg.publish(iss.public_key_pem, issuer="Org A")
        reg.revoke(kid)
        assert reg.public_key(kid) is None
        reg.publish(iss.public_key_pem, issuer="Org A")  # re-register
        assert reg.public_key(kid) == iss.public_key_pem


class TestCrossOrgVerification:
    """The network-effect path: org B verifies org A's token via a shared registry,
    with no prior key exchange between A and B."""

    def test_gate_built_from_registry_verifies_foreign_token(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss_a = _issuer("org-a")
        iss_b = _issuer("org-b")
        reg.publish(iss_a.public_key_pem, issuer="Org A")
        kb = reg.publish(iss_b.public_key_pem, issuer="Org B")

        token_a = iss_a.mint(agent_id="agent:a", tool="t", constraints={})
        gate_b = CapabilityGate(trusted_issuers=reg.as_issuer_map())
        assert gate_b.check(token_a, tool="t", args={}).allowed
        assert kb in reg.as_issuer_map()  # both orgs present

    def test_revoked_issuer_drops_from_issuer_map(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss_a = _issuer("org-a")
        ka = reg.publish(iss_a.public_key_pem, issuer="Org A")
        reg.publish(_issuer("org-b").public_key_pem, issuer="Org B")
        reg.revoke(ka)
        assert ka not in reg.as_issuer_map()
        assert len(reg.as_issuer_map()) == 1


class TestIntegrity:
    def test_signed_registry_authenticates(self, tmp_path):
        op = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        loaded = TrustRegistry.load(tmp_path / "r.jsonl")
        assert loaded.verify_integrity(operator_public_pem=op.public_key_pem())

    def test_header_records_version_and_signed_flag(self, tmp_path):
        op = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
        assert reg._entries[0]["version"] == REGISTRY_VERSION
        assert reg._entries[0]["signed"] is True

    def test_tampered_chain_detected(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        lines = (tmp_path / "r.jsonl").read_text().splitlines()
        lines[1] = lines[1].replace('"A"', '"EVIL"')
        (tmp_path / "t.jsonl").write_text("\n".join(lines) + "\n")
        with pytest.raises(RegistryIntegrityError):
            TrustRegistry.load(tmp_path / "t.jsonl")

    def test_wrong_operator_key_rejected(self, tmp_path):
        op = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "r.jsonl", operator_signer=op)
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        loaded = TrustRegistry.load(tmp_path / "r.jsonl")
        with pytest.raises(RegistryIntegrityError):
            loaded.verify_integrity(operator_public_pem=Ed25519Signer.generate().public_key_pem())

    def test_unsigned_registry_chain_only(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")  # no operator signer
        reg.publish(_issuer("a").public_key_pem, issuer="A")
        assert TrustRegistry.load(tmp_path / "r.jsonl").verify_integrity()


class TestPersistenceRoundTrip:
    def test_jsonl_round_trip(self, tmp_path):
        reg = TrustRegistry(tmp_path / "r.jsonl")
        iss = _issuer("a")
        kid = reg.publish(iss.public_key_pem, issuer="A", metadata={"org": "acme"})
        text = (tmp_path / "r.jsonl").read_text()
        reg2 = TrustRegistry.from_jsonl(text)
        rec = reg2.resolve(kid)
        assert rec.public_key_pem == iss.public_key_pem
        assert rec.metadata == {"org": "acme"}

    def test_append_persists_across_instances(self, tmp_path):
        path = tmp_path / "r.jsonl"
        reg = TrustRegistry(path)
        k1 = reg.publish(_issuer("a").public_key_pem, issuer="A")
        reg2 = TrustRegistry(path)  # reopen
        k2 = reg2.publish(_issuer("b").public_key_pem, issuer="B")
        reg3 = TrustRegistry(path)
        assert reg3.public_key(k1) and reg3.public_key(k2)


def test_duplicate_issuer_name_rejected(tmp_path):
    """Two different keys cannot hold the same active issuer name (codex re-review
    #3): the issuer string is the identity verifiers match on."""
    reg = TrustRegistry(tmp_path / "r.jsonl")
    reg.publish(_issuer("a").public_key_pem, issuer="Acme Bank")
    with pytest.raises(ValueError, match="already held by an active key"):
        reg.publish(_issuer("b").public_key_pem, issuer="Acme Bank")  # different key, same name
    # Re-publishing the SAME key under its name is fine.
    same = _issuer("c")
    reg.publish(same.public_key_pem, issuer="Other")
    reg.publish(same.public_key_pem, issuer="Other")  # no raise


def test_issuer_name_reusable_after_revoke(tmp_path):
    reg = TrustRegistry(tmp_path / "r.jsonl")
    k1 = reg.publish(_issuer("a").public_key_pem, issuer="Acme Bank")
    reg.revoke(k1)
    # After revocation the name is free for a new key.
    reg.publish(_issuer("b").public_key_pem, issuer="Acme Bank")  # no raise
