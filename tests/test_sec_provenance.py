"""Security regression tests for the provenance verifier.

Covers three findings, all VERIFIER-side / parse-hardening (no receipt wire
format change):

- PROV-CAP-OPEN  — unknown agent_key_id must fail when capabilities supplied.
- TAINT-LAUNDER  — a SANITISATION receipt may only clear tags the issuing
                   agent's statement authorises (sanitisation_authority).
- JWS-PARSE      — from_jws hardening: size caps, duplicate-key rejection,
                   strict JOSE header (alg + crit) enforcement.
"""

from __future__ import annotations

import json

import pytest

from raucle_detect.provenance import (
    AgentIdentity,
    CapabilityStatement,
    Operation,
    ProvenanceLogger,
    ProvenanceReceipt,
    ProvenanceVerifier,
    _b64url_encode,
    _canonical_json,
)


def _stmt(identity: AgentIdentity, **overrides) -> CapabilityStatement:
    """A capability statement matching an identity's key, with overrides.

    Self-signed by the identity so the verifier (which now authenticates
    statements) trusts it — mirroring real usage.
    """
    import base64

    from raucle_detect.provenance import _canonical_json

    s = identity.statement
    stmt = CapabilityStatement(
        agent_id=s.agent_id,
        key_id=s.key_id,
        public_key_pem=s.public_key_pem,
        allowed_models=overrides.get("allowed_models", list(s.allowed_models)),
        allowed_tools=overrides.get("allowed_tools", list(s.allowed_tools)),
        sanitisation_authority=overrides.get("sanitisation_authority", []),
    )
    stmt.signature = base64.b64encode(identity.sign(_canonical_json(stmt.body()))).decode("ascii")
    return stmt


# ---------------------------------------------------------------------------
# PROV-CAP-OPEN
# ---------------------------------------------------------------------------


class TestProvCapOpen:
    def test_unknown_key_fails_when_capabilities_supplied(self, tmp_path):
        identity = AgentIdentity.generate(agent_id="agent:unknown")
        chain = tmp_path / "chain.jsonl"
        with ProvenanceLogger(agent=identity, sink_path=chain) as log:
            log.record_user_input(text="hi")

        keys = {identity.key_id: identity.public_key_pem()}
        # Capabilities map supplied, but it does NOT contain this key.
        other = AgentIdentity.generate(agent_id="agent:other")
        verifier = ProvenanceVerifier(public_keys=keys, capabilities={other.key_id: _stmt(other)})
        report = verifier.verify_chain(chain)
        assert report.valid is False
        assert report.capability_violations >= 1
        assert any("unknown key" in e for e in report.errors)

    def test_known_key_still_passes(self, tmp_path):
        identity = AgentIdentity.generate(agent_id="agent:known")
        chain = tmp_path / "chain.jsonl"
        with ProvenanceLogger(agent=identity, sink_path=chain) as log:
            log.record_user_input(text="hi")

        verifier = ProvenanceVerifier(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities={identity.key_id: _stmt(identity)},
        )
        report = verifier.verify_chain(chain)
        assert report.valid is True
        assert report.capability_violations == 0

    def test_no_capabilities_map_keeps_old_behaviour(self, tmp_path):
        # When no capabilities are supplied, unknown keys are NOT a capability
        # failure (signature/DAG/taint still run as before).
        identity = AgentIdentity.generate(agent_id="agent:nocap")
        chain = tmp_path / "chain.jsonl"
        with ProvenanceLogger(agent=identity, sink_path=chain) as log:
            log.record_user_input(text="hi")

        verifier = ProvenanceVerifier(public_keys={identity.key_id: identity.public_key_pem()})
        report = verifier.verify_chain(chain)
        assert report.valid is True
        assert report.capability_violations == 0


# ---------------------------------------------------------------------------
# TAINT-LAUNDER
# ---------------------------------------------------------------------------


class TestTaintLaunder:
    def _build_sanitising_chain(self, tmp_path, removed):
        identity = AgentIdentity.generate(agent_id="agent:sani")
        chain = tmp_path / "chain.jsonl"
        with ProvenanceLogger(agent=identity, sink_path=chain) as log:
            h = log.record_user_input(text="hi", taint={"external_user", "pii"})
            log.record_sanitisation(
                parents=[h],
                removed_taints=removed,
                sanitiser_id="redactor",
                input_text="hi",
                output_text="ok",
            )
        return identity, chain

    def test_unauthorised_sanitisation_rejected(self, tmp_path):
        identity, chain = self._build_sanitising_chain(tmp_path, {"external_user"})
        # Statement authorises clearing 'pii' only, NOT 'external_user'.
        caps = {identity.key_id: _stmt(identity, sanitisation_authority=["pii"])}
        verifier = ProvenanceVerifier(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities=caps,
        )
        report = verifier.verify_chain(chain)
        assert report.valid is False
        assert report.unauthorised_sanitisations >= 1
        assert any("taint laundering" in e for e in report.errors)

    def test_authorised_sanitisation_passes(self, tmp_path):
        identity, chain = self._build_sanitising_chain(tmp_path, {"pii"})
        caps = {identity.key_id: _stmt(identity, sanitisation_authority=["pii"])}
        verifier = ProvenanceVerifier(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities=caps,
        )
        report = verifier.verify_chain(chain)
        assert report.valid is True
        assert report.unauthorised_sanitisations == 0

    def test_wildcard_authority_allows_any(self, tmp_path):
        identity, chain = self._build_sanitising_chain(tmp_path, {"external_user"})
        caps = {identity.key_id: _stmt(identity, sanitisation_authority=["*"])}
        verifier = ProvenanceVerifier(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities=caps,
        )
        report = verifier.verify_chain(chain)
        assert report.valid is True

    def test_empty_authority_denies_all(self, tmp_path):
        identity, chain = self._build_sanitising_chain(tmp_path, {"pii"})
        # Default empty sanitisation_authority => deny-all.
        caps = {identity.key_id: _stmt(identity)}
        verifier = ProvenanceVerifier(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities=caps,
        )
        report = verifier.verify_chain(chain)
        assert report.valid is False
        assert report.unauthorised_sanitisations >= 1

    def test_no_caps_preserves_old_trusting_behaviour(self, tmp_path):
        identity, chain = self._build_sanitising_chain(tmp_path, {"pii"})
        verifier = ProvenanceVerifier(public_keys={identity.key_id: identity.public_key_pem()})
        report = verifier.verify_chain(chain)
        assert report.valid is True
        assert report.unauthorised_sanitisations == 0


class TestCapabilityStatementSanitisation:
    def test_permits_sanitising(self):
        s = CapabilityStatement(
            agent_id="agent:x",
            key_id="k",
            public_key_pem="",
            sanitisation_authority=["pii"],
        )
        assert s.permits_sanitising("pii") is True
        assert s.permits_sanitising("external_user") is False

    def test_permits_sanitising_wildcard(self):
        s = CapabilityStatement(
            agent_id="agent:x",
            key_id="k",
            public_key_pem="",
            sanitisation_authority=["*"],
        )
        assert s.permits_sanitising("anything") is True

    def test_empty_is_deny_all(self):
        s = CapabilityStatement(agent_id="agent:x", key_id="k", public_key_pem="")
        assert s.permits_sanitising("pii") is False

    def test_body_backward_compatible_when_empty(self):
        # Field omitted from signed body when empty => old statements verify.
        s = CapabilityStatement(agent_id="agent:x", key_id="k", public_key_pem="")
        assert "sanitisation_authority" not in s.body()

    def test_body_includes_field_when_set(self):
        s = CapabilityStatement(
            agent_id="agent:x",
            key_id="k",
            public_key_pem="",
            sanitisation_authority=["pii"],
        )
        assert s.body()["sanitisation_authority"] == ["pii"]

    def test_signed_statement_still_verifies_with_new_field(self):
        # Round-trip self-sign/verify with the new field set proves the
        # signature path is unaffected.
        ident = AgentIdentity.generate(
            agent_id="agent:sig",
        )
        ident.statement.sanitisation_authority = ["pii"]
        from cryptography.hazmat.primitives import serialization

        sig = ident.sign(_canonical_json(ident.statement.body()))
        pub = serialization.load_pem_public_key(ident.public_key_pem())
        pub.verify(sig, _canonical_json(ident.statement.body()))  # no raise


# ---------------------------------------------------------------------------
# JWS-PARSE
# ---------------------------------------------------------------------------


def _signed_receipt(identity: AgentIdentity) -> ProvenanceReceipt:
    r = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.USER_INPUT,
        taint=["external_user"],
        issued_at=1,
    )
    r.sign(identity)
    return r


class TestJwsParse:
    def test_valid_receipt_parses_strict(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        r = _signed_receipt(ident)
        parsed = ProvenanceReceipt.from_jws(r.jws, strict=True)
        assert parsed.agent_id == ident.agent_id
        assert parsed.receipt_hash == r.receipt_hash

    def test_oversized_jws_rejected(self):
        big = "a" * (ProvenanceReceipt.MAX_JWS_BYTES + 1)
        with pytest.raises(ValueError, match="too large"):
            ProvenanceReceipt.from_jws(big)

    def test_oversized_payload_rejected(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        header = {"alg": "EdDSA", "crit": ["raucle/v1"], "raucle/v1": "provenance"}
        # Payload under the JWS cap but over the payload cap.
        huge_payload = {
            "agent_id": "agent:p",
            "agent_key_id": ident.key_id,
            "operation": "user_input",
            "pad": "x" * (ProvenanceReceipt.MAX_PAYLOAD_BYTES),
        }
        jws = (
            _b64url_encode(_canonical_json(header))
            + "."
            + _b64url_encode(_canonical_json(huge_payload))
            + ".sig"
        )
        assert len(jws) <= ProvenanceReceipt.MAX_JWS_BYTES
        with pytest.raises(ValueError, match="payload too large"):
            ProvenanceReceipt.from_jws(jws)

    def test_duplicate_keys_rejected(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        header = {"alg": "EdDSA", "crit": ["raucle/v1"], "raucle/v1": "provenance"}
        raw_payload = (
            '{"agent_id":"agent:p","agent_id":"agent:evil",'
            f'"agent_key_id":"{ident.key_id}","operation":"user_input"}}'
        )
        jws = (
            _b64url_encode(_canonical_json(header))
            + "."
            + _b64url_encode(raw_payload.encode())
            + ".sig"
        )
        with pytest.raises(ValueError, match="duplicate key"):
            ProvenanceReceipt.from_jws(jws)

    def _jws_with_header(self, ident, header):
        r = _signed_receipt(ident)
        _h, payload_b64, sig_b64 = r.jws.split(".")
        return _b64url_encode(_canonical_json(header)) + "." + payload_b64 + "." + sig_b64

    def test_wrong_alg_rejected_strict(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        jws = self._jws_with_header(
            ident, {"alg": "none", "crit": ["raucle/v1"], "raucle/v1": "provenance"}
        )
        with pytest.raises(ValueError, match="alg"):
            ProvenanceReceipt.from_jws(jws, strict=True)

    def test_missing_crit_rejected_strict(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        jws = self._jws_with_header(ident, {"alg": "EdDSA"})
        with pytest.raises(ValueError, match="crit"):
            ProvenanceReceipt.from_jws(jws, strict=True)

    def test_unknown_crit_param_rejected_strict(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        jws = self._jws_with_header(
            ident,
            {
                "alg": "EdDSA",
                "crit": ["raucle/v1", "evil/v9"],
                "raucle/v1": "provenance",
                "evil/v9": "x",
            },
        )
        with pytest.raises(ValueError, match="unknown critical"):
            ProvenanceReceipt.from_jws(jws, strict=True)

    def test_crit_param_named_but_absent_rejected(self):
        ident = AgentIdentity.generate(agent_id="agent:p")
        # crit names raucle/v1 but the header field itself is missing.
        jws = self._jws_with_header(ident, {"alg": "EdDSA", "crit": ["raucle/v1"]})
        with pytest.raises(ValueError, match="absent"):
            ProvenanceReceipt.from_jws(jws, strict=True)

    def test_non_strict_tolerates_stub_header(self):
        # The conformance harness reconstructs receipts via a stub header.
        ident = AgentIdentity.generate(agent_id="agent:p")
        r = _signed_receipt(ident)
        _h, payload_b64, _sig = r.jws.split(".")
        parsed = ProvenanceReceipt.from_jws("x." + payload_b64 + ".x")
        assert parsed.agent_id == ident.agent_id

    def test_verifier_rejects_tampered_header(self, tmp_path):
        # End-to-end: a chain whose header alg is swapped fails verification
        # (strict parse) rather than being silently accepted.
        ident = AgentIdentity.generate(agent_id="agent:p")
        chain = tmp_path / "chain.jsonl"
        with ProvenanceLogger(agent=ident, sink_path=chain) as log:
            log.record_user_input(text="hi")

        line = json.loads(chain.read_text().strip())
        h_b64, p_b64, s_b64 = line["jws"].split(".")
        bad_header = {"alg": "none", "crit": ["raucle/v1"], "raucle/v1": "provenance"}
        line["jws"] = _b64url_encode(_canonical_json(bad_header)) + "." + p_b64 + "." + s_b64
        chain.write_text(json.dumps(line) + "\n")

        verifier = ProvenanceVerifier(public_keys={ident.key_id: ident.public_key_pem()})
        report = verifier.verify_chain(chain)
        assert report.valid is False
