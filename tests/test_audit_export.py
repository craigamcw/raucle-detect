"""Tests for the audit-export artifact (E1)."""

from __future__ import annotations

import json

import pytest

cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle_detect.audit_export import (
    build_report,
    render_html,
    sign_manifest,
    verify_manifest,
)
from raucle_detect.provenance import AgentIdentity, ProvenanceLogger, ProvenanceVerifier


def _audit_key_pem() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _clean_chain(tmp_path):
    ident = AgentIdentity.generate(agent_id="agent:billing")
    chain = tmp_path / "chain.jsonl"
    with ProvenanceLogger(agent=ident, sink_path=chain) as log:
        log.record_user_input(text="pay alice")
    return ident, chain


def test_report_green_on_clean_chain(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    report = build_report(chain, keys, generated_at=1700000000)
    assert report.summary["chain_valid"] is True
    assert report.summary["red"] == 0
    assert all(n.status == "green" for n in report.nodes)
    # input hashes present and content-addressed
    assert report.input_hashes["chain_sha256"].startswith("sha256:")


def test_report_red_on_tampered_chain(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    rec = json.loads(chain.read_text().strip())
    rec["receipt_hash"] = "sha256:" + "0" * 64  # tamper
    chain.write_text(json.dumps(rec) + "\n")
    keys = {ident.key_id: ident.public_key_pem()}
    report = build_report(chain, keys, generated_at=1700000000)
    assert report.summary["chain_valid"] is False
    assert report.summary["red"] >= 1
    assert any(n.status == "red" for n in report.nodes)


def test_proof_obligations_colour_mapping(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    proofs = [
        {
            "prover": "JSONSchemaProver",
            "status": "PROVEN",
            "hash": "sha256:aa",
            "grammar_hash": "g",
            "policy_hash": "p",
        },
        {
            "prover": "JSONSchemaProver",
            "status": "REFUTED",
            "hash": "sha256:bb",
            "counterexample": {"amount": 999},
        },
        {"prover": "SQLClauseProver", "status": "UNDECIDED", "hash": "sha256:cc"},
    ]
    report = build_report(chain, keys, proofs, generated_at=1700000000)
    by_cert = {o.certificate: o for o in report.obligations}
    assert by_cert["sha256:aa"].status == "green"
    assert by_cert["sha256:bb"].status == "red"
    assert "counterexample" in by_cert["sha256:bb"].detail
    assert by_cert["sha256:cc"].status == "amber"


def test_manifest_signs_and_reverifies(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    report = build_report(chain, keys, generated_at=1700000000)
    manifest = sign_manifest(report, _audit_key_pem())
    assert verify_manifest(manifest) is True
    # Tampering with the body breaks the signature.
    manifest["body"]["summary"]["red"] = 99
    assert verify_manifest(manifest) is False


def test_manifest_is_deterministic(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    r1 = build_report(chain, keys, generated_at=1700000000)
    r2 = build_report(chain, keys, generated_at=1700000000)
    assert r1.body() == r2.body()


def test_html_renders_and_reflects_verdict(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    manifest = sign_manifest(build_report(chain, keys, generated_at=1700000000), _audit_key_pem())
    html = render_html(manifest)
    assert "raucle audit export" in html
    assert "VALID" in html
    # the honesty box ships in the report
    assert "reproducible attestation" in html
    assert "prover-soundness axiom" in html


def test_report_inputs_independently_reverifiable(tmp_path):
    """The verdict in the report must match a fresh verify_chain over the same
    inputs — the reproducibility property the report attests to."""
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    report = build_report(chain, keys, generated_at=1700000000)
    fresh = ProvenanceVerifier(public_keys=keys).verify_chain(chain)
    assert report.chain_verdict["valid"] == fresh.valid
    assert report.chain_verdict["receipt_count"] == fresh.receipt_count


def _chain_with_tool(tmp_path):
    """A two-receipt chain: a user_input root + a tool_call invoking 'transfer'."""
    ident = AgentIdentity.generate(agent_id="agent:billing")
    chain = tmp_path / "chain.jsonl"
    with ProvenanceLogger(agent=ident, sink_path=chain) as log:
        h = log.record_user_input(text="pay alice")
        log.record_tool_call(parents=[h], tool="transfer", input_args={"to": "alice"}, output={})
    return ident, chain


def test_finding_attributed_to_specific_node(tmp_path):
    """A signature/tamper finding lands on the offending node; clean nodes stay
    green even when the chain is INVALID elsewhere (precise attribution)."""
    ident, chain = _chain_with_tool(tmp_path)
    lines = chain.read_text().splitlines()
    rec = json.loads(lines[1])  # tamper the tool_call receipt
    rec["receipt_hash"] = "sha256:" + "0" * 64
    lines[1] = json.dumps(rec)
    chain.write_text("\n".join(lines) + "\n")
    keys = {ident.key_id: ident.public_key_pem()}
    report = build_report(chain, keys, generated_at=1700000000)
    assert report.summary["chain_valid"] is False
    by_kind = {n.kind: n for n in report.nodes}
    assert by_kind["tool"].status == "red"  # the tampered tool node
    assert by_kind["operation"].status == "green"  # the clean user_input node
    # no blanket "amber elsewhere"
    assert all(n.status != "amber" for n in report.nodes)


def test_node_joined_to_cited_proof(tmp_path):
    """A capability citing a PROVEN proof makes the tool node carry the
    certificate inline (the discharged-obligation magic moment)."""
    ident, chain = _chain_with_tool(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    proofs = [{"prover": "JSONSchemaProver", "status": "PROVEN", "hash": "sha256:abc"}]
    caps = [{"tool": "transfer", "policy_proof_hash": "sha256:abc"}]
    report = build_report(chain, keys, proofs, generated_at=1700000000, capabilities=caps)
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.proof_certificate == "sha256:abc"
    assert tool_node.proof_status == "green"
    assert "Theorem 3" in tool_node.lean_theorem
    assert tool_node.status == "green"


def test_node_red_when_cited_proof_refuted(tmp_path):
    ident, chain = _chain_with_tool(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    proofs = [{"prover": "JSONSchemaProver", "status": "REFUTED", "hash": "sha256:bad"}]
    caps = [{"tool": "transfer", "policy_proof_hash": "sha256:bad"}]
    report = build_report(chain, keys, proofs, generated_at=1700000000, capabilities=caps)
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.status == "red"


def test_node_amber_when_cited_proof_missing(tmp_path):
    ident, chain = _chain_with_tool(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    caps = [{"tool": "transfer", "policy_proof_hash": "sha256:notsupplied"}]
    report = build_report(chain, keys, [], generated_at=1700000000, capabilities=caps)
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.status == "amber"
    assert any("not supplied" in e for e in tool_node.evidence)
