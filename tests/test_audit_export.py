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
from raucle_detect.prove import ProofResult
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


def _proof(status: str, **kw) -> dict:
    """A real ProofResult dict (hash matches body) so the audit-export
    content-address check trusts it."""
    return ProofResult(
        status=status,
        prover="JSONSchemaProver",
        prover_version="jsonschema-prover/v1",
        grammar_hash="g",
        policy_hash="p",
        **kw,
    ).to_dict()


def test_proof_obligations_colour_mapping(tmp_path):
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    proven = _proof("PROVEN")
    refuted = _proof("REFUTED", counterexample={"amount": 999})
    undecided = _proof("UNDECIDED")
    report = build_report(chain, keys, [proven, refuted, undecided], generated_at=1700000000)
    by_cert = {o.certificate: o for o in report.obligations}
    assert by_cert[proven["hash"]].status == "green"
    assert by_cert[refuted["hash"]].status == "red"
    assert "counterexample" in by_cert[refuted["hash"]].detail
    assert by_cert[undecided["hash"]].status == "amber"


def test_forged_proof_hash_is_untrusted_not_green(tmp_path):
    """B2: a proof claiming PROVEN under a hash that does not match its own body
    is untrusted (amber), never green — and a node citing it does not go green."""
    ident, chain = _chain_with_tool(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    forged = {**_proof("PROVEN"), "hash": "sha256:" + "0" * 64}  # body no longer hashes to this
    caps = [{"tool": "transfer", "policy_proof_hash": forged["hash"]}]
    report = build_report(chain, keys, [forged], generated_at=1700000000, capabilities=caps)
    obl = report.obligations[0]
    assert obl.status == "amber"
    assert "does not match" in obl.detail
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.status != "green"


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
    proof = _proof("PROVEN")
    caps = [{"tool": "transfer", "policy_proof_hash": proof["hash"]}]
    report = build_report(chain, keys, [proof], generated_at=1700000000, capabilities=caps)
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.proof_certificate == proof["hash"]
    assert tool_node.proof_status == "green"
    assert "Theorem 3" in tool_node.lean_theorem
    assert tool_node.status == "green"


def test_node_red_when_cited_proof_refuted(tmp_path):
    ident, chain = _chain_with_tool(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    proof = _proof("REFUTED", counterexample={"amount": 999})
    caps = [{"tool": "transfer", "policy_proof_hash": proof["hash"]}]
    report = build_report(chain, keys, [proof], generated_at=1700000000, capabilities=caps)
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.status == "red"


def test_node_amber_when_cited_proof_missing(tmp_path):
    ident, chain = _chain_with_tool(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    caps = [{"tool": "transfer", "policy_proof_hash": "sha256:notsupplied"}]
    report = build_report(chain, keys, [], generated_at=1700000000, capabilities=caps)
    tool_node = next(n for n in report.nodes if n.kind == "tool")
    assert tool_node.status == "amber"
    assert any("no trusted" in e for e in tool_node.evidence)


def test_capability_violation_is_red_not_green(tmp_path):
    """B1: a chain calling a tool the agent's capability statement forbids must
    be RED. A malicious emitter bypasses the runtime gate; the verifier (given
    the signed statement) must still catch it. Without the statement enforced
    the bug shows it GREEN — which is why build_report now passes statements."""
    from raucle_detect.provenance import Operation, ProvenanceReceipt, hash_text

    ident = AgentIdentity.generate(agent_id="agent:billing", allowed_tools=["safe_tool"])
    # Build receipts manually (bypassing the logger's permission gate) so the
    # chain contains a tool the statement forbids — exactly the verifier's job.
    r1 = ProvenanceReceipt(
        agent_id=ident.agent_id,
        agent_key_id=ident.key_id,
        operation=Operation.USER_INPUT,
        input_hash=hash_text("go"),
        issued_at=1,
    )
    r1.sign(ident)
    r2 = ProvenanceReceipt(
        agent_id=ident.agent_id,
        agent_key_id=ident.key_id,
        operation=Operation.TOOL_CALL,
        parents=[r1.receipt_hash],
        tool="danger_tool",
        input_hash=hash_text("{}"),
        output_hash=hash_text("{}"),
        issued_at=2,
    )
    r2.sign(ident)
    chain = tmp_path / "chain.jsonl"
    chain.write_text(
        json.dumps({"receipt_hash": r1.receipt_hash, "jws": r1.jws})
        + "\n"
        + json.dumps({"receipt_hash": r2.receipt_hash, "jws": r2.jws})
        + "\n"
    )
    keys = {ident.key_id: ident.public_key_pem()}

    # Statements enforced → capability violation → INVALID + the tool node RED.
    enforced = build_report(
        chain, keys, generated_at=1700000000, capability_statements={ident.key_id: ident.statement}
    )
    assert enforced.summary["chain_valid"] is False
    tool_node = next(n for n in enforced.nodes if n.kind == "tool")
    assert tool_node.status == "red"
    assert "capability_statements" in enforced.input_hashes

    # Demonstrate the gap the fix closes: without statements, no permission check.
    unenforced = build_report(chain, keys, generated_at=1700000000)
    assert unenforced.summary["chain_valid"] is True  # documents why statements are required


def test_mutated_signer_key_id_fails_verification(tmp_path):
    """B3: the displayed signer_key_id is unsigned; a mutated label must be
    rejected (derived from the embedded key), not silently trusted."""
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    manifest = sign_manifest(build_report(chain, keys, generated_at=1700000000), _audit_key_pem())
    assert verify_manifest(manifest) is True
    manifest["signer_key_id"] = "trusted-looking"
    assert verify_manifest(manifest) is False


def test_html_escapes_unknown_status(tmp_path):
    """B4: a hand-crafted manifest with an unknown node status must not inject
    raw HTML through the badge fallback."""
    ident, chain = _clean_chain(tmp_path)
    keys = {ident.key_id: ident.public_key_pem()}
    manifest = sign_manifest(build_report(chain, keys, generated_at=1700000000), _audit_key_pem())
    manifest["body"]["nodes"][0]["status"] = "<script>alert(1)</script>"
    html = render_html(manifest)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_shows_capability_statement_inputs(tmp_path):
    """Reproducibility: when capability statements drive verdicts, the report
    must list their hashes and tell the verifier to rerun with them — not just
    PEM keys (Codex follow-up)."""
    ident = AgentIdentity.generate(agent_id="agent:billing", allowed_tools=["safe_tool"])
    chain = tmp_path / "chain.jsonl"
    with ProvenanceLogger(agent=ident, sink_path=chain) as log:
        log.record_user_input(text="hi")
    keys = {ident.key_id: ident.public_key_pem()}
    report = build_report(
        chain, keys, generated_at=1700000000, capability_statements={ident.key_id: ident.statement}
    )
    manifest = sign_manifest(report, _audit_key_pem())
    html = render_html(manifest)
    # the statement's hash appears in the Inputs section
    stmt_hash = report.input_hashes["capability_statements"][ident.key_id]
    assert stmt_hash in html
    assert "Capability statements" in html
    # the verify appendix tells the examiner to rerun with the statement files
    assert "capability-statement files" in html
