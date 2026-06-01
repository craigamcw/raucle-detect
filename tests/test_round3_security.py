"""Regression tests for the round-3 adversarial security audit (2026-06-01).

Each test pins a confirmed finding from docs/oss-security-audit-round3.md so a
future change that reintroduces the bug fails loudly. Dependency-light: tests
that would need optional extras (fastapi/langchain/autogen/pillow) are guarded.

Report: ../raucle/docs/oss-security-audit-round3.md
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from raucle_detect.audit import _canonical_json as audit_canon
from raucle_detect.audit import _merkle_root
from raucle_detect.feed import _assert_safe_url
from raucle_detect.feed import _canonical_json as feed_canon
from raucle_detect.prove import SQLClauseProver, URLPolicyProver
from raucle_detect.provenance import (
    AgentIdentity,
    CapabilityStatement,
    ProvenanceLogger,
    ProvenanceReceipt,
    ProvenanceVerifier,
)


# --- #1 SQL prover: set-operation table extraction bypass --------------------
@pytest.mark.parametrize("op", ["EXCEPT", "INTERSECT", "MINUS"])
def test_sql_setop_does_not_prove_forbidden_table(op):
    # Reading a forbidden table via a set operation must NOT be PROVEN.
    r = SQLClauseProver().prove(
        {"templates": [f"SELECT a FROM customers {op} SELECT a FROM admin_secrets"]},
        {"allowed_tables": ["customers"]},
    )
    assert r.status != "PROVEN"


def test_sql_legit_query_still_proven():
    r = SQLClauseProver().prove(
        {"templates": ["SELECT a FROM customers"]}, {"allowed_tables": ["customers"]}
    )
    assert r.status == "PROVEN"


# --- #7 SELECT ... INTO under read-only default ------------------------------
@pytest.mark.parametrize("tok", ["INTO", "MERGE", "CREATE"])
def test_sql_default_forbids_write_tokens(tok):
    sql = {
        "INTO": "SELECT * INTO admin_copy FROM customers",
        "MERGE": "MERGE INTO t USING s ON t.id=s.id",
        "CREATE": "CREATE TABLE x AS SELECT 1",
    }[tok]
    assert SQLClauseProver().prove({"templates": [sql]}, {}).status != "PROVEN"


# --- #8 forbid_query_keys over an open grammar -------------------------------
def test_forbid_query_keys_open_grammar_is_undecided():
    r = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com"]},
        {"forbid_query_keys": ["token"]},
    )
    assert r.status == "UNDECIDED"


def test_forbid_query_keys_closed_grammar_proves_or_refutes():
    safe = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["h"], "query_keys": ["q"], "query_keys_closed": True},
        {"forbid_query_keys": ["token"]},
    )
    assert safe.status == "PROVEN"
    bad = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["h"], "query_keys": ["token"], "query_keys_closed": True},
        {"forbid_query_keys": ["token"]},
    )
    assert bad.status == "REFUTED"


# --- provenance verifier hardening (#4 expiry, #5 agent_id, #6 kid) ----------
def _stmt(idn, **ov):
    s = idn.statement
    return CapabilityStatement(
        agent_id=ov.get("agent_id", s.agent_id),
        key_id=s.key_id,
        public_key_pem=s.public_key_pem,
        allowed_models=list(s.allowed_models),
        allowed_tools=list(s.allowed_tools),
        expires_at=ov.get("expires_at"),
    )


def _chain(tmp_path):
    idn = AgentIdentity.generate(agent_id="agent:good")
    c = tmp_path / "c.jsonl"
    with ProvenanceLogger(agent=idn, sink_path=c) as log:
        log.record_user_input(text="hi")
    return idn, c


def test_provenance_baseline_valid(tmp_path):
    idn, c = _chain(tmp_path)
    v = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()}, capabilities={idn.key_id: _stmt(idn)}
    )
    assert v.verify_chain(c).valid is True


def test_provenance_rejects_expired_statement(tmp_path):
    idn, c = _chain(tmp_path)
    v = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()},
        capabilities={idn.key_id: _stmt(idn, expires_at=1)},
    )
    rep = v.verify_chain(c)
    assert rep.valid is False
    assert any("expired" in e for e in rep.errors)


def test_provenance_rejects_agent_id_spoof(tmp_path):
    idn, c = _chain(tmp_path)
    v = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()},
        capabilities={idn.key_id: _stmt(idn, agent_id="agent:someone-else")},
    )
    rep = v.verify_chain(c)
    assert rep.valid is False
    assert any("agent_id" in e for e in rep.errors)


def test_strict_from_jws_rejects_kid_mismatch(tmp_path):
    import base64

    idn, c = _chain(tmp_path)
    rec = json.loads(c.read_text().strip().splitlines()[0])
    h, p, s = rec["jws"].split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "==" * (-len(h) % 4)))
    hdr["kid"] = "not-the-agent-key-id"
    newh = (
        base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(ValueError, match="kid"):
        ProvenanceReceipt.from_jws(f"{newh}.{p}.{s}", strict=True)


# --- audit (#9 keyless signed, #13 NaN, #22 non-hex leaf) --------------------
def test_audit_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        audit_canon({"x": float("nan")})


def test_feed_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        feed_canon({"x": float("inf")})


def test_merkle_root_raises_on_non_hex_leaf():
    with pytest.raises(ValueError, match="non-hex"):
        _merkle_root(["nothex!!"])


def test_merkle_root_valid_hex_ok():
    assert len(_merkle_root(["00" * 32])) == 64


# --- feed SSRF pin (#21 dead-code crash) -------------------------------------
def test_feed_assert_safe_url_returns_pinned_ip():
    infos = [(2, 1, 6, "", ("93.184.216.34", 443))] * 2
    with mock.patch("socket.getaddrinfo", return_value=infos):
        host, ip = _assert_safe_url("https://example.com/feed.json")
    assert host == "example.com"
    assert ip == "93.184.216.34"


def test_feed_assert_safe_url_blocks_metadata_ip():
    with (
        mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 443))]),
        pytest.raises(ValueError),
    ):
        _assert_safe_url("https://evil.example/x")


# --- #21 live DNS-rebind pin: connection dials the validated IP, resolves once ---
class _StopDial(Exception):
    """Sentinel raised from the mocked dial so we don't need a full TLS/HTTP fake."""


def test_feed_fetch_pins_validated_ip_and_resolves_once():
    """fetch_feed must dial the IP that _assert_safe_url validated, and must NOT
    perform a second DNS lookup at connect time (the DNS-rebind defense). Before
    the #21 fix this path was dead code (TypeError) and never exercised at all.
    """
    import socket as _socket

    from raucle_detect.feed import fetch_feed

    safe_ip = "93.184.216.34"
    getaddr = mock.Mock(return_value=[(2, 1, 6, "", (safe_ip, 443))])
    dialed: list = []

    def _fake_create_connection(addr, *a, **k):
        dialed.append(addr)
        raise _StopDial  # stop before TLS/HTTP — we only assert the dial target

    with (
        mock.patch.object(_socket, "getaddrinfo", getaddr),
        mock.patch.object(_socket, "create_connection", _fake_create_connection),
        pytest.raises(_StopDial),
    ):
        fetch_feed("https://example.com/feed.json")

    # Dialed exactly the pinned, pre-validated IP — not a re-resolved address.
    assert dialed == [(safe_ip, 443)]
    # Resolved exactly once: the pin means no second lookup a rebind could poison.
    assert getaddr.call_count == 1


def test_feed_fetch_rejects_url_whose_host_resolves_to_blocked_ip():
    import socket as _socket

    from raucle_detect.feed import fetch_feed

    with (
        mock.patch.object(_socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]),
        pytest.raises(ValueError),
    ):
        fetch_feed("https://internal.example/feed.json")


# --- LangChain blacklist-on-opaque-string guard (#3b/#5) ---------------------
def test_langchain_blacklist_helper():
    lc = pytest.importorskip("raucle_detect.integrations.langchain")

    class T:
        def __init__(self, c):
            self.constraints = c

    assert lc._blacklist_on_named_field(T({"forbidden_values": {"to": ["x"]}})) is True
    assert lc._blacklist_on_named_field(T({"forbidden_values": {"input": ["x"]}})) is False
    assert lc._blacklist_on_named_field(T({"forbidden_field_combinations": [["a", "b"]]})) is True
    assert lc._blacklist_on_named_field(T({"allowed_values": {"to": ["ok"]}})) is False
    assert lc._blacklist_on_named_field(T({})) is False
