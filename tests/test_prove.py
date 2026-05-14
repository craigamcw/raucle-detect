"""Tests for the formal-verification provers (v0.9.0)."""

from __future__ import annotations

import pytest

z3 = pytest.importorskip("z3")

from raucle_detect.prove import (
    JSONSchemaProver,
    ProofResult,
    SQLClauseProver,
    UnsupportedGrammar,
    URLPolicyProver,
)

# ---------------------------------------------------------------------------
# JSON Schema prover
# ---------------------------------------------------------------------------


def _txfer_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "amount": {"type": "number", "minimum": 0, "maximum": 1_000_000},
            "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
        },
        "required": ["to", "amount", "currency"],
    }


def test_jsonschema_proven_when_policy_holds():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"max_value": {"amount": 1_000_000}},
    )
    assert p.status == "PROVEN"
    assert p.counterexample is None
    assert p.prover == "JSONSchemaProver"


def test_jsonschema_refuted_with_concrete_counterexample():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"max_value": {"amount": 100}},
    )
    assert p.status == "REFUTED"
    assert p.counterexample is not None
    assert p.counterexample["amount"] > 100
    assert p.counterexample["currency"] in {"USD", "EUR", "GBP"}


def test_jsonschema_forbidden_recipient_refuted():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"forbidden_values": {"to": ["attacker@evil.example"]}},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["to"] == "attacker@evil.example"


def test_jsonschema_forbidden_recipient_proven_when_enum_excludes_it():
    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "string", "enum": ["alice@example.com", "bob@example.com"]},
        },
        "required": ["to"],
    }
    p = JSONSchemaProver().prove(schema, {"forbidden_values": {"to": ["attacker@evil.example"]}})
    assert p.status == "PROVEN"


def test_jsonschema_field_combination_refuted():
    schema = {
        "type": "object",
        "properties": {
            "delete_all": {"type": "boolean"},
            "tenant_id": {"type": "string"},
        },
    }
    p = JSONSchemaProver().prove(
        schema,
        {"forbidden_field_combinations": [["delete_all", "tenant_id"]]},
    )
    assert p.status == "REFUTED"


def test_jsonschema_trivial_policy_proven_with_note():
    p = JSONSchemaProver().prove(_txfer_schema(), {})
    assert p.status == "PROVEN"
    assert any("trivially proven" in n for n in p.notes)


def test_jsonschema_unsupported_grammar_raises():
    with pytest.raises(UnsupportedGrammar):
        JSONSchemaProver().prove({"type": "array"}, {})


def test_jsonschema_hash_is_deterministic():
    p1 = JSONSchemaProver().prove(_txfer_schema(), {"max_value": {"amount": 100}})
    p2 = JSONSchemaProver().prove(_txfer_schema(), {"max_value": {"amount": 100}})
    # Counterexample content may vary (Z3 model choice) but grammar/policy hashes are stable.
    assert p1.grammar_hash == p2.grammar_hash
    assert p1.policy_hash == p2.policy_hash


# ---------------------------------------------------------------------------
# URL prover
# ---------------------------------------------------------------------------


def test_url_https_only_proven_when_grammar_is_https():
    p = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com"]},
        {"require_https": True},
    )
    assert p.status == "PROVEN"


def test_url_https_only_refuted_when_grammar_allows_http():
    p = URLPolicyProver().prove(
        {"schemes": ["https", "http"], "hosts": ["api.example.com"]},
        {"require_https": True},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["scheme"] == "http"


def test_url_forbidden_query_key_refuted():
    p = URLPolicyProver().prove(
        {
            "schemes": ["https"],
            "hosts": ["api.example.com"],
            "query_keys": ["q", "api_key"],
        },
        {"forbid_query_keys": ["api_key", "token"]},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["query_key"] == "api_key"


def test_url_host_allowlist_wildcard_matches():
    p = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com", "v2.example.com"]},
        {"host_allowlist": ["*.example.com"]},
    )
    assert p.status == "PROVEN"


def test_url_host_allowlist_refuted_when_unauth_host_in_grammar():
    p = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com", "evil.attacker.com"]},
        {"host_allowlist": ["*.example.com"]},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["host"] == "evil.attacker.com"


# ---------------------------------------------------------------------------
# SQL prover
# ---------------------------------------------------------------------------


def test_sql_readonly_query_proven():
    p = SQLClauseProver().prove(
        {
            "templates": [
                "SELECT id, name FROM customers WHERE tenant_id = ?",
                "SELECT total FROM invoices WHERE id = ?",
            ],
            "allowed_tables": ["customers", "invoices"],
        },
        {"allowed_tables": ["customers", "invoices"]},
    )
    assert p.status == "PROVEN"


def test_sql_forbidden_drop_refuted():
    p = SQLClauseProver().prove(
        {"templates": ["DROP TABLE customers"]},
        {},
    )
    assert p.status == "REFUTED"
    assert "DROP" in p.counterexample["violation"]


def test_sql_unknown_table_refuted():
    p = SQLClauseProver().prove(
        {"templates": ["SELECT * FROM secrets"]},
        {"allowed_tables": ["customers"]},
    )
    assert p.status == "REFUTED"
    assert "secrets" in p.counterexample["violation"].lower()


def test_sql_statement_chaining_refuted():
    p = SQLClauseProver().prove(
        {"templates": ["SELECT 1; DROP TABLE customers"]},
        {"allow_statement_chaining": False},
    )
    assert p.status == "REFUTED"


def test_sql_chaining_allowed_when_flag_set():
    p = SQLClauseProver().prove(
        {"templates": ["SELECT 1; SELECT 2"]},
        {"allow_statement_chaining": True, "forbidden_tokens": []},
    )
    assert p.status == "PROVEN"


# ---------------------------------------------------------------------------
# ProofResult shape
# ---------------------------------------------------------------------------


def test_proof_result_hash_is_canonical():
    r1 = ProofResult(
        status="PROVEN",
        prover="JSONSchemaProver",
        prover_version="jsonschema-prover/v1",
        grammar_hash="sha256:aaa",
        policy_hash="sha256:bbb",
    )
    r2 = ProofResult(
        status="PROVEN",
        prover="JSONSchemaProver",
        prover_version="jsonschema-prover/v1",
        grammar_hash="sha256:aaa",
        policy_hash="sha256:bbb",
    )
    assert r1.hash == r2.hash
    assert r1.hash.startswith("sha256:")
