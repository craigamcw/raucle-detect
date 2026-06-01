"""CI drift guard for the Modelled Language Registry (§8.1).

The registry (``raucle_detect/registry.py``) is the executable source of truth
for the capability/policy constraint language. These tests fail if any consumer
(the gate/mint layer, the SMT prover) models a set of keys that diverges from
what the registry declares — the mechanism that prevents code and registry from
silently drifting apart (which is how round-4/round-6 fail-open holes appeared).

If you are adding or removing a constraint kind, edit ``registry.py`` and the
consumer in the SAME change; these tests will tell you exactly what is out of
sync.
"""

from __future__ import annotations

import inspect
import re

from raucle_detect import capability, prove, registry


def _all_get_keys(src: str, accessor: str) -> set:
    """ALL string-literal keys read via `<accessor>.get("...")` in a source body.

    Unlike a candidate-scan, this extracts EVERY literal — so a NEW unregistered
    read (e.g. policy.get("foo")) shows up and trips the equality assertions
    below, instead of being silently ignored. (Covers .get with or without a
    default arg; matches both quote styles.)
    """
    return set(re.findall(rf"{accessor}\.get\(\s*[\"']([^\"']+)[\"']", src))


def test_registry_rows_are_complete():
    """Every row must fill in every mandatory semantic column (§8.1)."""
    assert registry.CONSTRAINT_REGISTRY, "registry must not be empty"
    for key, row in registry.CONSTRAINT_REGISTRY.items():
        assert row.key == key
        assert row.arg_shape is not None
        assert row.collection_semantics is not None
        assert row.meet is not None
        assert isinstance(row.prover_encodable, bool)
        assert row.gate_verdict is not None
        assert row.prover_verdict is not None
        assert row.mint_verdict is not None
        # A kind must be pinned by at least one test (extension process).
        assert row.tests, f"constraint kind {key!r} has no pinning tests"


def test_gate_known_keys_match_registry():
    """capability._KNOWN_CONSTRAINT_KEYS must equal the registry's key set.

    The gate derives the set from the registry, so this also guards against a
    future refactor reintroducing a hand-maintained literal that drifts.
    """
    assert capability._KNOWN_CONSTRAINT_KEYS == registry.KNOWN_CONSTRAINT_KEYS


def test_prover_models_exactly_the_encodable_keys():
    """The keys the JSON prover reads from ``policy`` must equal the registry's
    ``prover_encodable`` set — no more (would be unsound: modelling a key the
    registry says is not modelled), no fewer (would be a decorative-proof hole:
    reading fewer than declared while still claiming the rest is encodable).
    """
    src = inspect.getsource(prove.JSONSchemaProver)
    # EVERY policy.get(...) literal — so an unregistered read trips this too.
    read_keys = _all_get_keys(src, "policy")
    assert read_keys == set(registry.PROVER_ENCODABLE_KEYS), (
        "prover's modelled policy keys drifted from registry.PROVER_ENCODABLE_KEYS: "
        f"prover reads {sorted(read_keys)}, registry says "
        f"{sorted(registry.PROVER_ENCODABLE_KEYS)}"
    )


def test_url_prover_keys_match_registry():
    """EVERY URL grammar/policy key the prover reads must equal the registry —
    a new unregistered grammar.get/policy.get literal fails this test."""
    src = inspect.getsource(prove.URLPolicyProver)
    assert _all_get_keys(src, "grammar") == set(registry.URL_GRAMMAR_KEYS), (
        f"URL grammar keys drifted: prover reads {sorted(_all_get_keys(src, 'grammar'))}, "
        f"registry {sorted(registry.URL_GRAMMAR_KEYS)}"
    )
    assert _all_get_keys(src, "policy") == set(registry.URL_POLICY_KEYS), (
        f"URL policy keys drifted: prover reads {sorted(_all_get_keys(src, 'policy'))}, "
        f"registry {sorted(registry.URL_POLICY_KEYS)}"
    )


def test_sql_prover_keys_match_registry():
    """EVERY SQL policy.get/grammar.get literal must be registered. policy keys
    equal the registry set; grammar reads (templates) are a subset of
    SQL_GRAMMAR_KEYS (allowed_tables is read via membership, not .get)."""
    src = inspect.getsource(prove.SQLClauseProver)
    assert _all_get_keys(src, "policy") == set(registry.SQL_POLICY_KEYS), (
        f"SQL policy keys drifted: prover reads {sorted(_all_get_keys(src, 'policy'))}, "
        f"registry {sorted(registry.SQL_POLICY_KEYS)}"
    )
    grammar_read = _all_get_keys(src, "grammar")
    assert grammar_read <= set(registry.SQL_GRAMMAR_KEYS), (
        f"SQL grammar read {sorted(grammar_read)} not all registered "
        f"{sorted(registry.SQL_GRAMMAR_KEYS)}"
    )
    assert "templates" in registry.SQL_GRAMMAR_KEYS


def test_sql_unmodelled_construct_surface_sourced_from_registry():
    """The SQL construct net must be built from registry data, and the compiled
    regex must match exactly the registry's construct list (no hard-coded
    divergence in prove.py)."""
    src = inspect.getsource(prove)
    assert "SQL_UNMODELLED_CONSTRUCTS" in src
    expected = re.compile("|".join(registry.SQL_UNMODELLED_CONSTRUCTS), re.IGNORECASE)
    assert prove._UNMODELLED_SQL_RE.pattern == expected.pattern


def test_schema_keywords_sourced_from_registry():
    """The JSON prover must derive its modelled keyword set from the registry,
    not a private literal (else schema-keyword drift recurs)."""
    src = inspect.getsource(prove.JSONSchemaProver)
    assert "JSON_SCHEMA_OBJECT_KEYS" in src


def test_envelope_field_helper():
    """The envelope helper flags every field outside the registry sets. There is
    no wildcard prefix: v1 has no registered extensions, so any extra field
    (including an x-raucle- one) is rejected."""
    assert registry.unknown_envelope_fields({"receipt_hash", "jws"}) == set()
    assert registry.unknown_envelope_fields({"receipt_hash", "jws", "evil"}) == {"evil"}
    # No blanket x- pass-through in v1 — it is rejected, not tolerated.
    assert registry.unknown_envelope_fields({"receipt_hash", "jws", "x-raucle-trace"}) == {
        "x-raucle-trace"
    }
    assert frozenset() == registry.ENVELOPE_EXTENSION_FIELDS


def test_unmodelled_policy_keys_helper():
    """The helper the prover uses to fail closed must flag exactly the
    non-encodable keys."""
    non_encodable = registry.KNOWN_CONSTRAINT_KEYS - registry.PROVER_ENCODABLE_KEYS
    # A policy carrying every known key reports exactly the non-encodable ones.
    every = {k: None for k in registry.KNOWN_CONSTRAINT_KEYS}
    assert registry.unmodelled_policy_keys(set(every)) == set(non_encodable)
    # A policy of only encodable keys reports nothing.
    assert registry.unmodelled_policy_keys(set(registry.PROVER_ENCODABLE_KEYS)) == set()
