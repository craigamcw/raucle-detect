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

from raucle_detect import capability, prove, registry


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
    # The prover accesses each modelled policy key as policy.get("<key>"...) or
    # policy.get("<key>", ...). Detect which registry keys actually appear in a
    # policy.get(...) call within the prover body.
    read_keys = {
        key
        for key in registry.KNOWN_CONSTRAINT_KEYS
        if f'policy.get("{key}"' in src or f"policy.get('{key}'" in src
    }
    assert read_keys == set(registry.PROVER_ENCODABLE_KEYS), (
        "prover's modelled policy keys drifted from registry.PROVER_ENCODABLE_KEYS: "
        f"prover reads {sorted(read_keys)}, registry says "
        f"{sorted(registry.PROVER_ENCODABLE_KEYS)}"
    )


def _keys_read(src: str, accessor: str, candidates) -> set:
    """Keys a source body reads via `<accessor>.get("<key>"` / .get('<key>'."""
    return {
        k for k in candidates if f'{accessor}.get("{k}"' in src or f"{accessor}.get('{k}'" in src
    }


def test_url_prover_keys_match_registry():
    """Every URL grammar/policy key the prover reads must be in the registry,
    and every registry URL key must be read by the prover (no drift)."""
    src = inspect.getsource(prove.URLPolicyProver)
    # The prover reads grammar keys via grammar.get(...) and policy keys via
    # policy.get(...). query_keys_closed is read via grammar.get too.
    grammar_read = _keys_read(src, "grammar", registry.URL_GRAMMAR_KEYS)
    policy_read = _keys_read(src, "policy", registry.URL_POLICY_KEYS)
    assert grammar_read == set(registry.URL_GRAMMAR_KEYS), (
        f"URL grammar keys drifted: prover reads {sorted(grammar_read)}, "
        f"registry {sorted(registry.URL_GRAMMAR_KEYS)}"
    )
    assert policy_read == set(registry.URL_POLICY_KEYS), (
        f"URL policy keys drifted: prover reads {sorted(policy_read)}, "
        f"registry {sorted(registry.URL_POLICY_KEYS)}"
    )


def test_sql_prover_keys_match_registry():
    """SQL policy keys the prover reads must match the registry. (templates is
    read via grammar.get; allowed_tables is a policy key mirrored in grammar.)"""
    src = inspect.getsource(prove.SQLClauseProver)
    policy_read = _keys_read(src, "policy", registry.SQL_POLICY_KEYS)
    assert policy_read == set(registry.SQL_POLICY_KEYS), (
        f"SQL policy keys drifted: prover reads {sorted(policy_read)}, "
        f"registry {sorted(registry.SQL_POLICY_KEYS)}"
    )
    assert "templates" in registry.SQL_GRAMMAR_KEYS


def test_schema_keywords_sourced_from_registry():
    """The JSON prover must derive its modelled keyword set from the registry,
    not a private literal (else schema-keyword drift recurs)."""
    src = inspect.getsource(prove.JSONSchemaProver)
    assert "JSON_SCHEMA_OBJECT_KEYS" in src


def test_envelope_field_helper():
    """The envelope helper flags exactly unknown non-extension fields."""
    assert registry.unknown_envelope_fields({"receipt_hash", "jws"}) == set()
    assert registry.unknown_envelope_fields({"receipt_hash", "jws", "evil"}) == {"evil"}
    # A registered versioned extension is tolerated.
    assert registry.unknown_envelope_fields({"receipt_hash", "jws", "x-raucle-trace"}) == set()


def test_unmodelled_policy_keys_helper():
    """The helper the prover uses to fail closed must flag exactly the
    non-encodable keys."""
    non_encodable = registry.KNOWN_CONSTRAINT_KEYS - registry.PROVER_ENCODABLE_KEYS
    # A policy carrying every known key reports exactly the non-encodable ones.
    every = {k: None for k in registry.KNOWN_CONSTRAINT_KEYS}
    assert registry.unmodelled_policy_keys(set(every)) == set(non_encodable)
    # A policy of only encodable keys reports nothing.
    assert registry.unmodelled_policy_keys(set(registry.PROVER_ENCODABLE_KEYS)) == set()
