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


def test_unmodelled_policy_keys_helper():
    """The helper the prover uses to fail closed must flag exactly the
    non-encodable keys."""
    non_encodable = registry.KNOWN_CONSTRAINT_KEYS - registry.PROVER_ENCODABLE_KEYS
    # A policy carrying every known key reports exactly the non-encodable ones.
    every = {k: None for k in registry.KNOWN_CONSTRAINT_KEYS}
    assert registry.unmodelled_policy_keys(set(every)) == set(non_encodable)
    # A policy of only encodable keys reports nothing.
    assert registry.unmodelled_policy_keys(set(registry.PROVER_ENCODABLE_KEYS)) == set()
