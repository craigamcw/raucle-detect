"""The Modelled Language Registry — the executable source of truth (§8.1).

This module is the *single* place that enumerates every constraint kind the
capability/prover/gate machinery reasons about, together with the full set of
mandatory semantics for each one. Both the runtime (``capability.py``,
``prove.py``) and the test suite derive from this registry, and a CI drift test
(``tests/test_registry_drift.py``) fails if any consumer's modelled set diverges
from what is declared here.

Why a code object and not a Markdown table: a table and the code inevitably
drift, and a silently-dropped or partially-specified constraint kind is exactly
how fail-open holes (round-4, round-6) were introduced. Here a kind cannot be
added with partial semantics — every column on :class:`ConstraintKind` is
required — and the drift test guarantees the rest of the codebase agrees.

Fail-closed is encoded structurally: a key absent from this registry hits its
dimension's *conservative verdict* by construction (gate → DENY, prover →
UNDECIDED, mint → reject), never a silent pass.

Design references: docs/proposals/fail-closed-redesign.md §8.1 (mandatory
columns), §8.6 (collection-arg semantics), §8.7 (attenuation meet).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ArgShape(str, Enum):
    """The shape of a constraint kind's argument, as it appears in a token."""

    FIELD_TO_VALUES = "field_to_values"  # {field: [scalar, ...]}
    FIELD_TO_SCALAR = "field_to_scalar"  # {field: scalar}
    FIELD_LIST = "field_list"  # [field, ...]
    COMBO_LIST = "combo_list"  # [[field, field], ...]


class CollectionSemantics(str, Enum):
    """How a collection-valued *argument value* is evaluated (§8.6).

    The fail-closed direction is always DENY; the difference between kinds is
    whether a single bad element denies (exists) or a single good element is
    insufficient (for-all).
    """

    EXISTS_DENY = "exists_deny"  # blacklist: any flattened scalar forbidden → DENY
    FORALL_ALLOW = "forall_allow"  # whitelist: present AND every scalar allowed, else DENY
    STRING_ONLY = "string_only"  # must be a string with the prefix; any collection → DENY
    FORALL_NUMERIC = "forall_numeric"  # every scalar a finite non-bool number in-bound, else DENY
    PRESENCE = "presence"  # only the field's presence matters; value irrelevant


class Meet(str, Enum):
    """The lattice meet used by attenuation narrowing (§8.7, ``_merge_narrowing``).

    A constraint kind is only sound under attenuation if its meet takes the
    *tighter* of parent/child on every dimension. Adding a kind without a
    reviewed meet here is impossible — the drift test requires it.
    """

    SET_UNION = "set_union"  # forbidden_values: more forbidden = tighter
    SET_INTERSECTION = "set_intersection"  # allowed_values: fewer allowed = tighter
    PREFIX_EXTEND = "prefix_extend"  # starts_with: longer prefix = tighter (disjoint → refuse)
    MIN = "min"  # max_value: smaller ceiling = tighter
    MAX = "max"  # min_value: larger floor = tighter
    LIST_UNION = "list_union"  # required_present / combos: more required = tighter


class Verdict(str, Enum):
    """The conservative (fail-closed) verdict for the owning component."""

    GATE_DENY = "gate:DENY"
    PROVER_UNDECIDED = "prover:UNDECIDED"
    MINT_REJECT = "mint:reject"


@dataclass(frozen=True)
class ConstraintKind:
    """One row of the capability/policy constraint dimension.

    Every column is mandatory (§8.1): a kind cannot be registered with partial
    semantics. ``prover_encodable`` records whether the SMT prover (``prove.py``)
    models this kind; if False, a policy carrying this key must yield UNDECIDED
    rather than a PROVEN that silently ignored it (the "decorative proof inputs"
    bug, §8.2).
    """

    key: str
    arg_shape: ArgShape
    collection_semantics: CollectionSemantics
    meet: Meet
    # The SMT prover encodes this kind faithfully. If False, the prover MUST NOT
    # return PROVEN for a policy that carries this key (→ UNDECIDED).
    prover_encodable: bool
    # Fail-closed verdicts, per owning component.
    gate_verdict: Verdict
    prover_verdict: Verdict
    mint_verdict: Verdict
    # Regression/fuzz tests pinning this kind's semantics.
    tests: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# The registry. Adding a key here is the ONLY supported way to model a new
# constraint kind; it forces every column to be filled in (extension process,
# §8.1). A new key also requires a version/namespace decision for any
# wire-format surface that carries it.
# ---------------------------------------------------------------------------

_CONSTRAINT_KINDS: tuple[ConstraintKind, ...] = (
    ConstraintKind(
        key="forbidden_values",
        arg_shape=ArgShape.FIELD_TO_VALUES,
        collection_semantics=CollectionSemantics.EXISTS_DENY,
        meet=Meet.SET_UNION,
        prover_encodable=True,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
    ConstraintKind(
        key="allowed_values",
        arg_shape=ArgShape.FIELD_TO_VALUES,
        collection_semantics=CollectionSemantics.FORALL_ALLOW,
        meet=Meet.SET_INTERSECTION,
        # The prover does NOT model whitelists (prove.py) — must yield UNDECIDED
        # when a policy carries this key, never a PROVEN that ignored it (§8.2).
        prover_encodable=False,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
    ConstraintKind(
        key="starts_with",
        arg_shape=ArgShape.FIELD_TO_SCALAR,
        collection_semantics=CollectionSemantics.STRING_ONLY,
        meet=Meet.PREFIX_EXTEND,
        # Prefix predicates are not modelled by the prover (prove.py) → UNDECIDED.
        prover_encodable=False,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
    ConstraintKind(
        key="max_value",
        arg_shape=ArgShape.FIELD_TO_SCALAR,
        collection_semantics=CollectionSemantics.FORALL_NUMERIC,
        meet=Meet.MIN,
        prover_encodable=True,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
    ConstraintKind(
        key="min_value",
        arg_shape=ArgShape.FIELD_TO_SCALAR,
        collection_semantics=CollectionSemantics.FORALL_NUMERIC,
        meet=Meet.MAX,
        prover_encodable=True,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
    ConstraintKind(
        key="required_present",
        arg_shape=ArgShape.FIELD_LIST,
        collection_semantics=CollectionSemantics.PRESENCE,
        meet=Meet.LIST_UNION,
        prover_encodable=True,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
    ConstraintKind(
        key="forbidden_field_combinations",
        arg_shape=ArgShape.COMBO_LIST,
        collection_semantics=CollectionSemantics.PRESENCE,
        meet=Meet.LIST_UNION,
        prover_encodable=True,
        gate_verdict=Verdict.GATE_DENY,
        prover_verdict=Verdict.PROVER_UNDECIDED,
        mint_verdict=Verdict.MINT_REJECT,
        tests=("test_round3_security", "test_capability"),
    ),
)

# Map form for lookup. Keys are insertion-ordered.
CONSTRAINT_REGISTRY: dict[str, ConstraintKind] = {k.key: k for k in _CONSTRAINT_KINDS}

# ---------------------------------------------------------------------------
# Derived views. Consumers MUST derive from these rather than maintaining their
# own literal sets; the drift test pins each consumer's set to the registry.
# ---------------------------------------------------------------------------

#: Every constraint key the gate/mint layer recognises. capability.py derives
#: ``_KNOWN_CONSTRAINT_KEYS`` from this; an unknown key is rejected at mint.
KNOWN_CONSTRAINT_KEYS: frozenset[str] = frozenset(CONSTRAINT_REGISTRY)

#: The subset the SMT prover encodes faithfully. A policy carrying any key
#: outside this set cannot be returned as PROVEN — prove.py yields UNDECIDED.
PROVER_ENCODABLE_KEYS: frozenset[str] = frozenset(
    k for k, v in CONSTRAINT_REGISTRY.items() if v.prover_encodable
)


def unmodelled_policy_keys(policy_keys: frozenset[str] | set[str]) -> set[str]:
    """Return the policy keys the prover does NOT model (→ forces UNDECIDED).

    This is the registry-driven check that closes the "decorative proof inputs"
    hole (§8.2): the prover calls this and, if the result is non-empty, returns
    UNDECIDED rather than a PROVEN that silently ignored those keys.
    """
    return set(policy_keys) - PROVER_ENCODABLE_KEYS


# ---------------------------------------------------------------------------
# Other modelled-language dimensions (§8.1). Each is an explicit allowlist; any
# key/field outside it hits the dimension's conservative verdict. Consumers
# derive their checks from these and the drift test pins them, so a fail-open
# gap cannot reappear outside the capability-constraint dimension (the residual
# Codex flagged after the first implementation pass).
# ---------------------------------------------------------------------------

#: JSON Schema object-level keywords the JSONSchemaProver models. An unmodelled
#: keyword downgrades a would-be PROVEN to UNDECIDED (it may reshape the value
#: space in a way the prover does not capture).
JSON_SCHEMA_OBJECT_KEYS: frozenset[str] = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "title",
        "description",
        "$schema",
        "$id",
        "$defs",
        "definitions",
    }
)

#: URLPolicyProver grammar keys. Unknown key → UNDECIDED (the prover cannot
#: certify completeness over a dimension it does not model).
URL_GRAMMAR_KEYS: frozenset[str] = frozenset(
    {"schemes", "hosts", "path_prefixes", "query_keys", "query_keys_closed"}
)

#: URLPolicyProver policy obligations. Unknown key → UNDECIDED.
URL_POLICY_KEYS: frozenset[str] = frozenset(
    {"require_https", "forbid_query_keys", "host_allowlist", "max_path_depth"}
)

#: SQLClauseProver grammar keys. Unknown key → UNDECIDED. ``allowed_tables`` is
#: tolerated here as a recognised (but ignored) mirror of the policy key — the
#: policy copy dominates, and passing it ONLY in the grammar is a distinct,
#: loudly-rejected caller error.
SQL_GRAMMAR_KEYS: frozenset[str] = frozenset({"templates", "allowed_tables"})

#: SQLClauseProver policy keys. Unknown key → UNDECIDED.
SQL_POLICY_KEYS: frozenset[str] = frozenset(
    {"forbidden_tokens", "allow_statement_chaining", "allowed_tables"}
)

#: SQL AST/construct surface the regex extractor does NOT model soundly (§8.4).
#: Each entry is a regex alternative; a template matching any of them downgrades
#: a would-be PROVEN to UNDECIDED. Owning the list here (rather than as a private
#: regex in prove.py) keeps the modelled SQL surface in the registry, so the
#: drift test pins it and adding/removing a construct is a registry edit.
SQL_UNMODELLED_CONSTRUCTS: tuple[str, ...] = (
    r"\"",  # double-quoted identifier
    r"`",  # back-quoted identifier
    r"\bLATERAL\b",
    r"\bUNNEST\b",
    r"\bVALUES\b",
    r"\bTABLESAMPLE\b",
    r"\bPIVOT\b",
    r"\bUNPIVOT\b",
    r"\bWITH\s+RECURSIVE\b",
)

#: Provenance JSONL chain-envelope fields (§8.1 verifier dimension). The wrapper
#: record around each receipt carries exactly these; any other top-level key is
#: rejected unless it is a registered versioned/namespaced extension (§8.1
#: versioned-extension rule).
ENVELOPE_FIELDS: frozenset[str] = frozenset({"receipt_hash", "jws"})

#: Explicitly registered envelope extension fields (§8.1 versioned-extension
#: rule). EMPTY in v1 — there are no extensions, so the verifier rejects every
#: field outside ENVELOPE_FIELDS. A future field is added here by name under a
#: version bump; there is deliberately NO blanket prefix pass-through (a wildcard
#: would let unvalidated security-relevant fields ride along silently).
ENVELOPE_EXTENSION_FIELDS: frozenset[str] = frozenset()


def _unknown(keys: frozenset[str] | set[str], allowed: frozenset[str]) -> set[str]:
    return set(keys) - allowed


def unmodelled_url_keys(
    grammar_keys: frozenset[str] | set[str], policy_keys: frozenset[str] | set[str]
) -> set[str]:
    """URL grammar/policy keys outside the modelled surface (→ UNDECIDED)."""
    return _unknown(grammar_keys, URL_GRAMMAR_KEYS) | _unknown(policy_keys, URL_POLICY_KEYS)


def unmodelled_sql_keys(
    grammar_keys: frozenset[str] | set[str], policy_keys: frozenset[str] | set[str]
) -> set[str]:
    """SQL grammar/policy keys outside the modelled surface (→ UNDECIDED)."""
    return _unknown(grammar_keys, SQL_GRAMMAR_KEYS) | _unknown(policy_keys, SQL_POLICY_KEYS)


def unknown_envelope_fields(fields: frozenset[str] | set[str]) -> set[str]:
    """Envelope fields that are neither modelled nor a registered extension.

    There is no wildcard: a field is allowed only if it is in ``ENVELOPE_FIELDS``
    or explicitly enumerated in ``ENVELOPE_EXTENSION_FIELDS`` (empty in v1).
    """
    return set(fields) - ENVELOPE_FIELDS - ENVELOPE_EXTENSION_FIELDS
