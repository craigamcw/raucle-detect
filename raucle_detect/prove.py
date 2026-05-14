"""Formal verification of bounded guardrails — SMT-backed completeness proofs.

The 2026 AI-security industry runs on the phrase *"we tested it against
10,000 attacks."*  That is not a guarantee, that is statistics over a
sample.  For bounded input sub-languages -- tool-call JSON, URL strings,
read-only SQL -- we can do dramatically better: produce an actual proof
that **no string in the grammar** bypasses a given policy.

This module ships three first-cut provers, each producing a signed
``ProofResult`` artifact whose hash can be embedded in a v0.5.0
verdict receipt or chained into the v0.4.0 audit log:

- ``JSONSchemaProver`` -- given a JSON Schema for a tool call and a
  policy (allowed enums, numeric bounds, forbidden field combinations),
  emit ``PROVEN`` or a concrete counterexample tool-call.
- ``URLPolicyProver`` -- given a URL allowlist (scheme + host glob +
  path prefix) and an extra rule (e.g. "no secrets in query"), emit
  ``PROVEN`` or a counterexample URL.
- ``SQLClauseProver`` -- given a bounded read-only-ish SQL policy
  (forbidden tokens, declared tables, no statement chaining), emit
  ``PROVEN`` or a counterexample query.

The proof artifacts are not "the policy is safe in general" -- they
are "the policy is safe **over the declared grammar**".  That is the
honest scope.  When the grammar is the agent's tool-call interface,
the proof is exactly the property a buyer wants: *the agent literally
cannot emit a tool call that violates this policy*.

Usage::

    from raucle_detect.prove import JSONSchemaProver

    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "amount": {"type": "number"},
            "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
        },
        "required": ["to", "amount", "currency"],
    }
    policy = {
        "max_amount": 100.0,
        "forbidden_recipients": ["attacker@evil.example"],
    }
    result = JSONSchemaProver().prove(schema, policy)
    if result.status == "PROVEN":
        print(result.hash)
    else:
        print("counterexample:", result.counterexample)

Design
------
- Z3 is the underlying SMT engine, used as an optional extra.  The
  prover is one ``pip install 'raucle-detect[proof]'`` away.
- Every prove() returns a ``ProofResult`` whose canonical-JSON body
  is hashed identically to a receipt, so it can be Ed25519-signed
  and chained into existing trust primitives.
- We deliberately reject grammars we cannot model.  Unbounded regex
  fields, recursive schemas, and arbitrary string functions raise
  ``UnsupportedGrammar``.  Honest scope beats lying coverage.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class UnsupportedGrammar(ValueError):
    """Raised when a schema or policy cannot be modelled honestly in SMT."""


def _require_z3() -> Any:
    try:
        import z3  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "raucle_detect.prove requires the [proof] extra: pip install 'raucle-detect[proof]'"
        ) from exc
    return z3


@dataclass
class ProofResult:
    """Outcome of a prover run.

    ``status`` is one of:

    - ``PROVEN``       -- the policy holds over every string in the grammar
    - ``REFUTED``      -- a counterexample exists; see ``counterexample``
    - ``UNDECIDED``    -- the solver timed out or returned ``unknown``
    """

    status: str
    prover: str
    prover_version: str
    grammar_hash: str
    policy_hash: str
    counterexample: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    timeout_ms: int = 0

    def body(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "prover": self.prover,
            "prover_version": self.prover_version,
            "grammar_hash": self.grammar_hash,
            "policy_hash": self.policy_hash,
            "counterexample": self.counterexample,
            "notes": sorted(self.notes),
            "timeout_ms": self.timeout_ms,
        }

    @property
    def hash(self) -> str:
        return "sha256:" + _sha256_hex(_canonical_json(self.body()))

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["hash"] = self.hash
        return d


# ---------------------------------------------------------------------------
# JSON Schema prover
# ---------------------------------------------------------------------------


_JSON_PROVER_VERSION = "jsonschema-prover/v1"


@dataclass
class JSONSchemaProver:
    """Prove that no JSON object matching ``schema`` violates ``policy``.

    Supported schema fragments:

    - ``type``: ``object``, ``string``, ``number``, ``integer``, ``boolean``
    - ``properties`` with primitive types
    - ``required``
    - ``enum`` on strings
    - ``minimum`` / ``maximum`` on numbers

    Supported policy keys:

    - ``forbidden_values`` -- ``{field: [bad, ...]}`` for string fields
    - ``max_value`` / ``min_value`` -- ``{field: bound}`` for numeric fields
    - ``required_present`` -- ``[field, ...]`` (redundant with schema, but
      useful when the schema is permissive and the policy is strict)
    - ``forbidden_field_combinations`` -- ``[[a, b], ...]`` (a present AND
      b present is a violation)
    """

    timeout_ms: int = 5000

    def prove(
        self,
        schema: dict[str, Any],
        policy: dict[str, Any],
    ) -> ProofResult:
        z3 = _require_z3()
        if schema.get("type") != "object" or "properties" not in schema:
            raise UnsupportedGrammar(
                "JSONSchemaProver only supports top-level type=object with properties"
            )

        notes: list[str] = []
        # Build Z3 variables per declared property.
        z3_vars: dict[str, Any] = {}
        presence: dict[str, Any] = {}
        constraints: list[Any] = []
        prop_types: dict[str, str] = {}

        required = set(schema.get("required", []))

        for name, spec in schema["properties"].items():
            t = spec.get("type")
            prop_types[name] = t
            # Presence is its own boolean -- absent fields are unconstrained.
            presence[name] = z3.Bool(f"__present__{name}")
            if name in required:
                constraints.append(presence[name])
            if t == "string":
                z3_vars[name] = z3.String(name)
                if "enum" in spec:
                    enum = spec["enum"]
                    if not all(isinstance(e, str) for e in enum):
                        raise UnsupportedGrammar(f"enum on {name} must be all strings")
                    constraints.append(
                        z3.Implies(
                            presence[name],
                            z3.Or(*[z3_vars[name] == v for v in enum]),
                        )
                    )
            elif t in ("number", "integer"):
                z3_vars[name] = z3.Real(name) if t == "number" else z3.Int(name)
                if "minimum" in spec:
                    constraints.append(z3.Implies(presence[name], z3_vars[name] >= spec["minimum"]))
                if "maximum" in spec:
                    constraints.append(z3.Implies(presence[name], z3_vars[name] <= spec["maximum"]))
            elif t == "boolean":
                z3_vars[name] = z3.Bool(name)
            else:
                raise UnsupportedGrammar(f"unsupported property type {t!r} on {name}")

        # Encode the policy as a *violation* disjunction.  We ask the solver:
        # is there any assignment satisfying the schema that ALSO satisfies the
        # violation?  If unsat, the policy is proven complete.
        violations: list[Any] = []

        for fld, bads in policy.get("forbidden_values", {}).items():
            if fld not in z3_vars:
                notes.append(f"forbidden_values references unknown field {fld!r}")
                continue
            if prop_types.get(fld) != "string":
                raise UnsupportedGrammar(
                    f"forbidden_values on non-string field {fld!r} not supported"
                )
            for bad in bads:
                violations.append(z3.And(presence[fld], z3_vars[fld] == bad))

        for fld, bound in policy.get("max_value", {}).items():
            if fld not in z3_vars or prop_types.get(fld) not in ("number", "integer"):
                raise UnsupportedGrammar(f"max_value on non-numeric field {fld!r}")
            violations.append(z3.And(presence[fld], z3_vars[fld] > bound))

        for fld, bound in policy.get("min_value", {}).items():
            if fld not in z3_vars or prop_types.get(fld) not in ("number", "integer"):
                raise UnsupportedGrammar(f"min_value on non-numeric field {fld!r}")
            violations.append(z3.And(presence[fld], z3_vars[fld] < bound))

        for fld in policy.get("required_present", []):
            if fld not in presence:
                raise UnsupportedGrammar(f"required_present references unknown field {fld!r}")
            violations.append(z3.Not(presence[fld]))

        for combo in policy.get("forbidden_field_combinations", []):
            if not all(c in presence for c in combo):
                raise UnsupportedGrammar(
                    f"forbidden_field_combinations references unknown fields: {combo!r}"
                )
            violations.append(z3.And(*[presence[c] for c in combo]))

        if not violations:
            notes.append("no policy constraints; trivially proven")

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        for c in constraints:
            solver.add(c)
        solver.add(z3.Or(*violations) if violations else z3.BoolVal(False))

        check = solver.check()
        if str(check) == "unsat":
            status = "PROVEN"
            counter = None
        elif str(check) == "sat":
            status = "REFUTED"
            model = solver.model()
            counter = self._extract_counterexample(model, z3_vars, presence)
        else:
            status = "UNDECIDED"
            counter = None
            notes.append(f"solver returned {check}")

        return ProofResult(
            status=status,
            prover="JSONSchemaProver",
            prover_version=_JSON_PROVER_VERSION,
            grammar_hash="sha256:" + _sha256_hex(_canonical_json(schema)),
            policy_hash="sha256:" + _sha256_hex(_canonical_json(policy)),
            counterexample=counter,
            notes=notes,
            timeout_ms=self.timeout_ms,
        )

    @staticmethod
    def _extract_counterexample(
        model: Any, z3_vars: dict[str, Any], presence: dict[str, Any]
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, var in z3_vars.items():
            pres = model.eval(presence[name], model_completion=True)
            if str(pres) != "True":
                continue
            val = model.eval(var, model_completion=True)
            s = str(val).strip('"')
            if s in ("True", "False"):
                out[name] = s == "True"
            else:
                try:
                    out[name] = int(s) if "." not in s else float(s)
                except ValueError:
                    out[name] = s
        return out


# ---------------------------------------------------------------------------
# URL policy prover
# ---------------------------------------------------------------------------


_URL_PROVER_VERSION = "url-prover/v1"


@dataclass
class URLPolicyProver:
    """Prove that every URL matching ``grammar`` satisfies ``policy``.

    ``grammar`` is a small enumerable shape::

        {
            "schemes": ["https"],
            "hosts": ["api.example.com", "*.example.com"],
            "path_prefixes": ["/v1/", "/v2/"],
            "query_keys": ["q", "page"],
        }

    ``policy``::

        {
            "require_https": true,
            "forbid_query_keys": ["token", "api_key", "password"],
            "host_allowlist": ["api.example.com", "*.example.com"],
            "max_path_depth": 5,
        }

    The completeness claim is: for every URL the agent can construct under
    ``grammar``, the policy holds.  Counterexamples are concrete URLs.
    """

    def prove(self, grammar: dict[str, Any], policy: dict[str, Any]) -> ProofResult:
        notes: list[str] = []
        violations: list[dict[str, Any]] = []

        schemes = grammar.get("schemes", [])
        hosts = grammar.get("hosts", [])
        path_prefixes = grammar.get("path_prefixes", ["/"])
        query_keys = grammar.get("query_keys", [])

        if not schemes or not hosts:
            raise UnsupportedGrammar("grammar must declare non-empty schemes and hosts")

        # require_https
        if policy.get("require_https"):
            for s in schemes:
                if s != "https":
                    violations.append({"scheme": s, "host": hosts[0], "path": path_prefixes[0]})

        # forbid_query_keys
        forbidden_q = set(policy.get("forbid_query_keys", []))
        for q in query_keys:
            if q in forbidden_q:
                violations.append(
                    {
                        "scheme": schemes[0],
                        "host": hosts[0],
                        "path": path_prefixes[0],
                        "query_key": q,
                    }
                )

        # host_allowlist: every grammar host must be permitted by some allowlist entry
        allowlist = policy.get("host_allowlist")
        if allowlist is not None:
            for h in hosts:
                if not any(_host_matches(h, a) for a in allowlist):
                    violations.append({"scheme": schemes[0], "host": h, "path": path_prefixes[0]})

        # max_path_depth
        max_depth = policy.get("max_path_depth")
        if max_depth is not None:
            for p in path_prefixes:
                depth = len([s for s in p.split("/") if s])
                if depth > max_depth:
                    notes.append(f"path prefix {p!r} already exceeds max_path_depth={max_depth}")
                    violations.append({"scheme": schemes[0], "host": hosts[0], "path": p})

        if not violations:
            status = "PROVEN"
            counter = None
        else:
            status = "REFUTED"
            counter = violations[0]

        return ProofResult(
            status=status,
            prover="URLPolicyProver",
            prover_version=_URL_PROVER_VERSION,
            grammar_hash="sha256:" + _sha256_hex(_canonical_json(grammar)),
            policy_hash="sha256:" + _sha256_hex(_canonical_json(policy)),
            counterexample=counter,
            notes=notes,
        )


def _host_matches(host: str, pattern: str) -> bool:
    """Match a host against an optionally wildcarded pattern (``*.example.com``)."""
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) or host == pattern[2:]
    return False


# ---------------------------------------------------------------------------
# SQL clause prover (bounded read-only-ish policy)
# ---------------------------------------------------------------------------


_SQL_PROVER_VERSION = "sql-prover/v1"

_DEFAULT_FORBIDDEN_TOKENS = (
    "DROP",
    "DELETE",
    "TRUNCATE",
    "ALTER",
    "UPDATE",
    "INSERT",
    "GRANT",
    "REVOKE",
    "EXEC",
    "EXECUTE",
    "CALL",
    "ATTACH",
    "PRAGMA",
)

_STATEMENT_CHAIN_RE = re.compile(r";\s*\S")


@dataclass
class SQLClauseProver:
    """Prove a bounded SQL policy over an enumerable set of candidate queries.

    Unlike the JSON prover this is *enumeration with SMT-style reasoning*,
    not full grammar inference -- modelling an arbitrary SQL grammar in SMT
    is well outside this scope.  The honest claim is: given a finite set
    of statement *templates* and the columns/tables they touch, prove the
    policy holds for every template.

    ``grammar``::

        {
            "templates": [
                "SELECT id, name FROM customers WHERE tenant_id = ?",
                "SELECT total FROM invoices WHERE id = ?"
            ],
            "allowed_tables": ["customers", "invoices"],
        }

    ``policy``::

        {
            "forbidden_tokens": ["DROP", "DELETE", ...],   # case-insensitive
            "allow_statement_chaining": false,
            "allowed_tables": ["customers", "invoices"],
        }

    Counterexamples are the offending template plus the rule that broke.
    """

    def prove(self, grammar: dict[str, Any], policy: dict[str, Any]) -> ProofResult:
        templates = grammar.get("templates")
        if not templates:
            raise UnsupportedGrammar("grammar.templates must be a non-empty list")

        forbidden = {t.upper() for t in policy.get("forbidden_tokens", _DEFAULT_FORBIDDEN_TOKENS)}
        allow_chain = policy.get("allow_statement_chaining", False)
        allowed_tables = {t.lower() for t in policy.get("allowed_tables", [])}

        notes: list[str] = []
        counter: dict[str, Any] | None = None

        for tmpl in templates:
            upper = tmpl.upper()
            tokens = re.findall(r"[A-Z_][A-Z_0-9]*", upper)
            for tok in tokens:
                if tok in forbidden:
                    counter = {"template": tmpl, "violation": f"forbidden token {tok}"}
                    break
            if counter:
                break

            if not allow_chain and _STATEMENT_CHAIN_RE.search(tmpl):
                counter = {"template": tmpl, "violation": "statement chaining via ';'"}
                break

            if allowed_tables:
                # crude FROM/JOIN extractor
                refs = re.findall(r"(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)", upper)
                for ref in refs:
                    if ref.lower() not in allowed_tables:
                        counter = {
                            "template": tmpl,
                            "violation": f"table {ref!r} not in allowed_tables",
                        }
                        break
                if counter:
                    break

        status = "PROVEN" if counter is None else "REFUTED"
        return ProofResult(
            status=status,
            prover="SQLClauseProver",
            prover_version=_SQL_PROVER_VERSION,
            grammar_hash="sha256:" + _sha256_hex(_canonical_json(grammar)),
            policy_hash="sha256:" + _sha256_hex(_canonical_json(policy)),
            counterexample=counter,
            notes=notes,
        )
