"""Capability-based agent permissions -- unforgeable tool handles.

Every prompt-injection mitigation in 2026 asks an LLM, in English, not
to misuse its tools. This module replaces that polite request with an
OS-style capability discipline: a tool simply refuses to execute unless
the caller presents a valid signed ``Capability`` token whose constraints
are satisfied by the actual call arguments.

The attacker can inject any prompt they want. The agent can decide to
call any tool it wants. The gate doesn't care: without an unforgeable
token, no tool runs.

Three pieces:

- :class:`Capability` -- the token. Ed25519-signed; binds
  ``(agent_id, tool, constraints, nbf, exp, parent_id)``.
- :class:`CapabilityIssuer` -- mints fresh tokens, attenuates parents
  into more-restricted children.
- :class:`CapabilityGate` -- the choke point. ``check(token, tool, args)``
  returns ``GateDecision.ALLOW`` or ``GateDecision.DENY`` with a reason.
  Failing closed is the default.

Attenuation is the killer property. A platform-level token can mint a
session-scoped child carrying extra constraints; the child can mint a
single-task grandchild. Children can only *narrow* permissions, never
broaden. The chain is verifiable end-to-end -- every link Ed25519-signed
by the issuer that minted it.

Composition with the rest of the stack:

- Constraint shape matches :class:`raucle_detect.prove.JSONSchemaProver`'s
  policy schema. A token can carry a ``policy_proof_hash`` from a v0.9.0
  proof, claiming "these constraints are formally complete over the
  declared schema for this tool."
- Every :meth:`CapabilityGate.check` decision emits a structured record
  consumable by the v0.4.0 audit chain and v0.5.0 verdict receipts.

Usage::

    from raucle_detect.capability import CapabilityIssuer, CapabilityGate

    issuer = CapabilityIssuer.generate(issuer="platform.example")
    issuer.save_private_key("issuer.key.pem")

    root = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "forbidden_values": {"to": ["attacker@evil.example"]},
        },
        ttl_seconds=3600,
    )

    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    decision = gate.check(root, tool="transfer_funds",
                          args={"to": "alice@example", "amount": 50})
    if not decision.allowed:
        raise PermissionError(decision.reason)
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonicalisation + crypto helpers (mirrors feed.py / provenance.py)
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _now() -> int:
    return int(dt.datetime.now(dt.timezone.utc).timestamp())


def _require_crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "raucle_detect.capability requires the [compliance] extra: "
            "pip install 'raucle-detect[compliance]'"
        ) from exc
    return serialization, ed25519


_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9][a-z0-9_\-./]{0,127}$")
_TOOL_RE = re.compile(r"^[a-z0-9][a-z0-9_\-./]{0,127}$")


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(f"agent_id {agent_id!r} must match {_AGENT_ID_RE.pattern!r}")


def _validate_tool(tool: str) -> None:
    if not _TOOL_RE.match(tool):
        raise ValueError(f"tool {tool!r} must match {_TOOL_RE.pattern!r}")


# ---------------------------------------------------------------------------
# Capability token
# ---------------------------------------------------------------------------


@dataclass
class Capability:
    """An unforgeable signed permission to invoke ``tool`` with constrained args.

    Constraint schema mirrors :class:`raucle_detect.prove.JSONSchemaProver`'s
    policy keys:

    - ``forbidden_values`` -- ``{field: [bad, ...]}``
    - ``max_value`` / ``min_value`` -- ``{field: bound}``
    - ``required_present`` -- ``[field, ...]``
    - ``forbidden_field_combinations`` -- ``[[a, b], ...]``
    - ``allowed_values`` -- ``{field: [ok, ...]}`` (whitelist)
    """

    token_id: str
    agent_id: str
    tool: str
    constraints: dict[str, Any]
    issuer: str
    key_id: str
    issued_at: int
    not_before: int
    expires_at: int
    parent_id: str | None = None
    policy_proof_hash: str | None = None
    signature: str = ""

    def body(self) -> dict[str, Any]:
        # NB: token_id is derived from this body and is NOT a member of it.
        return {
            "agent_id": self.agent_id,
            "tool": self.tool,
            "constraints": _normalise_constraints(self.constraints),
            "issuer": self.issuer,
            "key_id": self.key_id,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "parent_id": self.parent_id,
            "policy_proof_hash": self.policy_proof_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["token_id"] = self.token_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Capability:
        return cls(
            token_id=d["token_id"],
            agent_id=d["agent_id"],
            tool=d["tool"],
            constraints=d.get("constraints", {}),
            issuer=d["issuer"],
            key_id=d["key_id"],
            issued_at=int(d["issued_at"]),
            not_before=int(d["not_before"]),
            expires_at=int(d["expires_at"]),
            parent_id=d.get("parent_id"),
            policy_proof_hash=d.get("policy_proof_hash"),
            signature=d.get("signature", ""),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls, path: str | Path) -> Capability:
        return cls.from_dict(json.loads(Path(path).read_text()))


def _normalise_constraints(c: dict[str, Any]) -> dict[str, Any]:
    """Canonical form so attenuation comparisons are exact."""
    out: dict[str, Any] = {}
    if "forbidden_values" in c:
        out["forbidden_values"] = {k: sorted(v) for k, v in c["forbidden_values"].items()}
    if "allowed_values" in c:
        out["allowed_values"] = {k: sorted(v) for k, v in c["allowed_values"].items()}
    if "max_value" in c:
        out["max_value"] = dict(c["max_value"])
    if "min_value" in c:
        out["min_value"] = dict(c["min_value"])
    if "required_present" in c:
        out["required_present"] = sorted(c["required_present"])
    if "forbidden_field_combinations" in c:
        out["forbidden_field_combinations"] = sorted(
            sorted(combo) for combo in c["forbidden_field_combinations"]
        )
    return out


# ---------------------------------------------------------------------------
# Issuer
# ---------------------------------------------------------------------------


class CapabilityIssuer:
    """Holds an Ed25519 private key; mints and attenuates Capability tokens."""

    def __init__(self, issuer: str, private_key: Any) -> None:
        if not issuer:
            raise ValueError("issuer must not be empty")
        self.issuer = issuer
        self._priv = private_key
        serialization, _ = _require_crypto()
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = pub_pem.decode("ascii")
        self.key_id = _sha256_hex(pub_pem)[:16]

    @classmethod
    def generate(cls, issuer: str) -> CapabilityIssuer:
        _, ed25519 = _require_crypto()
        return cls(issuer=issuer, private_key=ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def load_private_key(cls, issuer: str, path: str | Path) -> CapabilityIssuer:
        serialization, _ = _require_crypto()
        priv = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        return cls(issuer=issuer, private_key=priv)

    def save_private_key(self, path: str | Path) -> None:
        serialization, _ = _require_crypto()
        pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        Path(path).write_bytes(pem)

    def mint(
        self,
        *,
        agent_id: str,
        tool: str,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 3600,
        not_before_offset: int = 0,
        policy_proof_hash: str | None = None,
    ) -> Capability:
        _validate_agent_id(agent_id)
        _validate_tool(tool)
        now = _now()
        cap = Capability(
            token_id="",
            agent_id=agent_id,
            tool=tool,
            constraints=_normalise_constraints(constraints or {}),
            issuer=self.issuer,
            key_id=self.key_id,
            issued_at=now,
            not_before=now + not_before_offset,
            expires_at=now + ttl_seconds,
            parent_id=None,
            policy_proof_hash=policy_proof_hash,
        )
        cap.token_id = "cap:" + _sha256_hex(_canonical_json(cap.body()))[:24]
        # Re-canonicalise with token_id included.
        cap.signature = _b64(self._priv.sign(_canonical_json(cap.body())))
        return cap

    def attenuate(
        self,
        parent: Capability,
        *,
        extra_constraints: dict[str, Any] | None = None,
        narrower_ttl_seconds: int | None = None,
        narrower_agent_id: str | None = None,
    ) -> Capability:
        """Derive a more-restricted child token from ``parent``.

        The child:

        - Must target the same ``tool`` (cannot broaden tool scope).
        - May target the same or a narrower ``agent_id``.
        - Inherits parent constraints plus any additional ``extra_constraints``.
        - Must expire no later than the parent.
        - Carries ``parent_id`` so the chain is reconstructible.

        Raises ``ValueError`` if the requested attenuation would broaden
        permissions in any dimension.
        """
        if not parent.signature:
            raise ValueError("parent token is unsigned")
        if parent.expires_at <= _now():
            raise ValueError("parent token has expired")

        child_agent = narrower_agent_id or parent.agent_id
        if narrower_agent_id and narrower_agent_id != parent.agent_id:
            _validate_agent_id(narrower_agent_id)
            # Narrowing is allowed only if the child agent_id is *more specific*,
            # interpreted as a prefix-extension of the parent's id (e.g.
            # agent:billing -> agent:billing.invoice).
            if not narrower_agent_id.startswith(parent.agent_id):
                raise ValueError(
                    f"narrower_agent_id {narrower_agent_id!r} is not a sub-scope of "
                    f"parent {parent.agent_id!r}"
                )

        merged = _merge_narrowing(parent.constraints, extra_constraints or {})

        now = _now()
        ttl = (
            narrower_ttl_seconds if narrower_ttl_seconds is not None else (parent.expires_at - now)
        )
        new_exp = now + ttl
        if new_exp > parent.expires_at:
            raise ValueError("child token cannot outlive its parent")

        child = Capability(
            token_id="",
            agent_id=child_agent,
            tool=parent.tool,
            constraints=merged,
            issuer=self.issuer,
            key_id=self.key_id,
            issued_at=now,
            not_before=max(now, parent.not_before),
            expires_at=new_exp,
            parent_id=parent.token_id,
            policy_proof_hash=parent.policy_proof_hash,
        )
        child.token_id = "cap:" + _sha256_hex(_canonical_json(child.body()))[:24]
        child.signature = _b64(self._priv.sign(_canonical_json(child.body())))
        return child


def _merge_narrowing(parent: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """Combine two constraint sets, taking the tighter bound on every key."""
    import copy

    out: dict[str, Any] = copy.deepcopy(parent)

    for fld, vals in extra.get("forbidden_values", {}).items():
        out.setdefault("forbidden_values", {})
        out["forbidden_values"][fld] = sorted(set(out["forbidden_values"].get(fld, [])) | set(vals))

    for fld, vals in extra.get("allowed_values", {}).items():
        out.setdefault("allowed_values", {})
        if fld in out["allowed_values"]:
            # Intersection = tighter
            out["allowed_values"][fld] = sorted(set(out["allowed_values"][fld]) & set(vals))
        else:
            out["allowed_values"][fld] = sorted(set(vals))

    for fld, bound in extra.get("max_value", {}).items():
        out.setdefault("max_value", {})
        existing = out["max_value"].get(fld)
        out["max_value"][fld] = min(existing, bound) if existing is not None else bound

    for fld, bound in extra.get("min_value", {}).items():
        out.setdefault("min_value", {})
        existing = out["min_value"].get(fld)
        out["min_value"][fld] = max(existing, bound) if existing is not None else bound

    if "required_present" in extra:
        out.setdefault("required_present", [])
        out["required_present"] = sorted(
            set(out["required_present"]) | set(extra["required_present"])
        )

    if "forbidden_field_combinations" in extra:
        out.setdefault("forbidden_field_combinations", [])
        merged = {tuple(sorted(c)) for c in out["forbidden_field_combinations"]}
        merged.update(tuple(sorted(c)) for c in extra["forbidden_field_combinations"])
        out["forbidden_field_combinations"] = sorted(sorted(c) for c in merged)

    return _normalise_constraints(out)


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


@dataclass
class GateDecision:
    """Outcome of :meth:`CapabilityGate.check`."""

    allowed: bool
    reason: str
    token_id: str | None = None
    chain: list[str] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return not self.allowed


class CapabilityGate:
    """The choke point. No token, no tool execution.

    Parameters
    ----------
    trusted_issuers
        Mapping of ``key_id -> public_key_pem``. Tokens signed by any other
        key are rejected. There is no global root.
    parent_resolver
        Optional callable ``(token_id) -> Capability | None`` used when a
        token carries ``parent_id`` and the gate is configured to verify
        the full chain. Default behaviour is to verify the immediate
        signature and trust the attenuation invariants enforced at mint.
    """

    def __init__(
        self,
        *,
        trusted_issuers: dict[str, str],
        parent_resolver: Any = None,
    ) -> None:
        if not trusted_issuers:
            raise ValueError("CapabilityGate requires at least one trusted issuer")
        self._issuers = dict(trusted_issuers)
        self._resolver = parent_resolver

    def check(
        self,
        token: Capability,
        *,
        tool: str,
        agent_id: str | None = None,
        args: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> GateDecision:
        ts = now if now is not None else _now()
        args = args or {}

        # 1) Issuer pinned?
        pem = self._issuers.get(token.key_id)
        if pem is None:
            return GateDecision(False, f"unknown key_id {token.key_id!r}", token.token_id)

        # 2) Signature valid?
        try:
            self._verify_signature(token, pem)
        except ValueError as exc:
            return GateDecision(False, f"bad signature: {exc}", token.token_id)

        # 3) token_id matches body?
        expected_id = "cap:" + _sha256_hex(_canonical_json(token.body()))[:24]
        if expected_id != token.token_id:
            return GateDecision(False, "token_id does not match body", token.token_id)

        # 4) Time bounds.
        if ts < token.not_before:
            return GateDecision(False, "token not yet valid", token.token_id)
        if ts >= token.expires_at:
            return GateDecision(False, "token expired", token.token_id)

        # 5) Tool match.
        if token.tool != tool:
            return GateDecision(
                False, f"token bound to tool {token.tool!r}, called {tool!r}", token.token_id
            )

        # 6) Agent match (when supplied).
        if (
            agent_id is not None
            and agent_id != token.agent_id
            and not agent_id.startswith(token.agent_id)
        ):
            return GateDecision(
                False,
                f"agent_id {agent_id!r} does not match token's {token.agent_id!r}",
                token.token_id,
            )

        # 7) Argument constraints.
        why = _check_constraints(token.constraints, args)
        if why:
            return GateDecision(False, f"constraint violated: {why}", token.token_id)

        # 8) Optional chain verification.
        chain: list[str] = []
        if token.parent_id and self._resolver is not None:
            current = token
            while current.parent_id:
                parent = self._resolver(current.parent_id)
                if parent is None:
                    return GateDecision(
                        False,
                        f"unresolved parent {current.parent_id!r}",
                        token.token_id,
                        chain,
                    )
                pem2 = self._issuers.get(parent.key_id)
                if pem2 is None:
                    return GateDecision(
                        False,
                        f"parent {parent.token_id} signed by untrusted key",
                        token.token_id,
                        chain,
                    )
                try:
                    self._verify_signature(parent, pem2)
                except ValueError as exc:
                    return GateDecision(
                        False,
                        f"parent {parent.token_id} bad signature: {exc}",
                        token.token_id,
                        chain,
                    )
                chain.append(parent.token_id)
                current = parent

        return GateDecision(True, "ok", token.token_id, chain)

    @staticmethod
    def _verify_signature(token: Capability, pem: str) -> None:
        serialization, _ = _require_crypto()
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        try:
            pub.verify(_b64d(token.signature), _canonical_json(token.body()))
        except Exception as exc:
            raise ValueError(str(exc)) from exc


def _check_constraints(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """Return a non-empty reason string on violation, or None on pass."""
    for fld, bads in c.get("forbidden_values", {}).items():
        if fld in args and args[fld] in bads:
            return f"{fld}={args[fld]!r} is in forbidden_values"
    for fld, oks in c.get("allowed_values", {}).items():
        if fld in args and args[fld] not in oks:
            return f"{fld}={args[fld]!r} is not in allowed_values"
    for fld, bound in c.get("max_value", {}).items():
        if fld in args and args[fld] > bound:
            return f"{fld}={args[fld]!r} exceeds max_value {bound!r}"
    for fld, bound in c.get("min_value", {}).items():
        if fld in args and args[fld] < bound:
            return f"{fld}={args[fld]!r} below min_value {bound!r}"
    for fld in c.get("required_present", []):
        if fld not in args:
            return f"required field {fld!r} missing"
    for combo in c.get("forbidden_field_combinations", []):
        if all(c2 in args for c2 in combo):
            return f"forbidden field combination {combo!r} all present"
    return None
