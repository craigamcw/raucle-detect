"""AI Provenance Graph — cryptographic chain-of-custody for the agentic stack.

Every step in a multi-agent / multi-tool workflow emits a signed receipt
binding ``(agent_id, parent_receipts, operation, input_hash, output_hash,
taint, timestamp)``.  Receipts compose into a Merkle DAG so that given any
output one can reconstruct the entire causal chain back to the original
user input and verify that nothing in the chain has been tampered with.

This is the LLM-equivalent of certificate transparency + SBOM + DNSSEC,
fused for AI workflows.

Usage::

    from raucle_detect.provenance import (
        AgentIdentity, ProvenanceLogger, Operation
    )

    identity = AgentIdentity.generate(
        agent_id="agent:billing-summariser",
        allowed_models=["claude-sonnet-4-6"],
        allowed_tools=["lookup_invoice", "send_email"],
    )
    logger = ProvenanceLogger(agent=identity, sink_path="chain.jsonl")

    # Root: untrusted user input enters the chain
    h1 = logger.record_user_input(
        text="Summarise May invoices and email the finance team.",
        taint={"external_user"},
    )

    # Model call, descends from user input — inherits taint
    h2 = logger.record_model_call(
        parents=[h1],
        model="claude-sonnet-4-6",
        input_text="...",
        output_text="...",
    )

    # Tool call, descends from the model call
    h3 = logger.record_tool_call(
        parents=[h2],
        tool="send_email",
        input_args={"to": "finance@…", "body": "…"},
        output={"status": "queued", "id": "msg_123"},
    )

    # Walk the DAG later
    from raucle_detect.provenance import ProvenanceVerifier
    v = ProvenanceVerifier(public_keys={identity.key_id: identity.public_key_pem()})
    report = v.verify_chain("chain.jsonl")
    print(report.valid, report.errors)

Design notes
------------
- Hashes only, never content. Receipts never embed the raw prompt/output —
  only ``sha256(text)``. Privacy by default.
- Taint is a monotonic string set. Once a chain carries ``external_user``
  taint, every descendant carries it unless an explicit ``sanitisation``
  operation removes specific tags.
- Receipts are compact JWS (EdDSA, Ed25519). Same crypto as the v0.4.0
  verdict-receipt and audit-checkpoint primitives.
- The receipt's own *hash* (sha256 of the compact JWS string) is what
  descendants cite in their ``parents`` list. Hashes are deterministic
  given the signed bytes, so the DAG is content-addressed.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


class Operation(str, Enum):
    """The kind of step a receipt represents."""

    USER_INPUT = "user_input"
    """A raw input entering the agentic graph (a user message, a fetched URL,
    a document from email, a retrieved RAG chunk). The root of every chain."""

    MODEL_CALL = "model_call"
    """An LLM invocation. Records model name, prompt hash, completion hash."""

    TOOL_CALL = "tool_call"
    """An agent invoked a tool / function. Records tool name, args hash,
    result hash."""

    RETRIEVAL = "retrieval"
    """A retrieval-augmented-generation step. Records corpus identifier and
    retrieved-chunks hash. Carries an inherent ``rag:<corpus>`` taint."""

    GUARDRAIL_SCAN = "guardrail_scan"
    """A guardrail scanned an input or output. Auto-emitted by ``Scanner``
    when an agent identity is configured. Records verdict + ruleset hash so
    downstream consumers can prove the scan actually ran."""

    AGENT_HANDOFF = "agent_handoff"
    """One agent passed work to another. Distinct from a tool call because
    the callee is itself an autonomous agent with its own identity."""

    SANITISATION = "sanitisation"
    """An explicit step that removes specific taint tags from its descendants.
    The only operation permitted to shrink the taint set."""

    MERGE = "merge"
    """A confluence point — N parents combine into one receipt. Used when an
    agent assembles results from multiple tool calls or sub-agents."""


# ---------------------------------------------------------------------------
# Utilities — canonical JSON, base64url, Ed25519
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _canonical_json(obj: Any) -> bytes:
    """Serialise *obj* with sorted keys, no whitespace, UTF-8 — for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    """Hash an input or output string for receipt inclusion."""
    return "sha256:" + _sha256_hex(text.encode("utf-8"))


def hash_obj(obj: Any) -> str:
    """Hash an arbitrary JSON-serialisable object for receipt inclusion."""
    return "sha256:" + _sha256_hex(_canonical_json(obj))


_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9][a-z0-9_\-./]{0,127}$")


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            f"agent_id {agent_id!r} must match {_AGENT_ID_RE.pattern!r} "
            "(lowercase, alphanumeric + _-./, 1-128 chars, prefix 'agent:')"
        )


# ---------------------------------------------------------------------------
# Agent identity + capability statement
# ---------------------------------------------------------------------------


@dataclass
class CapabilityStatement:
    """Signed declaration of what an agent is permitted to do.

    Distributed alongside the agent's public key. Verifiers cross-check
    that emitted receipts only invoke permitted models / tools.

    Lives outside the receipt body so receipts stay compact — receipts
    cite the capability statement by ``key_id``.
    """

    agent_id: str
    key_id: str
    public_key_pem: str
    allowed_models: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)
    issuer: str = "raucle-detect"
    issued_at: int = 0
    expires_at: int | None = None
    signature: str = ""  # base64 over the body

    def body(self) -> dict[str, Any]:
        """Return the canonical body that gets signed (excludes ``signature``)."""
        return {
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "allowed_models": sorted(self.allowed_models),
            "allowed_tools": sorted(self.allowed_tools),
            "data_classifications": sorted(self.data_classifications),
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CapabilityStatement:
        return cls(**d)

    def permits_model(self, model: str) -> bool:
        if not self.allowed_models:
            return True  # empty = unrestricted
        return model in self.allowed_models

    def permits_tool(self, tool: str) -> bool:
        if not self.allowed_tools:
            return True
        return tool in self.allowed_tools


class AgentIdentity:
    """An Ed25519 keypair + signed capability statement.

    Acts as the agent's "TLS certificate" — receipts emitted by this agent
    carry its ``key_id`` so verifiers know which public key to check.

    Parameters
    ----------
    agent_id : str
        Stable identifier, must match ``^agent:[a-z0-9_\\-./]+$``.
    private_key : cryptography Ed25519 private key object
    statement : CapabilityStatement
        The signed capability statement for this identity. Must already be
        signed — use :meth:`generate` or :meth:`load` to build a fresh one.
    """

    def __init__(
        self,
        agent_id: str,
        private_key: Any,
        statement: CapabilityStatement,
    ) -> None:
        _validate_agent_id(agent_id)
        self.agent_id = agent_id
        self._private_key = private_key
        self.statement = statement

    @classmethod
    def generate(
        cls,
        agent_id: str,
        *,
        allowed_models: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        data_classifications: list[str] | None = None,
        issuer: str = "raucle-detect",
        ttl_seconds: int | None = None,
    ) -> AgentIdentity:
        """Generate a fresh keypair + self-signed capability statement."""
        _validate_agent_id(agent_id)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = _sha256_hex(pub_pem)[:16]
        now = int(dt.datetime.now(dt.timezone.utc).timestamp())
        stmt = CapabilityStatement(
            agent_id=agent_id,
            key_id=key_id,
            public_key_pem=pub_pem.decode("ascii"),
            allowed_models=allowed_models or [],
            allowed_tools=allowed_tools or [],
            data_classifications=data_classifications or [],
            issuer=issuer,
            issued_at=now,
            expires_at=(now + ttl_seconds) if ttl_seconds else None,
        )
        # Self-sign the statement with the agent's own key for OSS mode.
        # In commercial deployments the issuer's key would sign instead.
        sig = priv.sign(_canonical_json(stmt.body()))
        stmt.signature = base64.b64encode(sig).decode("ascii")
        return cls(agent_id=agent_id, private_key=priv, statement=stmt)

    @classmethod
    def load(cls, private_key_pem: bytes, statement: CapabilityStatement) -> AgentIdentity:
        """Load an identity from a stored PEM + statement."""
        from cryptography.hazmat.primitives import serialization

        priv = serialization.load_pem_private_key(private_key_pem, password=None)
        return cls(agent_id=statement.agent_id, private_key=priv, statement=statement)

    @property
    def key_id(self) -> str:
        return self.statement.key_id

    def public_key_pem(self) -> bytes:
        return self.statement.public_key_pem.encode("ascii")

    def private_key_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceReceipt:
    """A decoded provenance receipt.

    The wire form is a compact JWS string (``header.payload.sig``).
    :meth:`to_jws` and :meth:`from_jws` are the canonical (de)serialisers.
    The ``receipt_hash`` field is the sha256 of the compact JWS string;
    descendants cite it in their ``parents`` list.
    """

    agent_id: str
    agent_key_id: str
    operation: Operation
    parents: list[str] = field(default_factory=list)
    input_hash: str = ""
    output_hash: str = ""
    model: str = ""
    tool: str = ""
    corpus: str = ""
    ruleset_hash: str = ""
    guardrail_verdict: str = ""
    taint: list[str] = field(default_factory=list)
    tenant: str | None = None
    issued_at: int = 0

    # Set after sign() / from_jws() — not part of the signed payload itself.
    jws: str = ""
    receipt_hash: str = ""

    def payload(self) -> dict[str, Any]:
        """Return the canonical signed-payload dict for this receipt."""
        out: dict[str, Any] = {
            "iss": "raucle-detect/provenance",
            "typ": "provenance-receipt/v1",
            "iat": self.issued_at,
            "agent_id": self.agent_id,
            "agent_key_id": self.agent_key_id,
            "operation": self.operation.value,
            "parents": sorted(self.parents),
            "taint": sorted(self.taint),
        }
        if self.input_hash:
            out["input_hash"] = self.input_hash
        if self.output_hash:
            out["output_hash"] = self.output_hash
        if self.model:
            out["model"] = self.model
        if self.tool:
            out["tool"] = self.tool
        if self.corpus:
            out["corpus"] = self.corpus
        if self.ruleset_hash:
            out["ruleset_hash"] = self.ruleset_hash
        if self.guardrail_verdict:
            out["guardrail_verdict"] = self.guardrail_verdict
        if self.tenant is not None:
            out["tenant"] = self.tenant
        return out

    def sign(self, identity: AgentIdentity) -> str:
        """Sign with *identity* and populate ``jws`` + ``receipt_hash``.

        Returns the compact JWS string for convenience.
        """
        header = {
            "alg": "EdDSA",
            "typ": "provenance-receipt/v1",
            "kid": identity.key_id,
            "crit": ["raucle/v1"],
            "raucle/v1": "provenance",
        }
        signing_input = (
            _b64url_encode(_canonical_json(header))
            + "."
            + _b64url_encode(_canonical_json(self.payload()))
        ).encode("ascii")
        sig = identity.sign(signing_input)
        self.jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
        self.receipt_hash = "sha256:" + _sha256_hex(self.jws.encode("ascii"))
        return self.jws

    def to_jws(self) -> str:
        if not self.jws:
            raise ValueError("receipt has not been signed yet — call sign() first")
        return self.jws

    @classmethod
    def from_jws(cls, jws: str) -> ProvenanceReceipt:
        """Parse a compact JWS string back into a receipt.

        Does NOT verify the signature — use :class:`ProvenanceVerifier`
        for verification.
        """
        try:
            header_b64, payload_b64, _sig_b64 = jws.split(".")
        except ValueError as exc:
            raise ValueError("malformed JWS — expected three dot-separated segments") from exc
        payload = json.loads(_b64url_decode(payload_b64))

        receipt = cls(
            agent_id=payload["agent_id"],
            agent_key_id=payload["agent_key_id"],
            operation=Operation(payload["operation"]),
            parents=list(payload.get("parents", [])),
            input_hash=payload.get("input_hash", ""),
            output_hash=payload.get("output_hash", ""),
            model=payload.get("model", ""),
            tool=payload.get("tool", ""),
            corpus=payload.get("corpus", ""),
            ruleset_hash=payload.get("ruleset_hash", ""),
            guardrail_verdict=payload.get("guardrail_verdict", ""),
            taint=list(payload.get("taint", [])),
            tenant=payload.get("tenant"),
            issued_at=payload.get("iat", 0),
        )
        receipt.jws = jws
        receipt.receipt_hash = "sha256:" + _sha256_hex(jws.encode("ascii"))
        return receipt

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["receipt_hash"] = self.receipt_hash
        d["jws"] = self.jws
        return d


# ---------------------------------------------------------------------------
# Logger — emits receipts and writes them to a chain sink
# ---------------------------------------------------------------------------


class ProvenanceLogger:
    """High-level API for emitting provenance receipts.

    Wraps an :class:`AgentIdentity` and a JSONL file (or any object with
    ``.write(str)`` + ``.flush()``). Each ``record_*`` method signs a receipt,
    appends it to the sink, and returns the receipt's hash so callers can
    pass it as a parent to the next step.

    Parameters
    ----------
    agent : AgentIdentity
        Identity whose key signs every emitted receipt.
    sink_path : str | Path, optional
        Append-only JSONL path. Mutually exclusive with *sink_file*.
    sink_file : file-like, optional
        Pre-opened file-like object to write to. The logger never closes it.
    tenant : str, optional
        Tenant label written into every receipt. Useful in multi-tenant SaaS.
    """

    def __init__(
        self,
        agent: AgentIdentity,
        sink_path: str | Path | None = None,
        sink_file: Any | None = None,
        tenant: str | None = None,
    ) -> None:
        if (sink_path is None) == (sink_file is None):
            raise ValueError("exactly one of sink_path or sink_file must be provided")
        self._agent = agent
        self._tenant = tenant
        if sink_path is not None:
            sink_path = Path(sink_path)
            # Pre-load any existing receipts so taint inheritance keeps working
            # across logger restarts on the same chain file.
            self._taint_by_hash: dict[str, set[str]] = {}
            if sink_path.exists():
                self._load_existing_taints(sink_path)
            self._file = open(sink_path, "a", encoding="utf-8")  # noqa: SIM115
            self._owns_file = True
        else:
            self._taint_by_hash = {}
            self._file = sink_file
            self._owns_file = False

    def _load_existing_taints(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    h = raw.get("receipt_hash")
                    taint = raw.get("taint", [])
                    if h:
                        self._taint_by_hash[h] = set(taint)
                except (json.JSONDecodeError, KeyError):
                    continue

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._owns_file:
            self._file.close()

    def __enter__(self) -> ProvenanceLogger:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def agent(self) -> AgentIdentity:
        return self._agent

    # ------------------------------------------------------------------
    # Recording API
    # ------------------------------------------------------------------

    def record_user_input(
        self,
        text: str,
        *,
        taint: set[str] | None = None,
    ) -> str:
        """Record an untrusted input entering the graph (chain root)."""
        receipt = self._build(
            operation=Operation.USER_INPUT,
            parents=[],
            input_hash=hash_text(text),
            taint=set(taint or {"external_user"}),
        )
        return self._emit(receipt)

    def record_model_call(
        self,
        *,
        parents: list[str],
        model: str,
        input_text: str,
        output_text: str,
        extra_taint: set[str] | None = None,
    ) -> str:
        """Record an LLM invocation descending from one or more parents."""
        self._check_model_permission(model)
        receipt = self._build(
            operation=Operation.MODEL_CALL,
            parents=parents,
            model=model,
            input_hash=hash_text(input_text),
            output_hash=hash_text(output_text),
            taint=self._inherit_taint(parents, extra_taint),
        )
        return self._emit(receipt)

    def record_tool_call(
        self,
        *,
        parents: list[str],
        tool: str,
        input_args: Any,
        output: Any,
        extra_taint: set[str] | None = None,
    ) -> str:
        """Record a tool / function invocation."""
        self._check_tool_permission(tool)
        receipt = self._build(
            operation=Operation.TOOL_CALL,
            parents=parents,
            tool=tool,
            input_hash=hash_obj(input_args),
            output_hash=hash_obj(output),
            taint=self._inherit_taint(parents, extra_taint),
        )
        return self._emit(receipt)

    def record_retrieval(
        self,
        *,
        parents: list[str],
        corpus: str,
        query: str,
        retrieved_chunks: Any,
        corpus_trusted: bool = False,
    ) -> str:
        """Record a retrieval step (RAG / vector store).

        By default adds a ``rag:<corpus>`` taint, marking the result as
        derived from third-party / external data. Set *corpus_trusted=True*
        only when the corpus has been independently attested.
        """
        extra: set[str] = set()
        if not corpus_trusted:
            extra.add(f"rag:{corpus}")
        receipt = self._build(
            operation=Operation.RETRIEVAL,
            parents=parents,
            corpus=corpus,
            input_hash=hash_text(query),
            output_hash=hash_obj(retrieved_chunks),
            taint=self._inherit_taint(parents, extra),
        )
        return self._emit(receipt)

    def record_guardrail_scan(
        self,
        *,
        parents: list[str],
        scanned_text: str,
        verdict: str,
        ruleset_hash: str,
        scan_target: str = "input",
    ) -> str:
        """Record that a guardrail scanned an input or output.

        Auto-emitted by :class:`Scanner` when an agent identity is wired in.
        Lets downstream consumers prove the guardrail actually ran.
        """
        receipt = self._build(
            operation=Operation.GUARDRAIL_SCAN,
            parents=parents,
            input_hash=hash_text(scanned_text),
            ruleset_hash=ruleset_hash,
            guardrail_verdict=verdict,
            taint=self._inherit_taint(parents, {f"guardrail-scan:{scan_target}"}),
        )
        return self._emit(receipt)

    def record_agent_handoff(
        self,
        *,
        parents: list[str],
        target_agent_id: str,
        handoff_payload: Any,
    ) -> str:
        """Record that this agent passed work to another agent."""
        _validate_agent_id(target_agent_id)
        receipt = self._build(
            operation=Operation.AGENT_HANDOFF,
            parents=parents,
            input_hash=hash_obj({"target": target_agent_id}),
            output_hash=hash_obj(handoff_payload),
            taint=self._inherit_taint(parents, None),
        )
        return self._emit(receipt)

    def record_sanitisation(
        self,
        *,
        parents: list[str],
        removed_taints: set[str],
        sanitiser_id: str,
        input_text: str,
        output_text: str,
    ) -> str:
        """Record an explicit sanitisation step.

        The only operation permitted to *shrink* the taint set. The removed
        tags are listed explicitly so verifiers can audit the claim.
        """
        inherited = self._inherit_taint(parents, None)
        remaining = inherited - removed_taints
        receipt = self._build(
            operation=Operation.SANITISATION,
            parents=parents,
            tool=sanitiser_id,
            input_hash=hash_text(input_text),
            output_hash=hash_text(output_text),
            taint=remaining,
        )
        # Stash the claim in a structured way via the corpus field — slightly
        # abusive but avoids inventing a new payload field for one operation.
        receipt.corpus = "removed:" + ",".join(sorted(removed_taints))
        return self._emit(receipt)

    def record_merge(
        self,
        *,
        parents: list[str],
        output: Any,
        extra_taint: set[str] | None = None,
    ) -> str:
        """Record a confluence — N parents combine into one descendant."""
        if len(parents) < 2:
            raise ValueError("merge requires at least 2 parents")
        receipt = self._build(
            operation=Operation.MERGE,
            parents=parents,
            output_hash=hash_obj(output),
            taint=self._inherit_taint(parents, extra_taint),
        )
        return self._emit(receipt)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build(
        self,
        *,
        operation: Operation,
        parents: list[str],
        taint: set[str],
        input_hash: str = "",
        output_hash: str = "",
        model: str = "",
        tool: str = "",
        corpus: str = "",
        ruleset_hash: str = "",
        guardrail_verdict: str = "",
    ) -> ProvenanceReceipt:
        return ProvenanceReceipt(
            agent_id=self._agent.agent_id,
            agent_key_id=self._agent.key_id,
            operation=operation,
            parents=list(parents),
            input_hash=input_hash,
            output_hash=output_hash,
            model=model,
            tool=tool,
            corpus=corpus,
            ruleset_hash=ruleset_hash,
            guardrail_verdict=guardrail_verdict,
            taint=sorted(taint),
            tenant=self._tenant,
            issued_at=int(dt.datetime.now(dt.timezone.utc).timestamp()),
        )

    def _emit(self, receipt: ProvenanceReceipt) -> str:
        receipt.sign(self._agent)
        self._file.write(json.dumps(receipt.to_dict(), ensure_ascii=False) + "\n")
        self._file.flush()
        self._taint_by_hash[receipt.receipt_hash] = set(receipt.taint)
        return receipt.receipt_hash

    def _inherit_taint(
        self,
        parents: list[str],
        extra: set[str] | None,
    ) -> set[str]:
        """Compute the inherited taint set from parents + any extra tags.

        Looks up each parent's taint in the in-memory map populated as
        receipts are emitted. Unknown parents (e.g. from a sibling logger
        on the same chain) contribute nothing — the verifier catches the
        broken link separately.
        """
        result: set[str] = set(extra or set())
        for parent_hash in parents:
            result.update(self._taint_by_hash.get(parent_hash, set()))
        return result

    def _check_model_permission(self, model: str) -> None:
        if not self._agent.statement.permits_model(model):
            raise PermissionError(
                f"agent {self._agent.agent_id} not permitted to call model {model!r}; "
                f"allowed: {self._agent.statement.allowed_models}"
            )

    def _check_tool_permission(self, tool: str) -> None:
        if not self._agent.statement.permits_tool(tool):
            raise PermissionError(
                f"agent {self._agent.agent_id} not permitted to call tool {tool!r}; "
                f"allowed: {self._agent.statement.allowed_tools}"
            )


# ---------------------------------------------------------------------------
# Verifier — walks the DAG and checks integrity
# ---------------------------------------------------------------------------


@dataclass
class VerificationReport:
    """Outcome of verifying a provenance chain."""

    valid: bool
    receipt_count: int
    signature_failures: int = 0
    parent_link_failures: int = 0
    taint_monotonicity_failures: int = 0
    tampered_receipts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "receipt_count": self.receipt_count,
            "signature_failures": self.signature_failures,
            "parent_link_failures": self.parent_link_failures,
            "taint_monotonicity_failures": self.taint_monotonicity_failures,
            "tampered_receipts": self.tampered_receipts,
            "errors": self.errors,
        }


class ProvenanceVerifier:
    """Verify a provenance chain end-to-end.

    Three classes of check, all of which must pass for ``valid=True``:

    1. **Signature** — every receipt's JWS verifies against the agent
       public key identified by its ``agent_key_id``.
    2. **DAG integrity** — every ``parent`` referenced by a receipt actually
       exists in the chain. The receipt's stored hash matches a recompute
       from the JWS bytes (tampering detection).
    3. **Taint monotonicity** — non-sanitisation receipts carry a taint set
       that is a superset of the union of their parents' taint sets.
       Sanitisation receipts may shrink the set, but only by tags listed in
       their ``removed:…`` claim.

    Parameters
    ----------
    public_keys : dict[str, bytes]
        Mapping ``key_id -> PEM-encoded public key bytes``.
    """

    def __init__(self, public_keys: dict[str, bytes]) -> None:
        from cryptography.hazmat.primitives import serialization

        self._keys: dict[str, Any] = {
            kid: serialization.load_pem_public_key(pem) for kid, pem in public_keys.items()
        }

    def verify_chain(self, path: str | Path) -> VerificationReport:
        """Verify a JSONL chain file."""
        receipts_by_hash: dict[str, ProvenanceReceipt] = {}
        report = VerificationReport(valid=True, receipt_count=0)

        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    receipt = ProvenanceReceipt.from_jws(raw["jws"])
                except (json.JSONDecodeError, ValueError, KeyError) as exc:
                    report.errors.append(f"line {line_no}: malformed record: {exc}")
                    report.valid = False
                    continue

                # Tampering: recomputed hash must match the stored one
                if raw.get("receipt_hash") != receipt.receipt_hash:
                    report.tampered_receipts.append(receipt.receipt_hash)
                    report.errors.append(f"line {line_no}: receipt_hash mismatch — record tampered")
                    report.valid = False

                # Signature verify
                if not self._verify_signature(receipt):
                    report.signature_failures += 1
                    report.errors.append(
                        f"line {line_no}: signature verification failed for "
                        f"agent_key_id={receipt.agent_key_id}"
                    )
                    report.valid = False

                receipts_by_hash[receipt.receipt_hash] = receipt
                report.receipt_count += 1

        # Second pass: DAG integrity + taint monotonicity
        for h, receipt in receipts_by_hash.items():
            for parent_hash in receipt.parents:
                if parent_hash not in receipts_by_hash:
                    report.parent_link_failures += 1
                    report.errors.append(f"receipt {h}: parent {parent_hash} not found in chain")
                    report.valid = False

            self._check_taint(receipt, receipts_by_hash, report)

        return report

    def trace(self, receipt_hash: str, path: str | Path) -> list[ProvenanceReceipt]:
        """Walk the DAG backwards from *receipt_hash* to all roots.

        Returns receipts in breadth-first order, deduplicated.
        """
        receipts = self._load_all(path)
        if receipt_hash not in receipts:
            raise KeyError(f"receipt {receipt_hash} not found in chain")

        visited: set[str] = set()
        order: list[ProvenanceReceipt] = []
        queue = [receipt_hash]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            r = receipts.get(current)
            if r is None:
                continue
            order.append(r)
            queue.extend(r.parents)
        return order

    def to_dot(self, receipt_hash: str, path: str | Path) -> str:
        """Render the ancestor DAG of *receipt_hash* as Graphviz DOT."""
        ancestors = self.trace(receipt_hash, path)
        lines = ["digraph provenance {", "  rankdir=LR;", "  node [shape=box, fontname=monospace];"]
        for r in ancestors:
            short = r.receipt_hash.split(":")[-1][:10]
            label_parts = [r.operation.value, r.agent_id]
            if r.model:
                label_parts.append(r.model)
            if r.tool:
                label_parts.append(r.tool)
            if r.taint:
                label_parts.append("taint=" + ",".join(r.taint))
            label = r"\n".join(label_parts) + r"\n[" + short + "]"
            lines.append(f'  "{r.receipt_hash}" [label="{label}"];')
        for r in ancestors:
            for parent in r.parents:
                lines.append(f'  "{parent}" -> "{r.receipt_hash}";')
        lines.append("}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _verify_signature(self, receipt: ProvenanceReceipt) -> bool:
        key = self._keys.get(receipt.agent_key_id)
        if key is None:
            return False
        try:
            header_b64, payload_b64, sig_b64 = receipt.jws.split(".")
            signing_input = (header_b64 + "." + payload_b64).encode("ascii")
            key.verify(_b64url_decode(sig_b64), signing_input)
            return True
        except Exception:
            return False

    def _check_taint(
        self,
        receipt: ProvenanceReceipt,
        receipts: dict[str, ProvenanceReceipt],
        report: VerificationReport,
    ) -> None:
        if not receipt.parents:
            return  # roots have no inherited taint to check

        inherited: set[str] = set()
        for p_hash in receipt.parents:
            p = receipts.get(p_hash)
            if p is not None:
                inherited.update(p.taint)

        my_taint = set(receipt.taint)
        if receipt.operation == Operation.SANITISATION:
            # Sanitisation may remove specific tags listed in `corpus` field.
            removed = set()
            if receipt.corpus.startswith("removed:"):
                removed = set(filter(None, receipt.corpus[len("removed:") :].split(",")))
            expected = inherited - removed
            if my_taint != expected:
                report.taint_monotonicity_failures += 1
                report.errors.append(
                    f"receipt {receipt.receipt_hash}: sanitisation taint mismatch "
                    f"(expected {sorted(expected)}, got {sorted(my_taint)})"
                )
                report.valid = False
        else:
            missing = inherited - my_taint
            if missing:
                report.taint_monotonicity_failures += 1
                report.errors.append(
                    f"receipt {receipt.receipt_hash}: taint not monotonic — "
                    f"dropped {sorted(missing)} without a sanitisation step"
                )
                report.valid = False

    def _load_all(self, path: str | Path) -> dict[str, ProvenanceReceipt]:
        out: dict[str, ProvenanceReceipt] = {}
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    r = ProvenanceReceipt.from_jws(raw["jws"])
                except (json.JSONDecodeError, ValueError, KeyError):
                    continue
                out[r.receipt_hash] = r
        return out
