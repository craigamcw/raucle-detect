#!/usr/bin/env python3
"""Generate canonical test vectors for the Raucle Provenance Receipt v1 spec.

Reads a deterministic seed corpus and emits a JSON file mapping vector name
to ``(input, expected_jws, expected_receipt_hash)``. Implementations claiming
v1 conformance MUST reproduce every vector byte-for-byte.

Usage::

    python scripts/gen_provenance_test_vectors.py > docs/spec/provenance/v1/test-vectors.json
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Deterministic Ed25519 seed — same bytes => same keys => same signatures.
# Anyone re-running this script gets identical output, including signatures.
_FIXED_SEED = bytes.fromhex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")


def _build_identity():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle_detect.provenance import CapabilityStatement, _sha256_hex

    priv = Ed25519PrivateKey.from_private_bytes(_FIXED_SEED)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = _sha256_hex(pub_pem)[:16]
    stmt = CapabilityStatement(
        agent_id="agent:test-vectors",
        key_id=key_id,
        public_key_pem=pub_pem.decode("ascii"),
        allowed_models=["test-model-v1"],
        allowed_tools=["test-tool"],
        issuer="raucle-detect",
        issued_at=1_700_000_000,
        expires_at=None,
    )
    # Self-sign the statement deterministically
    from raucle_detect.provenance import _canonical_json

    sig = priv.sign(_canonical_json(stmt.body()))
    stmt.signature = base64.b64encode(sig).decode("ascii")

    # Wrap as AgentIdentity without going through generate() (random key)
    from raucle_detect.provenance import AgentIdentity

    return AgentIdentity(agent_id="agent:test-vectors", private_key=priv, statement=stmt)


def _build_vectors() -> dict:
    from raucle_detect.provenance import Operation, ProvenanceReceipt, hash_obj, hash_text

    identity = _build_identity()
    vectors: dict = {
        "spec_version": "raucle-provenance-receipt/v1",
        "generator_version": "raucle-detect 0.5.0",
        "fixed_seed_hex": _FIXED_SEED.hex(),
        "agent_id": identity.agent_id,
        "agent_key_id": identity.key_id,
        "public_key_pem": identity.statement.public_key_pem,
        "vectors": [],
    }

    # Vector 1: minimal user_input root
    r1 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.USER_INPUT,
        input_hash=hash_text("Hello, world."),
        taint=["external_user"],
        issued_at=1_700_000_001,
    )
    r1.sign(identity)
    vectors["vectors"].append(
        {
            "name": "user_input_minimal",
            "description": "Minimal root receipt for a user_input operation",
            "expected_jws": r1.jws,
            "expected_receipt_hash": r1.receipt_hash,
        }
    )

    # Vector 2: model_call descending from vector 1
    r2 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.MODEL_CALL,
        parents=[r1.receipt_hash],
        model="test-model-v1",
        input_hash=hash_text("Hello, world."),
        output_hash=hash_text("Greetings."),
        taint=["external_user"],
        issued_at=1_700_000_002,
    )
    r2.sign(identity)
    vectors["vectors"].append(
        {
            "name": "model_call_inheriting_taint",
            "description": "model_call citing the user_input as parent; inherits taint",
            "expected_jws": r2.jws,
            "expected_receipt_hash": r2.receipt_hash,
        }
    )

    # Vector 3: tool_call with structured args/output
    r3 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.TOOL_CALL,
        parents=[r2.receipt_hash],
        tool="test-tool",
        input_hash=hash_obj({"argument": 42}),
        output_hash=hash_obj({"result": True}),
        taint=["external_user"],
        issued_at=1_700_000_003,
    )
    r3.sign(identity)
    vectors["vectors"].append(
        {
            "name": "tool_call_with_structured_args",
            "description": "tool_call hashing structured input args and output objects",
            "expected_jws": r3.jws,
            "expected_receipt_hash": r3.receipt_hash,
        }
    )

    # Vector 4: sanitisation removing a taint tag
    r4 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.SANITISATION,
        parents=[r3.receipt_hash],
        tool="redactor:pii-v1",
        corpus="removed:external_user",
        input_hash=hash_text("Greetings."),
        output_hash=hash_text("[REDACTED]"),
        taint=[],  # external_user removed
        issued_at=1_700_000_004,
    )
    r4.sign(identity)
    vectors["vectors"].append(
        {
            "name": "sanitisation_removes_tag",
            "description": "sanitisation operation explicitly removing the external_user taint",
            "expected_jws": r4.jws,
            "expected_receipt_hash": r4.receipt_hash,
        }
    )

    # Vector 5: guardrail_scan with verdict
    r5 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.GUARDRAIL_SCAN,
        parents=[r1.receipt_hash],
        input_hash=hash_text("Hello, world."),
        ruleset_hash="sha256:" + "0" * 64,
        guardrail_verdict="CLEAN",
        taint=["external_user", "guardrail-scan:input"],
        issued_at=1_700_000_005,
    )
    r5.sign(identity)
    vectors["vectors"].append(
        {
            "name": "guardrail_scan_clean",
            "description": "guardrail_scan emitting a CLEAN verdict with ruleset hash",
            "expected_jws": r5.jws,
            "expected_receipt_hash": r5.receipt_hash,
        }
    )

    return vectors


def main() -> int:
    vectors = _build_vectors()
    print(json.dumps(vectors, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
