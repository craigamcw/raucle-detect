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


def _canonicalization_vectors() -> list[dict]:
    """Pure JCS + SHA-256 vectors over EXPOSED preimage objects, so a peer
    implementation can byte-diff §4 canonicalisation directly (interop, e.g. the
    A2A/APS action_ref preimage) without reverse-engineering a receipt body.

    Each vector exposes the input object, the canonical UTF-8 JCS string, and its
    SHA-256 hex. Uses the SAME `_canonical_json` (§4.3 restricted subset) the
    receipts use.
    """
    import unicodedata

    from raucle_detect.provenance import _canonical_json, _sha256_hex

    def vec(name: str, desc: str, obj: dict) -> dict:
        jcs = _canonical_json(obj)  # bytes, §4.3 canonical form
        return {
            "name": name,
            "description": desc,
            "input_object": obj,
            "expected_canonical_utf8": jcs.decode("utf-8"),
            # Unambiguous byte artifact: hex of the exact UTF-8 canonical bytes,
            # so a peer can byte-diff without depending on how the outer JSON
            # escapes non-ASCII (the file itself uses ensure_ascii=True).
            "expected_canonical_hex": jcs.hex(),
            "expected_canonical_sha256": "sha256:" + _sha256_hex(jcs),
        }

    # APS action_ref preimage shape: 4 fields, all strings / arrays of strings.
    # scopeRequired pre-sorted by Unicode code point and NFC-normalised per the
    # action_ref definition (that ordering is a producer step, not JCS).
    scopes = sorted(unicodedata.normalize("NFC", s) for s in ["commerce.read", "commerce.write"])
    action_ref = {
        "actionType": "commerce_preflight",
        "agentId": "did:aps:z6MkExampleAgentIdInCanonicalMultibaseForm",
        "scopeRequired": scopes,
        "timestamp": "2026-04-08T12:00:00Z",
    }

    return [
        vec(
            "canon_action_ref_aps",
            "APS §4.1 action_ref preimage (4 string/array-of-string fields; no numbers, "
            "so the ±(2^53-1) integer bound is moot — restricted subset == full RFC 8785 here)",
            action_ref,
        ),
        vec(
            "canon_non_ascii_strings",
            "Non-ASCII strings MUST be raw UTF-8, never \\uXXXX-escaped (§4.3.4). "
            "Mix of Latin-1, CJK, and emoji to exercise multi-byte UTF-8.",
            {"corpus": "café — naïve — 日本語 — 🔒", "taint": ["external_user", "naïveté"]},
        ),
        vec(
            "canon_non_nfc_passthrough",
            "Canonicalisation is pure serialisation (RFC 8785) and does NOT apply "
            "Unicode normalisation: a decomposed string is emitted byte-for-byte as "
            "given, NOT folded to NFC. The value is U+0041 U+030A (LATIN A + COMBINING "
            "RING) — distinct bytes from the precomposed U+00C5 'Å'. Interop note: NFC "
            "is a *producer* responsibility (e.g. APS sorts/normalises scopeRequired "
            "before canonicalising); a canonicaliser that silently NFC-folds here would "
            "diverge on this input.",
            {"scope": "A\u030a"},  # decomposed: LATIN A + COMBINING RING ABOVE
        ),
        vec(
            "canon_non_bmp_key_ordering",
            "Object keys MUST be ordered by UTF-16 code unit (§4.3.1, RFC 8785 "
            "§3.2.3), NOT by Unicode code point. The key '\\uE000' (BMP private-use) "
            "vs '\\U0001F511' (🔑, non-BMP) is the discriminating case: by code "
            "point \\uE000 (57344) < 🔑 (128273) so \\uE000 sorts first; by UTF-16 "
            "the 🔑 surrogate lead unit 0xD83D (55357) < 0xE000 so 🔑 sorts first. "
            "A code-point sort (naive Python/Go/Rust) and a UTF-16 sort (JS/.NET) "
            "disagree here — this vector forces all implementations onto UTF-16.",
            {"": 1, "\U0001F511": 2, "a": 3},
        ),
        vec(
            "canon_boundary_integer",
            "Safe-integer boundary 2^53-1 = 9007199254740991 (§4.3.6). This value "
            "round-trips byte-identically everywhere; 2^53 (9007199254740992) is "
            "out of the signed-material domain and MUST be rejected at sign/verify.",
            {"amount": 9007199254740991, "currency": "USD"},
        ),
    ]


def _invalid_canonicalization_vectors() -> list[dict]:
    """Inputs that are INVALID signed/hashed material and MUST be rejected, not
    serialised (§4.3.5 floats, §4.3.6 integer domain). Makes the normative
    rejection rules machine-checkable instead of prose-only.

    Self-checked at generation time: each input is asserted to actually raise
    in `_canonical_json`, so the published `must_reject: true` is never a claim
    the reference implementation fails to honour.
    """
    from raucle_detect.provenance import _canonical_json

    cases = [
        ("invalid_integer_above_safe_range",
         "2^53 = 9007199254740992 is one past the safe-integer boundary (§4.3.6); "
         "MUST be rejected at sign and verify in every implementation.",
         {"amount": 9007199254740992}),
        ("invalid_integer_below_safe_range",
         "-(2^53) = -9007199254740992 is one past the negative boundary (§4.3.6); "
         "MUST be rejected.",
         {"amount": -9007199254740992}),
        ("invalid_float",
         "Non-integer numbers (floats) MUST be rejected, not serialised (§4.3.5): "
         "cross-implementation float canonicalisation is out of scope for v1.",
         {"amount": 1.5}),
    ]
    out = []
    for name, desc, obj in cases:
        try:
            _canonical_json(obj)
        except Exception as e:  # expected — this is the contract
            out.append({
                "name": name,
                "description": desc,
                "input_object": obj,
                "must_reject": True,
                "reference_error": type(e).__name__,
            })
        else:
            raise AssertionError(
                f"{name}: _canonical_json accepted input that the spec says MUST be rejected"
            )
    return out


def main() -> int:
    vectors = _build_vectors()
    vectors["canonicalization_vectors"] = _canonicalization_vectors()
    vectors["invalid_canonicalization_vectors"] = _invalid_canonicalization_vectors()
    print(json.dumps(vectors, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
