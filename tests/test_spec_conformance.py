"""Spec conformance tests for the Raucle Provenance Receipt v1 reference impl.

The canonical test vectors at docs/spec/provenance/v1/test-vectors.json define
what every conforming implementation MUST produce. This test re-runs the
deterministic generator and asserts byte-equality with the published vectors.
A divergence between the reference Python implementation and the spec vectors
means EITHER a regression in provenance.py OR an intended spec change that
also requires updating the published vectors.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_PATH = REPO_ROOT / "docs" / "spec" / "provenance" / "v1" / "test-vectors.json"
GENERATOR = REPO_ROOT / "scripts" / "gen_provenance_test_vectors.py"


class TestSpecConformance:
    def test_vectors_file_exists(self):
        assert VECTORS_PATH.is_file(), (
            f"Published test vectors missing at {VECTORS_PATH}. "
            "Regenerate with: python scripts/gen_provenance_test_vectors.py > "
            "docs/spec/provenance/v1/test-vectors.json"
        )

    def test_python_reference_reproduces_vectors_byte_for_byte(self):
        """The deterministic generator MUST output bytes identical to the
        committed test-vectors.json. Any drift means a spec or reference-impl
        regression."""
        result = subprocess.run(
            [sys.executable, str(GENERATOR)],
            capture_output=True,
            text=True,
            check=True,
        )
        committed = VECTORS_PATH.read_text()
        # Strip trailing newline if present in either; canonical form is no
        # trailing newline after the closing brace.
        assert result.stdout.rstrip("\n") == committed.rstrip("\n"), (
            "Generator output differs from committed test vectors. "
            "If this is intentional, regenerate and commit the new file."
        )

    def test_every_vector_verifies_with_published_public_key(self):
        """An independent re-verification of every published vector against the
        public key in the vectors file. This is the simplest possible
        compatibility check a third-party implementation must pass."""
        from raucle.provenance import ProvenanceReceipt, ProvenanceVerifier

        data = json.loads(VECTORS_PATH.read_text())
        public_key_pem = data["public_key_pem"].encode("ascii")
        verifier = ProvenanceVerifier(public_keys={data["agent_key_id"]: public_key_pem})

        for v in data["vectors"]:
            receipt = ProvenanceReceipt.from_jws(v["expected_jws"])
            # Hash the JWS ourselves and compare to the published expected hash.
            assert receipt.receipt_hash == v["expected_receipt_hash"], (
                f"vector {v['name']!r}: recomputed receipt_hash "
                f"{receipt.receipt_hash} does not match expected "
                f"{v['expected_receipt_hash']}"
            )
            # Verify the signature directly via the verifier's internal API.
            assert verifier._verify_signature(receipt), (
                f"vector {v['name']!r}: signature did not verify against the published public key"
            )

    def test_verifier_rejects_all_invalid_receipt_vectors(self):
        """SPEC §6 (canonical byte-equality) + R10 (duplicate keys): every
        invalid_receipt_vector carries a VALID signature over non-canonical /
        duplicate-key bytes, so a conformant verifier MUST reject it on the
        canonical/duplicate check — NOT on the signature. This test proves both:
        the signature genuinely verifies, AND strict parsing still rejects."""
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
        )

        from raucle.provenance import ProvenanceReceipt, _b64url_decode

        data = json.loads(VECTORS_PATH.read_text())
        pub = load_pem_public_key(data["public_key_pem"].encode("ascii"))
        vectors = data.get("invalid_receipt_vectors", [])
        assert vectors, "invalid_receipt_vectors missing from the published file"

        for v in vectors:
            header_b64, payload_b64, sig_b64 = v["jws"].split(".")
            signing_input = (header_b64 + "." + payload_b64).encode("ascii")
            # 1) the signature is genuinely valid over the non-canonical bytes
            #    (raises InvalidSignature and fails the test if it were tampered).
            pub.verify(_b64url_decode(sig_b64), signing_input)
            # 2) yet strict verify MUST reject it — and for the RIGHT reason
            #    (the canonical/duplicate check named in the vector), not some
            #    other ValueError that would give false confidence.
            with pytest.raises(ValueError) as exc:
                ProvenanceReceipt.from_jws(v["jws"], strict=True)
            assert v["expected_error_substr"] in str(exc.value), (
                f"vector {v['name']!r}: rejected with {exc.value!r}, expected a "
                f"message containing {v['expected_error_substr']!r}"
            )

    def test_vectors_cover_required_operation_types(self):
        """The published test vectors must exercise the operation types most
        likely to surface implementation bugs. Adding a vector here forces
        the generator + reference impl to support it."""
        data = json.loads(VECTORS_PATH.read_text())
        from raucle.provenance import ProvenanceReceipt

        operations_seen = {
            ProvenanceReceipt.from_jws(v["expected_jws"]).operation.value for v in data["vectors"]
        }
        required = {"user_input", "model_call", "tool_call", "sanitisation", "guardrail_scan"}
        missing = required - operations_seen
        assert not missing, f"published vectors missing required operations: {missing}"
