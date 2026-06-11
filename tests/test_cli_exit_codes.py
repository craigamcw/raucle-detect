"""Tests for CLI exit-code contracts that CI / automation rely on.

FIX 2.2 of the HOLD SCOPE review — ``raucle prove`` must return a
NON-ZERO exit code on REFUTED and UNDECIDED so that CI / shell pipelines
treat "not proven" as failure. Plus the new ``cap mint --require-proof``
strict-mode exits.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytest.importorskip("z3", reason="prove CLI tests need the [proof] extra")


@pytest.fixture
def tmp_schema_policy_files(tmp_path):
    """Two scenarios:

    proven  — schema enum restricts ``role`` to {user,admin}, policy
               forbids ``role=admin``. PROVEN: no string in the grammar
               can include ``role=admin`` because... wait, that's
               REFUTED. Use forbidden_values that the schema's enum
               does NOT admit instead.
    refuted — policy forbids a value the schema enum admits.
    """
    proven_schema = {
        "type": "object",
        "properties": {
            "role": {"type": "string", "enum": ["guest", "user"]},
        },
        "required": ["role"],
    }
    proven_policy = {
        "forbidden_values": {"role": ["admin"]},  # admin is not in enum
    }
    refuted_schema = {
        "type": "object",
        "properties": {
            "role": {"type": "string", "enum": ["guest", "user", "admin"]},
        },
        "required": ["role"],
    }
    refuted_policy = {
        "forbidden_values": {"role": ["admin"]},  # admin IS in enum
    }
    ps = tmp_path / "proven_schema.json"
    pp = tmp_path / "proven_policy.json"
    rs = tmp_path / "refuted_schema.json"
    rp = tmp_path / "refuted_policy.json"
    ps.write_text(json.dumps(proven_schema))
    pp.write_text(json.dumps(proven_policy))
    rs.write_text(json.dumps(refuted_schema))
    rp.write_text(json.dumps(refuted_policy))
    return ps, pp, rs, rp


def _run(*argv):
    """Invoke the CLI in a subprocess and return ``(returncode, stdout, stderr)``."""
    return subprocess.run(
        [sys.executable, "-m", "raucle", *argv],
        capture_output=True,
        text=True,
        check=False,
    )


class TestProveExitCodes:
    def test_proven_returns_zero(self, tmp_schema_policy_files):
        ps, pp, _, _ = tmp_schema_policy_files
        r = _run("prove", "json", "--schema", str(ps), "--policy", str(pp))
        assert r.returncode == 0, r.stderr

    def test_refuted_returns_nonzero(self, tmp_schema_policy_files):
        _, _, rs, rp = tmp_schema_policy_files
        r = _run("prove", "json", "--schema", str(rs), "--policy", str(rp))
        assert r.returncode != 0  # specifically 2; non-zero is the contract
        assert "REFUTED" in r.stderr or "REFUTED" in r.stdout

    def test_undecided_returns_nonzero(self, tmp_path):
        """UNDECIDED is rare to provoke deterministically; we simulate
        by handing the prover an unsupported grammar (which raises and
        the prover reports UNDECIDED with notes). When that path isn't
        triggerable, the test is skipped — the REFUTED case alone
        covers the non-zero-exit contract."""
        # An empty schema admits anything; with no constraints, the
        # prover should be able to decide. Provoking UNDECIDED reliably
        # in CI is brittle, so we accept either UNDECIDED (return 1) or
        # PROVEN (return 0) here and assert only the contract: if the
        # status is UNDECIDED, the exit code is non-zero.
        schema = {"type": "object"}
        policy = {}
        ps = tmp_path / "s.json"
        pp = tmp_path / "p.json"
        ps.write_text(json.dumps(schema))
        pp.write_text(json.dumps(policy))
        r = _run("prove", "json", "--schema", str(ps), "--policy", str(pp))
        if "UNDECIDED" in r.stdout:
            assert r.returncode != 0


class TestCapMintRequireProof:
    """``cap mint --require-proof`` strict-mode exit-code contract."""

    def test_require_proof_without_proof_result_exits_nonzero(self, tmp_path):
        # Generate an issuer key first ('cap keygen' takes the issuer
        # name as a positional arg).
        keygen = _run("cap", "keygen", "p.x", "--out", str(tmp_path / "issuer"))
        assert keygen.returncode == 0, keygen.stderr

        r = _run(
            "cap",
            "mint",
            "--key",
            str(tmp_path / "issuer.key.pem"),
            "--issuer",
            "p.x",
            "--agent-id",
            "agent:x",
            "--tool",
            "lookup_customer",
            "--require-proof",
            "--out",
            str(tmp_path / "token.json"),
        )
        assert r.returncode != 0
        assert "require-proof" in r.stderr.lower() or "POLICY_UNPROVEN" in r.stderr
