"""The portable-provable-custody demo must run end-to-end and self-verify.

Guards the wedge's headline artifact: gate → audit-pack → offline verify, exit 0.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "examples" / "aws_custody" / "demo.py"


def test_custody_demo_runs_and_verifies_offline(tmp_path):
    # Run in a throwaway cwd so the demo's ./demo-output lands there, not in repo.
    proc = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(REPO), "PATH": ""},
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "gate decision : ALLOW" in out
    assert "gate decision : DENY" in out
    assert "agent sees credentials/signature? no" in out
    assert "reached AWS?  : no" in out  # the denied call never forwarded
    assert "custody BROKEN" not in out
    assert "RESULT: VERIFIED" in out
    # The pack really exists and re-verifies offline from the test process too.
    pack = tmp_path / "demo-output" / "aws-custody" / "pack"
    assert (pack / "PACK.json").is_file()
    from raucle_detect.audit_pack import verify_pack

    assert verify_pack(pack).ok
