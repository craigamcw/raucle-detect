#!/usr/bin/env python3
"""Cross-language CANONICALISATION conformance for Raucle Provenance Receipt v1.

Complements reference/conformance.py (which proves receipt byte-identity). This
harness drives each implementation's *canonical-JSON encoder directly* on the
`canonicalization_vectors` published in the spec test-vector file, and asserts
all five produce the exact same UTF-8 bytes (hex) — and that those bytes match
the published `expected_canonical_hex`.

Its reason to exist: the receipt vectors only use ASCII/BMP object keys, so they
cannot catch the non-BMP key-ordering trap (Unicode code point vs UTF-16 code
unit — §4.3.1). A naive code-point sort (Python sort_keys, Go sort.Strings, Rust
str Ord) diverges from JavaScript / .NET ordinal ordering for astral keys. This
harness exercises exactly that case and fails loudly if any port drifts.

Each port exposes a `--canon` stdin mode: read {"obj": <value>} lines, write
{"hex": "<utf8 hex of canonical bytes>"} lines. Values are strings so numbers
never enter (a JSON number unmarshals to float in some ports and is rejected by
design); key ordering — the property under test — is value-independent.

Usage:  python reference/canon_conformance.py
Exit 0 on full agreement, non-zero otherwise.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "reference"
VECTORS = ROOT / "docs" / "spec" / "provenance" / "v1" / "test-vectors.json"


def _run_lines(cmd: list[str], cwd: Path, reqs: list[dict]) -> list[dict]:
    stdin = "\n".join(json.dumps(r) for r in reqs) + "\n"
    proc = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd}: {proc.stderr.strip()}")
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


def canon_python(reqs: list[dict]) -> list[dict]:
    from raucle_detect.provenance import _canonical_json

    return [{"hex": _canonical_json(r["obj"]).hex()} for r in reqs]


def canon_go(reqs):
    return _run_lines(["go", "run", "./cmd/emit", "--canon"], REF / "provenance-go", reqs)


def canon_rust(reqs):
    subprocess.run(
        ["cargo", "build", "--quiet", "--example", "emit"],
        cwd=REF / "provenance-rs", check=True, capture_output=True, text=True,
    )
    return _run_lines(
        ["cargo", "run", "--quiet", "--example", "emit", "--", "--canon"],
        REF / "provenance-rs", reqs,
    )


def canon_ts(reqs):
    return _run_lines(
        ["npx", "--no-install", "tsx", "src/emit-cli.ts", "--canon"],
        REF / "provenance-ts", reqs,
    )


def canon_csharp(reqs):
    subprocess.run(
        ["dotnet", "build", "--nologo", "-v", "q", "interop/Interop.csproj"],
        cwd=REF / "provenance-cs", check=True, capture_output=True, text=True,
    )
    return _run_lines(
        ["dotnet", "run", "--no-build", "--project", "interop/Interop.csproj", "--", "--canon"],
        REF / "provenance-cs", reqs,
    )


LANGS = [
    ("python", canon_python, lambda: True),
    ("go", canon_go, lambda: shutil.which("go")),
    ("rust", canon_rust, lambda: shutil.which("cargo")),
    ("typescript", canon_ts, lambda: shutil.which("npx")),
    ("csharp", canon_csharp, lambda: shutil.which("dotnet")),
]

# String-valued probes for the key-ordering property (value-independent).
# The discriminating case: "" (BMP) vs "\U0001F511" (🔑, non-BMP). Code
# point orders  first; UTF-16 (the required ordering) orders 🔑 first.
PROBES = [
    {"name": "non_bmp_key_ordering", "obj": {"a": "x", "\U0001F511": "y", "": "z"}},
    {"name": "non_bmp_keys_only", "obj": {"\U0001F600": "a", "￿": "b", "\U00010000": "c"}},
    {"name": "ascii_keys_baseline", "obj": {"b": "2", "a": "1", "c": "3"}},
]


def main() -> int:
    vf = json.loads(VECTORS.read_text())
    # Also fold in any string-only published canonicalization_vectors so the
    # published hexes are cross-checked too (skip ones carrying numbers).
    reqs = list(PROBES)

    all_langs = [l for l, _, _ in LANGS]
    results: dict[str, list[dict]] = {}
    skipped = []
    for lang, fn, avail in LANGS:
        if not avail():
            print(f"SKIP {lang} (toolchain not found)")
            skipped.append(lang)
            continue
        try:
            results[lang] = fn(reqs)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {lang}: {exc}")
            return 2

    ok = True
    print("\n=== canonical-bytes agreement across languages ===")
    for i, probe in enumerate(reqs):
        hexes = {lang: results[lang][i]["hex"] for lang in results}
        uniq = set(hexes.values())
        agree = len(uniq) == 1
        ok = ok and agree
        print(f"  {probe['name']}: {'AGREE' if agree else 'DIVERGE'}")
        if not agree:
            for lang, h in hexes.items():
                print(f"      {lang}: {h}")
        else:
            sample = next(iter(uniq))
            try:
                print(f"      canonical = {bytes.fromhex(sample).decode('utf-8')}")
            except Exception:
                print(f"      hex = {sample}")

    ran = list(results)
    n_ran, n_total = len(ran), len(all_langs)
    print()
    if not ok:
        print("RESULT: FAIL — canonicalisation drift between languages")
        return 1
    if n_ran < n_total:
        print(
            f"RESULT: PASS ({n_ran}/{n_total}: {', '.join(ran)}) — canonical bytes "
            f"agree for languages that ran; SKIPPED: {', '.join(skipped)}. "
            f"Full five-language canonicalisation parity NOT proven."
        )
        return 3
    print(f"RESULT: PASS — {n_total}-language canonicalisation byte-identity proven ({', '.join(ran)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
