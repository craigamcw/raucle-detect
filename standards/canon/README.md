# Raucle Canonical JSON — conformance kit

Canonical JSON is the exact byte sequence Raucle signs and hashes. If your
implementation produces the same bytes as the reference, your signed artifacts
verify against everyone else's. This directory is how you prove that.

> **Status:** the rules are stable and enforced in code, but the *normative,
> versioned* "Profile v1" is deferred until the library reaches 1.0. Treat this
> kit as the working interop contract, not a frozen standard. Rules:
> [`RULES.md`](RULES.md).

## What's in the kit

| Artifact | Role |
|---|---|
| [`../../docs/spec/provenance/v1/test-vectors.json`](../../docs/spec/provenance/v1/test-vectors.json) | The vectors. Generated from the Python canonicaliser (`raucle_detect/provenance.py`, which uses the `raucle_detect/_canon.py` ordering helpers), never hand-written. Single source of truth for expected bytes. |
| [`../../reference/canon_conformance.py`](../../reference/canon_conformance.py) | Runs every vector against all reference languages and checks agreement + published-hash match + rejection. |
| [`../../reference/conformance.py`](../../reference/conformance.py) | Full provenance-receipt byte-identity (JWS emit + cross-verify) across the five languages. |
| [`../../reference/provenance-{go,rs,ts,cs}/`](../../reference/) | The four non-Python reference ports. Python is `raucle_detect/provenance.py` (canonicaliser + validation) on top of `raucle_detect/_canon.py` (UTF-16 ordering helpers). |

Vectors are generated, not authored:
`python scripts/gen_provenance_test_vectors.py > docs/spec/provenance/v1/test-vectors.json`.
Editing the JSON by hand is wrong — change the canonicaliser (`provenance.py` / `_canon.py`) and regenerate.

## Running it

From the repo root, with the language toolchains you want to test installed
(missing ones are skipped, not failed):

```
python reference/canon_conformance.py   # canonicalisation parity + rejection
python reference/conformance.py          # full receipt byte-identity
```

## Reading the output

`canon_conformance.py` prints one line per vector in two groups.

**Valid vectors** must satisfy two things:
- `AGREE` — every language that ran produced identical canonical bytes.
- `HEX-OK` — those bytes match the `expected_canonical_hex` published in the
  vector file (so the kit catches a case where all languages agree but all drifted
  together).

A valid vector prints `AGREE + HEX-OK` when conformant. Anything else is a
divergence: the line names the disagreeing languages and their bytes.

**Invalid vectors** carry `must_reject: true`. Every language **must reject** the
input — exit non-zero and emit **no** output line. Important: a clean run that
emits nothing is *not* a reject (an encoder that does nothing would falsely pass);
a reject is a non-zero exit with no hex line. Conformant output is `ALL-REJECT`.

The run ends in `RESULT: PASS` only if every valid vector is `AGREE + HEX-OK`
and every invalid vector is `ALL-REJECT`.

## Self-certifying a new implementation

1. Implement the rules in [`RULES.md`](RULES.md).
2. Read `docs/spec/provenance/v1/test-vectors.json`. For each entry in
   `canonicalization_vectors`, canonicalise `input_object` and assert your bytes
   equal `expected_canonical_hex`.
3. For each entry in `invalid_canonicalization_vectors`, assert your
   canonicaliser **rejects** `input_object` (raises / errors), never emits.
4. The hard cases that catch most bugs: `canon_non_bmp_key_ordering` (UTF-16 vs
   code-point key sort), `canon_control_char_escaping` (escape exactness),
   `canon_boundary_integer` + `invalid_integer_above_safe_range` (safe-integer
   bound), and `invalid_lone_surrogate` (unpaired surrogate rejection). If those
   four pass, you are almost certainly byte-identical.

## Adding a vector

Add it to `scripts/gen_provenance_test_vectors.py` (a valid case via `vec(...)`,
or a must-reject case in `_invalid_canonicalization_vectors`), regenerate the
file, and run both harnesses. The generator self-checks that every must-reject
input actually raises in the reference encoder, so the published `must_reject`
claim can never be a lie.
