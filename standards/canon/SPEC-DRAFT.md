# Raucle Canonical JSON Profile — Version 1 (DRAFT)

> **STATUS: DRAFT. NOT PUBLISHED, NOT CITABLE, NOT FROZEN.**
> This is the working draft of the normative profile that will be published at
> raucle 1.0. Until 1.0 it MAY change without notice and MUST NOT be cited
> by external submissions (OWASP / A2A / NIST) or referenced as a stable version.
> The settled, code-enforced description of current behaviour lives in
> [`RULES.md`](RULES.md); this document is its normative-language form, prepared
> so that at 1.0 it can be frozen, versioned, and cited in one stroke.
>
> The single source of truth for byte-level behaviour is
> [`../../docs/spec/provenance/v1/test-vectors.json`](../../docs/spec/provenance/v1/test-vectors.json),
> generated from the Python canonicaliser (`raucle/provenance.py`, built on
> `raucle/_canon.py`). Where this prose and the vectors disagree, the
> vectors win.

## 1. Scope and purpose

This profile defines a deterministic byte encoding for a restricted subset of
JSON values, called **Raucle Canonical JSON**. It is the encoding over which all
Raucle signed material is hashed and signed (provenance receipts, capability
tokens, audit chains, verdicts, feed entries). Two conformant implementations
MUST produce byte-identical output for any input in the supported subset, and
MUST reject any input outside it.

This profile is **not** RFC 8785 (JCS) and **not** I-JSON conformant. It borrows
exactly one mechanism from RFC 8785 — the object-key ordering algorithm of
§3.2.3 (UTF-16 code-unit order) — and otherwise diverges: it is integer-only and
rejects floats, which JCS does not. Implementations MUST NOT claim RFC 8785
conformance on the basis of this profile.

The key words MUST, MUST NOT, SHALL, SHOULD, and MAY are to be interpreted as in
RFC 2119.

## 2. Supported value subset

A conformant value is recursively one of: a string, an integer (§5), a boolean,
null, an array of conformant values, or an object whose keys are strings and
whose values are conformant values. Any other type (float, non-string key, NaN,
Infinity) MUST be rejected, not encoded.

## 3. Normative encoding rules

**R1 — Object key ordering.** Object keys MUST be sorted by their UTF-16
code-unit sequence (equivalent to big-endian UTF-16 byte comparison), NOT by
Unicode code point. This matches JavaScript `a < b` and .NET
`StringComparer.Ordinal`. The two orderings differ only for non-BMP keys; see §7.

**R2 — Integers only, bounded.** Numbers MUST be integers in the closed range
`[-(2^53-1), 2^53-1]`. Values outside this range MUST be rejected. (`bool` is not
a number; it encodes as `true`/`false`.)

**R3 — Floats rejected.** Non-integer numbers MUST be rejected, never encoded.

**R4 — NaN / Infinity rejected.** These are not representable in JSON and MUST be
rejected.

**R5 — No Unicode normalisation.** Strings MUST be emitted byte-for-byte as
given. Implementations MUST NOT apply NFC or any other normalisation. Producers
are responsible for any normalisation they require before canonicalising.

**R6 — Strings as raw UTF-8.** String contents MUST be emitted as UTF-8 and MUST
NOT be `\uXXXX`-escaped merely for being non-ASCII (i.e. `ensure_ascii=false`).

**R7 — String escaping.** Within strings and keys: the two-character escapes
`\b \f \n \r \t` MUST be used where defined; every other code point below U+0020
MUST be escaped as `\u00XX` with **lowercase** hex; `"` and `\` MUST be escaped;
`/` MUST NOT be escaped; `<`, `>`, `&` MUST be passed through literally (no HTML
escaping).

**R8 — Lone surrogates rejected.** An unpaired UTF-16 surrogate (a code point in
U+D800..U+DFFF not part of a valid pair), in a string value or an object key,
MUST be rejected at sign and at verify.

**R9 — Structure.** Token separators MUST be `,` and `:` with no insignificant
whitespace. Array element order MUST be preserved (only object keys are
reordered). Object keys MUST be strings.

**R10 — Duplicate keys rejected on verify.** A JSON object containing a duplicate
key MUST be rejected at verify. (The encoder cannot produce one; this is a
parse-side rule. It is enforced by the canonical byte-equality check of §6 and,
in Python, additionally by an explicit parse-time hook.)

## 4. Output

The output is a UTF-8 byte string. It is the input over which SHA-256 and Ed25519
operate. There is no trailing newline.

## 5. Integer range rationale

`2^53-1` is the JavaScript safe-integer boundary and the most restrictive of the
five reference languages. An integer outside this range is not exactly
representable as an IEEE-754 double and would not round-trip byte-identically
across implementations; hence the hard bound in R2.

## 6. Verification invariant (canonical byte-equality)

A verifier MUST, before trusting any field, re-encode the parsed object under
this profile and compare the result byte-for-byte against the original on-wire
bytes; a mismatch MUST cause rejection. This single invariant enforces R1, R7,
R9, and R10 at verify time regardless of the parser's own quirks: a non-canonical
ordering, a non-canonical escape, or a duplicate key all cause the re-encoded
bytes to differ from the original, and the receipt is rejected before any field
is read.

## 7. Why UTF-16 code units (R1 rationale)

For BMP characters UTF-16 code-unit order equals code-point order, so all
ASCII/BMP material is unaffected. The discriminating case is a non-BMP key:
encoded as a surrogate pair, its lead unit (0xD800..0xDBFF, i.e. 55296..56319) is
numerically below BMP code points >= U+E000 (57344). A non-BMP key therefore
sorts before a private-use BMP key under UTF-16 and after it under a code-point
sort. Unifying every encoder on UTF-16 is what keeps the five reference encoders
byte-identical for objects with non-BMP keys.

## 8. Conformance

Conformance has two parts.

**Encoder conformance (machine-checked today).** An encoder/canonicaliser
satisfies the current published vector kit
([`test-vectors.json`](../../docs/spec/provenance/v1/test-vectors.json)) if and
only if it (a) reproduces every `canonicalization_vectors` entry's
`expected_canonical_hex` byte-for-byte, and (b) rejects every
`invalid_canonicalization_vectors` entry. The kit and pass criteria are described
in [`README.md`](README.md).

**Verifier conformance (machine-checked across all five ports).** A full
implementation MUST also enforce the verify-side rules — the §6 canonical
byte-equality invariant and R10 duplicate-key rejection. These are machine-checked
across **all five reference ports** (Python, Go, Rust, TypeScript, C#) via the
published `invalid_receipt_vectors`: receipts carrying a *valid* Ed25519 signature
over non-canonical / duplicate-key bytes, which a conformant verifier MUST reject
on the canonical/duplicate check (not on the signature). Each port exposes a
`--verify` mode driven by `reference/verify_conformance.py`, which asserts every
port ACCEPTs the published valid receipts (id-matched) and REJECTs every
`invalid_receipt_vector`. The verify path is therefore proven, not only Python.

Conformance is asserted against a stated profile version. The project is not
pursuing a "Raucle Compatible" certification mark at this time (no trademark is
being registered), so there is no mark policy to satisfy; the technical bar is
simply (a) + (b) for an encoder, and additionally the verify-side rules above for
a full implementation, against a stated profile version.

## 9. Versioning and stability (governance)

- This profile is versioned independently as "Raucle Canonical JSON Profile vN".
- Once a version is published at or after 1.0, its rules are **frozen**. Any
  change to the produced bytes for any previously-valid input, or any change to
  the accept/reject decision for any input, requires a **new version** (v2), not
  an edit to v1.
- External references MUST cite a specific version (e.g. "Profile v1"), never
  "latest".
- New versions SHALL ship with a migration note describing what changed and how
  v1 and v2 material are distinguished.
- Security-relevant clarifications that do not change any byte or any
  accept/reject decision MAY be made within a version as editorial errata.

## 10. Open before publication (1.0 gate)

- Verify-rejection conformance: **done across all five ports.** The published
  `invalid_receipt_vectors` (signed non-canonical / duplicate-key receipts) are
  machine-checked to reject in `tests/test_spec_conformance.py` (Python) and in
  `reference/verify_conformance.py`, which drives a `--verify` mode in every port
  CLI (Python, Go, Rust, TypeScript, C#) and asserts the verify-side MUSTs (§6,
  R10) hold cross-language.
- Capability-token canonicalisation: **done.** `capability.py` and the standalone
  `cap_verifier.py` now enforce R8 **explicitly** — a lone surrogate is rejected
  with a clean `ValueError` at sign/verify, not incidentally via a later UTF-8
  encode (shared helper `raucle._canon.reject_lone_surrogates`; the
  standalone verifier inlines an equivalent check to stay import-free). Covered by
  `tests/test_capability.py::test_canonical_json_rejects_lone_surrogates_explicitly`
  and `::test_standalone_cap_verifier_rejects_lone_surrogates`.
- Trademark + "Raucle Compatible" mark policy (counsel). **Deferred** — the
  project is not pursuing the "Raucle" trademark at this time, so the mark policy
  is out of scope for the technical profile; conformance is asserted against a
  stated profile version without invoking a certification mark.
