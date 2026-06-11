# Raucle Canonical JSON — rules (internal working notes)

> **Status: INTERNAL, UNVERSIONED, non-normative.** This document is the
> human-readable description of the canonicalisation rules that `raucle`
> already enforces in code. It is **not** a published standard and must **not**
> be cited by external submissions (OWASP / A2A / NIST) yet. The normative,
> versioned "Raucle Canonical JSON Profile v1" is deferred until the library
> reaches 1.0, so the wire format is not frozen by anything written here.
>
> The single source of truth for byte-level behaviour is
> [`docs/spec/provenance/v1/test-vectors.json`](../../docs/spec/provenance/v1/test-vectors.json),
> which is **generated from the Python canonicaliser** (`raucle/provenance.py`,
> built on the `raucle/_canon.py` ordering helpers) by
> `scripts/gen_provenance_test_vectors.py`. Every worked example below is cited
> by its vector name; do not hand-copy bytes here — read them from the generated
> file so this doc can never silently drift from the code.

## What this is

Canonical JSON is the exact byte sequence that gets signed and hashed for every
Raucle signed artifact (provenance receipts, capability tokens, audit chains,
verdicts, feed entries). Two implementations that agree on these rules produce
byte-identical signed material and can verify each other's signatures. Five
reference implementations (Python, Go, Rust, TypeScript, C#) are held
byte-identical by the conformance kit in this directory.

## Relationship to RFC 8785 (JCS)

This profile borrows **one** thing from RFC 8785 / JCS: the object-key ordering
algorithm (§3.2.3 — sort by UTF-16 code unit). It is otherwise **not** JCS and
**not** I-JSON conformant, because it rejects floats and is integer-only, which
contradicts JCS's core number rules (JCS mandates ECMAScript `Number`
serialisation and does not reject floats). Cite JCS for the key ordering only.
Do not claim RFC 8785 conformance.

## The rules

### R1 — Object keys ordered by UTF-16 code unit
Keys are sorted by their UTF-16 code-unit sequence (big-endian code-unit
comparison), **not** by Unicode code point. These differ only for non-BMP
(astral) keys: a surrogate lead unit (U+D800..U+DBFF) sorts before BMP code
points >= U+E000. This matches JavaScript `a < b` and .NET
`StringComparer.Ordinal`. A naive code-point sort (default Python/Go/Rust)
diverges and is a conformance bug.
Pinned by: `canon_non_bmp_key_ordering`, `probe_non_bmp_key_ordering`,
`probe_non_bmp_keys_only`.

### R2 — Integer-only, bounded to the safe-integer range
Numbers must be integers in `[-(2^53-1), 2^53-1]`. This is the JavaScript
safe-integer range, the most restrictive of the five languages; outside it a
value is not exactly representable as an IEEE-754 double and would not round-trip
byte-identically. `bool` serialises as `true`/`false`, not a number.
Pinned by: `canon_boundary_integer` (accepts 2^53-1),
`invalid_integer_above_safe_range` / `invalid_integer_below_safe_range` (reject).

### R3 — Floats rejected
Non-integer numbers are rejected at sign/verify, never serialised.
Cross-implementation float canonicalisation is out of scope.
Pinned by: `invalid_float`.

### R4 — NaN / Infinity rejected
Not representable in JSON; rejected.

### R5 — No Unicode normalisation (NFC pass-through)
Canonicalisation is pure serialisation. A decomposed string is emitted
byte-for-byte as given, never folded to NFC. NFC is a *producer* responsibility.
A canonicaliser that silently NFC-folds diverges.
Pinned by: `canon_non_nfc_passthrough` (U+0041 U+030A stays decomposed).

### R6 — Non-ASCII strings emitted as raw UTF-8
String contents are UTF-8, never `\uXXXX`-escaped for being non-ASCII
(equivalent to `ensure_ascii=false`). Necessary but not sufficient — see R7.
Pinned by: `canon_non_ascii_strings`.

### R7 — String escaping (exact)
Within string values and keys:
- Two-character short escapes for `\b \f \n \r \t` where defined.
- `\u00XX` with **lowercase** hex for every other code point < U+0020.
- `"` and `\` are escaped; `/` is **not** escaped.
- `<` `>` `&` are passed through **literally** (no HTML escaping).
The five reference encoders are hand-aligned on this. A port that emits `\u0008` for backspace (instead of `\b`), uppercase hex, or HTML-escapes these
characters diverges.
Pinned by: `canon_control_char_escaping`.

### R8 — Lone surrogates rejected
An unpaired UTF-16 surrogate (a code point in U+D800..U+DFFF not part of a valid
pair) is rejected at sign/verify. It cannot be encoded to UTF-8 and the ports
otherwise disagree: Python and Rust reject, Go and .NET substitute U+FFFD, and a
JS `JSON.stringify` emits a `\udXXX` escape. Rejection is the only portable
contract. Applies to both string values and object keys.
Pinned by: `invalid_lone_surrogate`.

### R9 — Structure and whitespace
- Separators are `,` and `:` with no insignificant whitespace.
- Arrays preserve input order (only object keys are reordered).
- Object keys must be strings.

### R10 — Duplicate object keys rejected on verify
A JSON object with a duplicate key is rejected at verify. Duplicate keys are
valid per the JSON grammar but their handling is implementation-defined (most
parsers silently take last-wins), which is a classic signature-confusion vector.
The emit side cannot produce them (an in-memory map has unique keys), so this is
purely a parse/verify rule. It is enforced cross-language by the **canonical
byte-equality check**: every port re-encodes the parsed payload and compares to
the original on-wire bytes, and a duplicate key collapses on parse so the
re-encoded bytes never equal the original — the receipt is rejected as
non-canonical *before* any field is read. Python additionally rejects duplicate
keys explicitly at parse (`_reject_duplicate_keys` object_pairs_hook) for a
clearer error. Verified present in all five reference implementations.

## Why UTF-16 code units, not code points (R1 rationale)

UTF-16 code-unit ordering is the one ordering JavaScript and .NET produce by
default, and it is what RFC 8785 §3.2.3 specifies. For BMP characters it is
identical to code-point ordering, so all ASCII/BMP material is unaffected. The
discriminating case is a non-BMP key: encoded as a surrogate pair, its lead unit
(0xD800..0xDBFF, i.e. 55296..56319) is numerically below BMP code points >=
U+E000 (57344). So a non-BMP key sorts **before** a private-use BMP key under
UTF-16, and **after** it under a code-point sort. Unifying every encoder on
UTF-16 is what keeps Python/Go/Rust/TS/C# byte-identical for objects with non-BMP
keys. (This is the bug fixed in B7 / v0.18.0; `canon_non_bmp_key_ordering`
exists to make it impossible to reintroduce.)

## Open items for the v1 SPEC (when it is written at 1.0)

- Duplicate object keys: **resolved — reject** (see R10). Enforced cross-language
  via canonical byte-equality, plus an explicit parse hook in Python. **Now also
  machine-checked at verify time across all five ports** via the published
  `invalid_receipt_vectors` and `reference/verify_conformance.py` (a `--verify`
  mode per port CLI), so the verify-side MUSTs (§6, R10) are proven, not only the
  emit/canon path.
- Capability tokens (`capability.py`) and the standalone `cap_verifier.py`:
  **resolved — R8 now enforced explicitly.** Both reject lone surrogates with a
  clean `ValueError` at sign/verify (shared `raucle._canon.reject_lone_surrogates`;
  the standalone verifier inlines an equivalent check to stay import-free) rather
  than relying on the incidental `UnicodeEncodeError` from the later UTF-8 encode.
