# Reference implementations — Raucle Provenance Receipt v1

Independent, interoperable implementations of the
[Provenance Receipt v1 spec](../docs/spec/provenance/v1.md). All emit and
verify the same wire format and compute **byte-identical content-addressed
receipt IDs** — a receipt produced by any one verifies in the others.

| Language | Directory | Crypto | Notes |
|---|---|---|---|
| **Python** | (in the main library: [`raucle_detect/provenance.py`](../raucle_detect/provenance.py)) | `cryptography` (Ed25519) | The canonical reference; ships with the engine. |
| **TypeScript** | [`provenance-ts/`](./provenance-ts) | Node `webcrypto` (Ed25519) | Zero runtime deps. |
| **Go** | [`provenance-go/`](./provenance-go) | stdlib `crypto/ed25519` | stdlib-only. |
| **Rust** | [`provenance-rs/`](./provenance-rs) | `ed25519-dalek` | `cargo test`. |
| **C# / .NET** | [`provenance-cs/`](./provenance-cs) | BouncyCastle (Ed25519) | net8.0; cross-platform, no Windows needed. |

Each implements: `emit` / `verify` (Compact JWS, `typ=provenance-receipt/v1`,
`crit=["raucle/v1"]`, content-addressed id), payload validation (§4),
and chain/DAG validation with taint monotonicity (§7–§9).

## Cross-language interoperability

The guarantee that makes this a *standard* and not five lookalikes: the
canonical-JSON encoder in every implementation produces the same bytes,
so the signed input and the SHA-256 receipt id are identical across
languages. This is verified end-to-end — e.g. a receipt emitted by the
C# or Rust implementation verifies in the Python implementation and
yields the same id for the same key + payload. Each implementation also
carries a `canonical parity` test pinning its output to the shared
vector:

```
{"iat":1,"iss":"x","parents":["a","b"],"taint":["a_t","z_t"]}
```

Shared conformance test vectors for the receipt and the related
capability/proof artifacts live in
[`../docs/spec/provenance/v1/test-vectors.json`](../docs/spec/provenance/v1/test-vectors.json)
and [`../standards/test-vectors/`](../standards/test-vectors).

## Building / testing each

```bash
# TypeScript
cd provenance-ts && npm install && npm test
# Go
cd provenance-go && go test ./...
# Rust
cd provenance-rs && cargo test
# C#
cd provenance-cs && dotnet test test/Raucle.Provenance.Tests.csproj
```

All five are MIT-licensed (same as the repository). Contributions of
further language ports are welcome — keep the canonical-JSON bytes
identical to the vector above and add a parity test.
