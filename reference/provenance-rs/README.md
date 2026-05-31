# raucle-provenance — Rust reference implementation

A Rust implementation of the
[Raucle Provenance Receipt v1 spec](https://raucle.com/spec/provenance/v1).

One of the cross-language reference implementations (Python,
TypeScript, Go, Rust). All four emit the same wire format and compute
identical content-addressed IDs — verified end-to-end: a receipt
emitted here verifies in the Python implementation, and vice versa.

## Use

```rust
use ed25519_dalek::SigningKey;
use raucle_provenance::{emit, verify, build_chain};
use serde_json::json;

let sk = SigningKey::generate(&mut rand_core::OsRng);

let payload = json!({
    "iss": "https://acme.example/raucle",
    "iat": 1748505600,
    "agent_id": "agent:acme.scanner",
    "agent_key_id": "k_1",
    "operation": "guardrail_scan",
    "parents": ["…parent ids…"],
    "input_hash": input_hash_hex,
    "output_hash": output_hash_hex,
    "taint": ["untrusted_user"],
    "ruleset_hash": ruleset_hash_hex,
    "guardrail_verdict": "ALLOW",
});

let r = emit(&payload, &sk)?;
let parsed = verify(&r.jws, &sk.verifying_key())?;
let _ = r.id; // content-addressed identifier

// Multi-receipt graph:
let chain = build_chain(vec![r1, r2, r3])?;
```

`build_chain` enforces DAG closure, acyclicity, and taint monotonicity
(§7–§9); `emit`/`verify` enforce the envelope (§3) and payload (§4)
rules including the `crit=raucle/v1` JWT-confusion guard.

## Dependencies

`ed25519-dalek` (Ed25519), `sha2` (SHA-256), `base64`, and `serde_json`
(payload parsing on verify; canonical *encoding* is our own since
serde_json does not guarantee a canonical form).

## Develop

```bash
cargo test
cargo run --example interop   # emit a receipt; pipe to the Python verifier to confirm interop
```

`canonical_parity` locks the canonical-JSON output to the exact bytes
the Python, TypeScript, and Go encoders produce.

## License

MIT.
