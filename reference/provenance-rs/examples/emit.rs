//! Conformance-harness helper: reads JSON requests
//! {"seed_hex":"...","payload":{...}} (one per line) from stdin and
//! writes {"jws":"...","id":"..."} (one per line) to stdout, using the
//! Rust reference implementation. See reference/conformance.py.

use ed25519_dalek::SigningKey;
use raucle_provenance::emit;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = serde_json::from_str(&line).unwrap();
        let seed = hex_to_bytes(req["seed_hex"].as_str().unwrap());
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let sk = SigningKey::from_bytes(&seed_arr);
        let r = emit(&req["payload"], &sk).expect("emit");
        let resp = json!({"jws": r.jws, "id": r.id});
        writeln!(out, "{}", resp).unwrap();
    }
}
