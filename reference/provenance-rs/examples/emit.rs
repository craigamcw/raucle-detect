//! Conformance-harness helper: reads JSON requests
//! {"seed_hex":"...","payload":{...}} (one per line) from stdin and
//! writes {"jws":"...","id":"..."} (one per line) to stdout, using the
//! Rust reference implementation. See reference/conformance.py.

use ed25519_dalek::{SigningKey, VerifyingKey};
use raucle_provenance::canonical_encode;
use raucle_provenance::emit;
use raucle_provenance::verify;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

// Verify one {"jws","public_key_hex"} request, returning the verdict JSON. ANY
// error (bad hex/key, bad signature, non-canonical bytes, duplicate key) is a
// REJECT — the verify-rejection conformance contract (reference/verify_conformance.py).
fn verify_one(req: &Value) -> Value {
    let jws = req["jws"].as_str().unwrap_or("");
    let pubhex = req["public_key_hex"].as_str().unwrap_or("");
    // Exactly 64 hex chars (32 bytes); reject odd/over-length or non-hex so a
    // trailing nibble can't truncate back to a valid key (matches Go's strict path).
    let raw = match try_hex_to_bytes(pubhex) {
        Some(b) if b.len() == 32 => b,
        _ => return json!({ "verdict": "REJECT" }),
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    match VerifyingKey::from_bytes(&arr) {
        Ok(vk) => match verify(jws, &vk) {
            Ok(r) => json!({ "verdict": "ACCEPT", "id": r.id }),
            Err(_) => json!({ "verdict": "REJECT" }),
        },
        Err(_) => json!({ "verdict": "REJECT" }),
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// Strict hex decode: returns None on odd length or any non-hex char (no panic,
// no trailing-nibble truncation). Operates on raw bytes so a non-ASCII multibyte
// char can't make a str-slice land mid-codepoint and abort the process — a bad
// key must be a per-line REJECT, matching TS/C#. Used by the verify key contract.
fn try_hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    (0..bytes.len() / 2)
        .map(|i| Some((nibble(bytes[2 * i])? << 4) | nibble(bytes[2 * i + 1])?))
        .collect()
}

fn main() {
    let canon = std::env::args().nth(1).as_deref() == Some("--canon");
    let verify_mode = std::env::args().nth(1).as_deref() == Some("--verify");
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if verify_mode {
        for line in stdin.lock().lines() {
            let line = line.unwrap();
            if line.trim().is_empty() {
                continue;
            }
            // Parse inside the verdict boundary: a malformed request line is a
            // REJECT, not a process abort (the "ANY error is REJECT" contract).
            let verdict = match serde_json::from_str::<Value>(&line) {
                Ok(req) => verify_one(&req),
                Err(_) => json!({ "verdict": "REJECT" }),
            };
            writeln!(out, "{}", verdict).unwrap();
        }
        return;
    }
    if canon {
        // Canonicalisation cross-check (key ordering): {"obj": <value>} ->
        // {"hex": "<utf8 hex of canonical bytes>"}.
        for line in stdin.lock().lines() {
            let line = line.unwrap();
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = serde_json::from_str(&line).unwrap();
            let bytes = canonical_encode(&req["obj"]).expect("canon");
            let resp = json!({ "hex": to_hex(&bytes) });
            writeln!(out, "{}", resp).unwrap();
        }
        return;
    }
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
