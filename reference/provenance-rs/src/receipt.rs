//! Receipt payload, envelope, emit/verify — §3, §4, §8.

use crate::canonical::canonical_encode;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const JWS_TYP: &str = "provenance-receipt/v1";

#[derive(Debug)]
pub struct ProvError(pub String);
impl std::fmt::Display for ProvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ProvError {}

fn err<T>(s: impl Into<String>) -> Result<T, ProvError> {
    Err(ProvError(s.into()))
}

fn known_field(k: &str) -> bool {
    matches!(
        k,
        "iss" | "iat"
            | "agent_id"
            | "agent_key_id"
            | "operation"
            | "parents"
            | "input_hash"
            | "output_hash"
            | "taint"
            | "ruleset_hash"
            | "guardrail_verdict"
            | "model"
            | "tool"
            | "corpus"
            | "tenant"
    )
}

fn valid_operation(op: &str) -> bool {
    matches!(
        op,
        "user_input"
            | "model_call"
            | "tool_call"
            | "retrieval"
            | "guardrail_scan"
            | "agent_handoff"
            | "sanitisation"
            | "merge"
    )
}

fn valid_verdict(v: &str) -> bool {
    matches!(v, "ALLOW" | "BLOCK" | "SANITISE" | "NA")
}

fn is_hex256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn valid_agent_id(s: &str) -> bool {
    let rest = match s.strip_prefix("agent:") {
        Some(r) => r,
        None => return false,
    };
    if rest.is_empty() || rest.len() > 128 {
        return false;
    }
    let mut chars = rest.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    rest.chars().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || matches!(c, '_' | '-' | '.' | '/')
    })
}

fn valid_taint(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars = s.chars();
    if !chars.next().unwrap().is_ascii_lowercase() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | ':' | '-'))
}

/// A signed receipt.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub jws: String,
    /// The parsed payload object.
    pub payload: Value,
    /// Content-addressed id (§8): hex SHA-256 of the JWS ASCII bytes.
    pub id: String,
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64u_decode(s: &str) -> Result<Vec<u8>, ProvError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ProvError(format!("base64: {e}")))
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex_encode(&h.finalize())
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Validate a payload object against §4.
pub fn validate_payload(p: &Value) -> Result<(), ProvError> {
    let obj = match p.as_object() {
        Some(o) => o,
        None => return err("payload must be an object"),
    };

    for k in obj.keys() {
        if !known_field(k) && !k.starts_with("x_") {
            return err(format!("reserved/unknown field: {k} (§14)"));
        }
    }

    let op = obj.get("operation").and_then(|v| v.as_str()).unwrap_or("");
    if !valid_operation(op) {
        return err(format!("unknown operation: {op}"));
    }
    let verdict = obj
        .get("guardrail_verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("NA");
    if !valid_verdict(verdict) {
        return err(format!("unknown verdict: {verdict}"));
    }
    let agent_id = obj.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
    if !valid_agent_id(agent_id) {
        return err(format!("invalid agent_id: {agent_id}"));
    }
    let input_hash = obj.get("input_hash").and_then(|v| v.as_str()).unwrap_or("");
    if !is_hex256(input_hash) {
        return err("input_hash must be 64-hex SHA-256");
    }
    let output_hash = obj.get("output_hash").and_then(|v| v.as_str()).unwrap_or("");
    if !is_hex256(output_hash) {
        return err("output_hash must be 64-hex SHA-256");
    }
    if let Some(rh) = obj.get("ruleset_hash").and_then(|v| v.as_str()) {
        if !is_hex256(rh) {
            return err("ruleset_hash must be 64-hex SHA-256");
        }
    }
    let has_ruleset = obj.get("ruleset_hash").and_then(|v| v.as_str()).is_some();
    if (op == "guardrail_scan" || op == "sanitisation") && !has_ruleset {
        return err(format!("{op} requires ruleset_hash (§5)"));
    }
    if op == "guardrail_scan" && verdict == "NA" {
        return err("guardrail_scan requires a concrete verdict");
    }

    let parents = obj.get("parents").and_then(|v| v.as_array());
    let parent_count = parents.map(|a| a.len()).unwrap_or(0);
    if op == "user_input" && parent_count > 0 {
        return err("user_input must have no parents");
    }
    if op != "user_input" && parent_count == 0 {
        return err(format!("{op} requires at least one parent"));
    }

    let taint = obj.get("taint").and_then(|v| v.as_array());
    if let Some(taint) = taint {
        let mut prev: Option<&str> = None;
        for t in taint {
            let s = match t.as_str() {
                Some(s) => s,
                None => return err("taint entries must be strings"),
            };
            if !valid_taint(s) {
                return err(format!("invalid taint tag: {s}"));
            }
            if let Some(p) = prev {
                if p > s {
                    return err("taint MUST be sorted (§4)");
                }
            }
            prev = Some(s);
        }
    }

    if op == "model_call" && obj.get("model").is_none() {
        return err("model_call requires .model");
    }
    if op == "tool_call" && obj.get("tool").is_none() {
        return err("tool_call requires .tool");
    }
    if op == "retrieval" && obj.get("corpus").is_none() {
        return err("retrieval requires .corpus");
    }
    Ok(())
}

/// Emit (sign) a payload object. The object MUST already contain the
/// spec fields; `guardrail_verdict` defaults to "NA" if absent.
pub fn emit(payload: &Value, signing_key: &SigningKey) -> Result<Receipt, ProvError> {
    // Normalise: fill guardrail_verdict default so the signed bytes are
    // explicit (matches the other reference impls).
    let mut obj: Map<String, Value> = payload
        .as_object()
        .ok_or_else(|| ProvError("payload must be an object".into()))?
        .clone();
    obj.entry("guardrail_verdict")
        .or_insert_with(|| json!("NA"));
    let payload = Value::Object(obj);

    validate_payload(&payload)?;

    let kid = payload
        .get("agent_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProvError("missing agent_key_id".into()))?;

    let header = json!({
        "alg": "EdDSA",
        "typ": JWS_TYP,
        "kid": kid,
        "crit": ["raucle/v1"],
    });

    let header_b = canonical_encode(&header).map_err(|e| ProvError(e.0))?;
    let payload_b = canonical_encode(&payload).map_err(|e| ProvError(e.0))?;
    let signing_input = format!("{}.{}", b64u(&header_b), b64u(&payload_b));
    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    let jws = format!("{}.{}", signing_input, b64u(&sig.to_bytes()));
    let id = sha256_hex(jws.as_bytes());
    Ok(Receipt {
        jws,
        payload,
        id,
    })
}

/// Verify a Compact JWS against a public key and parse it.
pub fn verify(jws: &str, verifying_key: &VerifyingKey) -> Result<Receipt, ProvError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return err("JWS must have three segments");
    }
    let (header_b, payload_b, sig_b) = (parts[0], parts[1], parts[2]);

    let header: Value = serde_json::from_slice(&b64u_decode(header_b)?)
        .map_err(|e| ProvError(format!("header parse: {e}")))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return err("unsupported alg");
    }
    if header.get("typ").and_then(|v| v.as_str()) != Some(JWS_TYP) {
        return err("unexpected typ");
    }
    let crit_ok = header
        .get("crit")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(|x| x.as_str() == Some("raucle/v1")))
        .unwrap_or(false);
    if !crit_ok {
        return err("crit must include 'raucle/v1'");
    }

    let sig_bytes = b64u_decode(sig_b)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| ProvError(format!("sig: {e}")))?;
    let signing_input = format!("{}.{}", header_b, payload_b);
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| ProvError("signature invalid".into()))?;

    let payload: Value = serde_json::from_slice(&b64u_decode(payload_b)?)
        .map_err(|e| ProvError(format!("payload parse: {e}")))?;

    if let Some(obj) = payload.as_object() {
        for k in obj.keys() {
            if !known_field(k) && !k.starts_with("x_") {
                return err(format!("reserved unknown field: {k}"));
            }
        }
    }
    validate_payload(&payload)?;

    if header.get("kid").and_then(|v| v.as_str())
        != payload.get("agent_key_id").and_then(|v| v.as_str())
    {
        return err("header.kid != payload.agent_key_id (§3)");
    }

    let id = sha256_hex(jws.as_bytes());
    Ok(Receipt {
        jws: jws.to_string(),
        payload,
        id,
    })
}
