use ed25519_dalek::SigningKey;
use raucle_provenance::{build_chain, canonical_encode, emit, verify};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

fn key() -> SigningKey {
    let mut secret = [0u8; 32];
    // Deterministic-but-varied per call isn't needed; use OS rng.
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

fn base_payload() -> Value {
    let h = sha("hello");
    json!({
        "iss": "https://test.example/raucle",
        "iat": 1748505600,
        "agent_id": "agent:test.scanner",
        "agent_key_id": "k_test01",
        "operation": "user_input",
        "parents": [],
        "input_hash": h,
        "output_hash": h,
        "taint": ["untrusted_user"],
        "guardrail_verdict": "NA",
    })
}

#[test]
fn emit_verify_roundtrip() {
    let sk = key();
    let r = emit(&base_payload(), &sk).unwrap();
    let parsed = verify(&r.jws, &sk.verifying_key()).unwrap();
    assert_eq!(
        parsed.payload.get("agent_id").unwrap().as_str().unwrap(),
        "agent:test.scanner"
    );
    assert_eq!(parsed.id, r.id);
    assert_eq!(r.id.len(), 64);
}

#[test]
fn verify_rejects_different_key() {
    let sk = key();
    let other = key();
    let r = emit(&base_payload(), &sk).unwrap();
    assert!(verify(&r.jws, &other.verifying_key()).is_err());
}

#[test]
fn verify_rejects_wrong_alg() {
    use base64::Engine;
    let sk = key();
    let r = emit(&base_payload(), &sk).unwrap();
    let parts: Vec<&str> = r.jws.split('.').collect();
    let bad_header = serde_json::to_vec(&json!({
        "alg": "HS256", "typ": "provenance-receipt/v1",
        "kid": "k_test01", "crit": ["raucle/v1"]
    }))
    .unwrap();
    let hb = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bad_header);
    let jws = format!("{}.{}.{}", hb, parts[1], parts[2]);
    assert!(verify(&jws, &sk.verifying_key()).is_err());
}

#[test]
fn rejects_unsorted_taint() {
    let sk = key();
    let mut p = base_payload();
    p["taint"] = json!(["z_x", "a_y"]);
    assert!(emit(&p, &sk).is_err());
}

#[test]
fn non_user_input_requires_parents() {
    let sk = key();
    let mut p = base_payload();
    p["operation"] = json!("model_call");
    p["parents"] = json!([]);
    p["model"] = json!({"provider": "t", "name": "e", "version": "1"});
    assert!(emit(&p, &sk).is_err());
}

#[test]
fn rejects_reserved_unknown_field() {
    let sk = key();
    let mut p = base_payload();
    p["rogue"] = json!(true);
    assert!(emit(&p, &sk).is_err());
}

#[test]
fn chain_topo_and_closure() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("model_call");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!(["untrusted_user"]);
    p2["model"] = json!({"provider": "t", "name": "e", "version": "1"});
    let r2 = emit(&p2, &sk).unwrap();
    let c = build_chain(vec![r1, r2]).unwrap();
    assert_eq!(c.receipts.len(), 2);
}

#[test]
fn chain_rejects_topo_break() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("model_call");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!(["untrusted_user"]);
    p2["model"] = json!({"provider": "t", "name": "e", "version": "1"});
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r2, r1]).is_err());
}

#[test]
fn chain_rejects_silent_taint_loss() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("model_call");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!([]);
    p2["model"] = json!({"provider": "t", "name": "e", "version": "1"});
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r1, r2]).is_err());
}

#[test]
fn sanitisation_must_declare_removed_taint() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("sanitisation");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!([]);
    p2["ruleset_hash"] = json!(sha("rules-v1"));
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r1, r2]).is_err());
}

#[test]
fn sanitisation_with_declared_removed_passes() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("sanitisation");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!([]);
    p2["ruleset_hash"] = json!(sha("rules-v1"));
    p2["x_removed_taint"] = json!(["untrusted_user"]);
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r1, r2]).is_ok());
}

#[test]
fn canonical_parity() {
    let got = canonical_encode(&json!({
        "iss": "x", "iat": 1, "parents": ["a", "b"], "taint": ["a_t", "z_t"]
    }))
    .unwrap();
    let want = r#"{"iat":1,"iss":"x","parents":["a","b"],"taint":["a_t","z_t"]}"#;
    assert_eq!(String::from_utf8(got).unwrap(), want);
}
