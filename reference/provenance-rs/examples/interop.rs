use ed25519_dalek::SigningKey;
use raucle_provenance::emit;
use serde_json::json;

fn main() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let p = json!({
        "iat": 1700000001,
        "agent_id": "agent:x",
        "agent_key_id": "k1",
        "operation": "user_input",
        "parents": [],
        "input_hash": "sha256:f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef",
        "taint": ["untrusted_user"]
    });
    let r = emit(&p, &sk).unwrap();
    let pub_hex: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("{}", r.jws);
    println!("{}", pub_hex);
}
