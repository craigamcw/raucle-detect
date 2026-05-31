use ed25519_dalek::SigningKey;
use raucle_provenance::emit;
use serde_json::json;
use sha2::{Digest, Sha256};
fn sha(s:&str)->String{let mut h=Sha256::new();h.update(s.as_bytes());h.finalize().iter().map(|b|format!("{:02x}",b)).collect()}
fn main(){
  let sk = SigningKey::from_bytes(&[7u8;32]);
  let h = sha("hello");
  let p = json!({"iss":"https://x/raucle","iat":1748505600,"agent_id":"agent:x","agent_key_id":"k1","operation":"user_input","parents":[],"input_hash":h,"output_hash":h,"taint":["untrusted_user"],"guardrail_verdict":"NA"});
  let r = emit(&p,&sk).unwrap();
  let pub_hex: String = sk.verifying_key().to_bytes().iter().map(|b|format!("{:02x}",b)).collect();
  println!("{}", r.jws);
  println!("{}", pub_hex);
}
