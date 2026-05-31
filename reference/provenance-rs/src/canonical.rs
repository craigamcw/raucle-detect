//! Canonical-JSON encoder (RFC 8785 JCS, minimal subset).
//!
//! Produces byte-identical output to the Python, TypeScript, and Go
//! reference encoders: sorted object keys, no insignificant
//! whitespace, UTF-8. Floats are rejected — the v1 payload schema does
//! not use them.
//!
//! Operates over `serde_json::Value`; we walk it ourselves rather than
//! relying on serde_json's serializer, which does not guarantee a
//! canonical form.

use serde_json::Value;

#[derive(Debug)]
pub struct CanonicalError(pub String);

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical-JSON: {}", self.0)
    }
}
impl std::error::Error for CanonicalError {}

pub fn canonical_encode(v: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = String::new();
    write_value(&mut out, v)?;
    Ok(out.into_bytes())
}

fn write_value(out: &mut String, v: &Value) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(CanonicalError(
                    "only integer numbers are supported in v1".into(),
                ));
            }
        }
        Value::String(s) => write_json_string(out, s),
        Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, e)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // serde_json::Map iterates in insertion order under the
            // default feature set; sort keys explicitly for canonical
            // output.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(out, k);
                out.push(':');
                write_value(out, &map[*k])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
