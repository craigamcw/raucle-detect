//! Chain DAG verifier — §7 taint monotonicity, §8 acyclicity + closure.

use crate::receipt::Receipt;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug)]
pub struct ChainError(pub String);
impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ChainError {}

pub struct Chain {
    pub receipts: Vec<Receipt>,
}

fn taint_of(r: &Receipt) -> BTreeSet<String> {
    r.payload
        .get("taint")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn parents_of(r: &Receipt) -> Vec<String> {
    r.payload
        .get("parents")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Validate an ordered slice of already-verified receipts.
pub fn build_chain(receipts: Vec<Receipt>) -> Result<Chain, ChainError> {
    let mut by_id: HashMap<String, &Receipt> = HashMap::new();

    for r in &receipts {
        if by_id.contains_key(&r.id) {
            return Err(ChainError(format!("duplicate receipt id in chain: {}", r.id)));
        }
        for p in parents_of(r) {
            if !by_id.contains_key(&p) {
                return Err(ChainError(format!(
                    "receipt {} references parent {} not earlier in the chain \
                     (topo or closure violation)",
                    r.id, p
                )));
            }
        }
        by_id.insert(r.id.clone(), r);
    }

    for r in &receipts {
        let mut parent_taint: BTreeSet<String> = BTreeSet::new();
        for p in parents_of(r) {
            parent_taint.extend(taint_of(by_id[&p]).into_iter());
        }
        let child_taint = taint_of(r);
        let op = r.payload.get("operation").and_then(|v| v.as_str()).unwrap_or("");

        if op == "sanitisation" {
            // Sanitisation may drop tags it lists in `corpus` as
            // "removed:<comma-separated>" (mirrors the Python verifier).
            let corpus = r.payload.get("corpus").and_then(|v| v.as_str()).unwrap_or("");
            let removed: BTreeSet<String> = corpus
                .strip_prefix("removed:")
                .map(|rest| {
                    rest.split(',')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let missing: Vec<&String> = parent_taint
                .iter()
                .filter(|t| !child_taint.contains(*t) && !removed.contains(*t))
                .collect();
            if !missing.is_empty() {
                return Err(ChainError(format!(
                    "sanitisation receipt {} dropped tags without declaring them \
                     in corpus removed-set: {:?}",
                    r.id, missing
                )));
            }
        } else {
            let missing: Vec<&String> = parent_taint
                .iter()
                .filter(|t| !child_taint.contains(*t))
                .collect();
            if !missing.is_empty() {
                return Err(ChainError(format!(
                    "taint monotonicity violation at {}: missing {:?}",
                    r.id, missing
                )));
            }
        }
    }

    Ok(Chain { receipts })
}
