//! Rust reference implementation of the Raucle Provenance Receipt v1
//! spec (<https://raucle.com/spec/provenance/v1>).
//!
//! Mirrors the Python (`promptguard.provenance`), TypeScript
//! (`@raucle/provenance`), and Go reference implementations: same JWS
//! envelope, same canonical-JSON bytes, same content-addressed
//! identifiers. A receipt emitted by any implementation verifies in
//! the others.

mod canonical;
mod graph;
mod receipt;

pub use canonical::{canonical_encode, CanonicalError};
pub use graph::{build_chain, Chain, ChainError};
pub use receipt::{emit, validate_payload, verify, ProvError, Receipt};
