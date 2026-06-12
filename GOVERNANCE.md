# Governance

This document describes how the **raucle** project and the
**Raucle Provenance Receipt** specification are governed.

## Stewardship

raucle and the Raucle Provenance Receipt specification are
created and maintained by **Raucle** as the originator and current
steward. Final decisions on the engine, the specification, and what
counts as a conformant implementation rest with the maintainers at
Raucle. We welcome contributions, review, and implementations from
anyone (see [CONTRIBUTING.md](./CONTRIBUTING.md)).

## What lives here, and under what terms

| Component | Location | Licence | Intent |
|---|---|---|---|
| **Detection / gate / prover engine** | `raucle/` | **Apache-2.0** | The product. Permissive so it is trivial to embed in any agent runtime, gateway, SDK, or cloud — with an explicit patent grant for adopters. |
| **Provenance Receipt specification** | `docs/spec/provenance/` | CC-BY-4.0 | An open standard. Anyone may implement it, in any language, under any licence. |
| **Reference implementations** | `reference/` | **MIT** (permissive, by design) | Deliberately permissive so the standard is trivial to adopt — embed them in any product, including proprietary ones. |

The posture is intentional: **the engine, the standard, and its reference
code are all permissive — maximise adoption so raucle becomes the
de-facto reference.** The project's defensibility lives in the **Raucle**
trademark (held separately — see [TRADEMARK.md](./TRADEMARK.md)), the brand,
and proprietary offerings built on top, not in copyleft on the core. Using the
engine, the spec, or a reference implementation never obliges you to open-source
your own code.

## The specification

- **Versioning.** The spec is versioned (currently v1). Breaking changes
  produce a new major version with a new `typ` / identifier; v1 is
  frozen on its wire format once finalised so existing receipts stay
  verifiable forever.
- **Conformance.** An implementation is "conformant" if it produces and
  verifies receipts that pass the shared test vectors in
  `docs/spec/provenance/v1/test-vectors.json` and the canonical-JSON
  parity vector in `reference/README.md`. Byte-identical content-
  addressed IDs across implementations is the bar.
- **Proposing changes.** Open a GitHub issue labelled `spec`. Substantive
  changes are discussed in the open before a maintainer merges. We will
  consider donating the specification to a neutral standards body once it
  is established; until then Raucle stewards it to keep it coherent.

## Decision-making

The project is maintainer-led. We operate by lazy consensus on the issue
tracker: proposals that attract no sustained objection from maintainers
are accepted; contested changes are decided by the maintainers, who
prioritise (in order) correctness, security, the durability of existing
receipts, and adoption.

## Trademark

The code is open; the name is not. See [TRADEMARK.md](./TRADEMARK.md).
