# Licensing

raucle-detect is licensed under the **Apache License, Version 2.0**
(Apache-2.0). See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE)
for the attribution notice.

Apache-2.0 is a permissive open-source licence. You may use, modify, embed, and
redistribute raucle-detect — including inside closed-source products and hosted
services — provided you comply with the licence's terms (preserve copyright and
NOTICE attribution, state significant changes, and honour the patent terms).

## What the licence covers (and what it doesn't)

- **Code.** The engine in `raucle_detect/` is Apache-2.0. The five reference
  implementations in `reference/` are **MIT**. The Provenance Receipt
  specification text is **CC-BY-4.0**.
- **Patents.** Apache-2.0 §3 includes an explicit patent grant from
  contributors to users, with a retaliation/termination clause — useful
  assurance for adopters building on raucle-detect as a standard.
- **Trademarks — not granted.** Apache-2.0 §6 does **not** grant rights to the
  **"Raucle"** name or logo. A software licence grants rights in the *code*, not
  the *name*. See [TRADEMARK.md](TRADEMARK.md): you may use the code freely, but
  you may not name a fork or product "Raucle" or imply endorsement.

## Why Apache-2.0?

raucle-detect aims to be the de-facto reference for verifiable agent
authorization and provenance receipts. A standard wins by being trivial to
adopt — embeddable in any agent runtime, gateway, SDK, or cloud without legal
friction. Apache-2.0 maximises that embeddability while still protecting
adopters (patent grant) and the project's identity (trademark, held separately).

## Earlier versions

- Releases **≤ v0.18.0** were published under **AGPL-3.0-or-later** (with a
  commercial licence option) and remain available under those terms.
- Even earlier history (at and before commit `ac9aed0`) was **MIT**.
- Starting with **v0.19.0**, the core package is **Apache-2.0**.

This change is forward-looking: it does not retroactively alter copies already
received under a prior licence.

## Contributing

Contributions are accepted under Apache-2.0 (inbound = outbound, per the Apache
contribution norm). Every contribution requires a [DCO](DCO) sign-off
(`git commit -s`), which certifies you have the right to submit it. No separate
copyright-assignment CLA is required. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Questions

Open an issue on the GitHub repository, or email `oss@raucle.com`. For trademark
or brand-use questions, email `legal@raucle.com`.
