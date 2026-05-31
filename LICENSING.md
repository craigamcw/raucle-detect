# Licensing

raucle-detect is released under a **dual licence**:

1. **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — the default. See [LICENSE](LICENSE) for the full text.
2. **A commercial licence** from epic28 Ltd (trading as Raucle), available for organisations who cannot or do not wish to comply with the AGPL.

Most users can stop reading here: if you use raucle-detect under AGPL, you are covered. The AGPL is a strong-copyleft licence that requires anyone who *modifies* raucle-detect and *makes it available to users over a network* — i.e., embeds it in a hosted service — to release their modifications under the same licence. If you self-host raucle-detect inside your organisation and do not redistribute or expose it as a service to third parties, the AGPL imposes no obligations beyond preserving the copyright notices.

For full details on when a commercial licence is appropriate and how to obtain one, see [COMMERCIAL.md](COMMERCIAL.md).

## Why AGPL + commercial?

We chose this model deliberately:

- **AGPL preserves the open-source character of the project.** The source is public, anyone may read it, audit it, learn from it, modify it, and redistribute it. Academic researchers, security teams, students, and self-hosting enterprises can use raucle-detect freely. The AGPL is an OSI-approved open-source licence in the strictest sense.
- **It prevents proprietary-SaaS clones.** A company that wants to host raucle-detect as a commercial service for third parties must either release their entire modified codebase under AGPL or obtain a commercial licence from us. This protects the project from being absorbed into a closed-source product by a third party that contributes nothing back.
- **It is the standard model for production-quality commercial open source.** MongoDB used AGPL for a decade before SSPL; MySQL used GPL + commercial for two decades; Sentry, GitLab, and Grafana all use variations of this pattern. It is well-understood by enterprise legal teams and not a barrier to adoption inside regulated industries.

## Contributing

Contributions to raucle-detect are accepted under the AGPL-3.0 by default. Significant contributors may be asked to sign a Contributor Licence Agreement (CLA) granting epic28 Ltd (trading as Raucle) the right to also license their contribution under our commercial licence; this is what makes the dual-licence model possible. The CLA does not remove your rights to your contribution — it adds rights for Raucle.

## Earlier versions

Versions of raucle-detect tagged before this relicensing remain available under the MIT licence under which they were originally released. The git history at and before commit `ac9aed0` is MIT-licensed; from the commit that introduces this file onward, the project is AGPL-3.0-or-later.

## Questions

Email `commercial@raucle.com` for commercial-licensing enquiries. For general licensing questions, open an issue on the GitHub repository.
