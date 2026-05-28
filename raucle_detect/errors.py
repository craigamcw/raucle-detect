"""Typed error hierarchy for raucle-detect cryptographic and policy paths.

Exists so the cryptographic and capability-issuance code paths can fail
loudly with named exceptions distinct from generic ``ValueError`` /
``Exception``. Callers (and operators) that need to distinguish "explicit
configuration was malformed" from "input data was bad" can match on these
named types.

The defining principle: **explicitly-configured-but-broken = REFUSE;
simply-absent = WARN loudly and continue in an explicitly-marked
unsigned mode.** Never silent.
"""

from __future__ import annotations


class ConfigurationError(Exception):
    """An explicitly-set configuration value cannot be loaded or used.

    Raised when:

    * ``RAUCLE_DETECT_VERDICT_KEY_PEM`` is set but the PEM is unparseable.
    * ``RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM`` is set but invalid.
    * A :class:`raucle_detect.verdicts.VerdictSigner` or
      :class:`raucle_detect.audit.Ed25519Signer` is supplied with a
      private key whose public bytes cannot be extracted.

    Distinct from the safe-default-with-warning path, which logs a
    ``WARNING`` and continues in explicitly-marked unsigned mode.
    """


class PolicyUnproven(Exception):
    """Strict capability-mint mode refused to mint a token.

    Raised by :meth:`raucle_detect.capability.CapabilityIssuer.mint` when
    the issuer was constructed with ``require_proof=True`` (or the
    ``RAUCLE_REQUIRE_PROOF=1`` env var) and one of:

    * no :class:`~raucle_detect.prove.ProofResult` was supplied,
    * the supplied ``ProofResult.status`` is not ``"PROVEN"``,
    * the supplied ``ProofResult``'s ``grammar_hash`` or ``policy_hash``
      does not match the caller-asserted ``grammar_hash`` / ``policy_hash``
      on the capability being minted.

    Default behaviour (``require_proof=False``) is unchanged: mint still
    succeeds without a proof, and the resulting token has no proof
    binding.
    """
