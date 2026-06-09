"""Minimal AWS Signature Version 4 signer (standard library only).

raucle's AWS Egress Gate signs each allowed request server-side with
raucle-held credentials, so the agent never receives any AWS credential or
``Authorization`` header. This module is the signer: it takes a fully-formed
HTTP request and returns the ``Authorization`` header plus the canonical request
hash that the receipt binds to.

It implements the SigV4 algorithm directly (``hmac`` + ``hashlib``) rather than
pulling in ``botocore`` — the algorithm is small, stable, and auditable, and
keeping it dependency-free matches the rest of the engine. Validated against the
published AWS ``aws-sig-v4-test-suite`` ``get-vanilla`` vector in the tests.

Scope (v1): non-streaming requests with a fully-known body. Streaming/chunked
payloads, presigned URLs, and ``UNSIGNED-PAYLOAD`` are intentionally out of
scope for the first build (see docs/proposals/aws-egress-gate.md). Signed header
values are trimmed but NOT internal-whitespace-folded per the full SigV4 spec —
the gate owns the header set (fixed, whitespace-free values for DynamoDB), so
this is correct for the v1 surface; a caller passing folded/multi-space header
values would need the full canonicalisation added first.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from urllib.parse import quote

_ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(body: bytes) -> str:
    """Hex SHA-256 of *body* — the value of the ``x-amz-content-sha256`` header
    that S3 requires as a signed header. Exposed so a caller can set the header
    to exactly the hash this module signs into the canonical request."""
    return _sha256_hex(body)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


@dataclass(frozen=True)
class SignedRequest:
    """A fully-signed AWS HTTP request, ready to forward.

    The ``authorization`` header is **signed material** and MUST NOT be returned
    to the agent — only raucle's egress proxy forwards it. ``canonical_hash`` is
    the SHA-256 of the canonical request and is what the receipt binds to, so one
    receipt attests exactly this wire request.
    """

    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    canonical_hash: str  # sha256 hex of the canonical request


def sign(
    *,
    method: str,
    service: str,
    region: str,
    host: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    access_key: str,
    secret_key: str,
    amz_date: str,
    session_token: str | None = None,
    query: str = "",
) -> SignedRequest:
    """Sign an AWS request with SigV4 and return it ready to forward.

    *amz_date* is the ``x-amz-date`` value (``YYYYMMDDTHHMMSSZ``); the caller
    passes it in (rather than reading the clock here) so signing is deterministic
    and testable. ``path`` must already be the absolute request path (``/`` for
    DynamoDB). ``query`` is the canonical query string (empty for DynamoDB).
    """
    datestamp = amz_date[:8]
    payload_hash = _sha256_hex(body)

    # Signed headers: host + x-amz-date are always signed, plus whatever the
    # caller provides (e.g. content-type, x-amz-target). Session token, when
    # present, is signed too. The payload hash goes in the canonical request's
    # final line (below), not as a forced signed header — adding
    # x-amz-content-sha256 is an S3 requirement, not a universal one, and forcing
    # it would diverge from the standard SigV4 test vectors. Callers that need it
    # (S3) pass it explicitly in *headers*.
    signed = {k.lower(): v.strip() for k, v in headers.items()}
    signed["host"] = host
    signed["x-amz-date"] = amz_date
    if session_token:
        signed["x-amz-security-token"] = session_token

    sorted_keys = sorted(signed)
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted_keys)
    signed_headers = ";".join(sorted_keys)

    canonical_uri = quote(path, safe="/-_.~")
    canonical_request = "\n".join(
        [method, canonical_uri, query, canonical_headers, signed_headers, payload_hash]
    )
    canonical_hash = _sha256_hex(canonical_request.encode("utf-8"))

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([_ALGORITHM, amz_date, scope, canonical_hash])
    signing_key = _signing_key(secret_key, datestamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"{_ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    out_headers = dict(signed)
    out_headers["authorization"] = authorization
    scheme_host = f"https://{host}"
    url = scheme_host + canonical_uri + (f"?{query}" if query else "")
    return SignedRequest(
        method=method,
        url=url,
        headers=out_headers,
        body=body,
        canonical_hash="sha256:" + canonical_hash,
    )
