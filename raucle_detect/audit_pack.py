"""Self-contained, offline-verifiable custody evidence pack (E2).

``audit-export`` produces a signed report but leaves the inputs a verifier needs
(the receipt chain, the public keys, the authorising capability tokens, the cited
proofs) as separate files the verifier must already possess and trust. A
**regulator** does not have those files and will not phone the cloud provider to
get them.

An *audit pack* bundles everything required to check the evidence into one
directory, with a ``PACK.json`` index that content-addresses every member. The
matched :func:`verify_pack` then verifies the whole thing **offline** — integrity
of every member, the manifest's own Ed25519 signature, the receipt chain against
the bundled public keys, and that the signed manifest is *reproducible* from the
bundled evidence — needing nothing external: no network, no AWS, no trust in the
party that produced it. This is the property a cloud provider's internal audit
log structurally cannot offer: independent, offline verifiability.

Layout::

    pack/
      PACK.json              index: every member + its sha256 + role
      chain.jsonl            the JWS provenance receipt chain
      manifest.json          the Ed25519-signed audit-export manifest
      report.html            human-readable report (same manifest, rendered)
      pubkeys/<key_id>.pem    public keys the chain verifies against
      statements/<key_id>.json  capability statements (tool/model enforcement)
      capabilities/<n>.json   authorising capability tokens (optional)
      proofs/<n>.json         cited ProofResult artifacts (optional)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .audit_export import build_report, render_html, sign_manifest, verify_manifest
from .provenance import (
    CapabilityStatement,
    ProvenanceVerifier,
    _canonical_json,
    _sha256_hex,
)

PACK_KIND = "raucle-audit-pack/v1"
INDEX_NAME = "PACK.json"


def _file_hash(path: Path) -> str:
    return "sha256:" + _sha256_hex(path.read_bytes())


def build_pack(
    *,
    chain_path: str | Path,
    public_keys: dict[str, bytes],
    audit_key_pem: bytes,
    out_dir: str | Path,
    generated_at: int,
    capability_statements: dict[str, CapabilityStatement] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    proofs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a self-contained, offline-verifiable audit pack.

    ``generated_at`` is injected (not read from the clock) so the signed manifest
    — and therefore the pack — is deterministic and reproducible. Returns the
    written ``PACK.json`` index dict.
    """
    capability_statements = capability_statements or {}
    capabilities = capabilities or []
    proofs = proofs or []

    report = build_report(
        chain_path,
        public_keys,
        proofs,
        generated_at=generated_at,
        capabilities=capabilities,
        capability_statements=capability_statements or None,
    )
    manifest = sign_manifest(report, audit_key_pem)

    out = Path(out_dir)
    (out / "pubkeys").mkdir(parents=True, exist_ok=True)
    members: list[dict[str, Any]] = []

    def _emit(rel: str, data: bytes, role: str, **extra: Any) -> None:
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        members.append({"path": rel, "role": role, "sha256": _file_hash(dest), **extra})

    _emit("chain.jsonl", Path(chain_path).read_bytes(), "receipt-chain")
    _emit(
        "manifest.json",
        json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"),
        "signed-manifest",
    )
    _emit("report.html", render_html(manifest).encode("utf-8"), "human-report")
    for key_id, pem in sorted(public_keys.items()):
        _emit(f"pubkeys/{key_id}.pem", pem, "public-key", key_id=key_id)
    for key_id, stmt in sorted(capability_statements.items()):
        _emit(
            f"statements/{key_id}.json",
            json.dumps(stmt.to_dict(), ensure_ascii=False).encode("utf-8"),
            "capability-statement",
            key_id=key_id,
        )
    for i, cap in enumerate(capabilities):
        _emit(
            f"capabilities/{i}.json",
            json.dumps(cap, ensure_ascii=False).encode("utf-8"),
            "capability-token",
        )
    for i, proof in enumerate(proofs):
        _emit(
            f"proofs/{i}.json",
            json.dumps(proof, ensure_ascii=False).encode("utf-8"),
            "proof",
        )

    index = {
        "kind": PACK_KIND,
        "generated_at": generated_at,
        "tool_version": __version__,
        "audit_key_id": manifest["signer_key_id"],
        "members": members,
        "verify": "raucle audit-pack verify <dir>",
    }
    (out / INDEX_NAME).write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    return index


def _resolve_member(pack: Path, rel: str) -> Path | None:
    """Resolve an index member path *inside* the pack, or ``None`` if it escapes.

    The ``PACK.json`` index is attacker-controllable, so a member ``path`` like
    ``../../etc/passwd`` or an absolute path must never make verification read
    outside the pack — that would break the self-contained / no-external-input
    guarantee. Returns the resolved path only when it stays under the pack root.
    """
    if os.path.isabs(rel) or ".." in Path(rel).parts:
        return None
    try:
        resolved = (pack / rel).resolve()
        root = pack.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root):
        return None
    return resolved


@dataclass
class PackVerdict:
    """Outcome of an offline pack verification. ``ok`` is the AND of all checks.

    ``signer_trusted`` is ``None`` when no expected signer was pinned (the pack is
    then only proven *internally consistent*, not proven to come from a specific
    custodian), ``True``/``False`` when an anchor was supplied and matched/didn't.
    """

    ok: bool
    integrity_ok: bool
    manifest_signature_ok: bool
    chain_valid: bool
    reproducible: bool
    signer_key_id: str | None = None
    signer_trusted: bool | None = None
    receipt_count: int = 0
    reasons: list[str] = field(default_factory=list)


def verify_pack(pack_dir: str | Path, *, expected_signer: str | None = None) -> PackVerdict:
    """Verify an audit pack **fully offline** — no network, no external inputs.

    Checks, all of which must pass for ``ok``:

    1. **Integrity** — every member's on-disk sha256 matches the ``PACK.json``
       index, every member path stays inside the pack, and the index ``kind`` is
       recognised (nothing added, dropped, altered, or pointing outside).
    2. **Manifest signature** — the manifest's Ed25519 signature verifies against
       the public key embedded in it, and the displayed signer id matches.
    3. **Chain validity** — the receipt chain verifies against the bundled public
       keys alone (the custody invariant, checked without the cloud provider).
    4. **Reproducibility** — rebuilding the report from the bundled evidence
       yields a byte-identical manifest *body* AND the bundled ``report.html``
       matches the manifest's own rendering, so neither the machine-readable nor
       the human-readable view can be doctored independently of the signature.

    Trust anchor: a self-signed manifest proves *internal consistency*, not that
    the pack came from the claimed custodian — an attacker can rebuild the whole
    pack and sign it with their own key. Pin ``expected_signer`` (the custodian's
    audit key id) to additionally require the manifest signer to match; without
    it, ``ok`` means "internally consistent" and ``signer_trusted`` is ``None``.
    """
    pack = Path(pack_dir)
    reasons: list[str] = []
    index_path = pack / INDEX_NAME
    if not index_path.is_file():
        return PackVerdict(False, False, False, False, False, reasons=[f"missing {INDEX_NAME}"])
    index = json.loads(index_path.read_text())

    integrity_ok = True
    if index.get("kind") != PACK_KIND:
        integrity_ok = False
        reasons.append(f"unexpected pack kind {index.get('kind')!r}")

    # 1. Integrity: resolve each member safely and check its hash.
    members = index.get("members", [])
    resolved: dict[str, Path] = {}
    for m in members:
        safe = _resolve_member(pack, m["path"])
        if safe is None:
            integrity_ok = False
            reasons.append(f"member path escapes the pack: {m['path']!r}")
            continue
        if not safe.is_file():
            integrity_ok = False
            reasons.append(f"missing member {m['path']}")
            continue
        if _file_hash(safe) != m["sha256"]:
            integrity_ok = False
            reasons.append(f"hash mismatch for {m['path']} (tampered)")
            continue
        resolved[m["path"]] = safe

    def _safe(rel: str) -> Path | None:
        return resolved.get(rel)

    # 2. Manifest self-signature (+ optional pinned-signer trust anchor).
    manifest_signature_ok = False
    manifest: dict[str, Any] = {}
    signer_key_id: str | None = None
    manifest_member = _safe("manifest.json")
    if manifest_member is not None:
        manifest = json.loads(manifest_member.read_text())
        manifest_signature_ok = verify_manifest(manifest)
        signer_key_id = manifest.get("signer_key_id")
        if not manifest_signature_ok:
            reasons.append("manifest signature did not verify")
    else:
        reasons.append("missing or untrusted manifest.json")

    signer_trusted: bool | None = None
    if expected_signer is not None:
        signer_trusted = manifest_signature_ok and signer_key_id == expected_signer
        if not signer_trusted:
            reasons.append(
                f"manifest signer {signer_key_id!r} does not match pinned "
                f"custodian key {expected_signer!r}"
            )

    # Reload bundled public keys + capability statements (only verified members).
    public_keys: dict[str, bytes] = {}
    statements: dict[str, CapabilityStatement] = {}
    capabilities: list[dict[str, Any]] = []
    proofs: list[dict[str, Any]] = []
    for m in members:
        safe = _safe(m["path"])
        if safe is None:
            continue
        role = m.get("role")
        if role == "public-key":
            public_keys[m["key_id"]] = safe.read_bytes()
        elif role == "capability-statement":
            statements[m["key_id"]] = CapabilityStatement.from_dict(json.loads(safe.read_text()))
        elif role == "capability-token":
            capabilities.append(json.loads(safe.read_text()))
        elif role == "proof":
            proofs.append(json.loads(safe.read_text()))

    # 3. Chain verifies against the bundled keys alone.
    chain_member = _safe("chain.jsonl")
    chain_valid = False
    receipt_count = 0
    if chain_member is not None and public_keys:
        verdict = ProvenanceVerifier(public_keys=public_keys).verify_chain(chain_member)
        chain_valid = verdict.valid
        receipt_count = verdict.receipt_count
        if not chain_valid:
            reasons.append("receipt chain did not verify against bundled keys")
    else:
        reasons.append("missing/untrusted chain.jsonl or bundled public keys")

    # 4. Reproducibility: signed manifest body AND rendered report must follow
    #    from the bundled evidence — neither view doctorable independently.
    reproducible = False
    if manifest and chain_member is not None and public_keys:
        try:
            rebuilt = build_report(
                chain_member,
                public_keys,
                proofs,
                generated_at=index["generated_at"],
                capabilities=capabilities,
                capability_statements=statements or None,
            )
            body_ok = _canonical_json(rebuilt.body()) == _canonical_json(manifest["body"])
            if not body_ok:
                reasons.append("manifest body is not reproducible from bundled evidence")
            html_member = _safe("report.html")
            html_ok = html_member is not None and html_member.read_bytes() == render_html(
                manifest
            ).encode("utf-8")
            if not html_ok:
                reasons.append("report.html does not match the signed manifest")
            reproducible = body_ok and html_ok
        except (ValueError, OSError, KeyError) as exc:
            reasons.append(f"reproducibility rebuild failed: {exc}")

    ok = (
        integrity_ok
        and manifest_signature_ok
        and chain_valid
        and reproducible
        and signer_trusted is not False
    )
    return PackVerdict(
        ok=ok,
        integrity_ok=integrity_ok,
        manifest_signature_ok=manifest_signature_ok,
        chain_valid=chain_valid,
        reproducible=reproducible,
        signer_key_id=signer_key_id,
        signer_trusted=signer_trusted,
        receipt_count=receipt_count,
        reasons=reasons,
    )
