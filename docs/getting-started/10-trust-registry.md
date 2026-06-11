# 10. Agent Trust Registry — cross-org verification

Until now, verifying another agent's capability token or receipt meant you
already held its issuer's public key: hardcoded in `trusted_issuers`, or pinned
out of band via an A2A card. That does not scale across organisations. An agent
in **your** company cannot verify an agent in **another** company without a prior
key exchange.

The **Trust Registry** is the shared, tamper-evident directory that closes the
gap — the certificate-transparency analogue for agent issuers. An issuer
publishes its public key once; any verifier in any org resolves
`key_id → public key` from the registry and checks revocation. Each new
publisher makes the next verification easier.

```bash
pip install 'raucle-detect[compliance]'
```

## Publish your issuer key (once)

```bash
# Operator (whoever runs the registry) generates a signing key, then:
raucle-detect registry init   trust.jsonl --operator-key operator.key.pem
raucle-detect registry publish trust.jsonl org-a.pub.pem --issuer "Org A" \
  --operator-key operator.key.pem
```

The registry is an append-only, hash-chained JSONL log. When `--operator-key`
is given it is also operator-signed, so a consumer who pins the operator key
trusts the whole log with one signature check.

## Verify across orgs (no prior key exchange)

```python
from raucle_detect.trust_registry import TrustRegistry
from raucle_detect.capability import CapabilityGate

# Fetch the shared registry (pin the operator key for an untrusted source).
registry = TrustRegistry.from_url(
    "https://trust.example.com/registry.jsonl",
    operator_public_pem=open("operator.pub.pem", "rb").read(),
)

# Build a gate straight from it: now you can verify ANY published issuer's
# token, including ones you have never exchanged keys with.
gate = CapabilityGate(trusted_issuers=registry.as_issuer_map())
decision = gate.check(foreign_token, tool="transfer_funds", args={...})
```

`registry.public_key(key_id)` is **fail-closed**: it returns `None` for an
unknown *or revoked* key, so a verifier built on the registry denies by default.

## Revoke (fail-closed, history preserved)

```bash
raucle-detect registry revoke trust.jsonl <key_id> --reason "key compromised" \
  --operator-key operator.key.pem
```

Revocation is a new append-only entry. The key drops out of `as_issuer_map()`
immediately; history stays auditable.

## Inspect / verify

```bash
raucle-detect registry list    trust.jsonl                 # active issuers
raucle-detect registry resolve trust.jsonl <key_id>        # full record (incl. revoked)
raucle-detect registry verify  trust.jsonl --operator-pubkey operator.pub.pem
```

`verify` checks the hash chain (tamper-evidence) always, and the operator
signatures (authentication) when you pin the operator public key. Tampering with
any past entry, or a wrong operator key, fails the check.

## Hosting

The registry is a static JSONL file. Serve it from any HTTPS endpoint (a CDN,
an object store, `raucle.com/registry`) and consumers fetch it with
`TrustRegistry.from_url(...)`. No server logic required; the integrity and
authentication live in the format, verified client-side.

---

Next: cross-org agent handoffs that resolve trust from this registry — see the
[A2A binding](../../raucle_detect/a2a.py) and the upcoming cross-org handshake.
