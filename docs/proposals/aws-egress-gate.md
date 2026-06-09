# raucle AWS Egress Gate — first credential-custody build (DRAFT)

> Status: DRAFT design. The first concrete implementation of the credential-custody
> model in [`raucle-mcp-gateway.md`](raucle-mcp-gateway.md). Proves "no receipt =
> no action" end-to-end for one real service before any compatibility breadth.

## Why AWS STS, and why egress proxy (not token minting)

AWS STS `AssumeRole` + session policies is the best first broker: IAM/STS is
already trusted and audited in regulated-fintech shops, CloudTrail gives a
corroborating trail, and the custody story is legible (raucle holds the
role-assumption capability; the agent never holds a standing AWS credential).

But STS credentials are **not single-use** — the practical minimum TTL is ~15
minutes. So *minting and handing the agent a scoped STS credential* proves only
"the agent has no standing credential"; within the window the agent could reuse
the credential for anything the scoped policy admits. That is **not** "no receipt
= no action" — a regulated buyer will see the replay gap immediately.

Therefore the first build is an **egress proxy**, custody mechanism (1) from the
gateway spec: the agent never receives an AWS credential at all. raucle holds the
credential, signs each *individual* allowed request, and forwards it. The agent's
only route to AWS is through raucle, and every signed request has a receipt.

## Flow

```
  agent ──(intended AWS call: service, action, params; NO creds)──▶ raucle AWS Egress Gate
                                                                      │
                                                    1. CapabilityGate.check(tool=action, args=params)
                                                                      │ DENY → JSON error + signed DENY receipt
                                                                      │ ALLOW
                                                    2. SigV4-sign the EXACT request with raucle-held creds
                                                       (or AssumeRole→sign, raucle holds the session)
                                                    3. forward to the real AWS endpoint
                                                    4. emit signed receipt bound to method+host+path+
                                                       region+SHA-256(canonical request)+expiry+decision
                                                                      │
                                                              ◀── AWS response (raucle relays) ──
```

The agent holds: nothing. raucle holds: the AWS credential / role-assumption
right, and is the sole signer and sole egress path.

## The honest claim this build supports

> The agent has no AWS credential and no route to AWS except through raucle.
> Every request AWS accepts was SigV4-signed by raucle after a gate ALLOW and is
> bound to a receipt. There is no replay window because the agent never holds a
> reusable credential — it holds no credential at all.

This is strictly stronger than token minting and is the version worth demoing.

## Receipt binding (close the replay gap)

Each receipt MUST bind the exact request, not just the decision: HTTP method,
host, canonical path + query, AWS region + service, a SHA-256 of the canonical
signed request (headers in scope + body), the gate decision, the capability token
chain, and the signature expiry. A receipt therefore attests one specific signed
AWS request, not a class of them.

## MVP scope

1. A signing egress proxy for **one** AWS service with a clean, narrow action set
   (candidate: S3 object GET/PUT, or STS-scoped DynamoDB GetItem) — small enough
   to demo, broad enough to be real.
2. raucle holds credentials via the standard provider chain or an explicit
   `AssumeRole` it performs; the agent is configured with the proxy URL only.
3. Gate each request through the existing `CapabilityGate`; emit receipts through
   the existing `HashChainSink` + `Ed25519Signer`, identical format to every
   other adapter.
4. A demo: an agent that can only reach S3 through the proxy, a signed receipt per
   object access, verifiable offline; an attempt to call a denied action returns
   an error + a DENY receipt and never reaches AWS.

## Reuse vs net-new

- **Reuse:** `CapabilityGate`, `CapabilityIssuer`, `HashChainSink`,
  `Ed25519Signer`, the receipt format.
- **Net-new:** the SigV4 signing path over raucle-held creds (or AssumeRole +
  session), the HTTP egress proxy, request-canonicalisation for the receipt
  binding, and the mapping from a gated `(action, params)` to a concrete signed
  AWS request.

## First-PR scope constraints (Codex-reviewed)

To keep the custody claim airtight, the first build is deliberately narrow:

- **Surface:** the narrowest non-streaming action — DynamoDB `GetItem`, or a small
  fixed-body S3 `GET`/`PUT` with explicit `Content-Length` and
  `x-amz-content-sha256`. **Excluded from the first PR:** SigV4 streaming/chunked
  payloads, presigned URLs, S3 multipart uploads, redirects, and SDK-transparent
  automatic retries — each is a way for one intended call to fan out into multiple
  accepted AWS requests.
- **One receipt per AWS attempt.** If raucle forwards more than one HTTP request
  for a logical call (retry, redirect), each gets its own receipt — never one
  receipt for many wire requests.
- **The agent must never receive signed material:** no AWS credentials, no STS
  session token, no `Authorization` header, no presigned URL, no direct AWS
  egress. raucle signs and forwards server-side only.
- **Single source of truth against canonicalisation drift (the biggest risk).**
  The proxy constructs the AWS request from normalised gated params, owns/strips
  sensitive headers, signs **only what it forwards**, and emits the receipt from
  the **final wire request per attempt** — so what the gate approved, what was
  signed, what was sent, and what the receipt hashes are byte-identical.

## Honest non-goals / risks

- This is one service. It is **not** universal agent enforcement; it proves the
  custody model on a single legible surface.
- "Just IAM done carefully" is the perception risk. The differentiator must be
  visible in the demo: one gate ALLOW = one signed, receipted AWS request, with
  the agent provably unable to act otherwise.
- Egress non-bypass is an operational requirement: the agent's network/runtime
  must not have a direct AWS route or credential. The build SHOULD document the
  deployment that guarantees this (no AWS creds in the agent env; egress allowlist
  to the proxy only).
