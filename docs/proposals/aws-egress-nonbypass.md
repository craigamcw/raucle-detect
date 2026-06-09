# Non-bypass deployment for the AWS Egress Gate

The gate enforces the **credential half** of custody in code: it holds the AWS
credentials, signs each request, and never returns signed material to the agent
(`raucle_detect/broker/aws_egress.py`). But "no receipt = no action" only holds
end to end if the agent *also* cannot reach AWS any other way. That is the
**egress half**, and it is a deployment guarantee — two independent controls,
neither of which the agent can lift:

1. **Identity custody (IAM).** The agent process runs under a principal with **no
   AWS permissions**. Even if it somehow obtained an endpoint, every direct AWS
   call returns `AccessDenied`. The only principal that can call AWS is the gate's
   broker role.
2. **Network isolation (VPC).** The agent's network egress is restricted so the
   *only* reachable destination is the gate. It cannot open a socket to
   `*.amazonaws.com` at all.

Either control alone substantially reduces blast radius; together they make
custody non-bypassable: the agent has neither the keys nor a route.

## Reference architecture (cost-minimal, NAT-free)

```
┌───────────────────────── VPC (no Internet Gateway, no NAT) ──────────────────────────┐
│                                                                                       │
│   ┌───────────────┐         ┌──────────────────┐        ┌──────────────────────────┐ │
│   │  Agent task   │  only   │  raucle gate     │  AWS   │  VPC Interface Endpoints  │ │
│   │ (Fargate)     │────────▶│  (Fargate)       │───────▶│  (PrivateLink):           │ │
│   │  IAM: NONE    │  :8080  │  IAM: broker role│        │  dynamodb, s3(gw), sqs,   │ │
│   │  SG: egress → │         │  holds AWS creds │        │  secretsmanager           │ │
│   │  gate SG only │         └──────────────────┘        └──────────────────────────┘ │
│   └───────────────┘                                                                   │
│        ▲ no IGW / no NAT → no path to the public internet or AWS public endpoints     │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Key choices, and why they keep cost at ~$0 for a demo:

- **No NAT gateway.** A NAT gateway is ~$32/month + data — the usual hidden cost
  of "private subnet" designs. We don't need it: AWS is reached over **VPC
  interface endpoints (PrivateLink)** and the **S3 gateway endpoint**, which keep
  traffic on the AWS backbone. The S3 gateway endpoint is **free**; interface
  endpoints are ~$0.01/hour each *while provisioned*, so a short-lived demo is
  cents and a torn-down demo is ~$0.
- **No Internet Gateway** on the agent subnet — there is literally no route to the
  public internet, so the agent cannot reach `*.amazonaws.com` directly even if it
  had keys.
- **Security groups, not NACLs, for the allowlist:** the agent task's SG allows
  egress **only** to the gate task's SG on the gate port. Nothing else.
- **Fargate, not EC2:** no always-on instance to pay for or patch.

## The two controls, proven independently

### 1. IAM custody — provable for $0
Create a second principal `raucle-agent` with an explicit **deny-all** (or simply
no policy). It models the agent. Prove that it gets `AccessDenied` on *every*
surface, while the gate's broker creds succeed on the same calls. This needs no
networking and costs nothing — see `scripts/live_aws_smoke.py --prove-agent-deny`.

CloudTrail then shows the punchline: every *successful* AWS call carries
`userIdentity = …:user/raucle-smoke` (the broker) and **never the agent** — see
`scripts/cloudtrail_correlate.py`.

### 2. Network isolation — the documented design (apply only when you want the live demo)
The diagram above is the deployable network proof: a VPC with **no IGW and no
NAT**, the agent and gate as Fargate tasks, AWS reached only via the S3 gateway
endpoint (free) and interface endpoints (~$0.01/hr each). The agent task's
security group allows egress **only** to the gate's security group — so the agent
has no route to `*.amazonaws.com` at all. This half is intentionally left as a
design to apply on demand (not shipped as standing IaC, because we don't commit
infrastructure we haven't run end to end). Stand it up only for a live network
demo and `terraform destroy` immediately after; the only billable items are the
interface endpoints and Fargate task-seconds — cents for a demo, ~$0 once torn
down. The **credential-custody half (control 1) is fully provable today for $0**
and is what the gate's code guarantees; the network half hardens it in a real VPC.

## What this buys a regulator

The agent cannot act outside the gate because it has **no key and no route**, and
AWS's own CloudTrail confirms every action ran under the broker identity — while
raucle's receipt binds the same action *and* the agent's authorisation *and* is
verifiable offline. The cloud provider's log proves who *technically* made the
call; raucle's receipt proves it was *authorised*, and survives leaving AWS. Only
the combination answers "prove this agent could not have done anything you didn't
authorise."

## Scope / non-goals

This document plus the Terraform is a **reference**, not a managed product. It
does not cover multi-tenant isolation, HA, or the TEE-attested variant (see
`tee-gate.md`). The custody *code* guarantees hold regardless of deployment; this
is how you make the egress half non-bypassable in a real VPC.
