# raucle sidecar for Azure AI Foundry's MCP Gateway

This directory contains everything needed to deploy raucle as an
APIM-routed sidecar that gates every MCP tool call your Foundry agents
make. Every call produces a signed, content-addressed capability
receipt; every receipt is verifiable offline by any third party
holding your published issuer public key.

The sidecar exists because [Foundry's own docs](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/governance)
state plainly:

> *"AI gateways don't log tool traces."*

This sidecar produces the trace.

## What you get

- Every MCP call routed through raucle, with ALLOW / DENY enforced
  by the existing raucle gate (see [docs/proposals/foundry-mcp-gateway.md](../../docs/proposals/foundry-mcp-gateway.md)
  for the design).
- A signed receipt for every decision, written to Azure Blob Storage,
  hash-chained for tamper evidence.
- An auditable record you can hand to your regulator that they can
  re-check offline without contacting Microsoft or you.

## Prerequisites

Before deploying, you need:

| | What | Why |
|---|---|---|
| 1 | An existing Foundry-attached APIM instance | The sidecar sits behind APIM as a backend pool member. |
| 2 | A Container App Environment in the APIM VNet | The sidecar runs as a Container App that the APIM ingress can reach over private networking. |
| 3 | A Key Vault entry with your raucle issuer Ed25519 private key | The sidecar uses this to sign receipts. Generate with `raucle cap keygen` and store via `az keyvault secret set --vault-name ... --name raucle-issuer-private-key --file issuer.key`. |
| 4 | A Storage Account + Blob container for the audit log | The sidecar writes the hash-chained receipt log here. A 1 GB container is more than enough for ~10⁷ receipts. |
| 5 | A public URL where you publish your issuer pubkey + policy registry | External verifiers fetch from this. Typically `https://<your-org>/.well-known/`. |

## Five-step deploy

### 1. Mint and store the issuer key

```bash
# Locally (or in a CI runner with appropriate role assignments):
raucle cap keygen acme.bank.kyc-platform --out issuer
# Produces: issuer.key (private), issuer.pub (public)

# Push the private key to Key Vault:
az keyvault secret set \
  --vault-name kv-acme-foundry \
  --name raucle-issuer-private-key \
  --file issuer.key

# Publish the public key on your .well-known/ endpoint:
cp issuer.pub /var/www/acme.bank/.well-known/raucle-issuer.pub
```

### 2. Provision the sidecar

Copy `bicep/parameters.example.json` to `bicep/parameters.json`, fill in
the resource ids for your environment, then:

```bash
az deployment group create \
  --resource-group rg-acme-foundry \
  --template-file deploy/foundry-mcp-sidecar/bicep/main.bicep \
  --parameters @deploy/foundry-mcp-sidecar/bicep/parameters.json
```

This creates:

- A user-assigned managed identity with Key Vault Secrets User +
  Storage Blob Data Contributor.
- A Container App running `raucle serve --mode foundry-sidecar`.
- An APIM Backend pool member pointing at the sidecar's internal FQDN.
- Two APIM Named Values (`raucle-sidecar-fqdn`, `raucle-mcp-path`) the
  policy XML references.

The deployment takes ~5 minutes. The sidecar starts with 2 replicas
(one warm) to hit the sub-100µs gate-latency target.

### 3. Apply the APIM policy

Apply `apim-policy.xml` to the APIM operation that fronts your MCP
server. In the Azure portal: APIM → APIs → [your MCP API] → All
operations → Policies → paste the XML. Or via CLI:

```bash
az apim api operation policy create \
  --resource-group rg-acme-foundry \
  --service-name apim-acme-foundry \
  --api-id mcp-api \
  --operation-id mcp-invoke \
  --xml-content "$(cat deploy/foundry-mcp-sidecar/apim-policy.xml)"
```

After this step, every Foundry-originated MCP call routes through the
sidecar. Direct calls bypassing APIM continue to work (if your network
permits them); to enforce no-bypass, restrict the MCP server's
inbound network rules to accept only the sidecar's egress IP.

### 4. Publish your verification material

External verifiers (regulators, auditors, partner organisations) need
to fetch your published material to verify receipts. Publish at the
URLs you configured in `verificationBaseUrl`:

```
https://acme.bank/.well-known/raucle-issuer.pub      # the issuer public key (PEM)
https://acme.bank/.well-known/raucle-policies/       # the policy registry (one file per policy_proof_hash)
https://acme.bank/raucle-proofs/                     # (optional) the Lean 4 development tree
```

The verifier-side walkthrough is in
[raucle.com /demo](https://raucle.com/demo/) — share that link with
your auditors.

### 5. Smoke-test

Send a tool call through Foundry and confirm a receipt lands in the
audit container:

```bash
# Trigger an MCP call from your Foundry agent — any normal user
# interaction with the agent will do.

# Then inspect the audit container:
az storage blob list \
  --account-name stacmefoundryaudit \
  --container-name raucle-audit \
  --output table

# Download and decode the most recent receipt:
az storage blob download \
  --account-name stacmefoundryaudit \
  --container-name raucle-audit \
  --name "$(az storage blob list --account-name stacmefoundryaudit \
              --container-name raucle-audit --query '[-1].name' -o tsv)" \
  --file /tmp/latest-receipt.json
cat /tmp/latest-receipt.json | jq .
```

You should see a fully-populated receipt with `decision: "ALLOW"`,
the signature, the `policy_proof_hash`, and the attenuation chain.

## Operational notes

- **Issuer key rotation.** Generate a new key with
  `raucle cap keygen`, push it to Key Vault under the same
  secret name, and bump the Container App revision. The sidecar
  picks up the new key on the next request. The previous receipts
  remain verifiable indefinitely under the old public key — publish
  rotated public keys alongside their valid-for timestamps.

- **Audit log durability.** The HashChainSink flushes every receipt
  to Blob Storage with a checkpoint every 1000 entries. A pod restart
  loses no more than the configured checkpoint window. For stronger
  guarantees, set `RAUCLE_AUDIT_CHECKPOINT_EVERY=1` (flush every
  receipt) at a small latency cost.

- **APIM cold-start.** APIM adds ~5-10ms on a warm path; the sidecar
  adds ~5ms more for the gate check + receipt emission. Plan for
  ~25-40ms total over a cold gateway (warm: ~15ms).

- **Composability with AGT.** If you also run the Microsoft Agent
  Governance Toolkit, register raucle as a Policy Decision Point via
  the proposed [AGT PDP contract](../../docs/proposals/agt-pdp-contract.md).
  Until that contract lands upstream, the sidecar and AGT compose
  independently: AGT's in-process policy engine runs at the agent
  framework layer; raucle's gate runs at the network/APIM layer.
  Receipts capture both.

## Status

This is the **M2 deliverable** for [`docs/proposals/foundry-mcp-gateway.md`](../../docs/proposals/foundry-mcp-gateway.md).
The APIM policy and Bicep template ship today; an end-to-end recorded
walkthrough lands in M4 alongside an opinionated sample MCP server.

For questions or to discuss a production deployment, email
`oss@raucle.com`.
