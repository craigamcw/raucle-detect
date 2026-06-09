# Give an agent AWS access it can't misuse — and prove every call

`raucle-aws-mcp` runs the AWS Egress Gate as an MCP server. Your agent (Claude
Desktop, Cursor, any MCP host) calls AWS through it; raucle holds the AWS
credentials, signs each allowed request, and emits a signed receipt. **The agent
never holds an AWS credential** — so it can only do what its capability allows,
and every call it makes has an offline-verifiable receipt. No receipt, no action.

This is the credential-custody model in [`docs/proposals/aws-egress-gate.md`](../proposals/aws-egress-gate.md):
the enforcement boundary is the *credential*, not the protocol.

## 1. Generate an issuer key (once)

The issuer is the authority that mints capabilities.

```bash
raucle-aws-mcp keygen --issuer acme.bank --key issuer.key.pem --pub issuer.pub.pem
```

## 2. Mint a capability scoped to exactly what the agent may do

```bash
raucle-aws-mcp mint \
  --issuer acme.bank --key issuer.key.pem \
  --agent-id agent:kyc-prod \
  --tool dynamodb.GetItem \
  --constraints '{"allowed_values": {"TableName": ["customers"]}}' \
  --token token.json
```

Mint one token per tool the agent needs (`dynamodb.GetItem`, `s3.GetObject`,
`s3.PutObject`). Constraints are the same capability model as the rest of
raucle — e.g. `{"max_value": {"ContentLength": 1048576}}` caps an S3 upload size.

## 3. Point your MCP host at it

The host launches `serve` with the AWS credentials in its **process environment**.
The credentials live in the raucle server process; the model never sees them.

Claude Desktop (`claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    "raucle-aws": {
      "command": "raucle-aws-mcp",
      "args": ["serve", "--token", "/abs/path/token.json",
               "--pub", "/abs/path/issuer.pub.pem",
               "--receipts", "/abs/path/receipts.log"],
      "env": {
        "AWS_ACCESS_KEY_ID": "AKIA...",
        "AWS_SECRET_ACCESS_KEY": "...",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

The agent now sees three tools (`aws.dynamodb.get_item`, `aws.s3.get_object`,
`aws.s3.put_object`). A call outside the capability is refused at the gate and
returned to the model as a tool error — it never reaches AWS.

## What you can hand an auditor

With `--receipts`, every call appends a hash-chained, Ed25519-signed receipt
binding the exact AWS request (method, host, path, region, and a SHA-256 of the
canonical signed request) to the gate decision. A third party can verify the
chain offline, with no contact with you or AWS.

## Custody depends on the deployment

This server enforces the credential half: it never returns AWS credentials or the
`Authorization` header to the agent. The egress half is yours: the agent's runtime
must have **no** AWS credentials of its own and **no** direct AWS route — only the
raucle server should reach AWS. Then "no receipt, no action" holds.

## Scope

v1 covers DynamoDB `GetItem` and fixed-body S3 `GetObject`/`PutObject`.
Streaming, presigned URLs, and multipart are not yet supported.
