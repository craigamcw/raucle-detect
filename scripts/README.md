# scripts

## `live_aws_smoke.py` — live-AWS validation of the egress gate (opt-in)

Proves the AWS Egress Gate's **from-scratch SigV4 works on the wire against real
AWS** — across every supported surface (DynamoDB `GetItem`, S3 `GetObject`/
`PutObject`, SQS `SendMessage`, Secrets Manager `GetSecretValue`) — and that the
resulting receipt chain builds an `audit-pack` that verifies offline. The unit
tests prove byte-correctness against AWS known-answer vectors; this proves the
end-to-end HTTP path that KATs can't.

It is **gated behind `RAUCLE_LIVE_AWS=1`** so it can never run by accident or in
CI. `boto3` scaffolds throwaway `<prefix>-*` resources; the **raucle gate** makes
the actual gated calls; everything is deleted in a `finally`. Cost is pennies
(Free-Tier eligible).

```bash
pip install boto3
export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...  AWS_DEFAULT_REGION=eu-west-2
RAUCLE_LIVE_AWS=1 python scripts/live_aws_smoke.py
```

### Use a least-privilege IAM user — never root

Create a dedicated IAM user whose access is scoped to only `raucle-smoke-*`
resources, so the credentials can touch nothing else in the account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "Dynamo", "Effect": "Allow",
      "Action": ["dynamodb:CreateTable","dynamodb:DeleteTable","dynamodb:DescribeTable","dynamodb:PutItem","dynamodb:GetItem"],
      "Resource": "arn:aws:dynamodb:*:*:table/raucle-smoke-*" },
    { "Sid": "S3", "Effect": "Allow",
      "Action": ["s3:CreateBucket","s3:DeleteBucket","s3:PutObject","s3:GetObject","s3:DeleteObject","s3:ListBucket"],
      "Resource": ["arn:aws:s3:::raucle-smoke-*","arn:aws:s3:::raucle-smoke-*/*"] },
    { "Sid": "SQS", "Effect": "Allow",
      "Action": ["sqs:CreateQueue","sqs:DeleteQueue","sqs:SendMessage","sqs:GetQueueUrl","sqs:GetQueueAttributes"],
      "Resource": "arn:aws:sqs:*:*:raucle-smoke-*" },
    { "Sid": "Secrets", "Effect": "Allow",
      "Action": ["secretsmanager:CreateSecret","secretsmanager:DeleteSecret","secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:*:*:secret:raucle-smoke-*" }
  ]
}
```

Validated against real AWS in `eu-west-2` on 2026-06-09 — all surfaces green, the
gate's DENY blocked an unauthorised call before it reached AWS, and an audit-pack
built from the real receipt chain verified offline against the pinned custodian
key. Delete the access key when you're done.
