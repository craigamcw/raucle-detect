"""``raucle-aws-mcp`` — run the AWS Egress Gate as an MCP server, turnkey.

Three subcommands make a complete demo:

    # 1. one-time: an issuer keypair (the authority that mints capabilities)
    raucle-aws-mcp keygen --issuer acme.bank --key issuer.key.pem --pub issuer.pub.pem

    # 2. mint a capability scoped to exactly what the agent may do
    raucle-aws-mcp mint --issuer acme.bank --key issuer.key.pem \\
        --agent-id agent:kyc-prod --tool dynamodb.GetItem \\
        --constraints '{"allowed_values": {"TableName": ["customers"]}}' \\
        --token token.json

    # 3. serve it (AWS creds come from the environment, never from the agent)
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1 \\
        raucle-aws-mcp serve --token token.json --pub issuer.pub.pem

The host (e.g. Claude Desktop) launches ``serve`` with the AWS credentials in its
*process environment* — they live in the raucle server, never reach the model.
See docs/getting-started/08-aws-mcp.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from ..capability import Capability, CapabilityGate, CapabilityIssuer
from .aws_egress import AWSEgressGate
from .mcp_server import RaucleMCPServer


def _cmd_keygen(args: argparse.Namespace) -> int:
    issuer = CapabilityIssuer.generate(issuer=args.issuer)
    issuer.save_private_key(args.key)
    with open(args.pub, "w") as fh:
        fh.write(issuer.public_key_pem)
    print(f"issuer key -> {args.key} (0600)\nissuer public key -> {args.pub}")
    return 0


def _cmd_mint(args: argparse.Namespace) -> int:
    issuer = CapabilityIssuer.load_private_key(args.issuer, args.key)
    constraints = json.loads(args.constraints) if args.constraints else None
    token = issuer.mint(
        agent_id=args.agent_id,
        tool=args.tool,
        constraints=constraints,
        ttl_seconds=args.ttl,
    )
    token.save(args.token)
    print(f"capability token -> {args.token} (tool={args.tool}, ttl={args.ttl}s)")
    return 0


def build_server(
    *,
    token_path: str,
    pub_path: str,
    region: str | None,
    env: dict[str, str],
    receipts_path: str | None = None,
) -> RaucleMCPServer:
    """Construct the MCP server from a token, the issuer public key, and AWS
    credentials in *env*. Separated from ``main`` so it is unit-testable."""
    token = Capability.load(token_path)
    with open(pub_path) as fh:
        pub_pem = fh.read()

    access_key = env.get("AWS_ACCESS_KEY_ID")
    secret_key = env.get("AWS_SECRET_ACCESS_KEY")
    region = region or env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
    if not (access_key and secret_key and region):
        raise SystemExit(
            "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and a region "
            "(--region or AWS_REGION) are required"
        )

    gate = CapabilityGate(trusted_issuers={token.key_id: pub_pem})

    sink: Any | None = None
    if receipts_path:
        from ..audit import Ed25519Signer, HashChainSink

        sink = HashChainSink(receipts_path, signer=Ed25519Signer.generate())

    egress = AWSEgressGate(
        gate,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        session_token=env.get("AWS_SESSION_TOKEN"),
        sink=sink,
    )
    return RaucleMCPServer(egress, token_provider=lambda: token, agent_id=token.agent_id)


def _cmd_serve(args: argparse.Namespace) -> int:
    server = build_server(
        token_path=args.token,
        pub_path=args.pub,
        region=args.region,
        env=dict(os.environ),
        receipts_path=args.receipts,
    )
    print("raucle AWS egress MCP server ready (stdio)", file=sys.stderr)
    server.serve_stdio()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="raucle-aws-mcp",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_key = sub.add_parser("keygen", help="generate an issuer keypair")
    p_key.add_argument("--issuer", required=True)
    p_key.add_argument("--key", required=True, help="output path for the private key (0600)")
    p_key.add_argument("--pub", required=True, help="output path for the public key PEM")
    p_key.set_defaults(func=_cmd_keygen)

    p_mint = sub.add_parser("mint", help="mint a capability token")
    p_mint.add_argument("--issuer", required=True)
    p_mint.add_argument("--key", required=True, help="issuer private key path")
    p_mint.add_argument("--agent-id", required=True)
    p_mint.add_argument("--tool", required=True, help="e.g. dynamodb.GetItem, s3.GetObject")
    p_mint.add_argument("--constraints", help="JSON constraints object")
    p_mint.add_argument("--ttl", type=int, default=3600)
    p_mint.add_argument("--token", required=True, help="output path for the token JSON")
    p_mint.set_defaults(func=_cmd_mint)

    p_serve = sub.add_parser("serve", help="run the MCP server over stdio")
    p_serve.add_argument("--token", required=True, help="capability token JSON path")
    p_serve.add_argument("--pub", required=True, help="issuer public key PEM path")
    p_serve.add_argument("--region", help="AWS region (else AWS_REGION env)")
    p_serve.add_argument("--receipts", help="path to a hash-chained receipts log")
    p_serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
