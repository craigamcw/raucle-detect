"""Credential-custody brokers: raucle holds the downstream credential and is the
sole signer + egress path, so an agent cannot act without a receipt.

Ships the AWS Egress Gate (DynamoDB ``GetItem``; S3 ``GetObject``/``PutObject``)
and an MCP server front-end so an MCP host reaches AWS only through the gate. See
docs/proposals/aws-egress-gate.md for the design and scope.
"""

from __future__ import annotations

from .aws_egress import AWSEgressGate, CapabilityDenied, EgressResult
from .mcp_server import RaucleMCPServer
from .sigv4 import SignedRequest, sign

__all__ = [
    "AWSEgressGate",
    "CapabilityDenied",
    "EgressResult",
    "RaucleMCPServer",
    "SignedRequest",
    "sign",
]
