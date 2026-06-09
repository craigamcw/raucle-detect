"""Credential-custody brokers: raucle holds the downstream credential and is the
sole signer + egress path, so an agent cannot act without a receipt.

v1 ships the AWS Egress Gate (DynamoDB ``GetItem``). See
docs/proposals/aws-egress-gate.md for the design and scope.
"""

from __future__ import annotations

from .aws_egress import AWSEgressGate, CapabilityDenied, EgressResult
from .sigv4 import SignedRequest, sign

__all__ = [
    "AWSEgressGate",
    "CapabilityDenied",
    "EgressResult",
    "SignedRequest",
    "sign",
]
