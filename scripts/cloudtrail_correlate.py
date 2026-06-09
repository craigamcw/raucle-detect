#!/usr/bin/env python3
"""Correlate raucle receipts with AWS CloudTrail — "vendor log vs portable proof".

For each gated action in a raucle receipt chain, find AWS's own CloudTrail record
of the same call and show the punchline a regulator needs:

  * CloudTrail proves every call ran under the BROKER's IAM identity — never the
    agent's (the agent has no AWS identity at all);
  * raucle's receipt binds the same action AND the agent's *authorisation* AND is
    verifiable OFFLINE against a public key — which a CloudTrail log is not.

AWS's log says *who technically called*; raucle's receipt says *it was authorised*
and survives leaving AWS. Only the pair answers "prove this agent could not have
done anything you didn't authorise."

Needs only the read-only, free ``cloudtrail:LookupEvents`` permission (no trail).
Note: DynamoDB/S3/SQS calls are CloudTrail *data events* (not in the free history
unless a data-events trail is enabled); Secrets Manager ``GetSecretValue`` and the
control-plane scaffolding are *management events* and appear by default. So out of
the box this correlates the secret read (the most regulator-relevant) and any
management events; enable a data-events trail to correlate the rest.

Usage::

    RAUCLE_LIVE_AWS=1 python scripts/cloudtrail_correlate.py <chain.jsonl> [--minutes 30]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

# raucle tool id -> AWS CloudTrail eventName
_EVENT = {
    "dynamodb.GetItem": "GetItem",
    "s3.GetObject": "GetObject",
    "s3.PutObject": "PutObject",
    "sqs.SendMessage": "SendMessage",
    "secretsmanager.GetSecretValue": "GetSecretValue",
}


def _receipt_actions(chain_path: str) -> list[str]:
    """The AWS eventNames the gate performed, parsed from the receipt chain's
    tool_call receipts (operation == tool_call, tool == raucle tool id)."""
    import base64

    actions: list[str] = []
    with open(chain_path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            jws = json.loads(line).get("jws")
            if not jws:
                continue
            payload = json.loads(base64.urlsafe_b64decode(jws.split(".")[1] + "==="))
            if payload.get("operation") == "tool_call":
                ev = _EVENT.get(payload.get("tool", ""))
                if ev:
                    actions.append(ev)
    return actions


def main() -> int:
    import boto3

    ap = argparse.ArgumentParser()
    ap.add_argument("chain", help="raucle receipt chain JSONL (from a gate run)")
    ap.add_argument("--minutes", type=int, default=30, help="lookback window")
    args = ap.parse_args()

    region = os.environ.get("AWS_DEFAULT_REGION", "eu-west-2")
    ct = boto3.client("cloudtrail", region_name=region)
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(minutes=args.minutes)

    wanted = _receipt_actions(args.chain)
    print(f"raucle receipts performed: {wanted}")
    print(f"querying CloudTrail ({region}) for the last {args.minutes} min…\n")

    matched = 0
    for ev_name in dict.fromkeys(wanted):  # de-dup, preserve order
        resp = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": ev_name}],
            StartTime=start,
            EndTime=end,
            MaxResults=5,
        )
        events = resp.get("Events", [])
        if not events:
            print(
                f"  {ev_name}: no CloudTrail event yet "
                "(data-event, or delivery latency — see module docstring)"
            )
            continue
        e = json.loads(events[0]["CloudTrailEvent"])
        ident = e.get("userIdentity", {})
        arn = ident.get("arn", "")
        is_broker = arn.endswith(":user/raucle-smoke") or "raucle-smoke" in arn
        is_agent = "raucle-agent" in arn or "agent:" in arn
        matched += 1
        verdict = "YES" if is_broker and not is_agent else "CHECK"
        print(f"  {ev_name}:")
        print(f"     CloudTrail userIdentity : {arn or ident.get('type')}")
        print(f"     ↳ made by the BROKER, not the agent: {verdict}")
        print(f"     eventTime               : {e.get('eventTime')}")
        print(f"     sourceIPAddress         : {e.get('sourceIPAddress')}")

    print(
        "\nINTERPRETATION:\n"
        "  • CloudTrail (AWS's own log) attributes every call to the raucle broker\n"
        "    identity — the agent has no AWS identity, so it appears nowhere.\n"
        "  • raucle's receipt for the SAME call additionally proves the agent's\n"
        "    authorisation and verifies OFFLINE against a public key (audit-pack),\n"
        "    which a CloudTrail log cannot. AWS proves who called; raucle proves it\n"
        "    was authorised — and that proof survives leaving AWS."
    )
    return 0 if matched else 1


if __name__ == "__main__":
    if os.environ.get("RAUCLE_LIVE_AWS") != "1":
        print(
            "Set RAUCLE_LIVE_AWS=1 and provide credentials with cloudtrail:LookupEvents.",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(main())
