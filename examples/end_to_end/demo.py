"""End-to-end demo: scan → proof → capability → tool exec → receipt → audit.

Runs one realistic agent interaction through every primitive raucle-detect
has shipped this year, and prints every hash and signature at every step so
the trust graph is visible.

Scenario: an agent receives a user message and tries to call a ``transfer_funds``
tool. The platform's guardrails:

1. **Scan** the user message for prompt injection (v0.3 / v0.7).
2. **Prove** the tool's policy is formally complete over its schema (v0.9).
3. **Mint** a capability token bound to the proof + this session (v0.10).
4. **Gate** the actual tool call against the token (v0.10).
5. **Sign** a verdict receipt covering the decision (v0.5).
6. **Chain** every record into a tamper-evident audit log (v0.4).

Run::

    pip install 'raucle-detect[compliance,proof]'
    python examples/end_to_end/demo.py

The script writes audit + receipts under ``./demo-output/``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from raucle_detect import Scanner
from raucle_detect.audit import AuditVerifier, Ed25519Signer, HashChainSink
from raucle_detect.capability import CapabilityGate, CapabilityIssuer
from raucle_detect.prove import JSONSchemaProver
from raucle_detect.verdicts import VerdictSigner

OUT = Path("demo-output")
OUT.mkdir(exist_ok=True)


def banner(title: str) -> None:
    print(f"\n\033[1m━━━ {title} ━━━\033[0m")


def show(label: str, value: str) -> None:
    print(f"  {label:18s} {value}")


# ---------------------------------------------------------------------------
# Setup: keys + audit chain
# ---------------------------------------------------------------------------

banner("0. Bootstrap")

audit_signer = Ed25519Signer.generate()
(OUT / "audit.pub.pem").write_bytes(audit_signer.public_key_pem())
sink = HashChainSink(OUT / "audit.jsonl", signer=audit_signer, checkpoint_every=10)
show("audit key", audit_signer.key_id())

verdict_signer = VerdictSigner.generate()
(OUT / "verdict.pub.pem").write_bytes(verdict_signer.public_key_pem())
show("verdict key", verdict_signer.key_id())

cap_issuer = CapabilityIssuer.generate(issuer="platform.example")
cap_issuer.save_private_key(OUT / "cap.key.pem")
(OUT / "cap.pub.pem").write_text(cap_issuer.public_key_pem)
show("cap issuer", cap_issuer.key_id)


# ---------------------------------------------------------------------------
# 1. Scan the user message
# ---------------------------------------------------------------------------

USER_MESSAGE = "Please transfer $50 to alice@example.com for last week's invoice."

banner("1. Scan user input")
scanner = Scanner(
    mode="standard",
    audit_sink=sink,
    verdict_signer=verdict_signer,
    model_version="demo-v1",
    tenant="acme-corp",
)
scan_result = scanner.scan(USER_MESSAGE)
show("verdict", scan_result.verdict)
show("confidence", f"{scan_result.confidence:.2%}")
show("receipt", scan_result.receipt[:80] + "...")

if scan_result.injection_detected:
    print("\n  \033[91mBLOCKED at scan stage.\033[0m")
    sys.exit(2)


# ---------------------------------------------------------------------------
# 2. Prove the tool policy is complete over the schema
# ---------------------------------------------------------------------------

banner("2. Formal verification of tool policy")

tool_schema = {
    "type": "object",
    "properties": {
        "to": {
            "type": "string",
            "enum": ["alice@example.com", "bob@example.com", "finance@example.com"],
        },
        "amount": {"type": "number", "minimum": 0, "maximum": 100},
        "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
    },
    "required": ["to", "amount", "currency"],
}
tool_policy = {
    "max_value": {"amount": 100},
    "forbidden_values": {"to": ["attacker@evil.example"]},
}

proof = JSONSchemaProver().prove(tool_schema, tool_policy)
show("prover", proof.prover)
show("status", proof.status)
show("grammar_hash", proof.grammar_hash)
show("policy_hash", proof.policy_hash)
show("proof_hash", proof.hash)

if proof.status == "REFUTED":
    print(f"  counterexample: {proof.counterexample}")
    print("\n  Policy is not complete over the schema. Refusing to mint a capability.")
    sys.exit(2)

sink.append({"kind": "proof", "proof": proof.to_dict()})


# ---------------------------------------------------------------------------
# 3. Mint a capability bound to the proof
# ---------------------------------------------------------------------------

banner("3. Mint capability token")
token = cap_issuer.mint(
    agent_id="agent:billing",
    tool="transfer_funds",
    constraints=tool_policy,
    ttl_seconds=300,
    policy_proof_hash=proof.hash,
)
token.save(OUT / "token.json")
show("token_id", token.token_id)
show("agent_id", token.agent_id)
show("tool", token.tool)
show("proof_hash", token.policy_proof_hash)
sink.append({"kind": "capability_mint", "token_id": token.token_id})


# ---------------------------------------------------------------------------
# 4. Agent constructs a call. Gate it.
# ---------------------------------------------------------------------------

banner("4. Gate two attempted tool calls")

gate = CapabilityGate(trusted_issuers={cap_issuer.key_id: cap_issuer.public_key_pem})

attempts = [
    ("legitimate", {"to": "alice@example.com", "amount": 50, "currency": "USD"}),
    ("over-bound", {"to": "alice@example.com", "amount": 5000, "currency": "USD"}),
    (
        "forbidden recipient",
        {"to": "attacker@evil.example", "amount": 10, "currency": "USD"},
    ),
]

for name, args in attempts:
    decision = gate.check(token, tool="transfer_funds", args=args)
    verdict = "\033[92mALLOW\033[0m" if decision.allowed else "\033[91mDENY\033[0m "
    print(f"  {verdict}  {name:22s} {decision.reason}")
    sink.append(
        {
            "kind": "capability_check",
            "token_id": token.token_id,
            "args": args,
            "allowed": decision.allowed,
            "reason": decision.reason,
        }
    )


# ---------------------------------------------------------------------------
# 5. Close the audit chain and verify
# ---------------------------------------------------------------------------

banner("5. Audit chain")
sink.close()

report = AuditVerifier(public_key_pem=audit_signer.public_key_pem()).verify_chain(
    OUT / "audit.jsonl"
)
show("events", str(report.event_count))
show("checkpoints", str(report.checkpoint_count))
show("valid_sigs", str(report.valid_signatures))
show("chain_ok", "\033[92myes\033[0m" if report.valid else "\033[91mno\033[0m")


# ---------------------------------------------------------------------------
# 6. The trust graph, restated
# ---------------------------------------------------------------------------

banner("6. Trust graph")
print(
    "\n  Receipt cites ruleset_hash; ruleset_hash includes feed contribution;\n"
    "  capability cites proof_hash; proof binds (grammar_hash, policy_hash);\n"
    "  every step is chained into one Merkle-rooted audit log signed once at close.\n"
)
print(
    f"  All artefacts in ./{OUT}/ — load + verify offline with:\n"
    f"    raucle-detect audit verify {OUT}/audit.jsonl --pubkey {OUT}/audit.pub.pem\n"
    f"    raucle-detect verify-receipt '<receipt>' --pubkey {OUT}/verdict.pub.pem\n"
    f"    raucle-detect cap verify {OUT}/token.json --pubkey {OUT}/cap.pub.pem\n"
)

print(
    json.dumps(
        {
            "scan_receipt": scan_result.receipt[:48] + "...",
            "proof_hash": proof.hash,
            "capability_token_id": token.token_id,
            "audit_events": report.event_count,
            "audit_valid": report.valid,
        },
        indent=2,
    )
)
