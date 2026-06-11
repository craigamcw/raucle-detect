"""Verifiable per-skill authorisation for Agent-to-Agent (A2A), end to end.

A2A lets agents discover and invoke each other's skills via an Agent Card, but
defines no **per-skill authorisation a third party can verify**: when agent A
asks agent B to run a skill, nothing in the protocol produces portable evidence
that A was authorised, or a verifiable record of the hand-off. This demo fills
that open slot with the Raucle ⇄ A2A binding — no change to A2A's wire format.

Scenario: an **orchestrator** agent (A) asks a **payments** agent (B) to run its
``transfer`` skill. B advertises that the skill requires a proven capability. A
emits a signed ``agent_handoff`` receipt, attaches it to the A2A Message, and
sends. B — and any third party, OFFLINE against A's published key — verifies the
hand-off authorises this skill on this agent, bound to the actual inbound input
and guarded against replay. Then five forged/unauthorised/replayed hand-offs are
shown to REJECT.

Run::

    pip install 'raucle[compliance]'
    python examples/a2a_handoff/demo.py

No network needed — the Agent Cards and Message are in-process dicts.
"""

from __future__ import annotations

import io
import sys

from raucle import a2a
from raucle.provenance import AgentIdentity, ProvenanceLogger

ISS = "https://acme.example/raucle"
FIXED_IAT = 1_700_000_000
CAP_HASH = "sha256:" + "ab" * 32  # a proven-policy/capability hash for `transfer`


def _card(identity: AgentIdentity, url: str, *, skills=None, skill_caps=None) -> dict:
    card = {
        "url": url,
        "skills": [{"id": s} for s in (skills or [])],
        "extensions": [a2a.agent_card_extension()],
        "metadata": a2a.card_metadata(
            iss=ISS,
            key_id=identity.key_id,
            public_key_b64=a2a.issuer_public_b64(identity.public_key_pem()),
            skill_capabilities=skill_caps,
        ),
    }
    return card


def main() -> int:
    print("=" * 72)
    print("raucle ⇄ A2A — verifiable per-skill authorisation")
    print("=" * 72)

    # B (payments) advertises a `transfer` skill that requires a capability.
    payments = AgentIdentity.generate(agent_id="agent:acme-payments")
    callee_card = _card(
        payments,
        "https://agents.acme.example/pay",
        skills=["transfer"],
        skill_caps={"transfer": CAP_HASH},
    )
    # A (orchestrator) is the caller; its Card publishes its issuer key.
    orch = AgentIdentity.generate(agent_id="agent:acme-orchestrator")
    caller_card = _card(orch, "https://agents.acme.example/orchestrator")
    # A's task root — the hand-off chains to it (agent_handoff is non-root).
    root_log = ProvenanceLogger(orch, sink_file=io.StringIO())
    root_id = root_log.record_user_input("user: transfer 100 to acct-9")

    skill_input = {"amount": 100, "to": "acct-9"}
    print("\n[B] payments Agent Card advertises:")
    print(f"    skill         : transfer  (requires capability {CAP_HASH[:18]}…)")
    print(f"    issuer key    : published in Card metadata under {a2a.RAUCLE_A2A_EXTENSION_URI}")

    # ── A invokes B.transfer — emit + attach a signed hand-off receipt ──
    print("\n[A] orchestrator → invoke transfer(amount=100, to=acct-9)")
    jws, receipt_id = a2a.emit_handoff(
        orch,
        iss=ISS,
        skill="transfer",
        target_url=callee_card["url"],
        skill_input=skill_input,
        parents=[root_id],
        issued_at=FIXED_IAT,
        capability_proof_hash=CAP_HASH,
    )
    message = a2a.attach_to_message(
        {"messageId": "msg-1", "role": "ROLE_USER", "parts": [skill_input]}, jws
    )
    print(f"    hand-off receipt : {receipt_id[:30]}…")
    print(f"    A2A Message.extensions : {message['extensions']}")

    # ── B (or any third party) verifies the hand-off OFFLINE, bound to the
    #    actual inbound input, with a replay guard. ──
    print("\n[B] verify the hand-off OFFLINE against A's published key…")
    seen: set[str] = set()
    verdict = a2a.verify_handoff(
        jws, caller_card, callee_card, expected_input=skill_input, seen_receipt_ids=seen
    )
    print("    signature + header + canonical + operation + target + skill + capability + input")
    print(f"    RESULT: {'AUTHORISED' if verdict.ok else 'REJECTED'} (skill={verdict.skill})")
    if not verdict.ok:
        return 1

    # ── The same verifier REJECTS forged / unauthorised / replayed hand-offs ──
    print("\n[!] the same offline check rejects bad hand-offs:")

    def _emit(identity, **kw):
        kw.setdefault("iss", ISS)
        kw.setdefault("target_url", callee_card["url"])
        kw.setdefault("skill_input", skill_input)
        kw.setdefault("parents", [root_id])
        kw.setdefault("issued_at", FIXED_IAT)
        return a2a.emit_handoff(identity, **kw)[0]

    evil = AgentIdentity.generate(agent_id="agent:attacker")
    cases = [
        (
            "skill not advertised",
            lambda: a2a.verify_handoff(
                _emit(orch, skill="drain_account", capability_proof_hash=CAP_HASH),
                caller_card,
                callee_card,
                expected_input=skill_input,
            ),
        ),
        (
            "capability not cited",
            lambda: a2a.verify_handoff(
                _emit(orch, skill="transfer"), caller_card, callee_card, expected_input=skill_input
            ),
        ),
        (
            "signed by a key not in A's Card",
            lambda: a2a.verify_handoff(
                _emit(evil, skill="transfer", capability_proof_hash=CAP_HASH),
                caller_card,
                callee_card,
                expected_input=skill_input,
            ),
        ),
        (
            "input substituted (receipt bound to other input)",
            lambda: a2a.verify_handoff(
                jws, caller_card, callee_card, expected_input={"amount": 999999, "to": "attacker"}
            ),
        ),
        (
            "replay of an already-seen receipt",
            lambda: a2a.verify_handoff(
                jws, caller_card, callee_card, expected_input=skill_input, seen_receipt_ids=seen
            ),
        ),
    ]
    all_rejected = True
    for label, check in cases:
        v = check()
        all_rejected &= not v.ok
        print(f"    {'✗ REJECTED' if not v.ok else '✓ ACCEPTED (BUG)'} — {label}")
    if not all_rejected:
        print("    AUTHZ BROKEN: an unauthorised hand-off verified")
        return 1

    print("\n" + "-" * 72)
    print("A2A has no per-skill authorisation slot a third party can verify. This")
    print("hand-off is portable evidence any party checks offline against a pinned")
    print("key — exactly what a regulator examining a multi-agent workflow needs,")
    print("and what a single-vendor guardrail or an unsigned RPC cannot provide.")
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
