# raucle as a Policy Decision Point for NemoClaw's OpenShell

**Status:** Draft proposal, 2026-06-12. **Deliberately doc-only** — NemoClaw is
alpha (GTC, March 2026) and its policy/extension interfaces are not yet stable;
we will not pin code to a moving target.
**Authors:** Raucle.
**Target:** design input to the NemoClaw/OpenShell project; raucle-detect side
ships independently of it (the [OpenClaw plugin](../../README.md) and
[SIEM export](../getting-started/08-siem-and-live-view.md) work today).
**Companion:** [Securing OpenClaw / NemoClaw deployments](../getting-started/09-openclaw-nemoclaw.md),
[`agt-pdp-contract.md`](./agt-pdp-contract.md) (the same PDP pattern, proposed
to Microsoft AGT).

## Summary

NVIDIA's NemoClaw wraps OpenClaw in **OpenShell** — a sandbox runtime that
isolates network/filesystem and interposes an **approve / deny** flow on
external access (TUI session approvals; permanent allowlisting via
`nemoclaw <agent> policy-add`). By its own documentation it gates at the
**host:port / binary** level, keeps **no signed audit record** of approvals,
and acknowledges that *"no sandbox offers complete protection against advanced
prompt injection."*

This proposal specifies the small contract under which OpenShell could
delegate (or subordinate) decisions to an external **Policy Decision Point**
(PDP) — and proposes raucle as the reference PDP, contributing the two things
the OpenShell flow lacks:

1. **Argument-level, structurally injection-proof tool-call decisions** —
   Ed25519-signed capability constraints evaluated by a gate that never reads
   the model's reasoning, with an SMT-verified subset.
2. **A signed, offline-verifiable record of every approve/deny** — including
   the human session-approvals OpenShell currently keeps only ephemerally.

## The contract (proposed)

Three integration points, smallest first. Each is independently useful; none
requires the others.

### P1 — Decision events out (works today, no OpenShell change)

OpenShell emits one JSON line per approval decision (allow/deny, host, port,
initiating binary, session, timestamp) to a file or unix socket. raucle's
[`SIEMSink`](../../raucle_detect/siem.py)-style consumer wraps each event into
the **signed hash chain**, giving NemoClaw deployments a tamper-evident,
third-party-verifiable record of what the operator approved and when — the
forensic artefact the TUI flow does not produce.

*Ask of OpenShell:* a `--decision-log <path>` flag (or documented log format).
That is the entire P1 surface.

### P2 — PDP consultation hook (the real bridge)

Before OpenShell prompts the operator, it consults a local PDP over a unix
socket with a minimal request:

```json
{"v": 1, "kind": "egress", "agent": "<agent-id>", "host": "api.example",
 "port": 443, "binary": "/usr/bin/node", "session": "<id>"}
```

The PDP answers one of three ways, each accompanied by a **signed receipt**:

| Answer | Meaning | OpenShell behaviour |
|---|---|---|
| `ALLOW` (+ receipt) | An in-force capability token authorises this | proceed, no human prompt |
| `DENY` (+ receipt, reason) | The token forbids it (e.g. injected exfil attempt) | block, surface raucle's signed reason in the TUI |
| `ABSTAIN` | No applicable token | fall back to today's human approve/deny |

Fail-closed composition: PDP unreachable ⇒ `ABSTAIN` (OpenShell's existing
flow), never implicit allow. The PDP can only *narrow* what OpenShell would
permit — it cannot grant access OpenShell's own policy denies.

### P3 — Capability-token-scoped sessions (future)

`nemoclaw <agent> policy-add` today produces a permanent allowlist entry. P3
replaces "permanent" with a **raucle capability token**: scoped to tool/host
patterns, time-boxed (TTL), attenuable (a sub-agent gets a narrower child
token), and revocable — with the mint and every use receipted. This is the
piece that turns NemoClaw's allowlist into auditable, expiring, least-privilege
grants. It depends on P2 and on NemoClaw's interfaces stabilising.

## Why raucle is the right PDP

- **Local-first, like NemoClaw**: zero-dependency core, no telemetry, runs on
  the same host. Adding the PDP does not reintroduce a cloud dependency.
- **Complementary, not overlapping**: OpenShell enforces the OS/network
  boundary; raucle decides at the tool-call/argument level and produces
  evidence. Neither replaces the other (see the
  [deployment guide](../getting-started/09-openclaw-nemoclaw.md)).
- **Standards-aligned**: decisions map to the published
  [cap:v1 token profile](../../standards/owasp-ai-exchange/01-capability-token.md)
  and Provenance Receipt v1 spec — five reference implementations, so an
  OpenShell written in Go/Rust can verify receipts natively.

## Honest boundaries

- This is a **proposal**, not a shipped integration. Nothing here implies
  NVIDIA endorsement; "NemoClaw" and "OpenShell" are NVIDIA's projects.
- P2/P3 require changes on the OpenShell side that only its maintainers can
  make; P1 needs only a documented decision-log format.
- raucle does not sandbox processes or filter egress itself; with the PDP
  unreachable, OpenShell's behaviour is exactly what it is today.

## Next steps

1. Track NemoClaw's interface stabilisation (alpha → beta) before writing code.
2. Raise P1 (`--decision-log`) as a discussion/issue upstream — smallest ask,
   immediately useful to any SIEM consumer, not raucle-specific.
3. Prototype the P2 socket protocol behind a feature flag in raucle once a
   stable hook exists; receipts and the gate already work unchanged.
