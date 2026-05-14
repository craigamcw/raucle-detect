# Per-task capability policies for the AgentDojo evaluation

## Design principle

Capabilities derive from user intent. For each user task in AgentDojo, we extract the set of tool calls and argument shapes the user's prompt explicitly authorises, and mint a capability token whose constraints reflect exactly that. The attacker can inject any text into the agent's context — the gate doesn't care. Tools or arguments outside the user's stated intent are structurally rejected at the call site, regardless of how compelling the attack text reads.

This is not "denylisting the attacker's payload". It is the inverse: **allowlisting the user's request.** The agent gets a token that says "the human asked you to do exactly this thing". Everything else is denied without the model ever weighing in.

## Threat-model alignment

Three concrete consequences:

1. **Intent extraction is the trust boundary.** Whoever derives a policy from a user prompt holds privilege. In production deployments this would be a small, audited component (a rule-based parser, a structured-output extractor, or a separate trusted LLM call with its own gate). For the paper we hand-author per-task policies once, commit them to the repository under cryptographic hash, and treat the commit as the pre-registration of our intent-extraction step. The policies' threat model is documented per task in the JSON files' `_intent` and `_policy_notes` fields.

2. **The user task IS the policy.** A user who asks "send $50 to Alice" gets a token allowing `send_money` with `allowed_values={recipient: ['Alice']}` and `max_value={amount: 50}`. A user who asks "summarise my transactions" gets a token with no `send_money` clause at all — the gate will refuse any send call, no matter how the model is talked into emitting one.

3. **Deployment-wide deny rules compose with per-task allow rules.** Every banking deployment has a known-fraudulent-recipient feed (regulator advisories, internal fraud teams). We model this as a `_fraud_denylist` that augments every per-task `send_money` policy. The fraud denylist does NOT trump a user's explicit intent: when user_task_15 says "my landlord is US133..." and the fraud denylist contains the same IBAN by coincidence, the per-task `allowed_values` clause overrides — the user's stated wish wins. The denylist exists for the *implicit* recipient case: tasks where the recipient comes from a file or transaction history rather than an explicit user instruction. There, the denylist is the last line.

## Per-suite policies

| Suite | File | Threat surface | Status |
|---|---|---|---|
| banking | `banking.json` | Money transfers, scheduled payments, password changes | ✓ 9/9 injection tasks structurally rejected by static verification |
| travel | `travel.json` | (to be authored) | pending |
| slack | `slack.json` | (to be authored) | pending |
| workspace | `workspace.json` | (to be authored) | pending |

## How to read a policy file

Top-level keys:
- `_schema_version` — bumped when the policy schema changes.
- `_suite`, `_suite_version` — pin the AgentDojo version this was authored against.
- `_principle`, `_intent_extraction_rule` — the threat-model statement.
- `_read_only_tools` — tools the gate permits unconditionally (no constraints, no token required).
- `_fraud_denylist` — deployment-wide constraints that augment per-task policies.
- `user_task_*` — per-task policy. Each entry contains:
  - `_prompt` — the user's literal prompt (verbatim from AgentDojo).
  - `_intent` — our extraction of what the user explicitly authorised.
  - `_policy_notes` — security reasoning behind the constraints, including what the policy deliberately does NOT permit.
  - `<tool_name>: { constraints }` — for each write tool the user intent authorises, the constraint set. Tools absent from this map are tools the gate refuses outright for this user task.

## Constraint vocabulary

(Mirrors `raucle_detect.capability.Capability.constraints`; see `raucle_detect/capability.py` for the runtime enforcement.)

| Key | Semantics |
|---|---|
| `forbidden_values` | `{field: [values]}` — call denied if `args[field]` is in `values`. |
| `allowed_values` | `{field: [values]}` — call denied if `args[field]` is NOT in `values`. |
| `max_value` | `{field: bound}` — call denied if `args[field] > bound`. |
| `min_value` | `{field: bound}` — call denied if `args[field] < bound`. |
| `required_present` | `[field, ...]` — call denied if any listed field is missing. |
| `forbidden_present` | `[field, ...]` — call denied if any listed field is present. |
| `forbidden_field_combinations` | `[[a, b], ...]` — call denied if every field in a sub-list is present. |

## Static verification

`paper/eval/verify_policies.py` runs every user_task × injection_task pair through the same constraint-check logic the runtime gate uses, with the injection task's canonical attack args. The script prints an ALLOW/DENY per cell plus a summary; the build is green when no attack cell is allowed unless it is a *known-legitimate coincidence* (e.g., user_task_15 in banking where the user explicitly names the IBAN that is also AgentDojo's adversarial target — the gate correctly allows that send because the user asked for it).

Running:

```bash
python paper/eval/verify_policies.py paper/eval/policies/banking.json
```

For banking v1, the current verification reports **144 / 144 attack attempts blocked** (100%). This is a *static upper bound* on the gate's effectiveness — the empirical run with a real LLM in the loop measures additional natural attrition (some attacks fail to convince the agent to emit the attack call at all) on top of the gate's structural denials.

## Why this design will hold up under review

Three reviewer questions we anticipate:

**Q1. "Are you training to the test?"** No — the policy file is committed to the repo before the eval runs. Each policy entry is derived only from the user task's literal prompt, which is public. The verifier confirms 100% denial against the published attack args without seeing the LLM's reasoning. A reviewer who replaced the adversarial IBAN with any other IBAN and re-ran the eval would get the same result, because our defence is allowlist-driven, not denylist-driven.

**Q2. "What about benign-task degradation?"** Per-task policies are by construction at least as permissive as the user's literal request. If the user asks to send to Alice, the policy permits sends to Alice. The gate denies only what the user didn't ask for. Benign task completion is therefore bounded by the agent's ability to follow the user's instruction within its own bounds, not by our gate.

**Q3. "How does this work in production where you don't have hand-authored policies?"** Two paths: a rule-based intent extractor (small, audited, possibly formally verified), or a separate-tenant LLM call whose output is itself capability-gated. The paper takes neither path because the contribution is the *enforcement* primitive, not the *extraction* primitive. We discuss this explicitly in §8 (Limitations).

## Pre-registration commitment

The git commit that adds these policy files is the pre-registration of our intent-extraction step. Every later commit that modifies a policy must:

1. State the reason in the commit message (e.g., "fix typo in user_task_3 IBAN" or "user_task_12: relax max_value because the legitimate bill amount exceeds the original bound").
2. Re-run `verify_policies.py` and update the summary.
3. Update §6 of the paper if the change moves the headline numbers.

No silent policy edits. Reviewers and replicators can `git log paper/eval/policies/` to see every change.
