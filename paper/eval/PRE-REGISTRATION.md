# Pre-registration — Verified Capability Discipline empirical evaluation

**Date frozen:** 2026-05-14
**Author:** Craig McWilliams
**Repository commit:** to be filled at commit time
**Paper target:** IEEE S&P 2027

This document fixes, *before any measurement run consumes the LLM API*, the methodology, hypotheses, and policies that the paper's §6 will report. Subsequent edits to the policy files require a separate commit explaining the change; the policy hashes below are the cryptographic anchor.

## Policy file hashes at registration

```
banking.json    sha256:4b78e6879aa6bad1d4907d6798d38b454766af9e82244d1e3a99286c1cd30148
slack.json      sha256:a06b03ba0ec06fd52c0a818243b610069dc5385ede4e76277b71b5921e7b3610
travel.json     sha256:0cdaf13b0d86f4b343f5cf9e1e1c881ad08c1250b4ad23f156a1ec45f0a85178
workspace.json  sha256:182674e52c4b807d917bb6395754d2e5c4ca76feebd43621a7dfa4e2e1149b7f
```

Any policy file used in the eval whose hash does not match one of these without a corresponding revision commit is invalid. The `paper/eval/verify_policies.py` runs the hash check before any measurement.

## Hypotheses

**H1 (primary).** Under VCD full-stack, the tool-call-mediated attack-success rate (ASR) on AgentDojo v1 across the four benchmark suites — banking, travel, slack, workspace — is at most 0.5%, against a no-defence ASR baseline of 30-60% measured on the same models in the same harness.

**H2 (utility).** Benign-task completion under VCD full-stack is at least 80% of the no-defence baseline measured on the same models. (Tighter formulations are not yet committed; we treat 80% as the floor below which we would consider the defence to have unacceptable utility cost.)

**H3 (latency).** Per-call gate overhead at p50 is below 1 ms on commodity x86_64 hardware (AMD EPYC or equivalent). Already measured pre-registration: 0.07 ms (`paper/eval/latency-x86.json`).

**H4 (composition).** VCD full-stack outperforms VCD text-only by at least 10 absolute ASR points on tool-call-mediated attacks. (The text-only configuration is the scanner; the full stack adds the capability gate.)

## Models

The evaluation will use one or more of:

- `claude-3-7-sonnet-20250219` — primary; the latest model in AgentDojo's default `ModelsEnum` registry.
- `gpt-4o-2024-05-13` — secondary cross-validation; only run if the primary results are surprising or budget allows.

The paper's abstract claim of "Claude Sonnet 4.6" requires either (a) lowering the abstract to whichever model is actually run, or (b) a local patch to AgentDojo's registry to add Sonnet 4.6 plus the corresponding `AnthropicLLM` wrapper. Decision deferred pending Anthropic credit response.

## Configurations evaluated

In the order they appear in the paper's headline table (§6.2):

| Tag | Label in paper | Source |
|---|---|---|
| `none` | None | AgentDojo `defense=None` |
| `spotlight` | Spotlighting | AgentDojo `defense="spotlighting_with_delimiting"` |
| `struq` | StruQ | Requires the released checkpoint; row is `[TBD]` unless time permits integration |
| `shields` | Prompt shields | AgentDojo `defense="transformers_pi_detector"` |
| `vcd_text` | VCD text-only | Custom pipeline: AgentDojo default pipeline + Raucle scanner pre-filter on every untrusted input |
| `vcd_full` | VCD full stack | Custom pipeline: AgentDojo default pipeline + `GatedToolsExecutor` |

Ablation rows:

| Tag | Label in paper | Description |
|---|---|---|
| `vcd_cap_only` | Capability gate only | `vcd_full` with the proof-binding check disabled (token issued without `policy_proof_hash`). |
| `vcd_proof_only` | SMT proof only | The proof verifies the policy is complete over the schema; constraints are checked at the tool-call boundary by a runtime function; no capability token is presented or required. |

## Benchmarks

**AgentDojo v1** — all four suites: workspace (40 user × 6 injection = 240 pairs), travel (140), banking (144), slack (105). Total: **629** attack-task pairs per defence configuration.

The benchmark's attack-success-rate metric is tool-call-mediated by construction (`SuiteResults.injection_tasks_utility_results[task_id][inj_id].security`). We report this metric directly; we do not report or claim defence efficacy against any attack outside this measurement.

**InjecAgent** — deferred pending adapter completion; if added, the headline table gets a second ASR column on the same defence configurations.

## Static verifier

`paper/eval/verify_policies.py` runs the gate's constraint-check logic on every `(user_task, injection_task)` pair without an LLM in the loop, against the injection task's canonical attack arguments. The static verifier returns the upper bound on attack-rejection: cells the verifier permits are cells the actual eval cannot do better on.

Current static verifier result (banking only, as of this registration):

```
SUMMARY: 144 / 144 banking attack attempts blocked (100.0%)
```

`slack.json`, `travel.json`, and `workspace.json` are scaffolds whose static verification is not yet at 100%; they are completed before the headline run.

## What this pre-registration commits us to

1. **No post-hoc policy modification.** Once a measurement run consumes API budget against a policy file, that policy file cannot be silently edited to improve the numbers. Any later edit is a separate registered commit.
2. **All measurement code paths run the verifier.** The `harness.py` will check policy hashes against this document before invoking the LLM. A hash mismatch aborts the run.
3. **Honest reporting of failures.** If `vcd_full` ASR comes out at 12% rather than the predicted ≤0.5%, the paper reports 12% with diagnostic discussion; the registration document remains and is cited as the prediction we missed.
4. **Negative results are reported.** Any attack class for which the policy is not authored (e.g., workspace `delete_file` against injection_task_1) is reported as such in §6.5 with a positive-acknowledgement of the limitation.

## What this pre-registration does NOT commit us to

- The exact spend cap or run duration. We adjust to what API credits allow.
- Adding a second model (Claude Sonnet 4.6, GPT-4o). These are stretch goals dependent on budget.
- A pilot deployment for §6.4. That section's content remains contingent on whether a real production user materialises before submission.

## How to verify this pre-registration in the future

```bash
# Re-hash the policy files
git checkout <registration commit SHA>
python -c "
import hashlib
from pathlib import Path
for f in sorted(Path('paper/eval/policies').glob('*.json')):
    print(f'{f.name:18s} sha256:{hashlib.sha256(f.read_bytes()).hexdigest()}')
"
# Compare to the table above. Re-run the static verifier:
python paper/eval/verify_policies.py paper/eval/policies/banking.json
```

The git history of `paper/eval/policies/` shows every edit since registration, with reasons in commit messages. The repository's `git log --follow paper/eval/PRE-REGISTRATION.md` shows the registration's own evolution.
