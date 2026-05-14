# Run plan — from smoke-tested adapter to paper-grade results

Status as of 2026-05-14: the AgentDojo adapter is wired against upstream 0.1.35, smoke-tested end-to-end on the VM, and confirmed to reproduce the paper's 629 attack-task count. The capability gate correctly allows legitimate calls and denies attacks when spliced into AgentDojo's pipeline.

What follows is the exact command sequence to take this from "smoke passes" to "every `[TBD]` in §6.2 of the paper is filled in".

## Prerequisites

On the VM (`/root/raucle-paper/raucle-detect`):

```bash
source .venv/bin/activate

# The transformers PI detector baseline needs torch + transformers.
pip install -q transformers torch  # ~2 GB

# StruQ requires the released fine-tuned checkpoint. As of 2026-05-14 this is
# hosted at https://huggingface.co/llm-attacks/StruQ-llama-3-8b — clone or
# leave the row blank in the paper with a footnote.

# API key for the LLM. Pick ONE:
export ANTHROPIC_API_KEY=sk-ant-...    # for claude-3-7-sonnet
export OPENAI_API_KEY=sk-...           # for gpt-4o
# Set spending caps on the provider dashboard *before* running.
```

## Budget guidance

Rough costs at current provider pricing (May 2026):

| Run | Tasks | Model | API spend |
|---|---|---|---|
| Smoke (1 suite, 5 user × 1 inj = 5 pairs) | 5 | Claude 3.7 | ~$0.10 |
| One suite × one configuration | ~140 | Claude 3.7 | ~$3 |
| All 4 suites × one configuration | 629 | Claude 3.7 | ~$15 |
| Full headline matrix (4 suites × 5 configurations) | ~3,150 | Claude 3.7 | ~$75 |
| Ablation matrix (4 suites × 2 ablation rows) | ~1,260 | Claude 3.7 | ~$30 |
| Cross-model sanity (full matrix × Claude + GPT) | ~6,300 | both | ~$150 |

Recommended sequence: smoke → one suite × all configurations (~$20 to validate the methodology) → full sweep on the primary model (~$75) → cross-model only if reviewers ask.

## Sequence

### 1. Pre-flight smoke

Confirms the adapter still imports cleanly and the gate is wired:

```bash
PYTHONPATH=. python paper/eval/smoke.py
```

Expected: prints suite counts (totalling 629), shows 4 of 5 pipeline configurations constructing cleanly (or 5 of 5 after `pip install transformers torch`), and reports the gate allowing 1 and denying 2 of 3 canned tool calls.

### 2. Pre-register tool policies

Before any real run, author `paper/eval/policies.json` with the per-tool constraint policies for every tool in the four AgentDojo suites. Commit this file before measurement starts; the harness will refuse to run with an empty policy file.

A reasonable starting point: for tools that take an `amount`, `recipient`, `email`, or similar attacker-controllable field, replicate the example policy in `smoke.py` (forbid known-attacker recipients, cap numeric fields, restrict enum fields). Audit the per-tool ground-truth tasks in AgentDojo's source to identify what legitimate use looks like.

### 3. Tiny end-to-end run with API spend

Smallest possible real-run sanity check: one suite, one configuration, five tasks:

```bash
PYTHONPATH=. python -c "
from paper.eval.agentdojo_adapter import run
from pathlib import Path
import logging
logging.basicConfig(level=logging.INFO)

results = run(
    defence='none',
    model='claude-3-7-sonnet-20250219',
    suites=['banking'],
    user_tasks=[f'user_task_{i}' for i in range(5)],
    logdir=Path('runs/smoke'),
)
for s in results:
    print(f'{s.suite}: ASR={100*s.asr:.1f}%  benign={100*s.benign_completion:.1f}%  n={s.total_tasks}')
"
```

Expected: ~5 minutes wall, ~$0.10 spend, prints a real ASR percentage. If the number is implausibly high (>80%) or implausibly low (0%), something is wrong before scaling up.

### 4. One-suite × all-configurations validation

```bash
for d in none spotlight shields vcd_text vcd_full vcd_cap_only vcd_proof_only; do
    PYTHONPATH=. python -c "
from paper.eval.agentdojo_adapter import run
results = run(defence='$d', model='claude-3-7-sonnet-20250219', suites=['banking'])
for s in results:
    print(f'$d/banking: ASR={100*s.asr:.1f}%  benign={100*s.benign_completion:.1f}%  n={s.total_tasks}')
"
done
```

Expected: ~$20 spend, ~3 hours wall, prints 7 lines. The `vcd_full` and `vcd_cap_only` rows should show ASR substantially below the `none` baseline; if not, the gate or the policies need work.

### 5. Full headline matrix

Only run after step 4 looks right:

```bash
PYTHONPATH=. python -m paper.eval.harness \
    --models claude-3-7-sonnet-20250219 \
    --output paper/eval/results.json
```

~12-15 hours wall (single-threaded; AgentDojo doesn't parallelise within a suite); ~$75-100 spend.

### 6. Patch the draft

```bash
PYTHONPATH=. python -m paper.eval.update_draft \
    paper/eval/results.json \
    paper/eval/latency-x86.json
```

This substitutes every measured `[TBD]` marker in `paper/DRAFT.md`. Remaining markers belong to §6.4 (case study) and the cross-benchmark fraction sentences; both stay manual.

## Caveats and known limitations

1. **AgentDojo's latest registered model is Claude 3.7 Sonnet (Feb 2025).** The paper's abstract claims "Claude Sonnet 4.6"; you have three options:
   - Lower the abstract claim to Claude 3.7 Sonnet (honest, simpler).
   - Add Sonnet 4.6 to AgentDojo's `ModelsEnum` via a small local patch and document it in §5 of the paper.
   - Upstream the patch to the AgentDojo repo.
2. **InjecAgent integration is not yet wired.** The companion `injecagent_adapter.py` is still a stub. AgentDojo and InjecAgent share design assumptions but have different APIs; expect ~1 day of similar work.
3. **StruQ row.** Either get the released checkpoint working as a custom `LocalLLM` (1-2 days), or drop the row with a footnote pointing reviewers to the StruQ paper's published numbers.
4. **Per-tool policies are load-bearing.** If `policies.json` over-tightens, benign completion drops; if it under-tightens, attacks succeed. A whole afternoon of careful authoring against AgentDojo's ground-truth traces is the right investment.

## What to publish after the run

- `paper/eval/results.json` — raw measurements, committed.
- `paper/eval/policies.json` — committed pre-registration.
- `paper/eval/latency-x86.json` — already in tree.
- Per-task traces from `runs/` — kept locally; sample a representative subset for the supplementary materials.
