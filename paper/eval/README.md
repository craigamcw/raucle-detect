# Evaluation harness — AgentDojo + InjecAgent

Scaffolding for the empirical work in `paper/DRAFT.md` §6.

This module is deliberately a scaffold, not a working integration. The two
benchmarks have specific install procedures, API surfaces, and dataset
licensing that have to be set up locally; this harness wires every
piece *around* that integration so all you have to do is fill in the two
adapter `TODO`s.

## What's here

| File | Purpose |
|---|---|
| `harness.py` | Orchestrates a run: iterates over `(benchmark, defence)` and emits `results.json`. |
| `configurations.py` | The six defence configurations and the two ablations. |
| `agentdojo_adapter.py` | Stub for AgentDojo — `def run(defence, model) -> Result`. Two `TODO`s. |
| `injecagent_adapter.py` | Stub for InjecAgent — same shape. |
| `defences.py` | Defence wrappers: None, Spotlighting, StruQ, prompt-shields, VCD text-only, VCD full stack. |
| `metrics.py` | ASR and benign-completion computations. |
| `update_draft.py` | Reads `results.json`, substitutes `[TBD]` markers in `paper/DRAFT.md`. |
| `bench_latency.py` | Microbenchmarks for §6.3 (gate path, proof cold/cached). |

## Setup (you run this)

```bash
# Benchmark dependencies
pip install agentdojo            # https://github.com/ethz-spylab/agentdojo
git clone https://github.com/uiuc-kang-lab/InjecAgent ./external/injecagent
pip install -e ./external/injecagent

# raucle-detect + the proof extra
pip install -e .[compliance,proof]

# Model API key (the harness reads from env)
export ANTHROPIC_API_KEY=sk-ant-...
# (or OPENAI_API_KEY / TOGETHER_API_KEY depending on `--model`)
```

## Running

```bash
# Full sweep — 8 configurations × 2 benchmarks. ~2-3 hours, ~$15-40 of API spend.
python -m paper.eval.harness \
    --models claude-sonnet-4-6 gpt-4o llama-3.1-70b \
    --output results.json

# Microbenchmarks — gate + proof latency. Local, ~30 seconds.
python -m paper.eval.bench_latency --output latency.json

# Patch the draft.
python -m paper.eval.update_draft results.json latency.json
```

## Pre-registration

To prevent reviewer accusations of post-hoc tuning, freeze the schema-policy
pairs *before* running the eval. The harness emits a `pre-registration.json`
on first invocation containing the constraint policies authored for every
AgentDojo/InjecAgent tool; commit that file to the repo before measurement
begins. Subsequent runs that load a different policy raise an error.

## What this scaffold deliberately does not do

It does not implement the AgentDojo or InjecAgent integration. Both benchmarks
have evolved several times in 2024-2026; using a frozen snapshot would risk
reviewer rejection on grounds of using a stale dataset. The two `TODO`s in
the adapters are where you bind to whatever the current upstream API looks like
at the time of measurement.

It also does not reimplement Spotlighting or StruQ. Both have reference
implementations from the original authors; we expect to vendor those.
