# Reproducibility — paper §6 empirical eval

These are the actual scripts used to produce every number in §6. They ran on a 23 GB / 12-core Linux VM via Ollama Cloud's OpenAI-compatible endpoint for LLM inference. The harness is `paper/eval/agentdojo_adapter.py` with `paper/eval/agentdojo_patches.py` registering the `ollama` provider.

## Environment

- Python 3.12, the repository's `.venv` (see `pyproject.toml` for pins).
- `OLLAMA_API_KEY` exported in the shell (we sourced it from a `.secrets/ollama.env` file).
- `RAUCLE_PARALLEL` env var sets per-cell worker count (default 1, recommended 8, drop to 1–2 for shields cells on memory-constrained hardware).
- `PYTHONPATH=.` from the repository root.

## Track layout

Each script writes per-cell results to `runs/<suite>-<modelshort>-<defence>/aggregate.json` (or `<suite>-<modelshort>-<attack>-<defence>` for attack-family tracks). Every script is idempotent — re-running re-uses the per-task JSONs AgentDojo writes under `<logdir>/<model>/<suite>/...`, so a crashed cell can be resumed without losing earlier work.

| Script | What it runs | Cells | Wall time (approx) |
|---|---|---|---|
| `track_d_v3.2.py` | deepseek-v3.2 banking × 6 defences | 6 | ~7h |
| `track_e_v4pro.py` | deepseek-v4-pro banking × 6 defences | 6 | ~5.5h |
| `track_f_crosssuite.py` | v4-flash × {none, shields, vcd_full} × {slack, travel, workspace} | 9 | (OOMed mid-run; superseded by `track_f_restart.py`) |
| `track_f_restart.py` | v4-flash cross-suite, per-cell subprocess isolation, shields cells at parallel=2 | 5 | ~5h |
| `track_h_attacks.py` | v4-flash banking × {none, shields, vcd_full} × {direct, ignore_previous} | 6 | ~13h |
| `track_klm.py` | v4-pro + v3.2 cross-suite × {none, vcd_full} + v4-flash banking × {spotlight, vcd_text, vcd_cap_only} × {direct, ignore_previous} | 18 | ~14h |

## Chaining queue

`weekend_queue.sh` shows the pattern we used: each track detached with `setsid nohup ... < /dev/null &`, the next launched only after the prior PID exits. This survives SSH disconnects and keeps the 10-connection Ollama Cloud cap saturated without overruns.

## Known incompatibilities

- AgentDojo 0.1.35's `transformers_pi_detector` (prompt-shields) integration raises `KeyError: 'www.our-company.com'` on the slack suite. We report the cell as benchmark-incompatible in §6.2.3 rather than retry it; the failure is in the shields code path, not in the harness.
- Shields on workspace at `RAUCLE_PARALLEL=2` OOMed at 21 GB RSS on our 23 GB VM. Dropping to `RAUCLE_PARALLEL=1` (one worker, DeBERTa loaded once) lands the cell in ~2.5h. Other defences are not memory-bound at parallel=8.

## Per-cell sample count

| Suite | User × injection pairs |
|---|---|
| banking | 144 (16 user_tasks × 9 injection_tasks) |
| slack | 105 (15 × 7) |
| travel | 140 (20 × 7) |
| workspace | 240 (40 × 6) |

A "cell" in the paper's tables is one of these grid totals.
