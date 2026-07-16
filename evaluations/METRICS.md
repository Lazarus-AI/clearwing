# Eval Metrics — Proposed Additions

## Wanted
- `tokens_used` — total input + output tokens across all hunters
- `duration_seconds` — wall-clock time for the full hunt
- `steps_taken` — total agent steps across all hunters

## What exists today

`SourceHuntResult` already has `tokens_used` and `duration_seconds`; the native
evaluation harness writes both into each result's `metrics` object.

`NativeHunter.arun()` tracks `step` internally and logs it, but doesn't return it in
`HunterRunResult`. `HunterPool` accumulates `cost_usd` per tier but not steps.

## Changes needed

### `clearwing/sourcehunt/hunter.py`
- Add `steps_taken: int = 0` to `HunterRunResult`
- Set it at both return sites in `arun()`: `step - 1` (early exit), `step` (completed)

### `clearwing/sourcehunt/pool.py`
- Add `self._total_steps: int = 0` accumulator alongside `_spent_per_tier`
- Accumulate `result.steps_taken` in the dispatch loop where `result.cost_usd` is summed
- Extend `_run_one_hunter` 4-tuple return to include `steps_taken`
- Add `total_steps` property mirroring `total_cost_usd`

### `clearwing/sourcehunt/runner.py`
- Add `total_steps: int = 0` to `SourceHuntResult`
- After each `pool.arun()`, read `pool.total_steps` into `SourceHuntResult`
- Accumulate subsystem hunter steps from `HunterRunResult.steps_taken`

### `evaluations/evaluate.py`
- Add `"steps_taken"` to the `METRICS` tuple once it exists on
  `SourceHuntResult`; the harness serializes every named field automatically.
