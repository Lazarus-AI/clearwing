# Sourcehunt Empirical Evaluation and Rollout Guide

This runbook turns the completed Sourcehunt proof-flow implementation into a
measured rollout decision. It covers the paired legacy/proof evaluation,
local/frontier model ablations, runtime and counterfactual validation,
scheduler calibration, cutover gates, shadow deployment, canary deployment,
and rollback.

The repository implementation of Phases 0–5 is complete. The empirical work
described here has not yet been run. Keep `legacy` as the default until the
full gate campaign and rollout checks pass.

## What is being decided

The primary decision is whether `--flow proof` is ready to replace `legacy`
as the default Sourcehunt flow. The required gates are:

| Gate | Required result |
|---|---|
| Frontier recall | Proof is no worse than legacy |
| Local recall | Proof improves by at least 10 percentage points |
| Precision | Proof is no worse than legacy |
| Mean recorded cost | Proof is no more than 1.25 times legacy |

These gates are necessary, not sufficient. The rollout also requires a
complete blind matrix, counterfactual consistency, acceptable unsupported-
claim and report-failure rates, clean model-call linkage, and a successful
shadow/canary period.

Use repository-only Level 1 as the primary blind gate. Levels 2–7 are
diagnostic ablations that reveal progressively more ground truth; they show
where a model or pipeline fails, but they must not replace Level-1 recall in a
go/no-go decision.

## Evaluation stages

| Stage | Purpose | Current status |
|---|---|---|
| 0. Freeze the experiment | Pin code, models, cases, budgets, and environment | Not run |
| 1. Smoke test | Verify providers, checkouts, sandboxes, and artifact capture | Not run |
| 2. Paired blind campaign | Compare legacy/proof and local/frontier at Level 1 | Not run |
| 3. Diagnostic ablations | Run Levels 2–7 to locate first failure stages | Not run |
| 4. Runtime and counterfactual validation | Test causal sensitivity and hard evidence | Not run |
| 5. Calibration and holdout | Train scheduling profiles, then test them out of sample | Not run |
| 6. Cutover decision | Evaluate the frozen metrics and operational guardrails | Not run |
| 7. Shadow and canary rollout | Observe production behavior without an irreversible flip | Not run |
| 8. Default cutover | Change the default in a separate reviewed change | Not run |

## 1. Freeze the experiment

Create an evaluation directory outside the target repositories:

```bash
export CLEARWING_REPO=/path/to/clearwing
export EVAL_ROOT=/path/to/sourcehunt-eval
mkdir -p "$EVAL_ROOT"/{checkouts,compile-db,validation,plans,sessions,reports,metadata}
cd "$CLEARWING_REPO"
```

Record the exact Clearwing revision and verify the test baseline:

```bash
git rev-parse HEAD | tee "$EVAL_ROOT/metadata/clearwing-commit.txt"
git status --short
uv run pytest -q
uv run ruff check clearwing tests
```

Freeze the following before looking at results:

- Ground-truth manifest and digest.
- Selected case IDs and ablation levels.
- Local and frontier model identifiers, including provider-side revisions
  when available.
- Endpoint/gateway version, local serving engine, quantization, context
  length, GPU type, and inference settings.
- Per-run dollar, action, model-call, and dynamic-action caps.
- Replicate count.
- Compile databases and validation-manifest digests.
- The aggregation rule used for precision and cost.
- Cutover and operational guardrails.

Store the manifest digest:

```bash
shasum -a 256 evaluations/sourcehunt_ground_truth.yaml \
  | tee "$EVAL_ROOT/metadata/ground-truth.sha256"
```

Do not change prompts, proof plans, ground truth, model aliases, provider
versions, budgets, or target snapshots during a campaign. If one changes,
create a new plan and checkpoint under a new experiment ID.

### Model endpoint requirement

`clearwing eval sourcehunt-run` varies the model name per arm but currently
uses one OpenAI-compatible endpoint configuration for the campaign. The
simplest setup is a gateway that can route both the local and frontier model
names:

```bash
export EVAL_GATEWAY_URL=https://your-gateway.example/v1
export CLEARWING_API_KEY=your-key
export LOCAL_MODEL=your-pinned-local-model
export FRONTIER_MODEL=your-pinned-frontier-model
```

If the local and frontier models cannot be reached through one endpoint, run
the arms with an external tier-aware executor and import the resulting
sessions with `clearwing eval sourcehunt-observe`. Do not point a local model
name at a frontier-only endpoint or silently substitute a different model.

Use immutable model revisions where the provider offers them. A moving
`latest` alias invalidates longitudinal comparisons.

### Corpus policy

The shipped manifest currently contains five acceptance cases:

| Case | Language | Primary class |
|---|---|---|
| `ffmpeg-h264-slice-sentinel` | C | Representation and spatial safety |
| `gitea-pre-receive-permission-cache` | Go | Authorization |
| `junrar-backslash-path-traversal` | Java | Path/injection boundary |
| `freerdp-cache-to-surface-oob` | C | Spatial safety |
| `praisonai-a2a-eval-injection` | Python | Code injection |

This corpus proves evaluation plumbing and exercises several classes, but it
is too small to establish broad vulnerability-hunting generalization by
itself. Before a default cutover, pre-register a separate holdout manifest
covering the languages, frameworks, repository sizes, and Phase-4 bug classes
expected in production. Keep calibration and learned-mechanism promotion data
out of that holdout.

## 2. Prepare immutable checkouts

Every campaign checkout must be at the vulnerable commit recorded in
`evaluations/sourcehunt_ground_truth.yaml`. The runner rejects a mismatched
HEAD or tracked changes.

The following helper clones and pins every shipped case without reading a fix
diff:

```bash
uv run python - "$EVAL_ROOT/checkouts" <<'PY'
from pathlib import Path
import subprocess
import sys
import yaml

root = Path(sys.argv[1]).resolve()
manifest = yaml.safe_load(Path("evaluations/sourcehunt_ground_truth.yaml").read_text())
for case in manifest["cases"]:
    target = root / case["id"]
    if not target.exists():
        subprocess.run(
            ["git", "clone", "--no-checkout", case["repository"], str(target)],
            check=True,
        )
    subprocess.run(
        ["git", "-C", str(target), "fetch", "origin", case["vulnerable_commit"]],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "switch", "--detach", case["vulnerable_commit"]],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != case["vulnerable_commit"]:
        raise SystemExit(f"{case['id']}: expected {case['vulnerable_commit']}, got {head}")
PY
```

Do not inspect fixed commits, public patches, CVE prose, or this repository's
ground-truth details from inside a discovery model context. The evaluation
driver may use ground truth for scoring and staged hints, but Level 1 passes no
oracle hint to Sourcehunt.

### C and C++ compilation databases

Proof extraction fails closed for C/C++ without a real
`compile_commands.json`. Build the vulnerable checkouts before running the
campaign.

For FFmpeg, follow the exact build in [FFmpeg.md](FFmpeg.md). In abbreviated
form:

```bash
cd "$EVAL_ROOT/checkouts/ffmpeg-h264-slice-sentinel"
./configure \
  --cc=clang \
  --cxx=clang++ \
  --disable-doc \
  --enable-decoder=h264 \
  --enable-parser=h264 \
  --disable-stripping \
  --disable-optimizations \
  --enable-debug=3 \
  --extra-cflags='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' \
  --extra-ldflags='-fsanitize=address,undefined'
bear -- make -j"$(getconf _NPROCESSORS_ONLN)"
test -s compile_commands.json
```

For FreeRDP, configure an out-of-tree CMake build with compilation database
export enabled. Install its normal build dependencies first:

```bash
cd "$EVAL_ROOT/checkouts/freerdp-cache-to-surface-oob"
cmake -S . -B build-eval \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug
test -s build-eval/compile_commands.json
```

Record the database digests and retain the build logs. Generated and untracked
build files are permitted; tracked source modifications are not.

```bash
shasum -a 256 \
  "$EVAL_ROOT/checkouts/ffmpeg-h264-slice-sentinel/compile_commands.json" \
  "$EVAL_ROOT/checkouts/freerdp-cache-to-surface-oob/build-eval/compile_commands.json" \
  | tee "$EVAL_ROOT/metadata/compile-databases.sha256"
```

## 3. Prepare runtime-validation inputs

Candidate discovery and reportable finding confirmation are different
measurements. A proof finding may correctly remain incomplete when a runtime
backend or retained trigger is absent.

The repository ships an FFmpeg manifest template at
`evaluations/ffmpeg_validation_manifest.example.json`. It becomes runnable
only after `proof-input.h264` exists inside the FFmpeg checkout. The other
shipped cases do not yet include real validation manifests; producing and
reviewing those manifests is part of the empirical work.

For every runtime manifest:

- Keep commands repository-relative and shell-free.
- Run only in the Sourcehunt sandbox.
- Tie each command to one obligation predicate and, when needed, one candidate
  mechanism.
- Retain the trigger, build output, stdout/stderr, environment digest, and
  reproduction count.
- Use at least one negative/fixed execution to detect harness artifacts.
- Never treat a crash alone as attacker reachability, exploitability, or
  security impact.
- Do not include secrets or production data.

Use two labeled reports when practical:

1. **Blind discovery report:** no retained trigger is supplied; score ranking,
   fact extraction, candidate recall, proof-plan selection, and unresolved
   obligations.
2. **Validation-complete report:** pre-registered sandbox manifests are
   supplied; score hard evidence and final certificate recall.

The validation manifest is not model prose, but it is still an evaluation
input. Record its digest and never add or repair it after seeing which arm
failed.

## 4. Run a smoke matrix

Start with one case, three information levels, both flows, and both model
tiers. This creates 12 runs:

```bash
cd "$CLEARWING_REPO"
clearwing eval sourcehunt-plan \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --cases ffmpeg-h264-slice-sentinel \
  --flows legacy,proof \
  --levels 1,4,7 \
  --replicates 1 \
  --local-model "$LOCAL_MODEL" \
  --frontier-model "$FRONTIER_MODEL" \
  --output "$EVAL_ROOT/plans/smoke.json"

clearwing eval sourcehunt-run \
  --plan "$EVAL_ROOT/plans/smoke.json" \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --checkout ffmpeg-h264-slice-sentinel="$EVAL_ROOT/checkouts/ffmpeg-h264-slice-sentinel" \
  --compile-commands ffmpeg-h264-slice-sentinel="$EVAL_ROOT/checkouts/ffmpeg-h264-slice-sentinel/compile_commands.json" \
  --budget-per-run 10 \
  --base-url "$EVAL_GATEWAY_URL" \
  --output-dir "$EVAL_ROOT/sessions/smoke" \
  --checkpoint "$EVAL_ROOT/reports/smoke-observations.json"
```

The run is sequential and checkpoints atomically after every completed arm.
Rerun the identical command to resume. A changed plan, model, case definition,
or unknown checkpoint run ID is rejected.

Before scaling up, verify:

- Every planned arm produced one observation.
- Level-1 proof manifests show `blind_boundary.sealed: true`.
- No learning registry or campaign hint reached Level 1.
- C/C++ extraction used the intended compilation database and sandbox.
- `metrics/run-metrics.json` reports zero unlinked physical model calls.
- Spend and token totals are non-negative and plausible.
- Failed or unavailable backends remain `blocked`/`unknown`, not findings.
- The local and frontier arms share the same `context_id` for each cell.

Create a smoke report:

```bash
clearwing eval sourcehunt-baseline \
  --plan "$EVAL_ROOT/plans/smoke.json" \
  --observations "$EVAL_ROOT/reports/smoke-observations.json" \
  --output "$EVAL_ROOT/reports/smoke-baseline.json" \
  --markdown-output "$EVAL_ROOT/reports/smoke-baseline.md"
```

Do not use `--allow-incomplete` for a decision report. That option is only for
visible progress reporting.

## 5. Run the paired gate campaign

The number of planned runs is:

```text
cases × flows × 2 model tiers × levels × replicates
```

The numeric gate uses Level 1 only. With five cases, two flows, two model
tiers, one level, and three replicates, the gate matrix is 60 runs. At a hard
cap of $10 per run, the maximum authorized spend is $600. Start with one
replicate, inspect the artifacts, and then use at least three pre-registered
replicates for a gate decision. More replicates measure stochastic stability
but do not add vulnerability-class diversity.

Build the full plan:

```bash
clearwing eval sourcehunt-plan \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --flows legacy,proof \
  --levels 1 \
  --replicates 3 \
  --local-model "$LOCAL_MODEL" \
  --frontier-model "$FRONTIER_MODEL" \
  --output "$EVAL_ROOT/plans/gate.json"
```

For the end-to-end certificate gate, first finish and freeze a reviewed
validation manifest for every case. The files below are campaign artifacts,
not files currently shipped by the repository:

```bash
test -s "$EVAL_ROOT/validation/ffmpeg.json"
test -s "$EVAL_ROOT/validation/gitea.json"
test -s "$EVAL_ROOT/validation/junrar.json"
test -s "$EVAL_ROOT/validation/freerdp.json"
test -s "$EVAL_ROOT/validation/praisonai.json"
```

Run the Level-1 gate against every pinned checkout and validation backend:

```bash
clearwing eval sourcehunt-run \
  --plan "$EVAL_ROOT/plans/gate.json" \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --checkout ffmpeg-h264-slice-sentinel="$EVAL_ROOT/checkouts/ffmpeg-h264-slice-sentinel" \
  --checkout gitea-pre-receive-permission-cache="$EVAL_ROOT/checkouts/gitea-pre-receive-permission-cache" \
  --checkout junrar-backslash-path-traversal="$EVAL_ROOT/checkouts/junrar-backslash-path-traversal" \
  --checkout freerdp-cache-to-surface-oob="$EVAL_ROOT/checkouts/freerdp-cache-to-surface-oob" \
  --checkout praisonai-a2a-eval-injection="$EVAL_ROOT/checkouts/praisonai-a2a-eval-injection" \
  --compile-commands ffmpeg-h264-slice-sentinel="$EVAL_ROOT/checkouts/ffmpeg-h264-slice-sentinel/compile_commands.json" \
  --compile-commands freerdp-cache-to-surface-oob="$EVAL_ROOT/checkouts/freerdp-cache-to-surface-oob/build-eval/compile_commands.json" \
  --validation-manifest ffmpeg-h264-slice-sentinel="$EVAL_ROOT/validation/ffmpeg.json" \
  --validation-manifest gitea-pre-receive-permission-cache="$EVAL_ROOT/validation/gitea.json" \
  --validation-manifest junrar-backslash-path-traversal="$EVAL_ROOT/validation/junrar.json" \
  --validation-manifest freerdp-cache-to-surface-oob="$EVAL_ROOT/validation/freerdp.json" \
  --validation-manifest praisonai-a2a-eval-injection="$EVAL_ROOT/validation/praisonai.json" \
  --budget-per-run 10 \
  --base-url "$EVAL_GATEWAY_URL" \
  --proof-max-actions 200 \
  --proof-max-model-calls 40 \
  --proof-max-dynamic-actions 20 \
  --output-dir "$EVAL_ROOT/sessions/gate" \
  --checkpoint "$EVAL_ROOT/reports/gate-observations.json"
```

Run a separate discovery-only Level-1 matrix without those five assignments
and with a different output directory/checkpoint. Use that report to measure
candidate and funnel performance without retained triggers. Use the frozen
validation-complete matrix above for end-to-end certificate recall and the
numeric cutover gates. Do not add validation manifests midway through an
existing checkpoint or combine observations from the two input regimes.

Aggregate the complete matrix:

```bash
clearwing eval sourcehunt-baseline \
  --plan "$EVAL_ROOT/plans/gate.json" \
  --observations "$EVAL_ROOT/reports/gate-observations.json" \
  --output "$EVAL_ROOT/reports/gate-baseline.json" \
  --markdown-output "$EVAL_ROOT/reports/gate-baseline.md"
```

### Optional diagnostic campaign

If a gate misses, build a separate Levels 2–7 plan using the same cases,
models, budgets, and replicates:

```bash
clearwing eval sourcehunt-plan \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --flows legacy,proof \
  --levels 2,3,4,5,6,7 \
  --replicates 3 \
  --local-model "$LOCAL_MODEL" \
  --frontier-model "$FRONTIER_MODEL" \
  --output "$EVAL_ROOT/plans/diagnostic.json"
```

That diagnostic matrix is 360 runs, with a $3,600 maximum at $10 per run. Use
its `failure_stage_counts` to locate misses during ranking, fact extraction,
candidate generation, proof-plan selection, path/guard resolution,
validation, threat modeling, or certificate compilation. Diagnostic assisted
levels never replace the Level-1 gate.

## 6. Calibrate, then validate out of sample

Compile scheduler profiles from completed proof sessions:

```bash
clearwing eval sourcehunt-calibrate \
  --observations "$EVAL_ROOT/reports/gate-observations.json" \
  --output "$EVAL_ROOT/reports/scheduler-calibration.json"
```

Calibration learns observed action yield, cost, and elapsed time. It does not
change proof requirements and does not consume model self-confidence.

Do not claim an improvement by applying calibration back to the same cases and
reporting only that result. Build a new plan over a pre-registered holdout
manifest, use a new output directory and checkpoint, and pass:

```text
--scheduler-calibration "$EVAL_ROOT/reports/scheduler-calibration.json"
```

Run both `legacy` and calibrated `proof` arms during the same time window so
provider drift and service incidents affect the comparison symmetrically.
Record the calibration digest in the decision package.

Do not pass `--proof-learning-registry` in a strict blind or cutover campaign.
A registry-assisted run is intentionally marked assisted and unseals the
blind boundary. Evaluate the learning flywheel as a separate train/test
experiment using `sourcehunt-promote` and `sourcehunt-learning-coverage`.

## 7. Run the FFmpeg counterfactual matrix

The counterfactual scorer requires exactly these proof session names:

```text
vulnerable, fixed, renamed, moved, guarded, unreachable, decoy, widened-domain
```

The scorer is shipped, but real renamed/moved/guarded/unreachable/decoy/
widened-domain checkouts and retained runtime inputs must be materialized and
reviewed as campaign artifacts. Preserve each transformation as a patch and
record the base commit and resulting tree digest. A variant must change only
the intended causal property.

Use [FFmpeg.md](FFmpeg.md) and `evaluations/ffmpeg_proof.sh` for the pinned
vulnerable and fixed runs. Run every variant with the same proof configuration,
model identity, budgets, compilation mode, and validation backend. Then score
the concrete session directories:

```bash
clearwing eval sourcehunt-counterfactual \
  --manifest evaluations/ffmpeg_proof.yaml \
  --session vulnerable=/path/to/vulnerable/session \
  --session fixed=/path/to/fixed/session \
  --session renamed=/path/to/renamed/session \
  --session moved=/path/to/moved/session \
  --session guarded=/path/to/guarded/session \
  --session unreachable=/path/to/unreachable/session \
  --session decoy=/path/to/decoy/session \
  --session widened-domain=/path/to/widened-domain/session \
  --output "$EVAL_ROOT/reports/ffmpeg-counterfactual.json"
```

The required result is full consistency: the mechanism survives rename/move,
the real repairs and unreachable form remove the finding, the guard adds a
rejection, and the decoy does not add a finding. Inspect every failed relation;
do not average a causal failure away with unrelated successes.

## 8. Evaluate the cutover gates

The gate evaluator is currently a Python API. The following command reads the
Level-1 baseline, uses frontier and local recall separately, and uses pooled
micro-precision plus run-weighted mean cost across both tiers. This aggregation
rule must be frozen before the campaign.

```bash
uv run python - "$EVAL_ROOT/reports/gate-baseline.json" \
  "$EVAL_ROOT/reports/cutover.json" <<'PY'
from dataclasses import asdict
import json
from pathlib import Path
import sys

from clearwing.eval import CutoverMetrics, evaluate_cutover

baseline_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
baseline = json.loads(baseline_path.read_text())
if not baseline["complete"]:
    raise SystemExit("refusing cutover evaluation for an incomplete matrix")

level_one = [group for group in baseline["groups"] if group["level"] == 1]

def group(flow, tier):
    matches = [
        item for item in level_one
        if item["flow"] == flow and item["model_tier"] == tier
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one Level-1 group for {flow}/{tier}, got {len(matches)}")
    return matches[0]

def pooled(flow):
    selected = [item for item in level_one if item["flow"] == flow]
    tp = sum(item["true_positives"] for item in selected)
    fp = sum(item["false_positives"] for item in selected)
    runs = sum(item["runs"] for item in selected)
    precision = tp / (tp + fp) if tp + fp else 0.0
    mean_cost = (
        sum(item["mean_cost_usd"] * item["runs"] for item in selected) / runs
        if runs else 0.0
    )
    return precision, mean_cost

proof_precision, proof_cost = pooled("proof")
legacy_precision, legacy_cost = pooled("legacy")
metrics = CutoverMetrics(
    frontier_recall=group("proof", "frontier")["recall"],
    legacy_frontier_recall=group("legacy", "frontier")["recall"],
    local_recall=group("proof", "local")["recall"],
    legacy_local_recall=group("legacy", "local")["recall"],
    precision=proof_precision,
    legacy_precision=legacy_precision,
    mean_cost=proof_cost,
    legacy_mean_cost=legacy_cost,
)
decision = evaluate_cutover(metrics)
payload = {"metrics": asdict(metrics), "decision": asdict(decision)}
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print(json.dumps(payload, indent=2, sort_keys=True))
if not decision.passed:
    raise SystemExit(1)
PY
```

The threshold evaluator does not calculate statistical significance. Require
the result to be stable across the pre-registered replicates and inspect
per-case failures. Repeated success on one vulnerability is not a substitute
for diversity across repositories and bug classes.

### Operational go/no-go checklist

All of the following should be true before shadow rollout expands:

- The gate baseline says `complete: true`.
- All four numeric cutover checks pass on Level 1.
- The same conclusion holds on the separate holdout campaign.
- FFmpeg counterfactual consistency is 100%.
- Proof unsupported-claim rate and report-failure rate are no worse than
  legacy; accepted proof findings should have no unsupported claims.
- Level-1 proof runs have a sealed blind boundary.
- Proof telemetry has zero unlinked physical model calls.
- No run silently converted missing analysis, context, or validation into a
  finding.
- Dynamic execution stayed inside the approved sandbox and retained auditable
  artifacts.
- No single high-impact production-relevant class shows a catastrophic recall
  regression hidden by the aggregate.
- Recorded cost is meaningful for the chosen accounting basis. Provider spend
  is the built-in metric; track local hardware/TCO separately if it matters to
  the deployment decision.

If any item fails, the decision is **no-go**. Fix the identified stage, create
a new experiment ID, and rerun rather than editing the existing report.

## 9. Roll out reversibly

### Step A: shadow

Keep `legacy` user-facing. For a pre-registered sample of repositories and
commits, run `proof` as a separate sidecar job with no ability to block merges,
suppress legacy findings, or publish externally.

Compare:

- Finding overlap and proof-only/legacy-only findings.
- Human adjudication of disagreements.
- Incomplete and rejection certificate usefulness.
- First-failure stages.
- Unsupported claims and report failures.
- Local-only completion and frontier-escalation rate.
- Model calls, latency, tokens, provider spend, and local infrastructure cost.
- Dynamic-backend success, flakiness, and sandbox incidents.

The proof engine must continue to fail closed. If a separate orchestration
layer runs legacy as a fallback/control, retain it as a separate session; do
not merge its conclusions into a proof certificate.

### Step B: opt-in canary

Enable `--flow proof` for an explicitly opted-in, low-blast-radius cohort.
Keep the default at `legacy`. Require human review for proof-only findings and
retain both result sets for comparison.

Freeze the canary window and rollback thresholds in advance. Roll back the
cohort if recall, precision, unsupported claims, report failures, latency,
cost, sandbox reliability, or provider availability crosses those thresholds.

### Step C: expanded canary

Expand by repository cohort, language, or bug class only after the earlier
cohort meets the same gates. Do not use aggregate success in Python or Go to
justify enabling an under-tested C/C++ dynamic path.

### Step D: default cutover

Change the default from `legacy` to `proof` in a separate pull request. The
change should contain no prompt, proof-plan, scoring, budget, or model update.
Attach the frozen decision package and preserve an immediate configuration
rollback to `legacy`.

Continue sampling paired legacy/proof runs after cutover until the agreed
monitoring window closes. Reopen the cutover decision whenever a model,
provider, proof plan, candidate generator, sandbox backend, or major target
distribution changes.

## 10. Decision package

Archive the following together:

```text
metadata/
  clearwing-commit.txt
  ground-truth.sha256
  compile-databases.sha256
  environment.json
  model-endpoints.redacted.json
plans/
  smoke.json
  gate.json
reports/
  smoke-observations.json
  smoke-baseline.{json,md}
  gate-observations.json
  gate-baseline.{json,md}
  scheduler-calibration.json
  ffmpeg-counterfactual.json
  cutover.json
sessions/
  <run-id>/...
counterfactual-patches/
validation-manifests/
retained-trigger-inventory/
rollout-decision.md
```

Do not place credentials, sensitive target data, or unsafe triggers in a
public artifact bundle. Store trigger hashes and access-controlled locations
when the raw input cannot be distributed.

The final decision record should state:

- Exact experiment and model versions.
- Whether the matrix and holdout are complete.
- Every cutover check and its underlying numerator/denominator.
- Counterfactual failures, if any.
- Operational guardrail results.
- Known coverage gaps.
- Approved rollout cohort and rollback owner.
- The date or change conditions that force reevaluation.

## Troubleshooting

- **Checkout mismatch:** reset the evaluation checkout to the manifest's
  vulnerable commit. Do not update the manifest to match an accidental HEAD.
- **Tracked changes rejected:** rebuild out of tree or restore the checkout;
  untracked build artifacts are allowed.
- **C/C++ preflight incomplete:** provide the correct compilation database and
  confirm Docker is available.
- **Wrong model served:** inspect provider logs and recorded model identity;
  stop the campaign rather than accepting an alias substitution.
- **Campaign interrupted:** rerun the same `sourcehunt-run` command and
  checkpoint. Completed run IDs are skipped.
- **Incomplete baseline:** inspect missing run IDs. Use `--allow-incomplete`
  only for progress, never cutover.
- **No proof finding:** inspect the funnel. A candidate or incomplete
  certificate may show that discovery worked but runtime evidence,
  falsification, threat modeling, or another obligation is missing.
- **Counterfactual failure:** inspect the named relation and transformation;
  do not dilute it into an average score.
- **Cost is zero or implausible:** verify provider pricing/accounting before
  applying the cost gate.
- **Learning registry supplied:** classify the run as assisted and exclude it
  from strict blind/cutover metrics.
