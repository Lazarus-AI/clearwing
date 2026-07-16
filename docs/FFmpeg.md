# FFmpeg H.264 Sourcehunt Walkthrough

This page describes how to recreate the FFmpeg H.264 slice-counter
vulnerability hunt with Clearwing in a way that keeps the discovery pass
blind. "Blind" means Clearwing is given only the vulnerable source tree:
no fix diff, no pull request, no CVE text, no blog post, and no human hint
that the issue is in H.264.

The public fix is useful after the run as an oracle for whether the finding
matches the real bug. Do not use it during the discovery pass.

## The `--flow proof` Engine Used Here

This walkthrough's primary discovery path uses
`clearwing sourcehunt --flow proof`. The flag selects a separate
investigation engine; it is not a depth, verbosity, or reporting option.
`--flow legacy` remains the CLI default during migration, so omitting
`--flow proof` runs a materially different file-agent pipeline.

For this FFmpeg case, the proof engine performs the following bounded flow:

```text
pinned repository snapshot
  → sandboxed Clang facts and extraction-completeness records
  → invariant-oriented candidates and explicit threat models
  → bug-class proof plans and obligation graphs
  → mechanical checks, local-first model judgments, and declared runtime tests
  → independent finite falsification
  → finding, rejection, or incomplete certificates
```

Every conclusion must point back to stored evidence. A finding certificate
means all mandatory obligations for its proof plan passed the evidence gates.
A rejection certificate records why a candidate was disproven for the pinned
snapshot. An incomplete certificate preserves useful progress when evidence,
context, a tool backend, or budget is missing. Neither a rejection nor an
incomplete certificate is silently converted into “repository is safe.”

Sections explicitly labeled **Legacy** are comparison controls only. Do not
pool their findings, costs, trajectories, or success rates with proof-flow
certificates. Likewise, the public fix, retro-hunt, N-day pipeline, and a
learned mechanism registry are post-discovery or assisted controls and do not
belong inside the strict blind proof boundary.

## Case Metadata

- Upstream repository: `https://code.ffmpeg.org/FFmpeg/FFmpeg.git`
- Fix commit: `39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89`
- Vulnerable parent commit: `795bccdaf57772b1803914dee2f32d52776518e2`
- Fix subject: `avcodec/h264_slice: reject slice_num >= 0xFFFF`
- Fixed file: `libavcodec/h264_slice.c`
- Public review: `https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/22499/files`

## Blindness Rules

Follow these rules if you want a meaningful recreation:

1. Run Clearwing against the vulnerable parent commit, not the fixed commit.
2. Do not pass the fix commit, pull request, patch, article text, or this
   page into the model context.
3. Do not run `sourcehunt --retro-hunt` for the blind pass. Retro-hunt is
   explicitly patch-derived and is useful only as a non-blind control.
4. Use a fresh `CLEARWING_HOME` or pass `--no-mechanism-memory` so prior
   runs cannot inject remembered mechanisms.
5. For formal benchmarking, use a Clearwing checkout that has not been
   modified with FFmpeg-specific or H.264-specific local hints.
6. Do not pass `--proof-learning-registry` to the strict blind pass. A registry
   built from this FFmpeg case, its fix, or a related oracle makes the run an
   assisted rescan and the manifest will record the blind boundary as unsealed.

## Prerequisites

Install Clearwing per README.md. The proof flow for C/C++ also requires:

- Docker, because Clang extraction and all target execution fail closed
  unless they run in a sandbox.
- Clang and a build toolchain for FFmpeg.
- `bear`, used below to capture `compile_commands.json`.
- `jq` and `rg` for the artifact queries in this walkthrough.

## Prepare The Vulnerable Checkout

Use a local checkout so the target is pinned to the parent of the fix commit.
FFmpeg's default branch is `master`, while Clearwing's `--branch` default is
`main`, so a local path avoids branch-name ambiguity.

```bash
mkdir -p ~/clearwing-cases/ffmpeg-h264
cd ~/clearwing-cases/ffmpeg-h264

git clone https://code.ffmpeg.org/FFmpeg/FFmpeg.git ffmpeg-vuln
cd ffmpeg-vuln
git switch --detach 795bccdaf57772b1803914dee2f32d52776518e2

git show --no-patch --pretty=fuller HEAD
```

Confirm that `HEAD` is:

```text
795bccdaf57772b1803914dee2f32d52776518e2
```

Do not fetch or inspect the fix diff yet if you are trying to preserve a
strict blind run.

## Build And Capture The Compilation Database

The proof flow does not guess C/C++ compiler flags. Build the pinned tree
and capture its real commands before starting discovery:

```bash
cd ~/clearwing-cases/ffmpeg-h264/ffmpeg-vuln

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

NPROC="$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN)"
bear -- make -j"$NPROC"
test -s compile_commands.json
```

The resulting database is an extraction input, not vulnerability evidence.
Clearwing records its build configuration and runs Clang inside the analysis
sandbox. If the database or sandbox is unavailable, the C/C++ proof run is
reported as incomplete; it never silently falls back to lexical analysis or
the legacy hunter.

## Run The Blind Discovery Pass

Create an isolated Clearwing home for this case. This keeps the mechanism
memory store, trajectories, logs, and knowledge graph separate from any
previous sourcehunt work.

```bash
cd ~/clearwing-cases/ffmpeg-h264

export CASE_DIR="$PWD"
export FFMPEG_DIR="$CASE_DIR/ffmpeg-vuln"
export CLEARWING_HOME="$CASE_DIR/.clearwing-blind-home"
export CLEARWING_SOURCEHUNT_TRACE_DIR="$CASE_DIR/trajectories"

rm -rf "$CLEARWING_HOME" "$CLEARWING_SOURCEHUNT_TRACE_DIR" \
  "$CASE_DIR/results-proof-blind"
mkdir -p "$CLEARWING_HOME" "$CLEARWING_SOURCEHUNT_TRACE_DIR" \
  "$CASE_DIR/results-proof-blind"

clearwing sourcehunt "$FFMPEG_DIR" \
  --flow proof \
  --compile-commands compile_commands.json \
  --build-configuration asan-debug \
  --model-routing local-first \
  --proof-local-model Qwen3.5-35B \
  --proof-frontier-model YOUR_FRONTIER_MODEL \
  --structured-budget 90% \
  --exploration-budget 10% \
  --proof-plan auto \
  --proof-max-actions 200 \
  --proof-max-model-calls 40 \
  --proof-max-dynamic-actions 20 \
  --retain-incomplete-certificates \
  --emit-rejection-certificates \
  --falsify \
  --no-mechanism-memory \
  --gvisor \
  --output-dir "$CASE_DIR/results-proof-blind" \
  --format all
```

Why these flags:

- `--flow proof` selects the candidate/evidence/obligation engine. During
  migration, `legacy` remains the default for backward compatibility.
- `--compile-commands` supplies the required C/C++ build truth.
- `--model-routing local-first` sends bounded judgments to the small-model
  route, escalating the same atomic question to the frontier route only
  after a local attempt remains unresolved.
- `--proof-local-model` and `--proof-frontier-model` give those two routes
  distinct, auditable model identities. With a single OpenAI-compatible
  endpoint, that endpoint must serve both names. With multi-provider config,
  configure `proof_local` and `proof_frontier` routes; the flags override the
  model on those existing routes.
- `--structured-budget` and `--exploration-budget` make the exploratory lane
  a bounded minority rather than an unbounded whole-repository agent.
- The three `--proof-max-*` limits are run-wide caps. Mechanical, dynamic,
  exploratory, frontier, and falsification actions share the same ledger.
- Incomplete and rejection certificates preserve negative results and
  unresolved state instead of converting either into a finding.
- `--falsify` runs a finite independent search for concrete counterexamples
  before a finding certificate can be issued.
- `--no-mechanism-memory` plus the fresh home prevents prior runs from
  influencing the strict baseline. The proof engine does not consume legacy
  mechanism memory, but keeping the flag makes the benchmark boundary clear.
- `--gvisor` uses the gVisor runtime for container isolation, adding an
  extra security layer when running untrusted PoC code inside sandboxes.
- Budget is unlimited by default. Add `--budget 50` to cap spend for a local
  recreation, or pass `--budget 0` explicitly to keep the unlimited default.

Do not add `--seed-cves` or a vulnerability-class `--campaign-hint` to this
strict baseline. Those are useful assisted controls, but they contaminate a
blind-discovery measurement.

The vulnerable run may legitimately end with an incomplete certificate if
it establishes the representation collision but lacks a retained trigger or
runtime evidence. That is a useful partial result, not a finding. A finding
requires every mandatory class obligation, hard memory-safety evidence, a
security boundary, and a completed falsification plan.

The CLI exits `0` for a completed run without medium-or-higher findings, `1`
for a medium finding, `2` for a high or critical finding, and `3` when the
proof remains incomplete or the run-wide budget is exhausted. When automating
this walkthrough, preserve the session directory before interpreting exit
`3`; it does not mean the process crashed.

## Optional Manifest-Driven Runtime Validation

Dynamic checks are never invented as arbitrary shell commands. They are
declared in a strict JSON manifest, matched to one candidate mechanism and
one obligation predicate, and executed without a shell inside the same
sandbox boundary.

After a blind run produces and retains a trigger, place it at
`$FFMPEG_DIR/proof-input.h264`, copy the example manifest, and rerun:

```bash
export CLEARWING_REPO=/path/to/your/clearwing-checkout
cp "$CLEARWING_REPO/evaluations/ffmpeg_validation_manifest.example.json" \
  "$CASE_DIR/ffmpeg-validation.json"

clearwing sourcehunt "$FFMPEG_DIR" \
  --flow proof \
  --compile-commands compile_commands.json \
  --build-configuration asan-debug \
  --validation-manifest "$CASE_DIR/ffmpeg-validation.json" \
  --model-routing local-first \
  --structured-budget 90% \
  --exploration-budget 10% \
  --falsify \
  --gvisor \
  --output-dir "$CASE_DIR/results-proof-validation"
```

The example repeats the production FFmpeg command three times. A sanitizer
observation can establish only the scoped runtime obligation; it cannot by
itself establish attacker reachability, a realistic deployment, remote code
execution, or security impact.

For a smaller target function that can be linked in isolation, the same
manifest can use a reusable harness template instead of a handwritten
command. Clearwing writes the generated source only to sandbox scratch,
compiles it with libFuzzer, ASan, and UBSan, and retains the build artifact and
runtime observation as separate evidence:

```json
{
  "schema_version": 1,
  "commands": [
    {
      "name": "fuzz isolated parser",
      "action_template": "fuzz",
      "obligation_predicate": "runtime_confirms_unsafe_memory_access",
      "candidate_mechanism": "allocation_access_extent_contrast",
      "harness_template": {
        "target_function": "parse_packet",
        "signature": "int parse_packet(const uint8_t *, size_t)",
        "source_files": ["lib/parser.c"],
        "include_dirs": ["include"],
        "duration_seconds": 30
      },
      "success_condition": "sanitizer"
    }
  ]
}
```

FFmpeg's full decoder is not a good isolated-template target, so the retained
production trigger manifest remains the appropriate backend for this case.

## Optional Legacy Agentic Control

The controls below describe the older file-agent engine. Use them only for a
separately labeled `--flow legacy` comparison; do not pool those findings or
trajectories with proof-flow certificates.

### Prompt Mode

The default `--prompt-mode unconstrained` gives hunters a simple open-ended
discovery prompt. The alternative `--prompt-mode specialist` uses legacy
prescriptive checklists. For FFmpeg blind hunts, `unconstrained` (the
default) produces better results because hunters explore freely rather than
following a fixed checklist.

### Tuning Band Promotion

The three-band promotion system (fast → standard → deep) auto-promotes
files when signals are detected. For a targeted deep dive you can override:

```bash
  --starting-band standard   # skip the fast band, start at standard
  --redundancy 3             # run 3 independent agents per high-ranked file
  --min-shard-rank 2         # shard files at rank 2+ instead of default 4+
```

Higher redundancy increases the chance of finding non-deterministic bugs
(especially race conditions) but costs proportionally more.

### Budget Split

The default tier budget is 70/25/5 (A/B/C). For FFmpeg, Tier B
(propagation-style headers like `codec_limits.h`) is unusually important.
Consider:

```bash
  --tier-split 60/35/5       # shift budget toward Tier B propagation files
  --skip-tier-c              # skip Tier C entirely (faster, but misses root-cause-in-boring-files bugs)
```

Unused budget rolls forward: A → B → C.

### Cross-Subsystem Hunting

FFmpeg's codecs interact heavily across subsystem boundaries. After the
per-file hunt, enable cross-subsystem analysis:

```bash
  --subsystem-hunt \
  --subsystem libavcodec \
  --subsystem libavutil \
  --subsystem libavformat
```

This runs additional agents that see all findings from the per-file phase
and can discover cross-file interaction bugs (e.g., a type mismatch between
`h264dec.h` declarations and `h264_slice.c` usage).

The legacy command writes a session directory under:

```text
~/clearwing-cases/ffmpeg-h264/results/<session_id>/
```

The important files are:

- `report.md` - human-readable findings with pipeline health summary.
- `findings.json` - structured findings, verifier output, and stability
  classifications.
- `findings.sarif` - IDE/code-scanning import.
- `manifest.json` - run metadata, spend by tier, and pipeline status.

## Inspect Proof Artifacts

Locate the sealed proof session:

```bash
SESSION_DIR="$(dirname "$(find "$CASE_DIR/results-proof-blind" \
  -mindepth 2 -maxdepth 2 -name manifest.json -print -quit)")"
test -n "$SESSION_DIR"
jq '{engine, status, proof_status, snapshot_id, blind_boundary, budget,
     spend, complete, candidate_count, certificate_counts, action_counts,
     metrics, errors, outputs}' \
  "$SESSION_DIR/manifest.json"
```

Interpret the manifest and certificates together:

- `engine == "proof"` confirms that the command did not run the legacy
  engine.
- `complete == true` means the run finished without residual incomplete
  certificates; it does not mean FFmpeg has no other vulnerabilities.
- `status == "budget_exhausted"` or `proof_status == "incomplete"` means
  unresolved state was deliberately retained for inspection and follow-up.
- `findings.json` and `findings.sarif` contain only current accepted finding
  certificates. A zero-length findings list is not a safety claim; check the
  rejection and incomplete certificate counts and their evidence.
- `outputs` is the authoritative index for the report, spend ledger,
  instrumentation, metrics, and other emitted artifacts.

The authoritative state is append-only JSONL plus content-addressed
artifacts:

```text
manifest.json
snapshots/snapshots.jsonl
facts/facts.jsonl
facts/extraction-coverage.json
candidates/candidates.jsonl
threats/threat-models.jsonl
obligations/obligations.jsonl
actions/action-log.jsonl
claims/claims.jsonl
evidence/evidence.jsonl
derivations/derivations.jsonl
context-packets/packets.jsonl
proof-graphs/<candidate-id>.json
falsification/<candidate-id>.json
metrics/run-metrics.json
spend-ledger.jsonl
spend-summary.json
certificates/{findings,rejections,incomplete}/
artifacts/sha256/
learning/retrospectives.json
report.md
findings.json
findings.sarif
```

Inspect whether the local-first routing is resolving atomic work efficiently
and whether every physical provider call is linked to a proof action:

```bash
jq '{totals, efficiency, by_model_route, by_action_template,
     model_call_linkage}' "$SESSION_DIR/metrics/run-metrics.json"
```

Any non-zero `unlinked_model_calls` is an instrumentation failure for a proof
run. `model_actions_without_ledger_call` can be non-zero when a model route is
unavailable or fails before provider dispatch; inspect the corresponding
action status and error rather than treating it as model evidence.

Query the expected mechanism and its selected plans:

```bash
jq -c 'select(.suspected_mechanism ==
  "live_identifier_aliases_reserved_sentinel") |
  {logical_id, title, invariant_families, proof_plan_ids, fact_ids}' \
  "$SESSION_DIR/candidates/candidates.jsonl"
```

Inspect the latest revision of every obligation. This preserves `unknown`,
`blocked`, `conflicting_evidence`, and `stale` instead of silently treating
them as false or absent:

```bash
jq -s '
  sort_by(.logical_id, .revision)
  | group_by(.logical_id)
  | map(last)
  | map({predicate, status, blocked_reason,
         supporting_claim_ids, contradicting_claim_ids})
' "$SESSION_DIR/obligations/obligations.jsonl"
```

Inspect extraction completeness and unknown edges:

```bash
jq '.items | to_entries[] |
  {name: .key, status: .value.status,
   limitations: .value.limitations, unresolved: .value.unresolved}' \
  "$SESSION_DIR/facts/extraction-coverage.json"
```

Inspect run-wide action routing and bounded falsification:

```bash
jq -s '
  sort_by(.logical_id, .revision)
  | group_by(.logical_id)
  | map(last)
  | map({template, model_route, status, obligation_ids, error})
' "$SESSION_DIR/actions/action-log.jsonl"

jq . "$SESSION_DIR"/falsification/*.json
```

Finally, inspect certificates rather than grepping report prose:

```bash
jq '{kind, decision, reason, proof_plan_ids, evidence_ids,
     unresolved_obligation_ids, blocked_obligation_ids}' \
  "$SESSION_DIR"/certificates/{findings,rejections,incomplete}/*.json
```

`findings.json` and SARIF contain only accepted finding certificates.
Rejections and incomplete investigations remain in their own certificate
directories and in `report.md`.

## Legacy Whole-Run Redundancy Control

The legacy scenario was not a guaranteed single-shot discovery. For a
separately labeled old-engine control, run several isolated passes and compare
their reports:

```bash
cd ~/clearwing-cases/ffmpeg-h264
export CASE_DIR="$PWD"
export FFMPEG_DIR="$CASE_DIR/ffmpeg-vuln"

for i in 1 2 3 4 5; do
  RUN_HOME="$CASE_DIR/.clearwing-blind-home-$i"
  RUN_OUT="$CASE_DIR/results-pass-$i"
  RUN_TRACE="$CASE_DIR/trajectories-pass-$i"
  rm -rf "$RUN_HOME" "$RUN_OUT" "$RUN_TRACE"
  mkdir -p "$RUN_HOME" "$RUN_OUT" "$RUN_TRACE"

  CLEARWING_HOME="$RUN_HOME" \
  CLEARWING_SOURCEHUNT_TRACE_DIR="$RUN_TRACE" \
  clearwing sourcehunt "$FFMPEG_DIR" \
    --flow legacy \
    --depth deep \
    --agent-mode deep \
    --max-parallel 8 \
    --shard-entry-points \
    --seed-cves \
    --elaborate-pipeline \
    --exploit \
    --campaign-hint "integer overflows and type mismatches in media codec parsers" \
    --no-mechanism-memory \
    --gvisor \
    --encrypt-artifacts \
    --output-dir "$RUN_OUT" \
    --format all
done
```

If shell automation treats high-severity findings as a failing command, check
the output directories before discarding the run. `sourcehunt` may return a
non-zero exit code when it finds high or critical issues.

## Evaluate The Expected Proof

Use the structured queries above to find a candidate whose mechanism is
`live_identifier_aliases_reserved_sentinel`. A finding certificate should
explain substantially this root cause:

- FFmpeg tracks macroblock ownership in a `slice_table`.
- The table entries are 16-bit values and are initialized to all `0xFF`
  bytes, making `0xFFFF` the "no slice owns this position" sentinel.
- The slice counter is wider and can continue increasing until a real slice
  number aliases that sentinel value.
- Neighbor/same-slice logic can then believe an out-of-bounds or padding
  neighbor belongs to the current slice.
- The deblocking path can follow that incorrect neighbor decision into an
  out-of-bounds heap write.

The best report will point at `libavcodec/h264_slice.c` and should also
notice the type mismatch with declarations in `libavcodec/h264dec.h`.

Do not count a candidate or an incomplete certificate as a successful
finding. They are stage-level signals. The evaluation harness in
`evaluations/sourcehunt_ground_truth.yaml` records the target files,
functions, expected extracted fact symbols, entry point, source, sinks,
transformation, invariant, guard,
trigger constraints, expected runtime behavior, threat model, mechanism,
proof plans, predicates, evidence kinds, and decision.
`evaluations/ffmpeg_proof.yaml` is the executable compact counterfactual
contract used to score the vulnerable, fixed, renamed, moved, guarded,
unreachable, decoy, and widened-domain sessions as one matrix.

To include FFmpeg in the identical local/frontier seven-level ablation matrix,
first build the plan:

```bash
clearwing eval sourcehunt-plan \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --cases ffmpeg-h264-slice-sentinel \
  --local-model Qwen3.5-35B \
  --frontier-model YOUR_FRONTIER_MODEL \
  --output "$CASE_DIR/eval-plan.json"
```

The plan's Level 1 arms receive no hint. Later levels cumulatively reveal the
target file, target function, source/sink pair, invariant/path, full trace, and
trigger. Every local/frontier pair has the same `context_id`. Run the plan
only after preparing the vulnerable checkout and compilation database:

```bash
clearwing eval sourcehunt-run \
  --plan "$CASE_DIR/eval-plan.json" \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --checkout ffmpeg-h264-slice-sentinel="$FFMPEG_DIR" \
  --compile-commands ffmpeg-h264-slice-sentinel="$FFMPEG_DIR/compile_commands.json" \
  --budget-per-run 10 \
  --output-dir "$CASE_DIR/eval-sessions" \
  --checkpoint "$CASE_DIR/eval-observations.json"
```

When using the full five-case plan, repeat `--checkout` (and the C/C++
`--compile-commands`) for every case. The runner verifies each checkout's HEAD
and tracked-file cleanliness against the ground-truth manifest, then
automatically reloads its atomic checkpoint and resumes by stable run ID.
Compile the baseline only after every planned arm completes:

```bash
clearwing eval sourcehunt-baseline \
  --plan "$CASE_DIR/eval-plan.json" \
  --observations "$CASE_DIR/eval-observations.json" \
  --output "$CASE_DIR/eval-baseline.json"

clearwing eval sourcehunt-calibrate \
  --observations "$CASE_DIR/eval-observations.json" \
  --output "$CASE_DIR/scheduler-calibration.json"
```

The compiler fails on a partial matrix instead of silently inflating recall.
Use `--allow-incomplete` only for a visibly marked progress report.
`sourcehunt-calibrate` learns action yield, cost, and elapsed-time profiles
from observed proof actions; it does not consume model self-confidence. Apply
the resulting artifact to a later direct run with:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --flow proof \
  --compile-commands compile_commands.json \
  --scheduler-calibration "$CASE_DIR/scheduler-calibration.json" \
  --proof-local-model Qwen3.5-35B \
  --proof-frontier-model YOUR_FRONTIER_MODEL \
  --falsify \
  --gvisor \
  --output-dir "$CASE_DIR/results-proof-calibrated"
```

For another ablation campaign, pass the same artifact to
`clearwing eval sourcehunt-run --scheduler-calibration ...` with a new plan or
checkpoint. The run manifest records its digest and the scheduler records the
profile used in each action's inputs.

After producing every checkout variant declared by the compact manifest,
evaluate causal consistency. The command fails if a session is missing or an
unexpected session is supplied:

```bash
clearwing eval sourcehunt-counterfactual \
  --manifest evaluations/ffmpeg_proof.yaml \
  --session vulnerable="$CASE_DIR/results-proof-blind" \
  --session fixed="$CASE_DIR/results-proof-fixed" \
  --session renamed="$CASE_DIR/results-proof-renamed" \
  --session moved="$CASE_DIR/results-proof-moved" \
  --session guarded="$CASE_DIR/results-proof-guarded" \
  --session unreachable="$CASE_DIR/results-proof-unreachable" \
  --session decoy="$CASE_DIR/results-proof-decoy" \
  --session widened-domain="$CASE_DIR/results-proof-widened" \
  --output "$CASE_DIR/ffmpeg-counterfactual.json"
```

### Legacy PoC Stability Control

If a finding includes a concrete PoC, check its stability classification
in `findings.json`:

```bash
jq '.[] | select(.file | contains("h264_slice")) |
  {id, stability_classification, stability_success_rate, stability_total_runs}' \
  results*/*/findings.json
```

Findings classified as `stable` (≥90% reproduction rate across 3 fresh
containers) are the strongest. `flaky` findings (50–90%) may indicate
ASLR sensitivity or timing dependence. The stability verifier automatically
attempts one hardening round for unreliable PoCs before archival.

### Legacy Four-Axis Validator Control

With the default v2 validator, each finding is evaluated on four
independent axes: REAL, TRIGGERABLE, IMPACTFUL, and GENERAL. Inspect
the validation details:

```bash
jq '.[] | select(.file | contains("h264_slice")) |
  {id, severity, evidence_level, verified,
   validator_real, validator_triggerable, validator_impactful, validator_general}' \
  results*/*/findings.json
```

## Validate Against The Public Fix

Only after the blind pass, fetch and inspect the official fix:

```bash
cd ~/clearwing-cases/ffmpeg-h264/ffmpeg-vuln

git fetch origin 39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89
git diff \
  795bccdaf57772b1803914dee2f32d52776518e2 \
  39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89 \
  -- libavcodec/h264_slice.c
```

The patch rejects excessive slice counts before assigning the next slice
number. A strong Clearwing finding does not need to reproduce the exact patch,
but it should converge on the same invariant: a slice number must never be
allowed to collide with the sentinel value used by the 16-bit slice table.

You can also run a fixed-commit control:

```bash
cd ~/clearwing-cases/ffmpeg-h264/ffmpeg-vuln
git switch --detach 39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89
git clean -fdx

# Repeat the configure + `bear -- make` commands from
# "Build And Capture The Compilation Database" above.

cd ~/clearwing-cases/ffmpeg-h264
export CASE_DIR="$PWD"
export FFMPEG_DIR="$CASE_DIR/ffmpeg-vuln"
export CLEARWING_HOME="$CASE_DIR/.clearwing-fixed-home"

rm -rf "$CLEARWING_HOME" "$CASE_DIR/results-proof-fixed"
mkdir -p "$CLEARWING_HOME" "$CASE_DIR/results-proof-fixed"

clearwing sourcehunt "$FFMPEG_DIR" \
  --flow proof \
  --compile-commands compile_commands.json \
  --build-configuration asan-debug \
  --model-routing local-first \
  --proof-local-model Qwen3.5-35B \
  --proof-frontier-model YOUR_FRONTIER_MODEL \
  --structured-budget 90% \
  --exploration-budget 10% \
  --emit-rejection-certificates \
  --falsify \
  --no-mechanism-memory \
  --gvisor \
  --output-dir "$CASE_DIR/results-proof-fixed"
```

The fixed control should emit a rejection certificate whose decisive
counterevidence is the earlier upper-bound guard. It must not emit the same
finding certificate. Compare the latest obligation revisions and certificate
directories across snapshots; do not add the fix diff to the vulnerable
session after the fact.

The repository also includes `evaluations/ffmpeg_proof.sh`, which automates
the build and vulnerable run. It stops after sealing the vulnerable snapshot
by default. After inspection, set `RUN_FIXED_CONTROL=1` to add the fixed
control. Set `VALIDATION_MANIFEST` only when a retained trigger is available.

## Post-Discovery Learning Flywheel

This is an optional assisted experiment, never part of the blind FFmpeg score.
After a genuinely exploratory candidate has earned a finding certificate and
completed falsification, inspect its typed retrospective before promotion:

```bash
jq . "$SESSION_DIR/learning/retrospectives.json"

clearwing eval sourcehunt-promote \
  --retrospectives "$SESSION_DIR/learning/retrospectives.json" \
  --output "$CASE_DIR/ffmpeg-learning-registry.json"
```

The promotion command ignores ineligible retrospectives. It does not turn raw
model prose into executable policy: the registry contains a content-addressed
structural generator seed, its reviewed binding to installed proof plans, and
vulnerable, guarded/policy, renamed, moved, unreachable, and decoy regression
specifications. Promotion fails if there is no eligible proof-carrying
discovery.

Apply the registry only to a later, explicitly labeled assisted control, such
as a moved/renamed counterfactual or a different repository snapshot:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --flow proof \
  --compile-commands compile_commands.json \
  --proof-learning-registry "$CASE_DIR/ffmpeg-learning-registry.json" \
  --proof-local-model Qwen3.5-35B \
  --proof-frontier-model YOUR_FRONTIER_MODEL \
  --falsify \
  --gvisor \
  --output-dir "$CASE_DIR/results-proof-learned"
```

The run stores the registry and digest as immutable provenance and sets
`blind_boundary.sealed` to `false`. Find the concrete session directory and
compare it with a comparable pre-promotion session:

```bash
LEARNED_SESSION_DIR="$(dirname "$(find "$CASE_DIR/results-proof-learned" \
  -mindepth 2 -maxdepth 2 -name manifest.json -print -quit)")"

clearwing eval sourcehunt-learning-coverage \
  --registry "$CASE_DIR/ffmpeg-learning-registry.json" \
  --before-session "$SESSION_DIR" \
  --after-session "$LEARNED_SESSION_DIR" \
  --output "$CASE_DIR/ffmpeg-learning-coverage.json"
```

The coverage report distinguishes structured rediscovery from the original
exploratory candidate and measures terminal local-only obligation completion
and frontier use for promoted mechanisms only. It reports improvement only
when rediscovery and the count of local-only resolved obligations increase
without a completion-rate regression. Never compare a registry-assisted
result to the strict blind run as if both had the same information boundary.

## Post-Discovery: Elaborate and Disclose

After a successful blind discovery, use the elaboration and disclosure
tools to upgrade the finding and prepare for responsible disclosure.

### Elaborate a Finding

Upgrade a partial finding (e.g., heap overflow → arbitrary write → code
execution) using the interactive (HITL) elaboration agent:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --elaborate <finding_id> \
  --elaborate-session <session_id> \
  --output-dir "$CASE_DIR/results"
```

Or run autonomous elaboration (no human guidance) on a single finding:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --elaborate <finding_id> \
  --elaborate-auto \
  --elaborate-session <session_id> \
  --output-dir "$CASE_DIR/results"
```

Or run autonomous elaboration on the top findings by severity:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --elaborate-top 3 \
  --elaborate-auto \
  --elaborate-session <session_id> \
  --output-dir "$CASE_DIR/results"
```

Use `--elaborate-cap 10%` (default) or `--elaborate-cap 5` to limit
how many findings are elaborated.

### Generate Disclosure Templates

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --depth quick \
  --export-disclosures \
  --reporter-name "Your Name" \
  --reporter-affiliation "Your Org" \
  --reporter-email "you@example.com" \
  --output-dir "$CASE_DIR/results"
```

This writes pre-filled MITRE CVE request and HackerOne templates for
verified findings into the session directory.

### Disclosure Workflow

Queue findings for human review and track disclosure timelines:

```bash
clearwing disclose queue                          # list all pending findings
clearwing disclose queue --state in_review        # filter by disclosure state
clearwing disclose review <finding_id>            # show full review context
clearwing disclose validate <finding_id>          # mark as human-validated
clearwing disclose reject <finding_id> --reason "false positive"
clearwing disclose send <finding_id> \
  --reporter-name "Your Name" \
  --reporter-affiliation "Your Org" \
  --reporter-email "you@example.com"
clearwing disclose status                         # dashboard of all states
clearwing disclose timeline --days 30             # approaching deadlines
clearwing disclose verify <finding_id> --document report.json
clearwing disclose commitments --format markdown  # export commitment log
```

The disclosure system tracks 90-day CVD timelines and creates SHA-3
cryptographic commitments to prove discovery priority.

### Auto-Patch

After discovery, Clearwing can generate and propose patches automatically:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --auto-patch \
  --auto-pr \
  --elaborate-session <session_id> \
  --output-dir "$CASE_DIR/results"
```

`--auto-patch` generates fix patches for validated findings. `--auto-pr`
opens draft pull requests via the `gh` CLI (requires `gh auth login`).

## N-Day Exploit Pipeline (Post-Fix)

After the blind experiment, use the N-day pipeline to develop a working
exploit against the known vulnerability. This is explicitly non-blind:

```bash
cd ~/clearwing-cases/ffmpeg-h264/ffmpeg-vuln
git switch --detach 795bccdaf57772b1803914dee2f32d52776518e2

clearwing sourcehunt "$FFMPEG_DIR" \
  --nday \
  --cve CVE-2025-XXXXX \
  --patch-commit 39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89 \
  --nday-budget deep \
  --exploit-budget deep \
  --output-dir "$CASE_DIR/results-nday"
```

The N-day pipeline builds the vulnerable version, develops a working
exploit using the agentic exploiter with sanitizer instrumentation, and
validates against the patched version.

Budget bands for `--nday-budget` and `--exploit-budget`:
- `standard` — $25 / 1 hour per CVE
- `deep` — $200 / 4 hours per CVE (default)
- `campaign` — $2000 / 12 hours per CVE

For batch N-day runs across multiple CVEs:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --nday \
  --cve-list cves.txt \
  --nday-budget deep \
  --output-dir "$CASE_DIR/results-nday-batch"
```

The `--cve-list` file has one entry per line: `CVE-ID [commit_sha]`.
Or use `--recent-cves --nday-days 90` to auto-discover CVEs from git
history.

## Retro-Hunt (Non-Blind Control)

After the blind experiment, use the fix diff and `sourcehunt --retro-hunt`
to test whether patch-derived variant hunting can rediscover the same
pattern:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --retro-hunt CVE-2025-XXXXX \
  --patch-source 39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89 \
  --patch-repo "$FFMPEG_DIR" \
  --output-dir "$CASE_DIR/results-retro"
```

Retro-hunt generates Semgrep rules from the fix and searches for variant
patterns across the codebase. Do not mix retro-hunt results with
blind-discovery claims.

## CI Integration: Watch and Webhook Modes

For continuous scanning of a repository, Clearwing supports two modes:

### Poll-based (Watch)

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --depth standard \
  --watch \
  --poll-interval 300 \
  --github-checks \
  --output-dir "$CASE_DIR/results-ci"
```

Watch mode polls git for new commits every `--poll-interval` seconds
(default: 300) and re-scans the blast radius. `--github-checks` posts
findings as GitHub check runs via the `gh` CLI. Use
`--max-watch-iterations N` to cap the number of poll cycles (0 = infinite).

### Event-driven (Webhook)

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --depth standard \
  --webhook \
  --webhook-port 8787 \
  --webhook-secret "$GITHUB_WEBHOOK_SECRET" \
  --webhook-allowed-repo FFmpeg/FFmpeg \
  --github-checks \
  --output-dir "$CASE_DIR/results-ci"
```

Webhook mode starts an HTTP server that receives GitHub push events and
runs sourcehunt on each commit. Use `--webhook-allowed-branch main` to
restrict which branches trigger scans.

## Model Override

By default, sourcehunt uses the provider configured via `clearwing setup`.
Override for a single run with:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --depth deep \
  --model claude-sonnet-4-6 \
  --output-dir "$CASE_DIR/results"
```

Or point at a local/alternative endpoint:

```bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --depth deep \
  --base-url http://localhost:11434/v1 \
  --api-key unused \
  --model llama3 \
  --output-dir "$CASE_DIR/results"
```

`--base-url` accepts any OpenAI-compatible API (OpenRouter, Ollama,
LM Studio, vLLM, Together, Groq, etc.). Also settable via the
`CLEARWING_BASE_URL` and `CLEARWING_API_KEY` environment variables.

Passing one `--model` binds every proof role to that override. To measure the
intended local-first policy, configure distinct task routes in
`~/.clearwing/config.yaml`:

```yaml
providers:
  local_qwen:
    base_url: http://localhost:8000/v1
    api_key: unused
    model: Qwen3.5-35B
  frontier:
    base_url: https://your-frontier-endpoint.example/v1
    api_key: ${FRONTIER_API_KEY}
    model: your-frontier-model

routes:
  proof_local: local_qwen
  proof_frontier: frontier
  proof_falsifier: frontier
  proof_exploration: local_qwen
```

`proof_local` receives the first bounded judgment. Only unresolved atomic
questions advance to `proof_frontier`. `proof_falsifier` is a distinct role
with a finite counterexample objective; its failure to find a counterexample
does not count as positive evidence.

## Manual ASan Reproduction

The proof-flow setup already builds FFmpeg with ASan and UBSan. The commands
below are useful when reproducing an emitted trigger manually outside the
Clearwing validation sandbox.

```bash
cd ~/clearwing-cases/ffmpeg-h264/ffmpeg-vuln
git switch --detach 795bccdaf57772b1803914dee2f32d52776518e2

./configure \
  --cc=clang \
  --cxx=clang++ \
  --disable-stripping \
  --disable-doc \
  --disable-optimizations \
  --enable-debug=3 \
  --extra-cflags='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' \
  --extra-ldflags='-fsanitize=address,undefined'

NPROC="$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN)"
make -j"$NPROC"
```

If Clearwing emits a PoC input, run it through the sanitizer-built binary and
keep the ASan report with the finding. Then rebuild at the fixed commit and
confirm the same input no longer reaches the out-of-bounds path.

## Troubleshooting

- `fatal: invalid reference: main`: FFmpeg uses `master`; use the local
  checkout flow above or pass `--branch master` for unpinned scans.
- Docker errors: run `clearwing doctor` and confirm Docker is reachable.
  C/C++ proof extraction fails closed without a sandbox. Add `--gvisor` for
  stronger isolation when the runtime is installed; the Docker default
  runtime remains sandboxed.
- No accepted finding: inspect candidates, completeness, obligations, and
  actions in that order. An incomplete certificate identifies the exact
  missing proof edge. Increase a budget only when the action log shows that
  its cap caused the unresolved state. Use CVE seeds or a campaign hint only
  in a labeled assisted control.
- Too much report noise: query `candidates.jsonl` and the latest obligation
  revisions before reading prose. Rejection certificates are durable negative
  results; incomplete certificates are queued work, not false positives.
- Need a non-blind control: after the blind experiment, use the fix diff and
  `sourcehunt --retro-hunt` to test whether patch-derived variant hunting can
  rediscover the same pattern. Do not mix that result with blind-discovery
  claims.
- Dynamic validation does not run: confirm the manifest command and working
  directory are repository-relative, the trigger is inside the mounted tree,
  the manifest predicate exactly matches an obligation, and its dependencies
  are proven. Non-reproduction leaves the obligation blocked; it does not
  disprove the candidate.
- Slow proof runs: inspect the action log's value-of-information ordering and
  reduce `--proof-max-actions`, `--proof-max-model-calls`, or
  `--proof-max-dynamic-actions`. The residual graph remains reusable.
- Using a different model: pass `--model <name>` to override the default
  provider. For local models, add `--base-url` and `--api-key`.
