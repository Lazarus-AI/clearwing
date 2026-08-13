# PR #140 SourceHunt resume handoff

Date: 2026-08-13
Branch: `feat/sourcehunt-resume`
PR: https://github.com/Lazarus-AI/clearwing/pull/140
Base: `origin/main` at `d0376498b896a34e32fd19b9ae4364208ce70d32`

## Pause point

The end-to-end resume rewrite is implemented, organized into the four requested
logical commits, and ready for review. The branch was force-pushed to the
existing draft PR after this handoff was written. No exact coroutine, provider
request, sandbox, or mid-agent transcript restoration is claimed.

The recovery invariant is:

> If a valid atomic work result exists, reuse it; otherwise run the work again.

## State authorities

- `session.json` owns schema version, effective behavior-affecting config,
  repository metadata, and exact selected-source identity. It contains no
  provider credentials.
- `rank-plan.json` is written atomically only after the entire ranking pass
  completes successfully. Missing, malformed, interrupted, or degraded ranking
  reruns from pristine preprocessed inputs.
- `work-results/<deterministic-work-id>.json` is the immutable completion proof
  for one hunt item, including successful zero-finding work and bounded context
  needed to reconstruct promotion work.
- `spend-ledger.jsonl` remains the sole authority for lifetime LLM spend.
- One advisory session lock prevents concurrent standalone session writers.
- Campaign `findings_pool.jsonl` remains campaign-owned and is not used as a
  second standalone recovery authority.

The prototype mutable checkpoint/journal implementation was replaced rather
than layered over. There are no persisted pending, in-progress, retryable,
cancelled, or failed work transitions.

## Implemented behavior

- Completed and completed-zero-finding work is restored and skipped.
- Missing, interrupted, malformed, truncated, or ID-mismatched work reruns.
- Unstarted work runs normally.
- Completed findings and cluster descriptors are restored into the live
  `FindingsPool` before unfinished hunters dispatch.
- Promotions are reconstructed recursively from completed parent results using
  persisted bounded transcript context; completed promoted work is not
  duplicated.
- A complete rank plan is restored exactly. Partial or degraded ranking is
  usable only for the current invocation and is never committed as complete.
- Preprocessing is rerun. Source identity hashes the exact selected relative
  paths and complete file bytes. The session output directory is excluded from
  all selected-input analyzers, including imports-by, callgraph, Semgrep, and
  taint. Git commit is metadata only.
- Verification, exploitation, reporting, and later enrichment may rerun.
- Settled spend restores once. Orphaned reservations settle conservatively once
  according to whether a cap was active when reserved. The saved lifetime cap
  is fixed on resume.
- Provider quota exhaustion is distinct from authentication failures, rate
  limits, and budget exhaustion. A run-shared stop state blocks new dispatch,
  sibling tasks unwind safely, committed work remains valid, and the runner
  returns `status="provider_exhausted"` with exit code 3.
- Fresh provider credentials, endpoint, or model may be supplied on resume.
- Lock ownership lives in `arun()`; `run()` does not duplicate it.
- Parent-owned campaign/evaluation runs do not create standalone resume state.
- CLI surface is intentionally narrow: `clearwing sourcehunt --resume SESSION_ID`
  plus runtime provider/model, output-root, live, and logging options.

## Commit structure

Run `git log --oneline --reverse origin/main..HEAD` for the current hashes. The
four commits are:

1. `Stop sourcehunt on provider exhaustion`
2. `Add immutable sourcehunt resume store`
3. `Integrate sourcehunt completion recovery`
4. `Expose sourcehunt resume in the CLI`

## Verification completed

Before the final bounded-cluster simplification:

- Full SourceHunt suite with writable Clearwing home and localhost socket
  permission: `895 passed in 83.62s`
- Affected resume/runner/pool/ranker/spend/preprocessor suite: `226 passed`
- Exact-source analyzer suite: `94 passed`
- Campaign suite: `22 passed`
- Live webhook suite: `22 passed`
- Ruff on every changed Python file: passed
- `git diff --check origin/main`: passed
- Persistence benchmark: 100 atomic result writes and reloads passed in the
  store suite; isolated pytest wall time was `0.37s`

After the final bounded-cluster simplification:

- Resume store, resume pool, and FindingsPool suites: `52 passed`
- Ruff for the touched files: passed
- `git diff --check`: passed

Recommended first command on the next machine:

```bash
git fetch fork feat/sourcehunt-resume
git switch feat/sourcehunt-resume
git reset --hard fork/feat/sourcehunt-resume

pytest -q \
  tests/test_sourcehunt_resume_store.py \
  tests/test_sourcehunt_resume_pool.py \
  tests/test_sourcehunt_resume_runner.py \
  tests/test_sourcehunt_provider_exhaustion.py \
  tests/test_sourcehunt_resume_spend.py \
  tests/test_sourcehunt_resume_cli.py \
  tests/test_sourcehunt_pool_budget.py \
  tests/test_sourcehunt_runner.py \
  tests/test_sourcehunt_ranker.py \
  tests/test_llm_spend_budget.py \
  tests/test_sourcehunt_preprocessor.py \
  tests/test_findings_pool.py \
  tests/test_sourcehunt_subsystem.py
```

For the full suite, use a writable home. Live webhook tests also need permission
to bind localhost sockets:

```bash
CLEARWING_HOME=/tmp/clearwing-test-home pytest -q 'tests/test_sourcehunt*.py'
```

## Remaining review concern

The architecture is materially narrower than the prototype, and the mutable
611-line checkpoint/journal plus 1,101-line grab-bag test were removed. However,
the final diff against `origin/main` is approximately `+3233/-144`, compared
with the prototype's `+3207/-134`. The focused replacement tests and strict
immutable-result validation account for much of the size, but the requested
"materially smaller" raw line-count target is not met. Do not claim otherwise.

`clearwing/sourcehunt/resume.py` is about 658 lines and remains the largest new
production component. Its strict validation is intentional, but it is the
clearest place for a future review-driven simplification if line count must be
reduced without weakening recovery guarantees.

## Important implementation notes

- `ProviderExhaustedError` deliberately subclasses `BaseException`. This keeps
  ordinary broad `except Exception` fallbacks from silently scheduling more paid
  work. Explicit orchestration boundaries catch it; cancellation/telemetry
  boundaries catch `BaseException` only to clean up and re-raise.
- `SourceHuntResumeStore.load_completed_work()` scans result files once per
  store instance and caches them. Each successful work item writes one small
  atomic file; no growing journal is rescanned on the hot path.
- Cluster membership is reconstructed from canonical completed findings. Work
  files persist bounded cluster descriptors only, avoiding O(n²) growth.
- The branch history was rewritten from the actual PR base, so updating the
  existing PR required `git push --force-with-lease fork
  feat/sourcehunt-resume:feat/sourcehunt-resume`.
