# Contributing to Clearwing

Thanks for wanting to help. This doc covers dev setup, the CI gate,
the PR checklist, and commit style.

## Dev setup

Clearwing targets Python 3.10+. The fastest path to a working dev
environment:

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing
python3 -m venv venv
source venv/bin/activate  # fish users: source venv/bin/activate.fish
make install-dev
```

`make install-dev` runs `pip install -e '.[dev]' build twine ruff`
against the active interpreter. Once it finishes, `clearwing --help`
should work and `make test` should pass.

If you prefer `uv` over pip, `uv sync --all-extras` reproduces the
locked environment from `uv.lock`.

## The local gate

Every PR is expected to pass `make gate` locally before it's opened.
That target mirrors CI exactly:

```bash
make gate
```

which is shorthand for:

```bash
make lint          # ruff check + ruff format --check
make type          # scoped mypy on the typed-core modules
make test-strict   # pytest -q --strict-markers --strict-config
make build         # python -m build + twine check
```

Individual targets:

| Target | What it runs |
|---|---|
| `make lint` | `ruff check clearwing/ tests/` + `ruff format --check clearwing/ tests/` |
| `make format` / `make fmt` | `ruff format` + `ruff check --fix` (writes changes) |
| `make type` | `mypy --follow-imports=silent clearwing/findings clearwing/sourcehunt clearwing/capabilities.py` |
| `make test` | `pytest -q` |
| `make test-strict` | `pytest -q --strict-markers --strict-config` (CI mode) |
| `make build` | `python -m build` + `twine check dist/*` (auto-cleans first) |
| `make clean` | wipes `dist/`, `build/`, `*.egg-info/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `.mypy_cache/` |

If `make gate` is green locally, CI will be green remotely. If it's
red locally, fix before pushing — CI won't give you anything new.

## PR checklist

Before opening a PR, confirm:

- [ ] `make gate` passes locally.
- [ ] New tests cover the change. For bug fixes, add a regression
      test that fails on main without the fix. For features, add a
      test that exercises the golden path and at least one edge case.
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` describing
      what changed (one bullet, user-facing language).
- [ ] `pyproject.toml` version is **not** bumped in the PR — version
      bumps happen on the release branch, not per-PR.
- [ ] No secrets, credentials, API keys, or customer data in the
      diff. Grep for `api_key`, `password`, `token`, `BEGIN` before
      committing if you're unsure.
- [ ] Commit messages follow the style below.

## Commit message style

Short, declarative subject line. Body explains **why**, not **what**
(the diff already tells you what).

```
Phase 5c: extract analysis tools to hunt/analysis.py

Third of four commits splitting hunter_tools.py.

Moves `compile_file`, `run_with_sanitizer`, `write_test_case`,
`fuzz_harness` into a `build_analysis_tools(ctx)` factory so each
workflow phase (discovery, analysis, reporting) lives in its own
file. The tool-registry snapshot test stays green because the
aggregator composes the four builders in the original order.

Co-Authored-By: ...
```

Rules:
- Imperative subject ("Add X", not "Added X").
- Keep the subject under 72 chars.
- Wrap the body at ~72 chars too — `git log` on a terminal doesn't
  soft-wrap, and neither do most code-review tools.
- Reference the phase number (`Phase 5c:`) for refactor work that
  tracks against the [refactor plan](https://github.com/Lazarus-AI/clearwing/blob/main/docs/refactor-plan.md).
- If the change has a non-obvious reason (avoided a race, worked
  around a library bug, responds to a code review concern) —
  explain it. Future-you will want to know.

## Branch naming

```
<kind>/<short-slug>
```

Where `<kind>` is one of:
- `feat/` — new feature or user-visible capability
- `fix/` — bug fix
- `refactor/` — internal restructuring with no behavior change
- `docs/` — docs-only change
- `test/` — test-only change
- `chore/` — tooling, CI, dependency bumps

Example: `refactor/hunt-split-discovery-tools`

## Running against a real target

Clearwing is an offensive-security tool. Do not run it against
systems you don't own or aren't explicitly authorized to test.
See `SECURITY.md` for the distinction between "vulnerabilities in
Clearwing" (report to us) and "vulnerabilities Clearwing finds in
other software" (report to that vendor).

## Reporting vulnerabilities in Clearwing itself

See [`SECURITY.md`](SECURITY.md). **Don't** open a public issue for
security impact — use GitHub Security Advisories or email the
maintainer.
