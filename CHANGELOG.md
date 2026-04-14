# Changelog

All notable changes to Clearwing are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Release hygiene scaffolding**: `SECURITY.md` responsible-disclosure
  policy, `CONTRIBUTING.md` dev-setup and PR-checklist guide,
  `CHANGELOG.md` (this file), `py.typed` PEP 561 marker so downstream
  consumers get Clearwing's type information, `dependabot.yml` for
  pip + GitHub Actions, `.github/ISSUE_TEMPLATE/` bug and feature
  templates.
- **Docs site** (MkDocs Material): `docs/index.md`, `docs/quickstart.md`,
  `docs/architecture.md`, `docs/cli.md`, `docs/api.md` (mkdocstrings
  autogen), served via GitHub Pages.
- `Makefile` with `test / lint / type / build / clean / install-dev /
  gate / all` targets that mirror the CI gate exactly.
- `clearwing/capabilities.py` — runtime detection of optional subsystems
  (guardrails, memory, telemetry, events, audit, knowledge) exposed as
  a `capabilities.has(name)` API.
- `tests/test_tool_registry.py` — snapshot test locking
  `get_all_tools()` at 63 tools with stable names and no duplicates,
  so tool reorgs can't silently drop coverage.
- `LICENSE` file at the repo root (the project was MIT-declared in
  `pyproject.toml` but missing the file).

### Changed

- **Package rebranded** from `vulnexploit` to `clearwing`. The
  on-disk package, PyPI name, CLI command, logger names, DB/log
  file names, config paths, and GitHub repo URL all flipped in one
  atomic commit. Existing `~/.vulnexploit/` state on user machines
  will NOT carry over — Clearwing reads from `~/.clearwing/` and
  treats the old path as absent. Back up first if you need the old
  state. The old `quixi-ai/totally-super-boring` repo was left in
  place; the new canonical remote is
  `git@github.com:Lazarus-AI/clearwing.git`.
- **Finding types unified**. The sourcehunt `SourceFinding`
  TypedDict is gone, replaced by the `clearwing.findings.Finding`
  dataclass used across network and source-hunt pipelines. Two
  unrelated `Finding` classes renamed to eliminate the collision:
  `clearwing/analysis/source_analyzer.py::Finding` →
  `AnalyzerFinding`, `clearwing/safety/scoring/dedup.py::Finding`
  → `DedupRecord`. A transitional dict-style access shim on the
  `Finding` dataclass keeps test fixtures that use dict literals
  working.
- **`clearwing/agent/tools/`** reorganized into seven domain
  subdirectories: `scan/`, `exploit/`, `hunt/`, `recon/`, `ops/`,
  `data/`, `meta/`. The top-level `__init__.py` is now a pure
  aggregator. `get_all_tools()` still returns the same 63 tools in
  the same order.
- **`clearwing/agent/tools/hunt/hunter_tools.py`** (791 LOC god file)
  split into four focused files under `hunt/`: `sandbox.py`
  (`HunterContext` + variant routing, 105 LOC), `discovery.py`
  (4 read-only FS probes, 226 LOC), `analysis.py` (4 sandboxed
  build/execute tools, 435 LOC), `reporting.py` (`record_finding`,
  85 LOC). Largest file in the subpackage is now 435 LOC, down from
  791. No public-API changes; the `hunt/__init__.py` aggregator
  composes the four builders in the original tool order so the
  Phase 4a registry snapshot stays green.
- **`graph.py` hardened**: six `try/except ImportError` blocks that
  stored `None` on failure replaced with unconditional imports plus
  a `capabilities.has(name)` gate. Static analysis tools now see
  real symbols instead of `Optional[None]` fallbacks.
- **CI gate expanded**: `ruff check`, `ruff format --check`, scoped
  mypy (`clearwing.findings` + `clearwing.sourcehunt` +
  `clearwing.capabilities`), `pytest -q --strict-markers
  --strict-config`, `python -m build`, `twine check` — all five
  steps run on every push/PR across Python 3.10, 3.11, 3.12.
- **All 22 deprecated shim packages deleted** (`vulnexploit.scanners`,
  `vulnexploit.exploiters`, `vulnexploit.payloads`, and 19 others).
  The canonical paths under `clearwing.scanning.*`,
  `clearwing.exploitation.*`, etc. are the only way to import these
  modules. A `DeprecationWarning`-as-error filter in `conftest.py`
  locks the trunk against accidental re-introduction.

### Fixed

- **`ChatAnthropic(model=model)` → `ChatAnthropic(model_name=model)`**
  in `clearwing/sourcehunt/runner.py::_build_llm_from_model_string`.
  The `model=` kwarg was removed in recent `langchain-anthropic`; the
  old call site would have raised `TypeError` on first use of
  `--model <name>` on the sourcehunt CLI.
- **Variable-shadowing type confusion** in `sourcehunt/runner.py`
  where `for f in files` (a FileTarget loop) leaked its narrowing
  into later `for f in all_findings` (a Finding loop). Loop variables
  renamed to disambiguate.
- **`_walk_ast_for_taint` signature** in `sourcehunt/taint.py`
  falsely claimed `source_text: str` when the caller passed raw
  bytes on purpose (for tree-sitter byte offsets under multi-byte
  UTF-8 source). Signature now honestly declares `bytes | str`.
- **Evidence-ladder threshold types**: `adversarial_threshold`,
  `PATCH_GATE`, and `min_evidence_level` across `verifier.py`,
  `patcher.py`, `disclosure.py`, and `runner.py` are now typed as
  the `EvidenceLevel` `Literal[...]` instead of plain `str`, so
  `evidence_at_or_above(level, threshold)` type-checks at every call
  site.
- **Python 3.10–3.12 `NameError`** in
  `clearwing/scanning/os_scanner.py` from a bare `except` pattern
  that 3.13 tolerated but earlier versions didn't.
- **225 tracked `__pycache__` files** removed from git. A new
  `.gitignore` keeps them out for good.
- **Build backend** in `pyproject.toml` fixed from the hallucinated
  `setuptools.backends._legacy:_Backend` to the real
  `setuptools.build_meta`. `python -m build` now produces a valid
  wheel + sdist.

### Removed

- **`.reference/`** (857 MB of vendored upstream projects) purged
  from git history via `git filter-repo`. Fresh clones drop from
  ~900 MB to <50 MB. Anyone with an existing clone of the old
  history needs to re-clone — `git pull` won't reconcile a
  rewritten history.
- **`vulnexploit`** package, CLI, module, and every reference. See
  the `Changed` section for migration notes.
- **`hunter_tools.py`** (the 791-LOC god file) deleted in favor of
  the `hunt/{sandbox,discovery,analysis,reporting}.py` split. The
  `hunt/__init__.py` aggregator preserves the existing public API.

## [1.0.0] — unreleased

First tagged release under the `clearwing` name. See
`[Unreleased]` above for the full change list; this section will
be filled in when `git tag v1.0.0` is cut.

[Unreleased]: https://github.com/Lazarus-AI/clearwing/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Lazarus-AI/clearwing/releases/tag/v1.0.0
