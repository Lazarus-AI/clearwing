# Changelog

All notable changes to Clearwing are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`clearwing setup` / `clearwing init`** — interactive provider
  wizard. Menu-driven selection from 10 backends (Anthropic,
  OpenRouter, Ollama, LM Studio, OpenAI, Together, Groq, Fireworks,
  DeepSeek, custom OpenAI-compatible), per-provider credential
  prompts with `${ENV_VAR}` reference support (so secrets don't land
  in the file), optional live test-invoke before writing, and
  persistence to `~/.clearwing/config.yaml`. `--provider KEY` skips
  the menu for scripted use; `-y` skips confirmations; `--no-test`
  skips the live test. `init` is a dispatcher alias for the same
  command.
- **`clearwing doctor`** — environment health check. Runs ~25
  probes across: Python version (`>=3.10`), clearwing version,
  LLM provider resolution + optional live test-invoke, filesystem
  (`~/.clearwing/` writable, `config.yaml` valid YAML, log file
  writable), Docker daemon reachability, external CLI tools (git,
  ripgrep, gh, gdb, strace), optional Python extras (langchain-ollama,
  langchain-google-genai, playwright, sentence-transformers, fastapi,
  pymetasploit3, chromadb), and TCP/DNS reachability to the currently-
  configured LLM endpoint. Per-section Rich tables with green/yellow/
  red glyphs and actionable hints. `--json` emits machine-readable
  output for CI use. Exit 0 on ok/warn, 1 on any err.
- **`clearwing/providers/catalog.py`** — shared `ProviderPreset`
  dataclass + `PROVIDER_PRESETS` tuple listing every known backend
  with its base URL, default model, docs URL, and env-var convention.
  Consumed by both the setup wizard and the doctor command so
  adding a new provider means one catalog entry.
- **Subcommand alias mechanism** — command modules can declare an
  `ALIASES: tuple[str, ...]` to route extra names through the same
  handler (e.g. `clearwing init` dispatches to `setup`).
- **`tests/test_setup_and_doctor.py`** — 27 tests across 10 classes
  covering catalog completeness, secret-masking, YAML write merging
  (preserves unrelated sections, doesn't bloat with default ports),
  doctor result aggregation, individual doctor checks (Python,
  filesystem, optional extras, LLM credentials with/without env
  vars), and the doctor handle()'s exit-code logic (err → 1,
  ok/warn → 0).

- **Multi-provider LLM support**. Clearwing now talks to any
  OpenAI-compatible endpoint — OpenRouter, Ollama (`/v1`),
  LM Studio, vLLM, Together, Groq, Fireworks, DeepSeek, OpenAI
  direct — in addition to the original Anthropic-direct path.
  Every command that builds an LLM (`interactive`, `sourcehunt`,
  `operate`, `ci`, `parallel`, `scan`) threads through a single
  `resolve_llm_endpoint()` helper so the configuration precedence
  is identical across the tool.
- **Three ways to configure the provider**, with clear precedence:
  1. CLI flags: `--base-url`, `--api-key`, `--model`
  2. Env vars: `CLEARWING_BASE_URL`, `CLEARWING_API_KEY`, `CLEARWING_MODEL`
  3. Config file: `~/.clearwing/config.yaml` `provider:` section
  4. Default: Anthropic direct via `ANTHROPIC_API_KEY`
- **`clearwing config --set-provider`** — one-line provider setup
  that persists to `~/.clearwing/config.yaml` without editing YAML
  by hand. Accepts `base_url=...`, `api_key=...`, `model=...`
  pairs. Supports `${ENV_VAR}` interpolation for the api_key so
  secrets stay out of the file.
- **`clearwing config --show-provider`** — prints the effective
  resolved endpoint (model / base_url / source) for debugging why a
  particular backend was chosen.
- **`docs/providers.md`** — copy-paste snippets for every supported
  backend, including per-task routing for source-hunt runs
  ("hunter on OpenRouter Opus, verifier on local Qwen for
  cross-provider independence").
- **`ProviderManager.for_endpoint(endpoint)`** factory — constructs
  a manager where every task (`ranker`/`hunter`/`verifier`/
  `sourcehunt_exploit`/`default`) routes to one cached LLM instance.
  The common "one endpoint for everything" case.
- **`ProviderManager.from_config(cfg)`** factory — reads a parsed
  YAML `providers:` + `routes:` + `task_models:` section and builds
  the multi-endpoint routing the plan's §Provider routing section
  describes.
- **`clearwing --version`** / **`-V`** flag (was missing — just
  `clearwing --help` existed).
- **`[ollama]` optional-dependencies extra** — `pip install
  clearwing[ollama]` adds `langchain-ollama` for the native Ollama
  transport (the OpenAI-compat endpoint at `http://localhost:11434/v1`
  works out of the box without this).
- **`[google]` optional-dependencies extra** — `pip install
  clearwing[google]` adds `langchain-google-genai` for Gemini.
- **`tests/test_providers_env.py`** — 32 tests covering the CLI/env/
  config/default precedence ladder, default-model guessing from
  known hosts, api_key placeholder behavior, `LLMEndpoint` helper
  properties, and both `ProviderManager.for_endpoint` /
  `from_config` factories.

### Fixed

- **`clearwing scan` returned 0 open ports for unprivileged users**.
  `ScanConfig.scan_type` defaulted to `"syn"`, which routed every
  probe through scapy's raw-socket SYN scan in
  `clearwing/scanning/port_scanner.py`. Without root (or `CAP_NET_RAW`)
  scapy silently dropped every packet ("No route found for IPv4
  destination ...") and the report showed a blank port list in
  ~80 ms even when the target had ports open. Default is now
  `"connect"` (TCP connect, equivalent to `nmap -sT`); SYN remains
  available by explicit opt-in. `PortScanner.scan` also emits a
  one-shot WARNING when a raw-socket scan type is requested by an
  unprivileged process so the failure is no longer silent.
- **`VulnerabilityScanner` NVD timeouts dumped multi-frame
  tracebacks** to the user terminal. The previous
  `logger.warning(..., exc_info=True)` in `_query_nvd` rendered the
  full aiohttp call stack on every routine network timeout. Replaced
  with a single-line WARNING (`"NVD API query timed out for 'HTTP'"`
  for `asyncio.TimeoutError`; class + message for other exceptions);
  full traceback is now emitted at DEBUG only.
- **`Unclosed client session` aiohttp warning at end of every scan**.
  `VulnerabilityScanner` lazily allocated an `aiohttp.ClientSession`
  but `CoreEngine._vulnerability_scan` never called the scanner's
  `close()`. Wrapped the scanner usage in `try/finally:
  await scanner.close()` so the session is reliably cleaned up.
- **Scan report rendered service versions as `vNone` / `vVercel`**.
  `ReportGenerator._generate_text` formatted versions with a naive
  `f"{service} v{version}"`, producing `HTTP vNone` when no version
  was captured and `HTTP vVercel` when the regex pulled a server
  name out of a `Server:` header instead of a real version. New
  `_format_service_label` helper omits the version when missing,
  prefixes with `v` only when the value starts with a digit, and
  parenthesises non-version labels (e.g. `HTTP (Vercel)`,
  `HTTP v2.4.41`).
- **`clearwing config --set-provider` config.yaml bloat regression**.
  The prior `cli.config.save()` path dumped the full merged default
  config (including the 1024-port scanning defaults) into
  `~/.clearwing/config.yaml`, ballooning the file to ~1000 lines for
  a 3-key write. Both `setup` and `config --set-provider` now read
  the existing YAML, merge in the `provider:` section, and write
  back — preserving unrelated sections untouched and keeping the
  file compact.

### Changed

- **`langchain-openai` is now a runtime dependency**, not a lazy
  `try/except ImportError` import. Every OpenAI-compatible endpoint
  works out of the box after `pip install clearwing` — no extra
  install needed for OpenRouter / Ollama / LM Studio / vLLM.
- **`clearwing sourcehunt` gains `--base-url` and `--api-key` flags**
  and threads them through to `SourceHuntRunner` via the new
  `ProviderManager.for_endpoint()` path. Previously sourcehunt was
  hardcoded to Anthropic.
- **`clearwing interactive` preflight** — "no ANTHROPIC_API_KEY"
  error message now lists all three credential sources (env var,
  CLEARWING_* triple, CLI flags) and points at `docs/providers.md`.
- **`~/.clearwing/config.yaml`** is auto-discovered on `Config()`
  construction. Previously only explicit `Config(path)` worked.
- **README install block** documents the full provider matrix
  alongside the `pip install git+...@v1.0.0` tagged-release path.

## [1.0.0] — 2026-04-14

First tagged release under the `clearwing` name. Covers the full
Phase 0–6 refactor that took the project from "works on my machine"
to a shippable release: rebrand from `vulnexploit`, shim demolition,
Finding-type unification, tools reorganization, graph hardening, full
CI gate, release-hygiene scaffolding, and MkDocs documentation site.

### Added

- **Release hygiene scaffolding**: `SECURITY.md` responsible-disclosure
  policy, `CONTRIBUTING.md` dev-setup and PR-checklist guide,
  `CHANGELOG.md` (this file), `py.typed` PEP 561 marker so downstream
  consumers get Clearwing's type information, `dependabot.yml` for
  pip + GitHub Actions (grouped weekly updates), `.github/ISSUE_TEMPLATE/`
  bug and feature templates with security-lane routing.
- **Docs site** (MkDocs Material): `docs/index.md`, `docs/quickstart.md`,
  `docs/architecture.md`, `docs/cli.md`, `docs/api.md` (mkdocstrings
  autogen). Built with `mkdocs build --strict`, deployed to GitHub
  Pages via a paths-filter-gated workflow.
- **`uv.lock`** — 4446-line lockfile pinning 154 packages against
  Python 3.12 for bit-for-bit reproducible dev environments via
  `uv sync --all-extras`.
- **`Makefile`** with `test / lint / type / build / clean / install-dev /
  gate / all / docs / docs-serve` targets that mirror the CI gate
  exactly. `make gate` is the local mirror.
- **`clearwing/capabilities.py`** — runtime detection of optional
  subsystems (guardrails, memory, telemetry, events, audit, knowledge)
  exposed as a `capabilities.has(name)` API. Replaces six
  `try/except ImportError` blocks in `clearwing/agent/graph.py`.
- **`tests/test_tool_registry.py`** — snapshot test locking
  `get_all_tools()` at 63 tools with stable names and no duplicates,
  so tool reorgs can't silently drop coverage.
- **`LICENSE`** file at the repo root (the project was MIT-declared in
  `pyproject.toml` but missing the file).

### Changed

- **Package rebranded** from `vulnexploit` to `clearwing`. The
  on-disk package, PyPI name, CLI command, logger names, DB/log
  file names, config paths, and GitHub repo URL all flipped in one
  atomic commit. Existing `~/.vulnexploit/` state on user machines
  will NOT carry over — Clearwing reads from `~/.clearwing/` and
  treats the old path as absent. Back up first if you need the old
  state. The new canonical remote is
  `git@github.com:Lazarus-AI/clearwing.git`.
- **Finding types unified**. The sourcehunt `SourceFinding` TypedDict
  is gone, replaced by the `clearwing.findings.Finding` dataclass
  used across network and source-hunt pipelines. Two unrelated
  `Finding` classes renamed to eliminate the collision:
  `clearwing/analysis/source_analyzer.py::Finding` → `AnalyzerFinding`,
  `clearwing/safety/scoring/dedup.py::Finding` → `DedupRecord`. A
  transitional dict-style access shim on the `Finding` dataclass
  (`__getitem__`, `__setitem__`, `get()`, `__contains__`) keeps test
  fixtures that use dict literals working.
- **`clearwing/agent/tools/`** reorganized into seven domain
  subdirectories: `scan/`, `exploit/`, `hunt/`, `recon/`, `ops/`,
  `data/`, `meta/`. The top-level `__init__.py` is now a pure
  aggregator. `get_all_tools()` still returns the same 63 tools in
  the same order.
- **`clearwing/agent/tools/hunt/hunter_tools.py`** (791-LOC god file)
  split into four focused files under `hunt/`: `sandbox.py`
  (`HunterContext` + variant routing, 105 LOC), `discovery.py` (4
  read-only FS probes, 226 LOC), `analysis.py` (4 sandboxed
  build/execute tools, 435 LOC), `reporting.py` (`record_finding`,
  85 LOC). Largest file in the subpackage is now 435 LOC, down from
  791. The `hunt/__init__.py` aggregator composes the four builders
  in the original tool order so the tool-registry snapshot stays
  green.
- **`graph.py` hardened**: six `try/except ImportError` blocks that
  stored `None` on failure replaced with unconditional imports plus
  a `capabilities.has(name)` gate. Static analysis tools now see
  real symbols instead of `Optional[None]` fallbacks.
- **CI gate expanded**: `ruff check`, `ruff format --check`, scoped
  mypy (findings + sourcehunt + capabilities + agent/tools + core),
  `pytest -q --strict-markers --strict-config`, `python -m build`,
  `twine check` — all six steps run on every push/PR across Python
  3.10, 3.11, 3.12.
- **Typed-core policy**: `disallow_untyped_defs = true` +
  `warn_unused_ignores = true` enforced on `clearwing.findings.*`,
  `clearwing.capabilities`, `clearwing.sourcehunt.*`,
  `clearwing.agent.tools.*`, and `clearwing.core.*` — 68 source files
  at zero mypy errors. No `# type: ignore[no-untyped-def]`
  suppressions; every annotation is real.
- **README** trimmed from 508 → 139 lines. Tagline, install,
  quickstart, architecture diagram, docs table, reporting lanes,
  license. Full detail moved to `docs/`.
- **All 22 deprecated shim packages deleted** (`vulnexploit.scanners`,
  `vulnexploit.exploiters`, `vulnexploit.payloads`, and 19 others).
  Canonical paths under `clearwing.scanning.*`,
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
- **`_walk_ast_for_taint` signature** in `sourcehunt/taint.py` falsely
  claimed `source_text: str` when the caller passed raw bytes on
  purpose (for tree-sitter byte offsets under multi-byte UTF-8 source).
  Signature now honestly declares `bytes | str`.
- **Evidence-ladder threshold types**: `adversarial_threshold`,
  `PATCH_GATE`, and `min_evidence_level` across `verifier.py`,
  `patcher.py`, `disclosure.py`, and `runner.py` are now typed as
  the `EvidenceLevel` `Literal[...]` instead of plain `str`.
- **Implicit Optional cleanup**: 23 `param: X = None` sites across
  `core/*`, `agent/tools/*` converted to `param: X | None = None`
  (mypy's `no_implicit_optional` default). Paired with 5 real
  arg-type mismatch fixes (`ports or []`, `credentials or {}`,
  `payload or ""`, `wordlist or []`, `options or {}`) where the
  downstream API required non-None.
- **`EventBus._handlers` / `_lock`** instance attributes — the
  singleton stores them via `__new__`, which mypy doesn't pick up
  without explicit class-level declarations. Added them.
- **`dynamic_tool_creator.py`** `importlib.util.spec_from_file_location()`
  returns `ModuleSpec | None`; added a guard that short-circuits to
  a structured failure response if the spec/loader are None instead
  of crashing on `module_from_spec()`.
- **`browser_tools.py`** `_browser_state` typed as `dict[str, Any]`
  with a local `browser =` binding in `_ensure_browser` so the
  chained `.new_context(...)` call type-checks.
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

- **`vulnexploit`** package, CLI, module, and every reference. See
  the `Changed` section for migration notes.
- **`hunter_tools.py`** (the 791-LOC god file) deleted in favor of
  the `hunt/{sandbox,discovery,analysis,reporting}.py` split.
- **`.reference/`** dangling gitlinks — 5 submodule pointers
  (cai, shannon, pentagi, PentestGPT, strix) that were started as
  submodules but never wired up with `.gitmodules` or
  `.git/modules/`. Dropped from the index with `git rm --cached` in
  a normal commit (no history rewrite was needed — the 857 MB lived
  in the operator's working tree, not in git history). Operators can
  still clone external projects into `.reference/<name>` locally;
  `.gitignore` covers the path.

[Unreleased]: https://github.com/Lazarus-AI/clearwing/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Lazarus-AI/clearwing/releases/tag/v1.0.0
