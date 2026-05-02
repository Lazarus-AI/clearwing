# CLI reference

```
clearwing [-h] {scan,report,history,config,interactive,graph,sessions,
                ci,parallel,mcp,operate,webui,sourcehunt,disclose,
                campaign,bench,eval} ...
```

Every subcommand supports `-h` / `--help` for flag-level details.
This page is the hand-written complement: it groups commands by
workflow and explains the non-obvious flags.

## `scan` — single-target network scan

```bash
clearwing scan <target>
  [-p PORTS]              # 22,80,443 or 1-1024; default = top 1000
  [--scan-type syn|connect]
  [--threads N]
  [--detect-services]     # banner grab + fingerprint
  [--detect-os]           # TTL + TCP fingerprinting
  [--vuln-scan]           # local CVE DB + NVD API lookup
  [--output FILE]         # write report to FILE (format by extension)
```

Writes to `~/.clearwing/clearwing.db` automatically. Retrieve later
with `clearwing report` or `clearwing history`.

## `sourcehunt` — source-code vulnerability hunting

```bash
clearwing sourcehunt <repo_url_or_path>
  [--branch BRANCH]           # default: main
  [--depth quick|standard|deep]
  [--budget USD]              # default: unlimited; 0 = unlimited
  [--max-parallel N]          # default: 8
  [--tier-split A/B/C]        # default: 70/25/5
  [--no-verify]               # skip the adversarial verifier
  [--no-exploit]              # skip exploit triage
  [--auto-patch]              # opt-in validated patch generation
  [--auto-pr]                 # open draft PRs for validated patches
  [--export-disclosures]      # write MITRE + HackerOne templates
  [--reporter-name NAME]
  [--reporter-affiliation AFFILIATION]
  [--reporter-email EMAIL]
  [--model MODEL_NAME]        # override per-task model selection
  [--base-url URL]            # OpenAI-compat endpoint (OpenRouter, Ollama, ...)
  [--api-key KEY]             # credential for --base-url
  [--output-dir DIR]          # default: ./results/sourcehunt (dev) or ~/.clearwing/results/sourcehunt
  [--format sarif markdown json all]  # default: all
```

See [LLM providers](providers.md) for the full precedence rules and
provider-specific snippets.

Depths:
- **`quick`** — preprocessor + ranker + static findings. No LLM
  hunters. Free. Useful as a sanity check or for CI.
- **`standard`** — adds sandboxed LLM hunters, adversarial verifier,
  patch oracle, mechanism memory, variant loop, exploit triage,
  taint analysis. Default mode.
- **`deep`** — adds the crash-first harness generator (libFuzzer,
  30s per file) and enables auto-patch mode. Most expensive in both
  wall time and tokens.

### Agent & prompt control (specs 001–002)

```bash
  [--agent-mode auto|constrained|deep]  # default: auto (derives from --depth)
  [--prompt-mode unconstrained|specialist]  # default: unconstrained
  [--campaign-hint OBJECTIVE]   # e.g. "bugs reachable from unauthenticated remote input"
  [--exploit]                   # instruct hunters to write exploits inline
```

- **`--agent-mode`**: `auto` derives from depth (standard/deep → full-shell
  agent with execute/read_file/write_file/think tools; quick → constrained
  9-tool hunter). `deep` forces full-shell regardless of depth.
- **`--prompt-mode`**: `unconstrained` uses a simple discovery prompt
  (Glasswing-style); `specialist` uses prescriptive checklists per CWE
  category.

### Band promotion & budget (spec 003)

```bash
  [--starting-band fast|standard|deep]  # override auto band selection
  [--redundancy N]              # override redundancy count for high-ranked files
  [--skip-tier-c]               # disable Tier C propagation audits
```

Three-band promotion system: fast ($2–5), standard ($10–25), deep
($40–100). Auto-promotes when signals (findings, evidence levels) are
detected. Redundancy defaults by rank: rank 5 → 3 runs, rank 4 → 2
runs, else 1.

### Entry-point sharding & seed context (spec 004)

```bash
  [--shard-entry-points]        # shard by function-level entry point
  [--min-shard-rank N]          # minimum file rank for sharding (default: 4)
  [--seed-corpus PATH]          # local seed corpus directory
  [--seed-cves]                 # extract CVE history from git log as seed context
  [--respect-gitignore]         # exclude files matched by the repo root .gitignore
```

For high-ranked files in large projects, shards agents by function-level
entry point (syscall handler, protocol parser, fuzz target, etc.) instead
of whole-file analysis.

### Shared findings pool (spec 005)

```bash
  [--no-findings-pool]          # disable cross-agent findings pool
```

Enabled by default. Cross-agent database with root-cause deduplication
and mid-run primitive queries. Agents can query known primitives
(arbitrary_read, use_after_free, etc.) to chain findings.

### Cross-subsystem hunting (spec 006)

```bash
  [--subsystem-hunt]            # enable cross-subsystem hunting after per-file hunts
  [--subsystem PATH]            # manually specify subsystem directory (repeatable)
  [--no-per-file-hunt]          # skip per-file hunting; only run subsystem hunts
```

Auto-identifies subsystems from ranked files or accepts manual
specification. Runs after per-file hunts with the full findings pool
for cross-file interaction discovery.

### Exploit development (spec 007)

```bash
  [--exploit-budget standard|deep|campaign]  # default: auto from --depth
```

Budget bands: standard=$25/1hr, deep=$200/4hr, campaign=$2000/12hr.
Multi-turn agentic exploiter with environment shaping (recompile with
debug, inject printf, etc.) and mitigation-applicability reasoning.

### Exploit elaboration (spec 008)

```bash
  [--elaborate FINDING_ID]      # interactive HITL session to upgrade a finding
  [--elaborate-auto]            # autonomous elaboration agent (no human guidance)
  [--elaborate-top N]           # elaborate top N findings by severity/primitive
  [--elaborate-cap PERCENT]     # cap at N% of verified findings (default: 10%)
  [--elaborate-session SESSION_ID]  # session to load findings from
  [--elaborate-pipeline]        # enable Stage 1.5 elaboration in the pipeline
```

Human-in-the-loop or autonomous agent for upgrading partial exploits
to higher-impact primitives. Rate-limited to top 10% of findings by
default.

### Validation (spec 009)

```bash
  [--validator-mode v1|v2]      # v1=legacy verifier, v2=4-axis validator (default)
  [--adversarial-threshold LEVEL]  # min evidence to spend verifier budget
  [--no-adversarial]            # use simpler v0.1 prompt
  [--calibrate SESSION_ID]      # interactively assign human severity ratings
```

The v2 validator evaluates four independent axes: REAL, TRIGGERABLE,
IMPACTFUL, GENERAL. Gets only the finding report + PoC (not the
discovery transcript) for independence. Calibration tracking targets
89% agreement with human reviewers.

### PoC stability (spec 010)

```bash
  [--no-stability-check]        # skip PoC stability verification
```

Enabled by default. Runs validated PoCs through 3 fresh containers
(20 runs each, ASLR variation). Classifies as stable (≥90%),
flaky (50–90%), or unreliable (<50%). One hardening attempt for
unreliable PoCs before archival. Race conditions (CWE-362 etc.)
use a lowered 70% threshold with 100 runs.

### Self-security (spec 013)

```bash
  [--gvisor]                    # use gVisor runtime for container isolation
  [--encrypt-artifacts]         # enable encrypted artifact storage
  [--no-behavior-monitor]       # disable behavioral monitoring
```

### Watch & webhook modes

```bash
  [--watch]                     # poll git for new commits and re-scan blast radius
  [--poll-interval N]           # watch poll interval in seconds (default: 300)
  [--max-watch-iterations N]    # max iterations, 0 = infinite
  [--github-checks]             # post findings as GitHub check runs
  [--webhook]                   # HTTP server for GitHub push events
  [--webhook-port PORT]         # default: 8787
  [--webhook-secret SECRET]     # HMAC-SHA256 secret (or GITHUB_WEBHOOK_SECRET env)
```

### Retro-hunt mode

```bash
  [--retro-hunt CVE_ID]         # generate Semgrep rule from a fix and find variants
  [--patch-source PATH_OR_SHA]  # patch diff file or git SHA (required with --retro-hunt)
  [--patch-repo REPO]           # repo to resolve patch SHAs from
```

### Pipeline toggles

```bash
  [--no-variant-loop]           # skip variant hunter loop
  [--no-mechanism-memory]       # skip cross-run mechanism memory
  [--no-patch-oracle]           # skip patch-oracle truth test
```

### `sourcehunt --nday` — N-day exploit pipeline

```bash
clearwing sourcehunt <repo_url_or_path>
  --nday                          # enable N-day pipeline
  [--cve-list CVE-2024-1234,...]  # specific CVEs to target
  [--recent-cves N]               # fetch N most recent CVEs for the project
  [--nday-budget standard|deep|campaign]
  [--patch-commit SHA]            # commit that patches the vuln
```

Builds the vulnerable version of a project, develops working exploits
for known CVEs, and validates against the patched version. Uses the
agentic exploiter with sanitizer instrumentation.

### `sourcehunt --reveng` — reverse engineering pipeline

```bash
clearwing sourcehunt <binary_path>
  --reveng                        # enable reverse engineering pipeline
  [--arch x86_64]                 # target architecture (default: x86_64)
  [--reveng-budget deep|campaign] # budget band (default: deep)
```

Decompiles a closed-source ELF binary via Ghidra headless, reconstructs
plausible source code with an LLM, then hunts vulnerabilities using
hybrid source + binary validation (GDB against the original binary).

## `disclose` — responsible disclosure workflow

```bash
clearwing disclose queue <results_dirs...>    # queue findings for review
clearwing disclose review                     # show next finding for review
clearwing disclose validate <finding_id>      # approve for disclosure
clearwing disclose reject <finding_id>        # reject finding
clearwing disclose send <finding_id>          # mark as sent to vendor
clearwing disclose status                     # dashboard of all findings
clearwing disclose timeline [--finding-id ID] # show/manage disclosure timelines
clearwing disclose verify <finding_id>        # verify SHA-3 commitment
clearwing disclose commitments [--format json|markdown] # list all commitments
```

Human-in-the-loop validation workflow. Generates pre-filled MITRE CVE
request and HackerOne templates. Tracks disclosure timelines with
60/75/90-day alerts. SHA-3 cryptographic commitments prove discovery
priority without revealing vulnerability details.

## `campaign` — campaign-scale orchestration

```bash
clearwing campaign run <config.yaml>       # start a campaign
  [--dry-run]                              # validate config, show plan
clearwing campaign status <config.yaml>    # progress dashboard
clearwing campaign pause <config.yaml>     # pause after current files
clearwing campaign resume <config.yaml>    # resume from checkpoint
clearwing campaign report <config.yaml>    # aggregate report
  [--format sarif|markdown|json|all]
```

Runs sourcehunt across many repositories from a single YAML config.
Features shared budget tracking, per-project checkpointing,
automatic pause/resume, and aggregate reporting.

## `bench` — benchmarking tools

```bash
clearwing bench ossfuzz                    # OSS-Fuzz crash severity benchmark
  --corpus-dir DIR | --targets-file FILE   # target source (one required)
  [--mode quick|standard|full|deep]        # default: standard
  [--output-dir DIR]                       # default: ./results/bench
  [--max-parallel N]                       # default: 4
  [--no-llm-classify]                      # skip LLM tier 3-5 classification
  [--model MODEL] [--base-url URL] [--api-key KEY]

clearwing bench compare <file_a> <file_b>  # compare two result files
  [--format table|json|markdown]
```

5-tier crash severity ladder benchmark (tier 0 = no crash through
tier 5 = full control flow hijack). Modes control scale: `quick`
(100 targets), `standard` (1000), `full` (7000), `deep` (100 x 10 runs).

## `eval` — evaluation and A/B testing

```bash
clearwing eval preprocessing              # A/B test preprocessing pipeline
  --project <repo_url_or_path>
  [--commit SHA]                           # checkout specific commit
  [--configs glasswing_minimal,sourcehunt_full,glasswing_plus_crashes]
  [--budget-per-config USD]                # default: $500
  [--runs N]                               # runs per config (default: 1)
  [--depth quick|standard|deep]            # default: standard
  [--output-dir DIR]                       # default: ./results/eval
  [--ground-truth CVE-ID...]               # known CVEs for recall
  [--model MODEL] [--base-url URL] [--api-key KEY]
  [--format table|json|markdown]

clearwing eval compare <file_a> <file_b>   # compare two eval results
  [--format table|json|markdown]
```

Runs the sourcehunt pipeline under different configurations for the
same (project, model, budget) triple. Compares: findings verified,
false positive rate, cost per finding, CWE diversity. Configurations:

- **glasswing_minimal** — unconstrained prompt, no preprocessing
- **sourcehunt_full** — specialist prompts, full preprocessing
  (callgraph + taint + Semgrep + specialist routing)
- **glasswing_plus_crashes** — minimal + seeded harness crashes

## `interactive` — ReAct-loop chat session

```bash
clearwing interactive
  [--model MODEL_NAME]
  [--base-url URL]            # OpenAI-compatible endpoint
  [--api-key KEY]
  [--resume SESSION_ID]
  [--no-guardrails]           # skip input/output guardrails (dev only)
  [--no-memory]               # skip episodic memory recording
  [--no-audit]                # skip audit log
```

Press Ctrl-C to exit cleanly; the session is persisted and resumable.

## `operate` — autonomous mission mode

```bash
clearwing operate
  --mission MISSION_FILE      # YAML with goals + constraints
  [--budget USD]
  [--max-steps N]
```

Loads a mission plan and runs the Operator agent (goal-directed
multi-step loop, distinct from the interactive ReAct loop) until
the mission succeeds, runs out of budget, or exceeds max steps.

## `parallel` — scan multiple targets concurrently

```bash
clearwing parallel <targets...>
  [--max-concurrent N]        # default: 5
  [--depth basic|standard|deep]
  [--output-dir DIR]
```

`<targets>` can be individual IPs, CIDR ranges, or a file (`-f`).

## `ci` — non-interactive CI/CD entry point

```bash
clearwing ci
  --config CICD_CONFIG.yaml
  [--sarif OUTPUT.sarif]      # write SARIF for GitHub Code Scanning
  [--fail-on critical|high|medium|low]
  [--baseline BASELINE.json]  # fail only on new findings
```

Designed to run inside GitHub Actions / GitLab CI. Zero interactive
prompts; every tool that would normally trigger a guardrail approval
gets denied by default.

## `report`, `history`, `sessions` — inspect prior runs

```bash
clearwing history                   # all sessions, newest first
clearwing sessions                  # all interactive sessions
clearwing report --session <id>    # full report for one session
clearwing report --session <id> -o report.html
```

## `graph` — attack-graph viewer

```bash
clearwing graph                    # TUI viewer
clearwing graph --serve [--port P] # D3.js web viewer on http://localhost:8000
```

Loads from `~/.clearwing/knowledge_graph.json` (populated by every
scan/source-hunt run).

## `mcp` — Model Context Protocol server

```bash
clearwing mcp                      # stdio transport, for IDE/agent integration
```

Exposes the full Clearwing tool set over the MCP stdio protocol.
Claude Desktop, Cline, Continue, and other MCP clients can then
call Clearwing tools from within their chat loop.

## `webui` — REST + WebSocket interface

```bash
clearwing webui                    # default: 127.0.0.1:8000
clearwing webui --host 0.0.0.0 --port 8080
```

FastAPI-based. REST endpoints for session management and metrics;
WebSocket endpoint for live agent streaming. Requires `clearwing[web]`
extras (`pip install -e '.[web]'`).

## `setup` / `init` — interactive provider wizard

```bash
clearwing setup                              # menu-driven
clearwing setup --provider openrouter        # skip the menu
clearwing setup --provider ollama --no-test  # skip the live test
clearwing setup -y                           # skip confirmations
clearwing init                               # alias — same wizard
```

Walks through LLM backend selection, credential entry, optional
connection testing, and persistence to `~/.clearwing/config.yaml`.
The menu currently lists Anthropic, OpenRouter, Ollama, LM Studio,
OpenAI, Together, Groq, Fireworks, DeepSeek, and a "custom
OpenAI-compatible endpoint" catch-all. Safe to re-run — existing
config is shown and can be overwritten.

The wizard offers to store credentials as `${ENV_VAR_NAME}`
references (pulled from your shell at runtime) instead of literal
secrets, so the YAML file never contains an api_key value.

## `doctor` — environment health check

```bash
clearwing doctor                       # full probe with live LLM test
clearwing doctor --skip-llm-invoke     # skip the test prompt
clearwing doctor --json                # machine-readable output for CI
```

Runs ~25 checks across: Python version, clearwing version, LLM
provider resolution (with an optional live test-invoke), filesystem
(`~/.clearwing/` writable, `config.yaml` valid, `clearwing.log`
writable), Docker daemon reachability, external CLI tools (git, rg,
gh, gdb, strace — or dtruss on macOS), optional Python extras
(genai-pyo3, playwright, sentence-transformers, fastapi, pymetasploit3,
chromadb), and network reachability to the configured LLM endpoint. Prints a per-section summary with green-yellow-red
glyphs plus a totals panel at the bottom.

Exit code is 0 when every check is ok/warn and 1 when any check is
in error state — useful in CI pipelines (`clearwing doctor || exit 1`).

## `config` — show/edit config

```bash
clearwing config                   # print current config
clearwing config --show-provider   # print resolved LLM endpoint + source
clearwing config --set-provider \
    base_url=https://openrouter.ai/api/v1 \
    api_key='${OPENROUTER_API_KEY}' \
    model=anthropic/claude-opus-4  # persist to ~/.clearwing/config.yaml
```

## Global flags

- `-h`, `--help` — command-level help
- `-V`, `--version` — print version (`clearwing 1.0.0`)
- `--log-level debug|info|warning|error` — root logger level
- `--log-file PATH` — redirect logs away from `~/.clearwing/clearwing.log`

## Global env vars

- `ANTHROPIC_API_KEY` — Anthropic direct credential (default LLM path)
- `CLEARWING_BASE_URL` — OpenAI-compatible endpoint override (OpenRouter,
  Ollama, LM Studio, vLLM, Together, Groq, etc.)
- `CLEARWING_API_KEY` — credential for the `CLEARWING_BASE_URL` endpoint
- `CLEARWING_MODEL` — model name for the endpoint
- `GITHUB_WEBHOOK_SECRET` — HMAC secret for `sourcehunt --webhook`
