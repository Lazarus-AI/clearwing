# CLI reference

```
clearwing [-h] {scan,report,history,config,interactive,graph,sessions,
                ci,parallel,mcp,operate,webui,sourcehunt} ...
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
  [--disclosure-reporter-name NAME]
  [--disclosure-reporter-affiliation AFFILIATION]
  [--disclosure-reporter-email EMAIL]
  [--model MODEL_NAME]        # override per-task model selection
  [--base-url URL]            # OpenAI-compat endpoint (OpenRouter, Ollama, ...)
  [--api-key KEY]             # credential for --base-url
  [-o OUTPUT_DIR]             # default: ./sourcehunt-results
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
gh, gdb, strace — or dtruss on macOS), optional Python extras (langchain-ollama,
langchain-google-genai, playwright, sentence-transformers, fastapi,
pymetasploit3, chromadb), and network reachability to the configured
LLM endpoint. Prints a per-section summary with green-yellow-red
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
