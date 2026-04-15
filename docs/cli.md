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
  [--budget USD]              # default: 5.0 (USD spend cap)
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
  [-o OUTPUT_DIR]             # default: ./sourcehunt-results
```

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

## `config` — show/edit config

```bash
clearwing config                   # print current config
clearwing config edit              # open ~/.clearwing/config.yaml in $EDITOR
```

## Global flags

- `-h`, `--help` — command-level help
- `--version` *(planned for v1.0)* — print version
- `--log-level debug|info|warning|error` — root logger level
- `--log-file PATH` — redirect logs away from `~/.clearwing/clearwing.log`
