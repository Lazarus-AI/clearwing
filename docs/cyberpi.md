# CyberPi

CyberPi is Clearwing's opt-in Sourcehunt engine built on the small Pi agent
harness. It changes only per-file discovery: ranking, isolation, validation,
budget accounting, reporting, and every native default remain Clearwing-owned.

## Install and verify

CyberPi requires Node.js 22.19 or newer. A full repository hunt also requires
a running Docker daemon; the smoke test and paired benchmark do not.

```bash
clearwing cyberpi install
clearwing cyberpi doctor
```

The installer uses the packaged lockfile and installs Pi 0.84.1 under
`~/.clearwing/cyberpi/pi-0.84.1`. It never writes npm dependencies into the
Python package or the current repository. `clearwing cyberpi doctor --json`
provides an unstyled, machine-readable preflight for CI and support scripts.

## Configure a model

CyberPi uses the normal Clearwing provider resolution. Configuration and
environment variables are preferable to putting a credential in shell history:

```bash
export CLEARWING_BASE_URL=https://provider.example/v1
export CLEARWING_API_KEY="$PROVIDER_API_KEY"
export CLEARWING_MODEL=provider-model-id

clearwing cyberpi smoke
```

Model identifiers are sent to the provider exactly as configured and may be
case-sensitive. If the provider returns “model not found,” copy the identifier
from that provider's model listing instead of changing its case.

The smoke command performs one bounded inference against an in-memory vulnerable
C fixture. It validates Node → Pi → provider → Clearwing tool routing without
Docker. A successful integration can still report a behavioral miss; that means
the harness ran correctly but the model did not identify the known issue.

## Compare the harnesses

```bash
clearwing cyberpi benchmark --runs 3 --max-turns 4
```

The paired micro-benchmark runs the native and CyberPi engines with the same
model, system prompt, tool definitions, positive/negative source fixtures,
turn cap, and 4,096-token per-turn output cap. Replicate order alternates to
reduce ordering bias. It writes:

- a JSON result with per-arm accuracy, tokens, reported cost and its basis, duration,
  stop reason, and errors;
- a compact Markdown summary; and
- complete JSONL trajectories containing the prompt, assistant reasoning/text,
  tool calls, tool results, usage, and final findings.

By default these live under `results/bench/cyberpi/` in a development checkout
or `~/.clearwing/results/bench/cyberpi/` from an installed package. Use
`--output-dir` to choose an exact destination.

This is a harness integration and regression benchmark, not a CVE recall claim.
Use several runs, inspect trajectories, and evaluate on a held-out vulnerability
corpus before promoting a prompt or CyberPi change. The JSONL records are also
the input artifact to retain for GEPA-style prompt optimization.

The native arm's dollar value uses Clearwing's built-in price estimate, while
CyberPi reports Pi's provider/model cost. Compare token counts unless both arms
have the same explicit endpoint pricing; the report records each cost basis.

## Run Sourcehunt with CyberPi

```bash
clearwing sourcehunt /path/to/repository \
  --depth deep \
  --hunt-engine cyberpi \
  --budget 25
```

CyberPi requires the deep tool set (`--depth standard` or `deep`, or an explicit
`--agent-mode deep`) and an isolated Docker-backed HunterSandbox. Clearwing runs
the CyberPi/Node/Docker preflight before preprocessing, so missing prerequisites
fail quickly with the command needed to fix them.

CyberPi is intentionally locked down: Pi receives only Clearwing's
`execute`, `read_file`, scratch-only `write_file`, `record_trace_step`, and
`record_finding` tools. Pi extensions, skills, prompts, sessions, retries,
compaction, and built-in tools are disabled. Only structured findings recorded
through the Clearwing tool boundary enter Sourcehunt results.

## Troubleshooting

```bash
clearwing cyberpi doctor
clearwing cyberpi install --force
clearwing cyberpi smoke --max-turns 2
```

- **Node is too old:** install Node 22.19+ and rerun the installer.
- **Pi SDK is missing or mismatched:** run `clearwing cyberpi install --force`.
- **Docker is a warning:** smoke and benchmark work; start Docker before
  `sourcehunt --hunt-engine cyberpi`.
- **Provider/model failure:** verify the configured endpoint and the exact,
  case-sensitive model identifier. Clearwing never persists the CLI API key.
