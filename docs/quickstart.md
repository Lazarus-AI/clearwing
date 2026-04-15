# Quickstart

## Install

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing
python3 -m venv venv
source venv/bin/activate  # fish: source venv/bin/activate.fish
pip install -e '.[dev]'
```

The `[dev]` extra pulls in pytest + mypy + ruff + build, which is
what CI uses. For a production install, drop the `[dev]`.

Faster alternative if you have [uv](https://docs.astral.sh/uv/)
installed: `uv sync --all-extras` reads `pyproject.toml` + `uv.lock`
and reproduces the locked environment exactly.

## Configure credentials

Clearwing talks to Anthropic by default. Either export the API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Or use an OpenAI-compatible endpoint for local / custom models:

```bash
clearwing interactive \
    --base-url http://localhost:8000/v1 \
    --api-key not-needed \
    --model qwen2.5-coder:32b-instruct
```

## Run a network scan

The simplest operation — scan a single host for open ports, services,
and known vulnerabilities:

```bash
clearwing scan 192.168.1.10
```

Scan a specific port range with service detection:

```bash
clearwing scan 192.168.1.10 -p 22,80,443,8080 --detect-services
```

Scan a whole CIDR in parallel:

```bash
clearwing parallel 192.168.1.0/24 --max-concurrent 10
```

Results are persisted to a SQLite DB at `~/.clearwing/clearwing.db`.
View history:

```bash
clearwing history
clearwing report --session <session_id>
```

## Run a source-hunt pass

Point Clearwing at a cloned repo or a git URL. The hunter will
clone, rank, and analyze files according to the attack-surface
ladder (see [architecture](architecture.md) for how ranking works).

```bash
# Quick pass — static analysis + regex patterns, no LLM, free
clearwing sourcehunt /path/to/repo --depth quick

# Standard pass — sandboxed LLM hunters, adversarial verifier,
# variant loop, mechanism memory, taint analysis. Default.
clearwing sourcehunt https://github.com/example/project \
    --depth standard --budget 5

# Deep pass — adds crash-first harness generation (libFuzzer)
# and auto-patch validation (recompile + rerun PoC). The most
# rigorous mode; expects real build deps in the sandbox.
clearwing sourcehunt /path/to/repo \
    --depth deep --budget 10 --max-parallel 8 \
    --auto-patch
```

Output lives in `./sourcehunt-results/<session_id>/` — SARIF for
IDE integration, markdown for humans, JSON for programmatic consumers.

## Interactive agent

Start a ReAct-loop chat session with the full tool set:

```bash
clearwing interactive
```

The agent will plan, call tools (which may pause for human approval
for anything destructive), and converge on a summary. Sessions are
persisted; resume with:

```bash
clearwing sessions                 # list
clearwing interactive --resume <session_id>
```

## Run the tests

```bash
make test          # pytest -q
make gate          # full CI gate locally: lint + type + test + build
```

## Next

- [**Architecture**](architecture.md) — how the pieces fit together.
- [**CLI reference**](cli.md) — every flag, with examples.
- [**Source-code hunter deep dive**](openglass.md) — the evidence
  ladder, variant loops, mechanism memory, adversarial verifier.
