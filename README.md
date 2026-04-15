# Clearwing

By Eric Hartford, Lazarus AI

**Autonomous vulnerability scanner and source-code hunter built on
LangGraph.**

Clearwing is a dual-mode offensive-security tool:

- **Network-pentest agent** — a ReAct-loop agent with 63 bind-tools
  that scans live targets, detects services and vulnerabilities,
  runs sandboxed Kali tools, attempts exploits (gated through a
  human-approval guardrail), and writes reports to a persistent
  knowledge graph.
- **Source-code hunter** — a file-parallel agent-driven
  pipeline that ranks source files, fans out per-file hunter agents,
  uses ASan/UBSan crashes as ground truth, verifies findings with an
  adversarial second-pass agent, optionally generates validated
  patches, and emits SARIF/markdown/JSON reports with explicit
  evidence levels
  (`suspicion → static_corroboration → crash_reproduced →
  root_cause_explained → exploit_demonstrated → patch_validated`).

**Authorized use only.** Clearwing is a dual-use offensive-security
tool. Run it only against targets you own or have explicit written
authorization to test. Operators are responsible for scope, legal
authorization, and disclosure. See `SECURITY.md`.

## Install

**End users** — install the tagged release straight from GitHub:

```bash
python3 -m venv venv && source venv/bin/activate
pip install 'git+https://github.com/Lazarus-AI/clearwing.git@v1.0.0#egg=clearwing[all]'

# Interactive setup wizard — menu-driven provider selection,
# credential entry, optional live test, persists to ~/.clearwing/config.yaml
clearwing setup

# Environment check — verifies Python, credentials, Docker daemon,
# external tools, optional extras, and network reachability
clearwing doctor

clearwing --version   # 1.0.0
clearwing --help
```

Or skip the wizard and configure directly:

```bash
# Anthropic direct
export ANTHROPIC_API_KEY=sk-ant-...

# Or any OpenAI-compatible endpoint — OpenRouter, Ollama, LM Studio,
# vLLM, Together, Groq, DeepSeek, OpenAI:
export CLEARWING_BASE_URL=https://openrouter.ai/api/v1
export CLEARWING_API_KEY=sk-or-...
export CLEARWING_MODEL=anthropic/claude-opus-4
```

See [`docs/providers.md`](docs/providers.md) for provider-specific
recipes and per-task routing.

**Developers** — clone and install editable so you can run `make gate`:

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing
python3 -m venv venv && source venv/bin/activate
pip install -e '.[dev]'
```

Faster alternative with [uv](https://docs.astral.sh/uv/) — reproduces
the locked environment from `uv.lock` in seconds:

```bash
uv sync --all-extras
uv run clearwing --help
```

Requirements: Python 3.10+, optionally Docker for the Kali container
and sanitizer-image sandbox features.

## Quickstart

```bash
# Network scan a single target
clearwing scan 192.168.1.10 -p 22,80,443 --detect-services

# Source-code hunt a repo (standard depth — sandboxed LLM hunters,
# adversarial verifier, mechanism memory, variant loop)
clearwing sourcehunt https://github.com/example/project \
    --depth standard --budget 5

# Interactive ReAct chat with the full tool set
clearwing interactive

# Non-interactive CI mode with SARIF output for GitHub Code Scanning
clearwing ci --config .clearwing.ci.yaml --sarif results.sarif
```

See [`docs/quickstart.md`](docs/quickstart.md) for a fuller walkthrough
including credentials, session resume, and mission-mode operation.

## Architecture at a glance

```
┌──────────────────────┐      ┌────────────────────────────────┐
│ Network-pentest agent│      │ Source-code hunter             │
│ clearwing.agent.graph│      │ clearwing.sourcehunt.runner    │
│  (63 tools, ReAct)   │      │                                │
│                      │      │ preprocess → rank → pool →     │
│                      │      │   hunter → verify → exploit →  │
│                      │      │   variant loop → auto-patch →  │
│                      │      │   report                       │
└─────────┬────────────┘      └────────┬───────────────────────┘
          │                             │
          └───────────┬─────────────────┘
                      ▼
┌───────────────────────────────────────────────────────────────┐
│                    Shared substrate                          │
│  Finding dataclass  │  capabilities probe  │  sandbox layer  │
│  knowledge graph    │  episodic memory     │  event bus      │
│  telemetry          │  guardrails + audit  │  CVSS scoring   │
└───────────────────────────────────────────────────────────────┘
```

Deep dives live in [`docs/`](docs/):

| Doc | What it covers |
|---|---|
| [`docs/index.md`](docs/index.md) | Landing page + table of contents |
| [`docs/quickstart.md`](docs/quickstart.md) | Full install + first run walkthrough |
| [`docs/providers.md`](docs/providers.md) | OpenRouter / Ollama / LM Studio / vLLM / Together / Groq recipes, per-task routing, env-var precedence |
| [`docs/architecture.md`](docs/architecture.md) | Both pipelines, substrate, capability gating, tool layout |
| [`docs/cli.md`](docs/cli.md) | Every subcommand flag, grouped by workflow |
| [`docs/api.md`](docs/api.md) | API reference (mkdocstrings autogen) |

Once the GitHub Pages workflow ships, docs will be hosted at
<https://lazarus-ai.github.io/clearwing/>.

## Development

```bash
make install-dev           # pip install -e '.[dev]' + build/twine/ruff
make gate                  # full CI gate locally (lint + type + test + build)
make test                  # pytest -q
make lint                  # ruff check + ruff format --check
make type                  # scoped mypy on the typed-core modules
make docs-serve            # live-reload docs site on 127.0.0.1:8000
```

`make gate` mirrors CI exactly — if it's green locally, it's green
remotely. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full
dev-setup guide and PR checklist.

## Reporting vulnerabilities

There are two lanes, and they go to different places:

- **Vulnerabilities *in* Clearwing** → GitHub Security Advisories
  (<https://github.com/Lazarus-AI/clearwing/security/advisories/new>).
  See [`SECURITY.md`](SECURITY.md) for scope, SLA, and safe-harbor.
- **Vulnerabilities Clearwing *finds* in someone else's software** →
  that vendor's disclosure channel. `clearwing sourcehunt
  --export-disclosures` generates pre-filled MITRE CVE-request and
  HackerOne templates for every finding at
  `evidence_level >= root_cause_explained`.

## License

MIT. See [`LICENSE`](LICENSE).
