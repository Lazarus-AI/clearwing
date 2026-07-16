# Clearwing

<img width="400" alt="image" src="https://github.com/user-attachments/assets/c0444f24-32d8-4d62-af66-f1b7d8a123ba" />

By Eric Hartford, Lazarus AI

Inspired by Anthropic's Glasswing.  

The challenge:  Produce similar results as Glasswing - using models everyone has access to.

**Autonomous vulnerability scanner and source-code hunter.** Built on
`genai-pyo3`, a native Rust-backed LLM runtime speaking every major
provider (Anthropic, OpenAI, OpenRouter, Ollama, LM Studio, Together,
Groq, DeepSeek, MiniMax, Gemini, any OpenAI-compatible endpoint).

Clearwing is a dual-mode offensive-security tool:

- **Network-pentest agent** — a ReAct-loop agent with 63 bind-tools
  that scans live targets, detects services and vulnerabilities,
  runs sandboxed Kali tools, attempts exploits (gated through a
  human-approval guardrail), and writes reports to a persistent
  knowledge graph.
- **Source-code hunter** — a file-parallel agent-driven
  pipeline that ranks source files, fans out per-file hunter agents
  (full-shell or constrained), uses ASan/UBSan crashes as ground
  truth, verifies findings with a 4-axis validator (REAL /
  TRIGGERABLE / IMPACTFUL / GENERAL), runs PoC stability checks
  across fresh containers, optionally generates validated patches,
  and emits SARIF/markdown/JSON reports with explicit evidence levels
  (`suspicion → static_corroboration → crash_reproduced →
  root_cause_explained → exploit_demonstrated → patch_validated`).
  Features three-band budget promotion, entry-point sharding for
  large files, cross-subsystem hunting, a shared findings pool with
  root-cause deduplication, multi-turn agentic exploit development,
  and human-in-the-loop exploit elaboration.
- **N-day exploit pipeline** — given CVE IDs, builds the
  vulnerable version, develops working exploits, and validates
  against the patched version to confirm the fix.
- **Reverse engineering pipeline** — decompiles closed-source
  ELF binaries via Ghidra, reconstructs plausible source with an
  LLM, then hunts vulnerabilities using a hybrid source + binary
  validation approach.
- **Campaign orchestration** — runs sourcehunt across dozens or
  hundreds of repositories from a single YAML config with shared
  budget, checkpoint/resume, and aggregate reporting.
- **Responsible disclosure** — human-in-the-loop validation
  workflow with MITRE/HackerOne template generation, SHA-3
  cryptographic commitments for provable priority, timeline
  tracking, and batched disclosure.
- **Benchmarking & evaluation** — OSS-Fuzz crash severity
  ladder for model comparison, and an A/B testing framework for
  measuring whether preprocessing helps or hurts finding quality.

**Authorized use only.** Clearwing is a dual-use offensive-security
tool. Run it only against targets you own or have explicit written
authorization to test. Operators are responsible for scope, legal
authorization, and disclosure. See `SECURITY.md`.

## Install

**End users** — install the tagged release straight from GitHub:

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing

# uv sync is recommended because Clearwing pins genai-pyo3 through
# tool.uv.sources in pyproject.toml.
uv sync --all-extras
source .venv/bin/activate  # fish: source .venv/bin/activate.fish

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

**Developers** — clone and install the locked development environment:

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing
uv sync --all-extras
source .venv/bin/activate  # fish: source .venv/bin/activate.fish
clearwing --help
```

Requirements: Python 3.10+ and optionally Docker for the Kali container
and sanitizer-image sandbox features. `genai-pyo3` ships as prebuilt
wheels on PyPI (linux x86_64/aarch64, macOS universal2, windows x86_64,
Python 3.9–3.13), so no Rust toolchain is needed for installation.

## Quickstart

```bash
# Network scan a single target
clearwing scan 192.168.1.10 -p 22,80,443 --detect-services

# Source-code hunt a repo (standard depth — sandboxed LLM hunters,
# adversarial verifier, mechanism memory, variant loop)
clearwing sourcehunt https://github.com/example/project \
    --depth standard

# Proof-carrying hunt — typed facts, obligations, evidence, falsification,
# and auditable finding/rejection/incomplete certificates
clearwing sourcehunt /path/to/project \
    --flow proof \
    --compile-commands compile_commands.json \
    --budget 50

# N-day exploit pipeline — build and exploit known CVEs
clearwing sourcehunt https://github.com/example/project \
    --nday --cve-list CVE-2024-1234,CVE-2024-5678

# Reverse engineering — hunt vulnerabilities in closed-source binaries
clearwing sourcehunt /path/to/binary --reveng --arch x86_64

# Campaign-scale orchestration across multiple projects
clearwing campaign run campaign.yaml

# Responsible disclosure workflow
clearwing disclose queue ./results/sourcehunt/sh-*/
clearwing disclose review

# OSS-Fuzz crash severity benchmark
clearwing bench ossfuzz --corpus-dir ./oss-fuzz-projects --mode standard

# A/B test whether preprocessing helps or hurts
clearwing eval preprocessing --project https://github.com/example/project \
    --configs glasswing_minimal,sourcehunt_full --runs 3

# Interactive ReAct chat with the full tool set
clearwing interactive

# Non-interactive CI mode with SARIF output for GitHub Code Scanning
clearwing ci --config .clearwing.ci.yaml --sarif results.sarif
```

See [`docs/quickstart.md`](docs/quickstart.md) for a fuller walkthrough
including credentials, session resume, and mission-mode operation.

## Proof-carrying sourcehunt (`--flow proof`)

`clearwing sourcehunt` has two separate investigation engines. The default,
`--flow legacy`, uses the file-oriented hunter, verifier, and exploiter
pipeline. The opt-in `--flow proof` engine moves investigation state out of
the model context and into typed, inspectable artifacts:

```text
repository snapshot
  → extracted facts and completeness manifest
  → invariant-oriented candidates and threat models
  → proof-plan obligation graphs
  → bounded mechanical, model, and dynamic actions
  → independent falsification
  → finding, rejection, or incomplete certificates
```

The proof engine uses models for bounded judgments rather than asking one
agent to remember the whole investigation. Its default `local-first` policy
tries the configured `proof_local` route first and escalates an unresolved
atomic question to `proof_frontier`. Exploratory work receives a separate,
bounded share of the action budget and cannot become a reportable finding
without satisfying the same evidence obligations.

For a C or C++ repository, generate `compile_commands.json` from the real
build and run Docker before starting. The path passed to
`--compile-commands` is resolved relative to the target repository. Proof
preflight fails closed when the compilation database or analysis sandbox is
unavailable; it does not silently fall back to lexical extraction or the
legacy engine.

```bash
clearwing sourcehunt /path/to/project \
  --flow proof \
  --compile-commands compile_commands.json \
  --model-routing local-first \
  --structured-budget 90% \
  --exploration-budget 10% \
  --proof-max-actions 200 \
  --proof-max-model-calls 40 \
  --proof-max-dynamic-actions 20 \
  --retain-incomplete-certificates \
  --emit-rejection-certificates \
  --falsify \
  --budget 50 \
  --output-dir ./results/sourcehunt-proof
```

`--budget` is the run-wide monetary cap; omit it or pass `--budget 0` for
the unlimited default. The three `--proof-max-*` flags separately bound all
proof actions, model calls, and dynamic actions. Dynamic validation is
performed only from a typed `--validation-manifest` inside the sandbox; add
`--gvisor` when that runtime is installed for an additional isolation layer.

Each session is written under `<output-dir>/sh-<session-id>/`. Start with
`manifest.json`, which records the engine, snapshot, blind boundary, run
status, spend, action counts, certificate counts, and output index. The
session also retains append-only facts, candidates, obligations, actions,
claims, evidence, derivations, context packets, proof graphs, falsification
results, and content-addressed runtime artifacts. Human and tool consumers
can use `report.md`, `findings.json`, and `findings.sarif`; only accepted
finding certificates appear in JSON and SARIF. Rejected and unresolved work
remains under `certificates/rejections/` and `certificates/incomplete/`.

An exit status of `3` means the proof is incomplete or the run-wide budget
was exhausted. It is a preserved partial investigation, not proof that the
repository is safe and not necessarily a process failure.

See the [FFmpeg proof-flow walkthrough](docs/FFmpeg.md) for an end-to-end
blind C/C++ example, [the design document](docs/sourcehunt_improvement.md)
for the evidence model, and [the evaluation and rollout guide](docs/eval_rollout.md)
before comparing or promoting proof-flow results.

## Running sourcehunt on a local repo (FFmpeg example)

The positional repository argument accepts either a Git URL or a local
checkout. A local checkout is preferable for a reproducible FFmpeg proof run
because it can be pinned to an exact commit and built before discovery:

```bash
git clone https://code.ffmpeg.org/FFmpeg/FFmpeg.git
cd FFmpeg

./configure \
  --cc=clang \
  --cxx=clang++ \
  --disable-doc \
  --disable-stripping \
  --enable-debug=3

bear -- make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"

clearwing sourcehunt "$PWD" \
  --flow proof \
  --compile-commands compile_commands.json \
  --model-routing local-first \
  --falsify \
  --budget 50 \
  --output-dir ../results/sourcehunt-ffmpeg-proof
```

This is only the shortest useful invocation. The full walkthrough pins the
known vulnerable parent, preserves a strict blind boundary, captures an
ASan/UBSan build, separates local and frontier model routes, validates with a
typed runtime manifest, and explains every proof artifact. Follow
[`docs/FFmpeg.md`](docs/FFmpeg.md) when reproducing the case or collecting
evaluation results. See [`docs/providers.md`](docs/providers.md) for managed
and self-hosted provider configuration.

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
│ N-day pipeline │ Reveng pipeline │ Campaign orchestrator      │
│ Disclosure workflow + SHA-3 commitments                       │
├───────────────────────────────────────────────────────────────┤
│                    Shared substrate                          │
│  Finding dataclass  │  capabilities probe  │  sandbox layer  │
│  knowledge graph    │  episodic memory     │  event bus      │
│  telemetry          │  guardrails + audit  │  CVSS scoring   │
│  artifact store     │  behavior monitor    │  seccomp        │
├───────────────────────────────────────────────────────────────┤
│  Bench: OSS-Fuzz severity ladder  │  Eval: preprocessing A/B │
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
uv sync --all-extras
source .venv/bin/activate  # fish: source .venv/bin/activate.fish
pytest -q
ruff check clearwing/ tests/
ruff format --check clearwing/ tests/
mypy --follow-imports=silent \
  clearwing/findings \
  clearwing/sourcehunt \
  clearwing/capabilities.py \
  clearwing/agent/tools \
  clearwing/core
python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full dev-setup guide and PR
checklist.

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
