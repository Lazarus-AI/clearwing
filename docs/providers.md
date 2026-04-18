# LLM providers

Clearwing talks to any of five LLM backends:

- **Anthropic direct** — default, via `ANTHROPIC_API_KEY`
- **OpenAI-compatible endpoints** — the same `/v1/chat/completions`
  wire format used by OpenRouter, Ollama, LM Studio, vLLM, Together,
  Groq, DeepSeek, and OpenAI itself
- **Native Ollama** — via `pip install clearwing[ollama]`
- **Google Gemini** — via `pip install clearwing[google]`
- **Custom routing** — per-task provider selection via
  `~/.clearwing/config.yaml`

This page walks through each backend with copy-paste snippets.

## Fastest path: `clearwing setup`

If you just installed Clearwing and want to get going, run:

```bash
clearwing setup
```

You'll get a menu of every supported provider, prompts for the API
key and model, an optional live-invoke test, and the result written
to `~/.clearwing/config.yaml`. The wizard offers to store API keys
as `${ENV_VAR}` references pulled from your shell at runtime, so
you don't have to commit secrets to the file.

Direct variants:

```bash
clearwing setup --provider openrouter
clearwing setup --provider ollama --no-test
clearwing init   # alias
```

Then run `clearwing doctor` to validate your environment:

```bash
clearwing doctor
```

Doctor probes Python version, credentials, Docker daemon, external
CLI tools (git, ripgrep, gh), optional Python extras, filesystem
permissions, and network reachability to the configured LLM
endpoint — plus an optional live test-invoke with the resolved
model. Green/yellow/red table output with actionable hints on every
warning or error.

## How Clearwing picks an LLM

Four sources, highest precedence first:

| # | Source | Fields |
|---|---|---|
| 1 | CLI flags | `--base-url` / `--api-key` / `--model` |
| 2 | Env vars | `CLEARWING_BASE_URL` / `CLEARWING_API_KEY` / `CLEARWING_MODEL` |
| 3 | Config file | `~/.clearwing/config.yaml` → `provider:` section |
| 4 | Default | Anthropic via `ANTHROPIC_API_KEY` |

Every command that builds an LLM (`interactive`, `operate`, `scan`,
`parallel`, `ci`, `sourcehunt`) threads through the same resolution
function, so setting `CLEARWING_BASE_URL` once covers every code path.

Check the current resolution with:

```bash
clearwing config --show-provider
```

which prints the effective model, base URL, API key status, and
source (`cli` / `env` / `config` / `default`).

## Anthropic direct (default)

No setup beyond the API key. This is what Clearwing used before
multi-provider support existed and it still works unchanged.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
clearwing interactive --model claude-sonnet-4-6
clearwing sourcehunt /path/to/repo
```

## OpenRouter

OpenRouter routes your request to the specific model you name.
Model names follow the `provider/model` convention:
`anthropic/claude-opus-4`, `openai/gpt-4o`, `meta-llama/llama-3.3-70b-instruct`,
`google/gemini-2.0-flash`, `mistralai/mixtral-8x22b-instruct`, etc.

### Per-command (flags)

```bash
clearwing sourcehunt /path/to/repo \
    --base-url https://openrouter.ai/api/v1 \
    --api-key "$OPENROUTER_API_KEY" \
    --model anthropic/claude-opus-4
```

### Per-session (env vars)

```bash
export CLEARWING_BASE_URL=https://openrouter.ai/api/v1
export CLEARWING_API_KEY=$OPENROUTER_API_KEY
export CLEARWING_MODEL=anthropic/claude-opus-4

# Every command picks this up automatically
clearwing interactive
clearwing sourcehunt /path/to/repo
```

### Persistent (config file)

```bash
clearwing config --set-provider \
    base_url=https://openrouter.ai/api/v1 \
    api_key='${OPENROUTER_API_KEY}' \
    model=anthropic/claude-opus-4
```

This writes `~/.clearwing/config.yaml` with:

```yaml
provider:
  base_url: https://openrouter.ai/api/v1
  api_key: ${OPENROUTER_API_KEY}
  model: anthropic/claude-opus-4
```

The `${OPENROUTER_API_KEY}` literal is expanded from the environment
at runtime — don't commit real secrets to the YAML. Clearwing's
`config set-provider` quotes the literal for you; if you edit the
YAML by hand, quote it so the shell doesn't eat the `$`.

## Ollama

Two paths: the OpenAI-compatible endpoint (works out of the box,
no extra install) or the native `langchain-ollama` transport
(`pip install clearwing[ollama]`, tighter tool-calling semantics on
some models).

### OpenAI-compat (recommended for most models)

```bash
# Start Ollama
ollama serve &
ollama pull qwen2.5-coder:32b

# Point Clearwing at the /v1 endpoint
export CLEARWING_BASE_URL=http://localhost:11434/v1
export CLEARWING_API_KEY=ollama            # placeholder, Ollama ignores it
export CLEARWING_MODEL=qwen2.5-coder:32b

clearwing sourcehunt /path/to/repo --depth standard
```

**Tool calling caveat**: Clearwing requires function calling. Not
every Ollama-served model handles it well. Known-good models as of
2026-04: `qwen2.5-coder:32b`, `qwen2.5:72b`, `llama3.3:70b`,
`mistral-small3:24b`. Base Llama models without function-calling
training will fail on the first tool dispatch.

### Native transport (optional)

```bash
pip install clearwing[ollama]
```

There's no CLI path for "use native" yet — you need the
`~/.clearwing/config.yaml` form:

```yaml
providers:
  local_ollama:
    provider: ollama                     # forces native langchain-ollama
    base_url: http://localhost:11434
    model: qwen2.5-coder:32b

routes:
  default: local_ollama
```

## LM Studio

LM Studio exposes an OpenAI-compatible endpoint at
`http://localhost:1234/v1` by default. Load a model in the UI, click
"Start Server" in the Developer tab, then:

```bash
export CLEARWING_BASE_URL=http://localhost:1234/v1
export CLEARWING_API_KEY=lm-studio       # placeholder
export CLEARWING_MODEL=local-model       # or the exact LM Studio model name

clearwing interactive
```

LM Studio's `local-model` placeholder works with whichever model is
currently loaded in the server. If you have multiple models loaded,
pass the exact name from the "Local Server" tab.

## vLLM

```bash
# Start vLLM with an OpenAI-compatible server
python -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2.5-Coder-32B-Instruct \
    --host 0.0.0.0 --port 8000

# Point Clearwing at it
export CLEARWING_BASE_URL=http://localhost:8000/v1
export CLEARWING_API_KEY=vllm
export CLEARWING_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct

clearwing sourcehunt /path/to/repo
```

## Together, Groq, Fireworks, Anyscale, SiliconFlow, DeepSeek

All OpenAI-compatible — same pattern, different base URL.

```bash
# Together
export CLEARWING_BASE_URL=https://api.together.xyz/v1
export CLEARWING_API_KEY=$TOGETHER_API_KEY
export CLEARWING_MODEL=meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo

# Groq
export CLEARWING_BASE_URL=https://api.groq.com/openai/v1
export CLEARWING_API_KEY=$GROQ_API_KEY
export CLEARWING_MODEL=llama-3.3-70b-versatile

# Fireworks
export CLEARWING_BASE_URL=https://api.fireworks.ai/inference/v1
export CLEARWING_API_KEY=$FIREWORKS_API_KEY
export CLEARWING_MODEL=accounts/fireworks/models/qwen2p5-coder-32b-instruct

# DeepSeek
export CLEARWING_BASE_URL=https://api.deepseek.com/v1
export CLEARWING_API_KEY=$DEEPSEEK_API_KEY
export CLEARWING_MODEL=deepseek-chat

# OpenAI direct
export CLEARWING_BASE_URL=https://api.openai.com/v1
export CLEARWING_API_KEY=$OPENAI_API_KEY
export CLEARWING_MODEL=gpt-4o
```

## Per-task routing (advanced)

For source-hunt runs, Clearwing has five distinct tasks:

| Task | What it does | Typical model tier |
|---|---|---|
| `ranker` | Scores files by attack surface | Small / fast |
| `hunter` | Per-file vulnerability discovery (ReAct loop) | Largest available |
| `verifier` | Adversarial second-pass check | Different tier than hunter (independence) |
| `sourcehunt_exploit` | Exploit triage on crash-reproduced findings | Strongest reasoning |
| `default` | Fallback for anything else | Medium |

By default they all route to the same endpoint. You can override
per-task via `~/.clearwing/config.yaml`:

```yaml
providers:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: ${OPENROUTER_API_KEY}
  local_qwen:
    base_url: http://localhost:11434/v1
    api_key: ollama

routes:
  default: openrouter
  ranker: openrouter
  hunter: openrouter
  verifier: local_qwen              # Independence via cross-provider
  sourcehunt_exploit: openrouter

task_models:
  ranker: anthropic/claude-haiku-4-5
  hunter: anthropic/claude-opus-4
  verifier: qwen2.5-coder:32b
  sourcehunt_exploit: anthropic/claude-opus-4
```

The verifier-on-a-different-provider pattern is specifically called
out in Clearwing's source-hunt design: independence between the
primary hunter and the adversarial verifier comes from *tier* rather
than provider by default, but splitting them across providers gives
the strongest independence guarantee.

## Model capability checklist

Clearwing's agents REQUIRE the backing model to support:

- **Function calling / tool use** — the ReAct loop needs
  `bind_tools()` to work, which means the model has to support the
  OpenAI `tools: [...]` or Anthropic `tools: [...]` schema. Confirm
  with your provider's docs before running.
- **Multi-turn conversations with system prompts** — every provider
  listed above supports this. Mentioned here for completeness.
- **Token budget ≥ 32k context** — smaller contexts cause the ReAct
  loop to thrash as the conversation history grows. 128k+ is
  recommended.

Models that definitely work (tested during Phase 5):

- Anthropic: `claude-opus-4-7`, `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`
- OpenRouter: any `anthropic/*`, `openai/gpt-4o`, `openai/gpt-4o-mini`
- OpenAI direct: `gpt-4o`, `gpt-4o-mini`, `o1-preview` (no tool calling on o1)
- Ollama (qwen2.5-coder:32b, llama3.3:70b with function-calling prompts)
- Groq: `llama-3.3-70b-versatile`, `qwen-2.5-coder-32b`
- Together: `meta-llama/Meta-Llama-3.3-70B-Instruct-Turbo`

If a model Clearwing hits doesn't support tool calling, the first
tool dispatch will fail with a LangChain `tool_calls` attribute
error. That's not a Clearwing bug — pick a different model.
