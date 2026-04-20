# LLM providers

Clearwing runs on `genai-pyo3` (native Rust bindings to `rust-genai`),
which speaks every major provider directly. The wizard
(`clearwing setup`) exposes a menu of the known backends, each
carrying an explicit **adapter** name that decides the wire
protocol — `anthropic`, `openai` (chat completions), `openai_resp`
(responses API), `openai_codex` (ChatGPT OAuth), `ollama`, or
`gemini`. There's no heuristic guessing: the preset you pick in
the wizard persists `adapter:` into `~/.clearwing/config.yaml`
alongside `base_url`, `api_key`, and `model`.

Backends covered below:

- **Anthropic direct** — Claude via `api.anthropic.com` (`anthropic` adapter).
- **OpenAI (Chat Completions)** — GPT-4o / GPT-4o-mini via
  `/v1/chat/completions` (`openai` adapter).
- **OpenAI (Responses API)** — GPT-5.x / o-series via `/v1/responses`
  (`openai_resp` adapter). Required for GPT-5.x and o-series.
- **OpenAI OAuth (ChatGPT)** — Plus/Pro login via Codex backend (`openai_codex`).
- **OpenRouter, Together, Groq, Fireworks, DeepSeek, LM Studio, vLLM, custom** —
  anything that speaks `/v1/chat/completions` (`openai` adapter).
- **MiniMax** — M2.7 / M2.5 via the Anthropic-compatible endpoint
  (`anthropic` adapter at `api.minimax.io/anthropic`).
- **Ollama** — local models via the native rust-genai Ollama adapter
  (`ollama` adapter at `http://localhost:11434`, no `/v1` suffix).
- **Gemini** — reserved for when a Gemini preset is added; adapter
  name is `gemini`.

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

Adapter: `anthropic` (the wizard writes this automatically; no
heuristic is involved).

## OpenAI (Chat Completions API)

The classic OpenAI API. Use this for GPT-4o / GPT-4o-mini. For
GPT-5.x and the o-series (o1, o3) use the Responses API preset
below — those models require it.

```bash
clearwing setup --provider openai
# or explicitly
export CLEARWING_BASE_URL=https://api.openai.com/v1
export CLEARWING_API_KEY=$OPENAI_API_KEY
export CLEARWING_MODEL=gpt-4o
```

`~/.clearwing/config.yaml`:

```yaml
provider:
  base_url: https://api.openai.com/v1
  api_key: ${OPENAI_API_KEY}
  model: gpt-4o
  adapter: openai
```

## OpenAI (Responses API)

Required for GPT-5.x and o-series models — those only speak the
newer `/v1/responses` streaming protocol. Works for GPT-4o as well,
but chat-completions is slightly cheaper for older models so pick
the preset that matches your model generation.

```bash
clearwing setup --provider openai-responses
# or explicitly
export CLEARWING_BASE_URL=https://api.openai.com/v1
export CLEARWING_API_KEY=$OPENAI_API_KEY
export CLEARWING_MODEL=gpt-5.4
```

`~/.clearwing/config.yaml`:

```yaml
provider:
  base_url: https://api.openai.com/v1
  api_key: ${OPENAI_API_KEY}
  model: gpt-5.4
  adapter: openai_resp
```

The `adapter: openai_resp` line is what switches the wire protocol
from chat-completions to responses. Leave it out and the request
will 404 against GPT-5.x models. The wizard writes it automatically
when you pick the `openai-responses` preset.

Any `/v1/responses` proxy works — point `base_url` at your proxy
host, keep `adapter: openai_resp`.

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
  adapter: openai
```

The `${OPENROUTER_API_KEY}` literal is expanded from the environment
at runtime — don't commit real secrets to the YAML. Clearwing's
`config set-provider` quotes the literal for you; if you edit the
YAML by hand, quote it so the shell doesn't eat the `$`.

## Ollama

Ollama is spoken natively by `rust-genai` via its own adapter — no
extra install, no `/v1` shim needed. You can also point Clearwing at
Ollama's OpenAI-compatible endpoint if you prefer.

### Native Ollama adapter (recommended)

```bash
# Start Ollama
ollama serve &
ollama pull qwen2.5-coder:32b

# Point Clearwing at the native Ollama port (no /v1 suffix)
export CLEARWING_BASE_URL=http://localhost:11434
export CLEARWING_MODEL=qwen2.5-coder:32b
# No API key required

clearwing sourcehunt /path/to/repo --depth standard
```

Or pin it explicitly in `~/.clearwing/config.yaml`:

```yaml
provider:
  base_url: http://localhost:11434
  model: qwen2.5-coder:32b
  adapter: ollama
```

### OpenAI-compat endpoint (alternative)

```bash
export CLEARWING_BASE_URL=http://localhost:11434/v1
export CLEARWING_API_KEY=ollama            # placeholder, Ollama ignores it
export CLEARWING_MODEL=qwen2.5-coder:32b
```

**Tool calling caveat**: Clearwing requires function calling. Not
every Ollama-served model handles it well. Known-good models as of
2026-04: `qwen2.5-coder:32b`, `qwen2.5:72b`, `llama3.3:70b`,
`mistral-small3:24b`. Base Llama models without function-calling
training will fail on the first tool dispatch.

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

All `/v1/chat/completions` endpoints — same pattern, different base
URL, `adapter: openai`. The wizard handles them directly; the env-var
paths are here for scripting.

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
```

For OpenAI itself, use the [Chat Completions](#openai-chat-completions-api)
or [Responses](#openai-responses-api) section above — the model
generation decides which.

## MiniMax

MiniMax's M-series reasoning models are served via an
Anthropic-compatible endpoint at `https://api.minimax.io/anthropic`
(not an OpenAI-compat one). The wizard picks the right adapter
automatically.

```bash
clearwing setup --provider minimax
# writes adapter: anthropic + base_url: https://api.minimax.io/anthropic
```

`~/.clearwing/config.yaml`:

```yaml
provider:
  base_url: https://api.minimax.io/anthropic
  api_key: ${MINIMAX_API_KEY}
  model: MiniMax-M2.7
  adapter: anthropic
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
