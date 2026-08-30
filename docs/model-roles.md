# Model roles

Clearwing has ~100 tools and a dozen LLM call sites, but only a handful
of *kinds* of cognition. Model **roles** name those kinds — "investigate
through tools", "produce a testable artifact", "independently falsify a
claim" — without naming a model. You pick a provider (or two); Clearwing
fills every role from that provider's capability ladder. You override a
role only when you want to.

This page describes the taxonomy, how a role becomes a concrete model,
and the config surface. For the wire-protocol / backend details (adapters,
base URLs, OAuth) see [LLM providers](providers.md).

## The layers

Each layer answers exactly one question:

```
Provider       connectivity / auth / protocol
   │
Model          identity + intrinsic capabilities   ("what CAN it do?")
   │
Role binding   model + reasoning + output/context budget   ("how much cognition do I buy?")
   │
Task route     which role a call site uses (+ agent limits)   ("how does this workflow run?")
   │
Agent          the runtime call
```

The split that matters: **capabilities live on the model, policy lives on
the binding.** A model's context window, output ceiling, and which
reasoning levels exist are intrinsic facts. How hard to make it think and
how much to let it write are decisions Clearwing makes *per role* — the
same model can be a `low`-reasoning coordinator and a `high`-reasoning
researcher at once.

A role is **vendor-neutral**. It decomposes into what a provider can
actually be asked for:

```
task string  ->  role  ->  (tier, inference profile)  ->  concrete model
(call site)      (fixed)    (fixed defaults)             (provider ladder)
```

- **`task string`** is what a call site passes today (`hunter`, `ranker`,
  `verifier`, `sourcehunt_exploit`, `operator`, …). Nothing changes there.
- **`role`** is the kind of cognition (`utility`, `researcher`, …). The
  task→role map lives in `clearwing/providers/roles.py:TASK_ROLES`.
- **`tier`** is a rung on a provider's ladder (`small` / `mid` / `large`).
  A provider only answers three questions, and every role resolves.
- **`inference profile`** is the policy: `reasoning` budget (in
  `AsyncLLMClient` vocabulary, `none` … `max`), `temperature`, and (staged)
  `context_budget_tokens`, `tool_choice`,
  `parallel_tool_calls`, `timeout_seconds`.

Concrete model ids never appear in the role layer. That indirection is
what lets `hunter` mean "the mid-tier model, thinking hard" whether you're
on Anthropic, OpenRouter, or a local Ollama box.

## The roles

| Role | Tier | Reasoning | Output | What it does |
|------|------|-----------|--------|--------------|
| `utility` | small | none | 8K | Bounded transforms: ranking, classification, dedup, summaries, reports |
| `coordinator` | mid | low | 8K | Plan, delegate, track progress, decide the next step |
| `researcher` | mid | high | 32K | Investigate a security question through tools and evidence |
| `builder` | mid | high | 32K | Produce an executable artifact the environment then tests |
| `frontier` | large | max | 64K | Resolve a hard, stuck, or high-value problem |
| `reviewer` | large | xhigh | 32K | Independently review / falsify a claim it did not make |

These reasoning/output values are the role *defaults* (in
`clearwing/providers/roles.py`), overridable per binding and per route.

Two things worth noting:

- **`coordinator`, `researcher`, `builder` share the mid tier.** They are
  the same physical model at different reasoning budgets (and different
  names, so `builder` can later be re-pointed at a coder model without
  touching `researcher`). So six roles ride on just **three model tiers**.
- **`reviewer` is `independent`.** It prefers a provider whose model is a
  *different family* than the primary — a model shouldn't be the sole judge
  of its own output. If no independent family is configured (one provider,
  or a second provider in the same family), the binding is still made but
  flagged `independent_satisfied: false`, so `clearwing models` warns and
  the constraint is never silently pretended to be met.

`mechanical` is deliberately *not* a role: code with no LLM (typed proof
rules, AST/taint analysis, callgraph, sanitizer evidence, CI policy) has
no model to pick.

## Provider ladders

Each backend in `clearwing/providers/catalog.py` declares a `tier_models`
ladder — the entire recommendation dataset:

```python
# anthropic
tier_models={
    "small": "claude-haiku-4-5-20251001",
    "mid":   "claude-sonnet-4-6",
    "large": "claude-opus-4-7",
},
# openrouter
tier_models={
    "small": "anthropic/claude-haiku-4-5",
    "mid":   "anthropic/claude-sonnet-4",
    "large": "anthropic/claude-opus-4.7",
},
# ollama (local)
tier_models={
    "small": "qwen2.5-coder:7b",
    "mid":   "qwen2.5-coder:32b",
    "large": "qwen2.5:72b",
},
```

A tier left out of a ladder falls back to the preset's `default_model`.
Adding a provider — or filling in a newer model family — means editing one
`tier_models` dict; every role picks it up.

## Configuring roles

Four levels of control, simplest first. You normally touch **`roles:`
(≤6 lines)**, never per-task tables.

### Level 0 — nothing

The Anthropic ladder fills all six roles. Same behavior as before roles
existed.

### Level 1 — pick a provider

```yaml
model_roles:
  providers: [deepseek]     # every role fills from DeepSeek's ladder
```

### Level 1b — two providers (reviewer independence, free)

```yaml
model_roles:
  providers: [deepseek, anthropic]   # [0] primary; [1] takes the reviewer role
```

`researcher` / `builder` / `frontier` land on `deepseek`; `reviewer` lands
on `anthropic` automatically.

### Level 2 — override individual roles

```yaml
model_roles:
  providers: [deepseek, anthropic]
  overrides:
    frontier: { provider: anthropic, model: claude-opus-4-7, reasoning: max }
    reviewer: { provider: openrouter, model: qwen/qwen3-235b, reasoning: xhigh }
```

An override always wins over the ladder recommendation.

### Level 2b — named models + full bindings

For production tuning, declare models once (with their capabilities) and
bind roles to them with explicit inference profiles. The same model can
back several roles at different profiles:

```yaml
model_roles:
  providers: [deepseek]          # ladder still fills unlisted roles

  models:                        # named models + intrinsic capabilities
    flash:
      provider: openrouter
      model: deepseek-ai/DeepSeek-V4-Flash-0731
      capabilities:
        context_window: 1000000
        reasoning: { levels: [low, high, max] }
    a95b:
      provider: openrouter
      model: Qwen/Qwen3.8-2.4T-A95B
      capabilities:
        reasoning: { levels: [low, medium, xhigh] }

  roles:
    researcher:
      model: flash
      inference: { reasoning: high, temperature: 0.2 }
    builder:
      model: flash
      inference: { reasoning: high, temperature: 0.1 }
    reviewer:
      model: a95b
      inference: { reasoning: xhigh }
      constraints: { independent_model_family: true }
```

**Bindings are validated at load time** against the model's declared
capabilities. Asking for a reasoning level a model doesn't have, or an
output budget past its ceiling, fails immediately:

```
Invalid model role bindings:
  - role 'utility' requests reasoning='xhigh', but model
    'Qwen/Qwen3.8-27B' supports only: low, high
```

better than discovering it halfway through a scan. When capabilities
aren't declared, Clearwing still infers reasoning support from the same
denylist the client uses (Qwen2 / Gemma / Llama / Mistral reject the
parameter) and validates against that — it just never invents a ceiling
it doesn't actually know.

**Provider request settings:** `reasoning`, `temperature`, and `top_p`.
`timeout_seconds` is a per-attempt wall clock enforced by the client;
`context_budget_tokens` controls local context management (see below); and
`fallback:` controls availability failover (see below). **Schema + validation
only:** `tool_choice` and
`parallel_tool_calls` — the native `genai_pyo3` transport doesn't expose
these yet, so they're carried and validated but not sent; they light up
once the transport gains support. **Further step:** runtime call-failure
failover.

Per-route agent limits are their own layer — see [Task routes](#task-routes).

### Context budget

`context_budget_tokens` is how much conversation the agent loop carries
before it summarizes older turns — distinct from the model's hard context
window and from output budget. It is **opt-in and unset by default**
(roles keep the summarizer's built-in 150K threshold), because the right
value depends on the model: 500K is deliberate on a million-token frontier
model but wrong on a 200K one.

```yaml
model_roles:
  providers: [deepseek]
  roles:
    researcher: { inference: { context_budget_tokens: 120000 } }
    frontier:   { inference: { context_budget_tokens: 500000 } }   # only on a large-window model
```

Validation catches a budget that exceeds a *declared* model
`context_window`. The mid model may support 1M context, but that doesn't
mean your researcher should receive 1M tokens on every call — the frontier
can deliberately see much more evidence when escalation happens.

### Fallback

A binding may list fallbacks. The candidates are `[primary, *fallbacks]`,
and Clearwing selects the first *available* one — a provider is available
when its API key is set (or it is local / OAuth):

```yaml
model_roles:
  providers: [deepseek]
  roles:
    frontier:
      model: deepseek_pro
      inference: { reasoning: max }
      fallback:
        - model: qwen_a95b
          inference: { reasoning: xhigh }
```

Every fallback target is validated at load time too, so a broken failover
target fails immediately rather than at failover time.

The reviewer's independence is enforced *through* the fallback selection:
it prefers an available candidate whose model is a **different family**
than the generator. If none is available — say Qwen is down and the only
reachable reviewer is the same family as the model that produced the
finding — Clearwing does **not** silently use it. It binds the best
available option but flags `independent_available: false`, and
`clearwing models` warns that independent review is unavailable. That's a
security-relevant distinction: a same-family model rubber-stamping its own
family's finding is not an independent review.

This is *availability* failover (resolved at load). Runtime failover —
retrying a different binding when a call actually errors mid-scan — is a
further step.

### Task routes

The route layer answers a different question than the binding — not "how
much cognition do I buy" but "how should this *workflow* run." A `routes:`
entry binds a call-site name to **agent-workflow limits** and, optionally,
an explicit `role` and a per-route `inference` override:

```yaml
model_roles:
  providers: [deepseek]
  routes:
    hunter:                         # an existing task string
      agent: { max_steps: 30, max_tool_calls: 80 }
    network.investigate:            # a new named route
      role: researcher
      agent: { max_steps: 20 }
      inference: { temperature: 0.1 }
```

`agent:` limits (`max_steps` / `max_tool_calls` / `max_retries`, positive
integers, validated at load) bound the agentic loop — `max_steps` caps
assistant turns, `max_tool_calls` caps cumulative tool invocations. They're
enforced in the agent runtime loop, which was previously unbounded. Read
them with `ProviderManager.get_agent_limits(task)` (falling back to the
task's role, so a limit on `researcher` covers `hunter`/`recon`).

The `inference:` block overrides the role binding for this route only — the
researcher's default is generous, but `network.investigate` doesn't need
32K of output, so trim it without minting a `network_researcher` role. This
keeps the boundary clean: **model** (what's possible) → **role binding**
(how much cognition) → **task route** (how the workflow runs).

`clearwing models` prints a Task routes table when a `routes:` block is
configured. Enforcement currently lives in the central agent runtime loop;
the hunter, operator, and exploiter loops carry their own limits today and
can adopt `get_agent_limits` incrementally.

### Level 3 — pin a single task (escape hatch)

The existing `task_models:` / `routes:` / `model_aliases:` mechanisms
still work for surgically pinning one task string. Reserve them for the
rare case a single call site needs a specific model.

## Inspecting roles: `clearwing models`

`clearwing models` prints the resolved role table — model, reasoning
budget, and the task strings each role serves — for your current config:

```
clearwing models                       # what the current config resolves to
clearwing models --provider deepseek   # preview a provider's ladder
clearwing models --provider deepseek --provider anthropic   # + reviewer split
clearwing models --task hunter         # which model one call site uses
clearwing models --list-providers      # every preset's small/mid/large ladder
```

The table shows each role's model, reasoning budget, output budget, and
the tasks it serves. The banner tells you whether the assignments are
**active** (a `model_roles:` block is configured) or just a
**recommendation** (you're running a single endpoint for every task). It
flags what bites silently: a provider whose API key env var is unset, a
reasoning budget the model family will drop, a reviewer that isn't actually
independent, and any binding that fails capability validation. Add `--json`
for machine-readable output.

`clearwing setup` offers to scaffold a `model_roles:` block after you
configure a provider (pick a primary, optionally a second for independent
review), so you don't have to hand-write the YAML to get started.

## How resolution works

`recommend_roles(providers, overrides)` (in `roles.py`) is the engine:

1. `providers[0]` is the primary and supplies most roles.
2. `providers[1]` (if present) receives the `independent` roles.
3. Each role reads `provider.model_for_tier(role.tier)`.
4. `overrides[role]` replaces any of provider / model / reasoning.

`ProviderManager.from_roles(...)` turns the assignments into routes: one
per role name (so `get_native_client("researcher")` works) and one per
task string via `TASK_ROLES` (so the existing `hunter` / `verifier` /
`sourcehunt_exploit` call sites keep working). `ProviderManager.from_config`
recognizes the `model_roles:` block and builds through this path.

## Reasoning and the family denylist

A role's `reasoning` value is passed to `AsyncLLMClient` as
`reasoning_effort`. Some model families (Qwen2, Gemma, Llama, Mistral)
reject that parameter with HTTP 400. `effective_reasoning_effort(model,
requested)` (in `clearwing/llm/native.py`) honors the role's request
*unless* the model family rejects it, in which case it downgrades to
"omit the parameter". So forcing `reasoning: high` onto a local Qwen is
safe — it silently runs without the flag rather than erroring.

Routes with no reasoning set (everything built the old way) pass `"auto"`,
preserving the per-model auto-resolution Clearwing used before roles.
