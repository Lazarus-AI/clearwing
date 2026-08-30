from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from typing import Any

from clearwing.llm import AsyncLLMClient
from clearwing.llm.native import effective_reasoning_effort

from .binding import (
    AgentLimits,
    BindingValidationError,
    InferenceProfile,
    ModelCapabilities,
    capabilities_for,
    model_family,
    validate_agent_limits,
    validate_inference,
)
from .catalog import preset_by_key
from .env import EndpointPricing, LLMEndpoint, resolve_llm_endpoint
from .roles import ROLES, TASK_ROLES, RoleAssignment, Tier, recommend_roles, role_for_task
from .runtime import runtime_routing

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider."""

    name: str  # anthropic, openai, google, ollama, bedrock
    model: str  # model identifier
    api_key: str = ""  # empty = use env var
    base_url: str = ""  # for custom endpoints (Ollama, etc.)
    max_tokens: int = 4096
    temperature: float = 0.0
    # Optional explicit genai-pyo3 adapter name. When set, overrides the
    # base-URL heuristic in _adapter_for_base_url. Expected values:
    # "openai", "openai_resp", "openai_codex", "anthropic", "gemini",
    # "ollama". Left empty for the default behavior (heuristic).
    adapter: str = ""
    # Optional authoritative price supplied by the route owner. This follows
    # the provider config to the native client so aliases can use distinct rates.
    pricing: EndpointPricing | None = None


@dataclass
class ModelRoute:
    """Maps a task type to a specific provider/model."""

    task: str  # recon, exploit, report, planning, default
    provider: str
    model: str
    reason: str = ""  # why this model for this task
    # Reasoning budget in AsyncLLMClient vocabulary ("none".."max"), when the
    # route came from a role. None means "let the client auto-resolve per
    # model" — the pre-roles behavior, so unset routes are unchanged.
    reasoning: str | None = None
    # Full inference profile from the role binding (output/temperature/etc.).
    # None for legacy routes. When set, its reasoning wins over `reasoning`.
    inference: InferenceProfile | None = None

    @property
    def effective_reasoning(self) -> str | None:
        if self.inference is not None and self.inference.reasoning is not None:
            return self.inference.reasoning
        return self.reasoning


PROVIDER_PRESETS = {
    "anthropic": {
        "env_key": "ANTHROPIC_API_KEY",
        "models": [
            "claude-opus-4-7",
            "claude-opus-4-6",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
        ],
    },
    "openai": {
        "env_key": "OPENAI_API_KEY",
        "models": ["gpt-4o", "gpt-4o-mini", "o1-preview"],
    },
    "google": {
        "env_key": "GOOGLE_API_KEY",
        "models": ["gemini-2.0-flash", "gemini-2.5-pro"],
    },
    "ollama": {
        "env_key": "",
        "models": [],  # dynamic
        "default_base_url": "http://localhost:11434",
    },
}

DEFAULT_ROUTES = [
    ModelRoute(
        task="recon",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="Fast, cheap for scanning",
    ),
    ModelRoute(
        task="exploit",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Strong reasoning for exploitation",
    ),
    ModelRoute(
        task="report",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="Report generation doesn't need top model",
    ),
    ModelRoute(
        task="planning",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Good planning capabilities",
    ),
    ModelRoute(
        task="default", provider="anthropic", model="claude-sonnet-4-6", reason="Default model"
    ),
    # Sourcehunt routes — see plan §Provider routing.
    # Hunter and verifier are deliberately different tiers from the same provider:
    # independence comes from tier, not provider, so users with only ANTHROPIC_API_KEY
    # get sensible defaults without needing a second account. YAML config can upgrade.
    ModelRoute(
        task="ranker",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="File ranking is simple classification",
    ),
    ModelRoute(
        task="hunter",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Core vuln-finding reasoning",
    ),
    ModelRoute(
        task="verifier",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Independent verification — different tier from hunter",
    ),
    ModelRoute(
        task="sourcehunt_exploit",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Exploit generation is hardest reasoning",
    ),
    ModelRoute(
        task="remediator",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Production security patch generation",
    ),
    ModelRoute(
        task="remediation_architect",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Independent root-cause and design review",
    ),
    ModelRoute(
        task="remediation_adversary",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Adversarial bypass review",
    ),
    ModelRoute(
        task="remediation_regression",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Independent regression and minimality review",
    ),
    ModelRoute(
        task="proof_local",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="Small-model tier for bounded atomic proof obligations",
    ),
    ModelRoute(
        task="proof_frontier",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Escalation tier for ambiguities that survive bounded local review",
    ),
    ModelRoute(
        task="proof_falsifier",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Independent tier for finite counterexample searches",
    ),
    ModelRoute(
        task="proof_exploration",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Bounded exploratory lane for unmodeled vulnerability hypotheses",
    ),
]


class ProviderManager:
    """Manages multiple LLM providers with task-based routing.

    There are three ways to construct a ProviderManager:

    1. `ProviderManager()` — default constructor with no overrides.
       Every task routes to its `DEFAULT_ROUTES` entry, which means
       Anthropic direct via `ANTHROPIC_API_KEY`.

    2. `ProviderManager.for_endpoint(endpoint)` — one endpoint routes
       every task. Used when the operator wants ONE model/backend for
       everything (the common case: OpenRouter, Ollama, LM Studio).
       The `endpoint` arg comes from `resolve_llm_endpoint()`, which
       merges CLI / env / config / default.

    3. `ProviderManager.from_config(cfg)` — multi-provider routing
       from a `~/.clearwing/config.yaml` `providers:` + `routes:`
       section. Each task can land on a different provider. This is
       the power-user case (e.g., "hunter uses OpenRouter Opus,
       verifier uses local Qwen, ranker uses Haiku direct").
    """

    def __init__(
        self,
        configs: list[ProviderConfig] | None = None,
        routes: list[ModelRoute] | None = None,
        endpoint: LLMEndpoint | None = None,
        task_model_overrides: dict[str, str] | None = None,
    ):
        self._configs: dict[str, ProviderConfig] = {}
        self._routes: dict[str, ModelRoute] = {}
        self._agent_limits: dict[str, AgentLimits] = {}
        self._native_cache: dict[str, AsyncLLMClient] = {}
        # When `endpoint` is set, every get_native_client() call returns the
        # same client instance for identical resolved endpoints. Task-
        # specific model overrides still produce separate cache entries.
        self._global_endpoint: LLMEndpoint | None = endpoint
        self._task_model_overrides: dict[str, str] = dict(task_model_overrides or {})

        if configs:
            for c in configs:
                self._configs[c.name] = c

        # Set up routes
        for route in routes or DEFAULT_ROUTES:
            self._routes[route.task] = route

    # --- Constructors -----------------------------------------------------

    @classmethod
    def for_endpoint(
        cls,
        endpoint: LLMEndpoint,
        *,
        task_model_overrides: dict[str, str] | None = None,
    ) -> ProviderManager:
        """Build a ProviderManager that routes every task to one endpoint.

        The common case: operator sets `--base-url https://openrouter.ai/api/v1
        --model anthropic/claude-opus-4 --api-key sk-or-...` (or the
        `CLEARWING_BASE_URL` / `CLEARWING_MODEL` / `CLEARWING_API_KEY`
        env triple), and every sourcehunt task (ranker / hunter /
        verifier / sourcehunt_exploit / default) dispatches against
        that same endpoint.
        """
        return cls(
            endpoint=endpoint,
            task_model_overrides={
                **_default_task_model_overrides(endpoint),
                **(task_model_overrides or {}),
            },
        )

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> ProviderManager:
        """Build a ProviderManager from a parsed YAML config dict.

        Expected shape (all fields optional):

            provider:                  # single-endpoint mode
              base_url: https://...
              api_key: ${ENV_VAR}
              model: anthropic/claude-opus-4

            # OR

            providers:                 # multi-endpoint routing mode
              openrouter:
                base_url: https://openrouter.ai/api/v1
                api_key: ${OPENROUTER_API_KEY}
              local_llama:
                base_url: http://localhost:11434/v1
                api_key: ollama

            routes:
              default: openrouter
              hunter: openrouter
              verifier: local_llama       # independence via tier
              ranker: openrouter
              sourcehunt_exploit: openrouter

            task_models:
              hunter: anthropic/claude-opus-4
              verifier: qwen2.5-coder:32b
              ranker: anthropic/claude-haiku-4-5
        """
        # Role mode: pick provider(s) by preset key, auto-fill every role from
        # their tier ladders. `roles:` / `task_models:` overrides still apply.
        roles_cfg = cfg.get("model_roles")
        if roles_cfg and isinstance(roles_cfg, dict):
            return cls._from_model_roles(roles_cfg)

        # cwpro model_aliases mode: {"model_aliases": {"task": {"provider": {...}}}}
        aliases = cfg.get("model_aliases")
        if aliases and isinstance(aliases, dict):
            return cls._from_model_aliases(aliases)

        # Single-endpoint mode
        single = cfg.get("provider")
        if single:
            endpoint = resolve_llm_endpoint(config_provider=single)
            return cls.for_endpoint(endpoint)

        # Multi-endpoint routing mode
        providers_cfg = cfg.get("providers", {})
        routes_cfg = cfg.get("routes", {})
        models_cfg = cfg.get("task_models", {})

        configs: list[ProviderConfig] = []
        for name, pcfg in providers_cfg.items():
            base_url = pcfg.get("base_url", "")
            raw_key = pcfg.get("api_key")
            api_key = _expand_env(raw_key) if raw_key else ""
            configs.append(
                ProviderConfig(
                    name=name,
                    model=pcfg.get("model", ""),
                    api_key=api_key,
                    base_url=base_url,
                    adapter=pcfg.get("adapter", ""),
                    pricing=_pricing_from_config(pcfg.get("pricing")),
                )
            )

        routes: list[ModelRoute] = list(DEFAULT_ROUTES)
        # Override any task that has a routes: entry
        for task, target_provider in routes_cfg.items():
            model = (
                models_cfg.get(task)
                or providers_cfg.get(target_provider, {}).get("model")
                or "default"
            )
            # Replace any existing default for this task
            routes = [r for r in routes if r.task != task]
            routes.append(
                ModelRoute(
                    task=task,
                    provider=target_provider,
                    model=model,
                    reason=f"Configured via ~/.clearwing/config.yaml routes:{task}",
                )
            )

        return cls(configs=configs, routes=routes)

    @classmethod
    def _from_model_aliases(cls, aliases: dict[str, Any]) -> ProviderManager:
        """Build from cwpro's model_aliases routing format.

        Shape: {"task_name": {"provider": {"model": ..., "api_key": ...,
        "base_url": ..., "adapter": ...}}}

        Each alias becomes a named provider config, and a route mapping
        that task to that provider. The "default" alias routes all tasks
        not explicitly listed.
        """
        configs: list[ProviderConfig] = []
        routes: list[ModelRoute] = []
        for alias_name, alias_value in aliases.items():
            if not isinstance(alias_value, dict):
                continue
            pcfg = alias_value.get("provider", alias_value)
            configs.append(
                ProviderConfig(
                    name=alias_name,
                    model=pcfg.get("model", ""),
                    api_key=pcfg.get("api_key", ""),
                    base_url=pcfg.get("base_url", ""),
                    adapter=pcfg.get("adapter", ""),
                    pricing=_pricing_from_config(pcfg.get("pricing")),
                )
            )
            routes.append(
                ModelRoute(
                    task=alias_name,
                    provider=alias_name,
                    model=pcfg.get("model", ""),
                    reason="cwpro model_aliases routing",
                )
            )
        # Ensure a "default" route exists — fall back to the first alias.
        if not any(r.task == "default" for r in routes) and configs:
            first = configs[0]
            routes.append(
                ModelRoute(
                    task="default",
                    provider=first.name,
                    model=first.model,
                    reason="cwpro model_aliases fallback",
                )
            )
        return cls(configs=configs, routes=routes)

    @classmethod
    def _from_model_roles(cls, roles_cfg: dict[str, Any]) -> ProviderManager:
        """Build from a role-based config block (see docs/model-roles.md).

        Shape (all fields optional)::

            model_roles:
              providers: [deepseek, anthropic]   # ladder defaults; [0] primary,
                                                 # reviewer prefers a different
                                                 # family from the rest
              models:                            # named models + capabilities
                qwen_a95b:
                  provider: openrouter
                  model: Qwen/Qwen3.8-2.4T-A95B
                  capabilities: {reasoning: {levels: [low, high, xhigh]}}
              roles:                             # explicit bindings
                reviewer:
                  model: qwen_a95b               # -> a models: name, or literal
                  inference: {reasoning: xhigh}
                  constraints: {independent_model_family: true}
              overrides: {frontier: {reasoning: max}}   # legacy flat overrides

        Bindings are validated against model capabilities at load time — an
        unsupported inference setting raises
        :class:`clearwing.providers.binding.BindingValidationError` here,
        before any scan starts.
        """
        assignments, presets_by_key, problems = cls.resolve_role_assignments(roles_cfg)
        if problems:
            raise BindingValidationError(
                "Invalid model role bindings:\n  - " + "\n  - ".join(problems)
            )
        mgr = cls.from_roles(assignments, presets_by_key)
        mgr._attach_routes(roles_cfg.get("routes") or {}, assignments)
        return mgr

    @classmethod
    def resolve_role_assignments(
        cls, roles_cfg: dict[str, Any]
    ) -> tuple[dict[str, RoleAssignment], dict[str, Any], list[str]]:
        """Resolve a ``model_roles:`` block to assignments + presets + problems.

        The single source of truth both :meth:`_from_model_roles` (which
        raises on ``problems``) and ``clearwing models`` (which displays them)
        share — so the inspector never disagrees with what actually runs.
        Does not raise on validation failure; returns the problem list.
        """
        provider_keys = roles_cfg.get("providers") or []
        if not provider_keys and roles_cfg.get("provider"):
            provider_keys = [roles_cfg["provider"]]
        presets = [p for p in (preset_by_key(k) for k in provider_keys) if p is not None]
        if not presets:
            anthropic = preset_by_key("anthropic")
            presets = [anthropic] if anthropic else []
        if not presets:
            raise ValueError("model_roles: no usable provider presets resolved")

        # Named models: name -> (provider_key, model_id, declared capabilities).
        models_defs = roles_cfg.get("models") or {}
        caps_by_model: dict[str, ModelCapabilities] = {}
        model_ref: dict[str, tuple[str, str]] = {}
        for mname, mdef in models_defs.items():
            if not isinstance(mdef, dict):
                continue
            model_ref[mname] = (mdef.get("provider", ""), mdef.get("model", ""))
            if "capabilities" in mdef:
                caps_by_model[mdef.get("model", "")] = ModelCapabilities.from_dict(
                    mdef["capabilities"]
                )

        overrides = cls._role_overrides(roles_cfg, model_ref)
        assignments = recommend_roles(presets, overrides)

        # Fallback: pick the first available binding in [primary, *fallbacks],
        # enforcing the independence rule for the reviewer. Runs before
        # validation so the *selected* binding is what gets validated below.
        problems: list[str] = cls._resolve_fallbacks(
            assignments, roles_cfg, model_ref, caps_by_model, presets[0]
        )

        for name, a in assignments.items():
            caps = capabilities_for(a.model, caps_by_model.get(a.model))
            problems.extend(validate_inference(name, a.model, a.inference, caps))

        # Task routes: agent-limit values + any per-route inference override.
        for route_name, rc in (roles_cfg.get("routes") or {}).items():
            if not isinstance(rc, dict):
                continue
            problems.extend(validate_agent_limits(route_name, rc.get("agent")))
            role_name = rc.get("role") or role_for_task(route_name).name
            a = assignments.get(role_name)
            if a is not None and rc.get("inference"):
                inf = a.inference.merged(InferenceProfile.from_dict(rc["inference"]))
                caps = capabilities_for(a.model, caps_by_model.get(a.model))
                problems.extend(validate_inference(route_name, a.model, inf, caps))

        problems = list(dict.fromkeys(problems))  # dedupe (a selected fallback is validated twice)

        presets_by_key = {p.key: p for p in presets}
        # An override / named model may point a role at a provider not in the
        # primary list; pull its preset in so from_roles can build that endpoint.
        for a in assignments.values():
            if a.provider and a.provider not in presets_by_key:
                extra = preset_by_key(a.provider)
                if extra is not None:
                    presets_by_key[a.provider] = extra
        return assignments, presets_by_key, problems

    @staticmethod
    def _role_overrides(
        roles_cfg: dict[str, Any], model_ref: dict[str, tuple[str, str]]
    ) -> dict[str, dict]:
        """Fold ``roles:`` bindings and legacy ``overrides:`` into one map.

        A binding's ``model:`` may name a ``models:`` entry (resolved to its
        provider/model) or be a literal model id alongside a ``provider:``.
        """
        overrides: dict[str, dict] = {
            name: dict(ov) for name, ov in (roles_cfg.get("overrides") or {}).items()
        }
        for role_name, binding in (roles_cfg.get("roles") or {}).items():
            if not isinstance(binding, dict):
                continue
            ov = dict(overrides.get(role_name, {}))
            ref = binding.get("model")
            if ref in model_ref:
                provider_key, model_id = model_ref[ref]
                ov["provider"] = provider_key
                ov["model"] = model_id
            else:
                if binding.get("provider"):
                    ov["provider"] = binding["provider"]
                if ref:
                    ov["model"] = ref
            for key in ("inference", "reasoning", "constraints"):
                if key in binding:
                    ov[key] = binding[key]
            overrides[role_name] = ov
        return overrides

    @classmethod
    def _resolve_fallbacks(
        cls,
        assignments: dict[str, RoleAssignment],
        roles_cfg: dict[str, Any],
        model_ref: dict[str, tuple[str, str]],
        caps_by_model: dict[str, ModelCapabilities],
        primary_preset: Any,
    ) -> list[str]:
        """Pick each role's first *available* binding from its fallback chain.

        For a role with a ``fallback:`` list, the candidates are
        ``[primary, *fallbacks]``. A candidate is available when its provider's
        API key is present (or it is local / OAuth). The first available one is
        selected; the reviewer additionally requires a different model family
        than the generator, and a same-family model is never silently
        substituted — if no independent candidate is available the binding is
        kept but flagged ``independent_available: false``.

        Mutates ``assignments`` in place; returns validation problems for the
        fallback candidates (so a broken fallback fails at load, not at
        failover time). ``caps_by_model`` is extended with fallback models.
        """
        problems: list[str] = []
        roles_bindings = roles_cfg.get("roles") or {}
        generator_family = model_family(primary_preset.model_for_tier(Tier.MID.value))

        for role_name, binding in roles_bindings.items():
            if not isinstance(binding, dict) or role_name not in assignments:
                continue
            fb_list = binding.get("fallback") or []
            if not fb_list:
                continue
            base = assignments[role_name]
            candidates: list[dict] = [
                {"provider": base.provider, "model": base.model, "inference": base.inference}
            ]
            for entry in fb_list:
                if not isinstance(entry, dict):
                    continue
                ref = entry.get("model")
                if ref in model_ref:
                    prov, mid = model_ref[ref]
                else:
                    prov, mid = entry.get("provider", base.provider), ref or base.model
                inf = base.inference.merged(InferenceProfile.from_dict(entry.get("inference")))
                candidates.append({"provider": prov, "model": mid, "inference": inf})

            # Validate every candidate — a failover target must be usable too.
            for c in candidates:
                caps = capabilities_for(c["model"], caps_by_model.get(c["model"]))
                problems.extend(validate_inference(role_name, c["model"], c["inference"], caps))

            chosen, meta = cls._select_candidate(role_name, candidates, generator_family)
            constraints = {
                **base.constraints,
                **meta,
                "fallback_chain": [c["model"] for c in candidates],
            }
            reason = base.reason
            if chosen["model"] != base.model:
                constraints["fallback_used"] = chosen["model"]
                reason = f"failover → {chosen['model']} (primary unavailable)"
            assignments[role_name] = replace(
                base,
                provider=chosen["provider"],
                model=chosen["model"],
                inference=chosen["inference"],
                constraints=constraints,
                reason=reason,
            )
        return problems

    def _attach_routes(
        self, routes_cfg: dict[str, Any], assignments: dict[str, RoleAssignment]
    ) -> None:
        """Register task-route agent limits and per-route inference overrides.

        A ``routes:`` entry binds a call-site name to agent-workflow limits
        (``max_steps`` / ``max_tool_calls`` / ``max_retries``) and, optionally,
        an explicit ``role`` and an ``inference`` override applied on top of
        that role's binding — e.g. trimming the researcher's output budget for
        a cheap recon route without minting a new role.
        """
        for route_name, rc in routes_cfg.items():
            if not isinstance(rc, dict):
                continue
            limits = AgentLimits.from_dict(rc.get("agent"))
            if limits is not None and not limits.is_empty:
                self._agent_limits[route_name] = limits

            role_name = rc.get("role") or role_for_task(route_name).name
            a = assignments.get(role_name)
            if a is None:
                continue
            # Only mint/replace a route when the route customizes the model
            # call (an inference override) or names a route not already routed.
            if rc.get("inference") or route_name not in self._routes:
                inf = a.inference.merged(InferenceProfile.from_dict(rc.get("inference")))
                self._routes[route_name] = ModelRoute(
                    task=route_name,
                    provider=a.provider,
                    model=a.model,
                    reason=f"route {route_name} → {role_name}",
                    reasoning=a.reasoning,
                    inference=inf,
                )

    def get_agent_limits(self, task: str) -> AgentLimits | None:
        """Agent-workflow limits for a task/route, or None (unbounded).

        Falls back to the limits registered for the task's role name, so a
        limit set on ``researcher`` applies to ``hunter`` and ``recon`` too.
        """
        limits = self._agent_limits.get(task)
        if limits is not None:
            return limits
        return self._agent_limits.get(role_for_task(task).name)

    @staticmethod
    def _select_candidate(
        role_name: str, candidates: list[dict], generator_family: str
    ) -> tuple[dict, dict]:
        """Choose a candidate + selection metadata. See :meth:`_resolve_fallbacks`."""
        role = ROLES.get(role_name)
        available = [c for c in candidates if _provider_available(c["provider"])]
        if role is not None and role.independent:
            independent = [
                c for c in available if model_family(c["model"]) != generator_family
            ]
            if independent:
                return independent[0], {
                    "independent_satisfied": True,
                    "independent_available": True,
                }
            if available:
                # An available reviewer exists but shares the generator's family.
                # Bind it (system stays functional) but flag loudly — never a
                # silent same-family substitution.
                return available[0], {
                    "independent_satisfied": False,
                    "independent_available": False,
                }
            return candidates[0], {"independent_satisfied": False, "available": False}
        if available:
            return available[0], {}
        return candidates[0], {"available": False}

    @classmethod
    def from_roles(
        cls,
        assignments: dict[str, RoleAssignment],
        presets: dict[str, Any],
    ) -> ProviderManager:
        """Build a manager from resolved role assignments.

        Each assignment becomes a route named after its role (so
        ``get_native_client("researcher")`` works) and, via
        :data:`clearwing.providers.roles.TASK_ROLES`, a route for every task
        string that maps to that role (so the existing ``hunter`` /
        ``verifier`` / ``sourcehunt_exploit`` call sites keep working). The
        provider endpoints are synthesized from *presets* (base_url, adapter,
        and the ``${ENV}`` API key each preset declares).
        """
        configs: dict[str, ProviderConfig] = {}
        for a in assignments.values():
            if a.provider in configs:
                continue
            preset = presets.get(a.provider)
            api_key = ""
            if preset is not None and preset.api_key_env_var:
                api_key = os.environ.get(preset.api_key_env_var, "")
            configs[a.provider] = ProviderConfig(
                name=a.provider,
                model=a.model,
                api_key=api_key,
                base_url=(preset.default_base_url or "") if preset else "",
                adapter=(preset.provider_adapter or "") if preset else "",
            )

        routes: list[ModelRoute] = []
        for role_name, a in assignments.items():
            routes.append(
                ModelRoute(
                    task=role_name,
                    provider=a.provider,
                    model=a.model,
                    reason=a.reason,
                    reasoning=a.reasoning,
                    inference=a.inference,
                )
            )
        for task, role_name in TASK_ROLES.items():
            a = assignments.get(role_name)
            if a is None:
                continue
            routes.append(
                ModelRoute(
                    task=task,
                    provider=a.provider,
                    model=a.model,
                    reason=f"{task} → {role_name}",
                    reasoning=a.reasoning,
                    inference=a.inference,
                )
            )
        return cls(configs=list(configs.values()), routes=routes)

    @classmethod
    def resolve(cls) -> ProviderManager:
        """Build the provider manager for the current process.

        Machine-mode routing preserves the full per-task configuration.
        Interactive processes use Clearwing's endpoint resolution.
        """
        process_config = runtime_routing()
        if process_config:
            return cls.from_config(process_config)
        return cls.for_endpoint(resolve_llm_endpoint())

    # --- Get an LLM for a task --------------------------------------------

    def get_native_client(self, task: str = "default") -> AsyncLLMClient:
        """Get the native async LLM client for a task type."""
        if self._global_endpoint is not None:
            endpoint = self._endpoint_for_task(task)
            cache_key = self._global_cache_key("native", endpoint)
            if cache_key not in self._native_cache:
                self._native_cache[cache_key] = self._create_native_from_endpoint(endpoint, task)
            return self._native_cache[cache_key]

        route = self._route_for_task(task)
        if not route:
            raise ValueError(f"No route configured for task: {task}")

        inf = route.inference
        cache_key = ":".join(
            [
                route.provider,
                route.model,
                str(route.effective_reasoning),
                str(inf.max_output_tokens if inf else None),
                str(inf.temperature if inf else None),
                "native",
            ]
        )
        if cache_key not in self._native_cache:
            self._native_cache[cache_key] = self._create_native(
                route.provider,
                route.model,
                task,
                reasoning=route.effective_reasoning,
                inference=inf,
            )
        return self._native_cache[cache_key]

    def _route_for_task(self, task: str) -> ModelRoute | None:
        """Resolve a task to a route: exact match, then its role, then default.

        The role fallback only fires for role-aware managers (built via
        :meth:`from_roles`), where a route named after the role — e.g.
        ``researcher`` — exists. For DEFAULT_ROUTES / model_aliases managers
        no such route is present, so an unrouted task lands on ``default``
        exactly as before.
        """
        route = self._routes.get(task)
        if route is not None:
            return route
        role_route = self._routes.get(role_for_task(task).name)
        if role_route is not None:
            return role_route
        return self._routes.get("default")

    def _create_native_from_endpoint(
        self, endpoint: LLMEndpoint, task: str = "default"
    ) -> AsyncLLMClient:
        provider_name = _adapter_for_endpoint(endpoint)
        return AsyncLLMClient(
            model_name=endpoint.model,
            base_url=endpoint.base_url,
            api_key=endpoint.api_key or "",
            provider_name=provider_name,
            max_concurrency=_native_concurrency_for_task(task, provider_name),
            pricing=endpoint.pricing,
        )

    def _endpoint_for_task(self, task: str) -> LLMEndpoint:
        endpoint = self._global_endpoint
        if endpoint is None:
            raise ValueError("_endpoint_for_task requires a global endpoint")
        override_model = self._task_model_overrides.get(task)
        if override_model and override_model != endpoint.model:
            return replace(endpoint, model=override_model)
        return endpoint

    @staticmethod
    def _global_cache_key(kind: str, endpoint: LLMEndpoint) -> str:
        return ":".join(
            [
                "_global",
                kind,
                endpoint.provider,
                endpoint.model,
                endpoint.base_url or "",
                endpoint.api_key or "",
            ]
        )

    def _create_native(
        self,
        provider: str,
        model: str,
        task: str = "default",
        *,
        reasoning: str | None = None,
        inference: InferenceProfile | None = None,
    ) -> AsyncLLMClient:
        config = self._configs.get(provider)
        preset = PROVIDER_PRESETS.get(provider)
        # When a role supplied a reasoning budget, resolve it against the
        # model family (a local Qwen that rejects the param is downgraded to
        # None). Unset reasoning keeps the client's "auto" per-model default.
        effort = effective_reasoning_effort(model, reasoning) if reasoning is not None else "auto"
        # Inference settings become client-level defaults.
        temp = inference.temperature if inference else None
        max_out = inference.max_output_tokens if inference else None
        ctx_budget = inference.context_budget_tokens if inference else None
        top_p = inference.top_p if inference else None
        timeout = inference.timeout_seconds if inference else None
        common = {
            "reasoning_effort": effort,
            "default_temperature": temp,
            "default_max_tokens": max_out,
            "default_top_p": top_p,
            "default_timeout_seconds": timeout,
            "context_budget_tokens": ctx_budget,
        }

        if provider == "anthropic":
            return AsyncLLMClient(
                model_name=model,
                api_key=config.api_key if config else "",
                provider_name="anthropic",
                max_concurrency=_native_concurrency_for_task(task, "anthropic"),
                pricing=config.pricing if config else None,
                **common,
            )

        if provider == "openai":
            provider_name = _adapter_for_provider_config(provider, config)
            return AsyncLLMClient(
                model_name=model,
                base_url=config.base_url if config else None,
                api_key=config.api_key if config else "",
                provider_name=provider_name,
                max_concurrency=_native_concurrency_for_task(task, provider_name),
                pricing=config.pricing if config else None,
                **common,
            )

        if provider == "google":
            return AsyncLLMClient(
                model_name=model,
                api_key=config.api_key if config else "",
                provider_name="gemini",
                max_concurrency=_native_concurrency_for_task(task, "gemini"),
                pricing=config.pricing if config else None,
                **common,
            )

        if provider == "ollama":
            base_url = (
                config.base_url
                if config and config.base_url
                else preset.get("default_base_url", "http://localhost:11434")
            )
            return AsyncLLMClient(
                model_name=model,
                base_url=base_url,
                api_key=config.api_key if config else "",
                provider_name="ollama",
                max_concurrency=_native_concurrency_for_task(task, "ollama"),
                pricing=config.pricing if config else None,
                **common,
            )

        if config and config.base_url:
            provider_name = _adapter_for_provider_config(provider, config)
            return AsyncLLMClient(
                model_name=model,
                base_url=config.base_url,
                api_key=config.api_key,
                provider_name=provider_name,
                max_concurrency=_native_concurrency_for_task(task, provider_name),
                pricing=config.pricing,
                **common,
            )
        raise ValueError(f"Unknown provider: {provider}")

    def list_providers(self) -> list[str]:
        """List all configured provider names."""
        return list(self._configs.keys())

    def list_routes(self) -> list[ModelRoute]:
        """List all configured routes."""
        return list(self._routes.values())

    def set_route(self, task: str, provider: str, model: str, reason: str = ""):
        """Update or add a route for a task type."""
        self._routes[task] = ModelRoute(task=task, provider=provider, model=model, reason=reason)
        # Invalidate cache for this route
        cache_key = f"{provider}:{model}:native"
        self._native_cache.pop(cache_key, None)

    def get_route_info(self) -> str:
        """Human-readable summary of current routing."""
        if self._global_endpoint is not None:
            return (
                "Model Routing:\n"
                f"  (all tasks) → {self._global_endpoint.describe()}\n"
                f"  provider: {self._global_endpoint.provider}"
            )
        lines = ["Model Routing:"]
        for task, route in sorted(self._routes.items()):
            lines.append(f"  {task}: {route.provider}/{route.model} ({route.reason})")
        return "\n".join(lines)


def _provider_available(provider_key: str) -> bool:
    """True when a provider can actually be called right now.

    Local backends and OAuth flows are always considered available; a
    key-based provider is available only when its API-key env var is set.
    Unknown provider keys (e.g. a ``providers:`` connection name) can't be
    verified, so they're assumed available rather than falsely skipped.
    """
    preset = preset_by_key(provider_key)
    if preset is None:
        return True
    if preset.is_local or preset.auth_flow:
        return True
    if preset.api_key_env_var:
        return bool(os.environ.get(preset.api_key_env_var))
    return True


def _expand_env(value: Any) -> str:
    """Expand `${ENV_VAR}` in a config string. Empty string if unset.

    Kept module-private so `from_config` can reuse the same expansion
    rule as `providers.env._resolve_config_secret` without either
    module depending on the other.
    """
    if value is None:
        return ""
    s = str(value).strip()
    if s.startswith("${") and s.endswith("}"):
        return os.environ.get(s[2:-1], "")
    return s


def _pricing_from_config(value: Any) -> EndpointPricing | None:
    """Parse an optional provider pricing block without treating zero as absent."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("provider pricing must be an object")
    missing = [name for name in ("input_per_mtok", "output_per_mtok") if name not in value]
    if missing:
        raise ValueError(f"provider pricing is missing: {', '.join(missing)}")
    return EndpointPricing(
        input_per_mtok=float(value["input_per_mtok"]),
        output_per_mtok=float(value["output_per_mtok"]),
        cached_per_mtok=(
            float(value["cached_per_mtok"]) if value.get("cached_per_mtok") is not None else None
        ),
        cache_creation_per_mtok=(
            float(value["cache_creation_per_mtok"])
            if value.get("cache_creation_per_mtok") is not None
            else None
        ),
    )


def _adapter_for_endpoint(endpoint: LLMEndpoint) -> str:
    # Explicit `adapter:` on the endpoint (propagated from the
    # `provider:` config block) wins over every other rule.
    if endpoint.adapter:
        return endpoint.adapter.strip()
    if endpoint.provider == "anthropic_oauth":
        return "anthropic_oauth"
    if endpoint.provider == "anthropic":
        return "anthropic"
    if endpoint.provider == "openai_codex":
        return "openai_codex"
    return _adapter_for_base_url(endpoint.base_url, endpoint.model)


def _adapter_for_provider_config(provider: str, config: ProviderConfig | None) -> str:
    # Explicit `adapter:` on the provider config wins over every heuristic.
    # Setup wizard writes this for presets that carry `provider_adapter`
    # (e.g. the `openai-responses` preset → `adapter: openai_resp`).
    if config is not None and config.adapter:
        return config.adapter.strip()
    explicit = provider.lower().strip()
    if explicit in {"anthropic_oauth", "anthropic-oauth"}:
        return "anthropic_oauth"
    if explicit == "anthropic":
        return "anthropic"
    if explicit in {"openai_codex", "openai-codex", "openai_oauth", "openai-oauth"}:
        return "openai_codex"
    if explicit == "google":
        return "gemini"
    if explicit == "ollama":
        return "ollama"
    return _adapter_for_base_url(
        config.base_url if config else None, config.model if config else ""
    )


def _adapter_for_base_url(base_url: str | None, model: str) -> str:
    """Fallback adapter resolution when no explicit `adapter:` is set.

    Pure URL / model-name heuristics — no per-host hardcoded special
    cases. Users on endpoints that aren't disambiguated by URL should
    set `adapter:` on their provider config (the `openai-responses`
    preset does this automatically).
    """
    host = (base_url or "").lower()
    if "11434" in host:
        return "ollama"
    if "generativelanguage.googleapis.com" in host or "googleapis.com" in host:
        return "gemini"
    if "anthropic.com" in host:
        return "anthropic"
    if "minimax.io" in host and host.rstrip("/").endswith("/anthropic"):
        return "anthropic"
    if model.startswith("gemini-"):
        return "gemini"
    return "openai"


def _native_concurrency_for_task(task: str, provider_name: str) -> int:
    normalized_task = task.strip().lower()
    normalized_provider = provider_name.strip().lower()

    if normalized_provider == "openai_resp":
        if normalized_task == "ranker":
            return 1
        if normalized_task in {"hunter", "verifier", "sourcehunt_exploit", "default"}:
            return 15

    if normalized_task == "ranker":
        return 4
    return 8


def _default_task_model_overrides(endpoint: LLMEndpoint) -> dict[str, str]:
    overrides: dict[str, str] = {}
    if endpoint.provider == "openai_compat" and endpoint.model == "gpt-5.4":
        overrides["ranker"] = "gpt-5.4-mini"
    return overrides
