from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from typing import Any

from clearwing.llm import AsyncLLMClient, ChatModel

from .env import LLMEndpoint, resolve_llm_endpoint

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


@dataclass
class ModelRoute:
    """Maps a task type to a specific provider/model."""

    task: str  # recon, exploit, report, planning, default
    provider: str
    model: str
    reason: str = ""  # why this model for this task


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
        self._llm_cache: dict[str, ChatModel] = {}
        self._native_cache: dict[str, AsyncLLMClient] = {}
        # When `endpoint` is set, every get_llm() call returns the
        # same model instance for identical resolved endpoints. Task-
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
    def for_endpoint(cls, endpoint: LLMEndpoint) -> ProviderManager:
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
            task_model_overrides=_default_task_model_overrides(endpoint),
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

    # --- Get an LLM for a task --------------------------------------------

    def get_llm(self, task: str = "default") -> ChatModel:
        """Get the appropriate LLM for a task type."""
        # Single-endpoint mode: every task gets the same LLM
        if self._global_endpoint is not None:
            endpoint = self._endpoint_for_task(task)
            cache_key = self._global_cache_key("chat", endpoint)
            if cache_key not in self._llm_cache:
                self._llm_cache[cache_key] = self._create_llm_from_endpoint(endpoint)
            return self._llm_cache[cache_key]

        route = self._routes.get(task, self._routes.get("default"))
        if not route:
            raise ValueError(f"No route configured for task: {task}")

        cache_key = f"{route.provider}:{route.model}"
        if cache_key not in self._llm_cache:
            self._llm_cache[cache_key] = self._create_llm(route.provider, route.model)

        return self._llm_cache[cache_key]

    def get_native_client(self, task: str = "default") -> AsyncLLMClient:
        """Get the native async LLM client for a task type."""
        if self._global_endpoint is not None:
            endpoint = self._endpoint_for_task(task)
            cache_key = self._global_cache_key("native", endpoint)
            if cache_key not in self._native_cache:
                self._native_cache[cache_key] = self._create_native_from_endpoint(endpoint, task)
            return self._native_cache[cache_key]

        route = self._routes.get(task, self._routes.get("default"))
        if not route:
            raise ValueError(f"No route configured for task: {task}")

        cache_key = f"{route.provider}:{route.model}:native"
        if cache_key not in self._native_cache:
            self._native_cache[cache_key] = self._create_native(route.provider, route.model, task)
        return self._native_cache[cache_key]

    def _create_llm_from_endpoint(self, endpoint: LLMEndpoint) -> ChatModel:
        """Build a native ChatModel from a resolved LLMEndpoint."""
        if endpoint.is_openai_compat:
            return ChatModel(
                model_name=endpoint.model,
                base_url=endpoint.base_url,
                api_key=endpoint.api_key or "",
                provider_name=_adapter_for_endpoint(endpoint),
            )

        # Anthropic direct, or an Anthropic-compatible gateway (e.g. MiniMax's
        # api.minimax.io/anthropic). base_url is None for the direct case.
        return ChatModel(
            model_name=endpoint.model,
            base_url=endpoint.base_url,
            api_key=endpoint.api_key or "",
            provider_name=_adapter_for_endpoint(endpoint),
        )

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

    def _create_llm(self, provider: str, model: str) -> ChatModel:
        """Create a native chat model for a given provider and model."""
        config = self._configs.get(provider)
        preset = PROVIDER_PRESETS.get(provider)

        if provider == "anthropic":
            return ChatModel(
                model_name=model,
                api_key=config.api_key if config else "",
                provider_name="anthropic",
            )

        elif provider == "openai":
            return ChatModel(
                model_name=model,
                base_url=config.base_url if config else None,
                api_key=config.api_key if config else "",
                provider_name=_adapter_for_provider_config(provider, config),
            )

        elif provider == "google":
            return ChatModel(
                model_name=model,
                api_key=config.api_key if config else "",
                provider_name="gemini",
            )

        elif provider == "ollama":
            base_url = (
                config.base_url
                if config and config.base_url
                else preset.get("default_base_url", "http://localhost:11434")
            )
            return ChatModel(
                model_name=model,
                base_url=base_url,
                api_key=config.api_key if config else "",
                provider_name="ollama",
            )

        else:
            if config and config.base_url:
                return ChatModel(
                    model_name=model,
                    base_url=config.base_url,
                    api_key=config.api_key,
                    provider_name=_adapter_for_provider_config(provider, config),
                )
            raise ValueError(f"Unknown provider: {provider}")

    def _create_native(self, provider: str, model: str, task: str = "default") -> AsyncLLMClient:
        config = self._configs.get(provider)
        preset = PROVIDER_PRESETS.get(provider)

        if provider == "anthropic":
            return AsyncLLMClient(
                model_name=model,
                api_key=config.api_key if config else "",
                provider_name="anthropic",
                max_concurrency=_native_concurrency_for_task(task, "anthropic"),
            )

        if provider == "openai":
            provider_name = _adapter_for_provider_config(provider, config)
            return AsyncLLMClient(
                model_name=model,
                base_url=config.base_url if config else None,
                api_key=config.api_key if config else "",
                provider_name=provider_name,
                max_concurrency=_native_concurrency_for_task(task, provider_name),
            )

        if provider == "google":
            return AsyncLLMClient(
                model_name=model,
                api_key=config.api_key if config else "",
                provider_name="gemini",
                max_concurrency=_native_concurrency_for_task(task, "gemini"),
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
            )

        if config and config.base_url:
            provider_name = _adapter_for_provider_config(provider, config)
            return AsyncLLMClient(
                model_name=model,
                base_url=config.base_url,
                api_key=config.api_key,
                provider_name=provider_name,
                max_concurrency=_native_concurrency_for_task(task, provider_name),
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
        cache_key = f"{provider}:{model}"
        self._llm_cache.pop(cache_key, None)

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


def _adapter_for_endpoint(endpoint: LLMEndpoint) -> str:
    if endpoint.provider == "anthropic":
        return "anthropic"
    if endpoint.provider == "openai_codex":
        return "openai_codex"
    return _adapter_for_base_url(endpoint.base_url, endpoint.model)


def _adapter_for_provider_config(provider: str, config: ProviderConfig | None) -> str:
    explicit = provider.lower().strip()
    if explicit == "anthropic":
        return "anthropic"
    if explicit in {"openai_codex", "openai-codex", "openai_oauth", "openai-oauth"}:
        return "openai_codex"
    if explicit == "google":
        return "gemini"
    if explicit == "ollama":
        return "ollama"
    if explicit == "openai":
        return _adapter_for_base_url(
            config.base_url if config else None, config.model if config else ""
        )
    return _adapter_for_base_url(
        config.base_url if config else None, config.model if config else ""
    )


def _adapter_for_base_url(base_url: str | None, model: str) -> str:
    host = (base_url or "").lower()
    if "localhost:8183" in host or "127.0.0.1:8183" in host:
        return "openai_resp"
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
