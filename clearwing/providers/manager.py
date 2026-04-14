from __future__ import annotations

from dataclasses import dataclass

from langchain_core.language_models import BaseChatModel


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
        "class": "langchain_anthropic.ChatAnthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "models": ["claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
    },
    "openai": {
        "class": "langchain_openai.ChatOpenAI",
        "env_key": "OPENAI_API_KEY",
        "models": ["gpt-4o", "gpt-4o-mini", "o1-preview"],
    },
    "google": {
        "class": "langchain_google_genai.ChatGoogleGenerativeAI",
        "env_key": "GOOGLE_API_KEY",
        "models": ["gemini-2.0-flash", "gemini-2.5-pro"],
    },
    "ollama": {
        "class": "langchain_ollama.ChatOllama",
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
    """Manages multiple LLM providers with task-based routing."""

    def __init__(self, configs: list[ProviderConfig] = None, routes: list[ModelRoute] = None):
        self._configs: dict[str, ProviderConfig] = {}
        self._routes: dict[str, ModelRoute] = {}
        self._llm_cache: dict[str, BaseChatModel] = {}

        if configs:
            for c in configs:
                self._configs[c.name] = c

        # Set up routes
        for route in routes or DEFAULT_ROUTES:
            self._routes[route.task] = route

    def get_llm(self, task: str = "default") -> BaseChatModel:
        """Get the appropriate LLM for a task type."""
        route = self._routes.get(task, self._routes.get("default"))
        if not route:
            raise ValueError(f"No route configured for task: {task}")

        cache_key = f"{route.provider}:{route.model}"
        if cache_key not in self._llm_cache:
            self._llm_cache[cache_key] = self._create_llm(route.provider, route.model)

        return self._llm_cache[cache_key]

    def _create_llm(self, provider: str, model: str) -> BaseChatModel:
        """Create an LLM instance for a given provider and model."""
        config = self._configs.get(provider)
        preset = PROVIDER_PRESETS.get(provider)

        if provider == "anthropic":
            from langchain_anthropic import ChatAnthropic

            kwargs = {"model": model}
            if config and config.api_key:
                kwargs["api_key"] = config.api_key
            if config and config.max_tokens:
                kwargs["max_tokens"] = config.max_tokens
            return ChatAnthropic(**kwargs)

        elif provider == "openai":
            try:
                from langchain_openai import ChatOpenAI
            except ImportError as e:
                raise ImportError("Install langchain-openai: pip install langchain-openai") from e
            kwargs = {"model": model}
            if config and config.api_key:
                kwargs["api_key"] = config.api_key
            if config and config.base_url:
                kwargs["base_url"] = config.base_url
            return ChatOpenAI(**kwargs)

        elif provider == "google":
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
            except ImportError as e:
                raise ImportError(
                    "Install langchain-google-genai: pip install langchain-google-genai"
                ) from e
            kwargs = {"model": model}
            if config and config.api_key:
                kwargs["google_api_key"] = config.api_key
            return ChatGoogleGenerativeAI(**kwargs)

        elif provider == "ollama":
            try:
                from langchain_ollama import ChatOllama
            except ImportError as e:
                raise ImportError("Install langchain-ollama: pip install langchain-ollama") from e
            kwargs = {"model": model}
            base_url = (
                config.base_url
                if config and config.base_url
                else preset.get("default_base_url", "http://localhost:11434")
            )
            kwargs["base_url"] = base_url
            return ChatOllama(**kwargs)

        else:
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
        lines = ["Model Routing:"]
        for task, route in sorted(self._routes.items()):
            lines.append(f"  {task}: {route.provider}/{route.model} ({route.reason})")
        return "\n".join(lines)
