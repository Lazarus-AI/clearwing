"""Endpoint resolution for the multi-provider LLM layer.

Clearwing picks an LLM from four possible sources, in precedence
order (highest wins):

    1. CLI flags         (--base-url / --api-key / --model)
    2. Environment vars  (CLEARWING_BASE_URL / CLEARWING_API_KEY /
                          CLEARWING_MODEL)
    3. Config YAML       (~/.clearwing/config.yaml provider: section)
    4. Default           (Anthropic claude-sonnet-4-6 via
                          ANTHROPIC_API_KEY)

The `resolve_llm_endpoint()` function threads all four sources into a
single `LLMEndpoint` dataclass that every call site (network agent,
sourcehunt runner, retro-hunt, operator mode) can consume uniformly.
This is the one place the precedence rules live — updating it here
updates every command.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# --- Env var names (single source of truth) --------------------------------


ENV_BASE_URL = "CLEARWING_BASE_URL"
ENV_API_KEY = "CLEARWING_API_KEY"
ENV_MODEL = "CLEARWING_MODEL"

# Fallback: the Anthropic-direct credentials that predate the multi-provider
# work. If neither CLEARWING_* nor CLI flags are set, we keep honoring these
# so the existing default-install UX doesn't break.
ENV_ANTHROPIC_KEY = "ANTHROPIC_API_KEY"

# Sensible built-in default — users with only ANTHROPIC_API_KEY set get the
# same behavior they got pre-multi-provider: Claude Sonnet 4.6 via Anthropic
# direct.
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"


# --- LLMEndpoint result type -----------------------------------------------


@dataclass(frozen=True)
class LLMEndpoint:
    """The resolved LLM configuration for one command invocation.

    Fields:
        provider: "anthropic" | "openai_compat" | "openai_codex" | "ollama" — decides
                  which native transport configuration handles the actual call.
        model:    The model identifier as the provider expects it
                  (e.g. "claude-sonnet-4-6", "anthropic/claude-opus-4"
                  for OpenRouter, "llama3:70b" for Ollama, "gpt-4o"
                  for OpenAI direct).
        base_url: The HTTP endpoint to dispatch against. None for
                  Anthropic direct; set for every OpenAI-compatible
                  backend.
        api_key:  The credential to authenticate with. May be None
                  for fully local endpoints; provider constructors
                  fill in a placeholder when needed.
        source:   "cli" | "env" | "config" | "default" — where the
                  triple came from. Used by `--verbose` / debug
                  logging to show operators why a particular endpoint
                  was chosen.
    """

    provider: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    source: str = "default"
    #: Optional explicit genai-pyo3 adapter override. When set, the
    #: ProviderManager uses it instead of the base-URL heuristic. Set
    #: via `adapter:` in the `provider:` config block (e.g. the
    #: `openai-responses` preset writes `adapter: openai_resp`).
    adapter: str | None = None

    @property
    def is_openai_compat(self) -> bool:
        """True if this endpoint talks the OpenAI-compatible dialect.

        That covers: OpenRouter, Ollama (via /v1), LM Studio, vLLM,
        Together, Fireworks, Groq, Anyscale, SiliconFlow, DeepSeek,
        and OpenAI direct. ChatGPT/Codex OAuth is not OpenAI-compatible.
        """
        return self.provider == "openai_compat"

    @property
    def is_anthropic_direct(self) -> bool:
        """True if this endpoint talks to Anthropic directly."""
        return self.provider == "anthropic" and self.base_url is None

    def describe(self) -> str:
        """Human-readable one-liner for preflight / debug output."""
        target = self.base_url or "https://api.anthropic.com"
        return f"{self.model} via {target} (source: {self.source})"


# --- Resolution ------------------------------------------------------------


def resolve_llm_endpoint(
    cli_model: str | None = None,
    cli_base_url: str | None = None,
    cli_api_key: str | None = None,
    config_provider: dict[str, Any] | None = None,
) -> LLMEndpoint:
    """Merge CLI / env / config / default sources into one endpoint.

    Precedence (highest wins):
        1. CLI flags
        2. CLEARWING_BASE_URL / CLEARWING_API_KEY / CLEARWING_MODEL
        3. config_provider dict (from YAML)
        4. Anthropic default via ANTHROPIC_API_KEY

    Args:
        cli_model:    Value of `--model` if passed.
        cli_base_url: Value of `--base-url` if passed.
        cli_api_key:  Value of `--api-key` if passed.
        config_provider: The `provider:` section of
                      `~/.clearwing/config.yaml`, already parsed into
                      a dict. When None, `resolve_llm_endpoint` tries
                      to auto-discover the default config path; pass
                      `{}` explicitly to disable auto-discovery.

    Returns:
        An `LLMEndpoint` with every field filled in, including a
        `source` marker for debug output. Never returns None — the
        default case produces an `LLMEndpoint(provider="anthropic",
        model="claude-sonnet-4-6", ..., source="default")` regardless
        of whether ANTHROPIC_API_KEY is actually set. The caller is
        responsible for checking that its `api_key` is non-None
        before making a call.
    """
    if config_provider is None:
        config_provider = _load_default_config_provider()
    config_provider = config_provider or {}

    # 1. CLI flags win when any are set
    if cli_base_url or cli_model or cli_api_key:
        base_url = cli_base_url
        if base_url:
            if _is_anthropic_compat_base_url(base_url):
                return LLMEndpoint(
                    provider="anthropic",
                    model=cli_model or _default_anthropic_compat_model(base_url),
                    base_url=base_url,
                    api_key=cli_api_key or os.environ.get(ENV_API_KEY),
                    source="cli",
                )
            provider = "openai_compat"
            model = cli_model or _default_openai_compat_model(base_url)
            api_key = cli_api_key or os.environ.get(ENV_API_KEY) or _placeholder_for(base_url)
            return LLMEndpoint(
                provider=provider,
                model=model,
                base_url=base_url,
                api_key=api_key,
                source="cli",
            )
        # CLI passed --model and/or --api-key but no --base-url. That's
        # Anthropic-direct with a model override.
        return LLMEndpoint(
            provider="anthropic",
            model=cli_model or DEFAULT_ANTHROPIC_MODEL,
            base_url=None,
            api_key=cli_api_key or os.environ.get(ENV_ANTHROPIC_KEY),
            source="cli",
        )

    # 2. CLEARWING_* env vars
    env_base_url = os.environ.get(ENV_BASE_URL)
    env_api_key = os.environ.get(ENV_API_KEY)
    env_model = os.environ.get(ENV_MODEL)
    if env_base_url or env_model:
        if env_base_url:
            if _is_anthropic_compat_base_url(env_base_url):
                return LLMEndpoint(
                    provider="anthropic",
                    model=env_model or _default_anthropic_compat_model(env_base_url),
                    base_url=env_base_url,
                    api_key=env_api_key or os.environ.get(ENV_ANTHROPIC_KEY),
                    source="env",
                )
            return LLMEndpoint(
                provider="openai_compat",
                model=env_model or _default_openai_compat_model(env_base_url),
                base_url=env_base_url,
                api_key=env_api_key or _placeholder_for(env_base_url),
                source="env",
            )
        return LLMEndpoint(
            provider="anthropic",
            model=env_model or DEFAULT_ANTHROPIC_MODEL,
            base_url=None,
            api_key=env_api_key or os.environ.get(ENV_ANTHROPIC_KEY),
            source="env",
        )

    # 3. YAML config.yaml provider: section
    if config_provider:
        cfg_auth = _normalize_auth_flow(
            config_provider.get("auth") or config_provider.get("auth_flow")
        )
        if cfg_auth == "openai_codex":
            cfg_base_url = config_provider.get("base_url") or _openai_codex_default_base_url()
            cfg_model = config_provider.get("model") or _openai_codex_default_model()
            return LLMEndpoint(
                provider="openai_codex",
                model=str(cfg_model),
                base_url=str(cfg_base_url),
                api_key=_openai_oauth_access_token(),
                source="config",
            )

        cfg_base_url = config_provider.get("base_url")
        cfg_model = config_provider.get("model")
        cfg_api_key = _resolve_config_secret(config_provider.get("api_key"))
        cfg_adapter = config_provider.get("adapter")  # None if unset
        if cfg_base_url:
            if _is_anthropic_compat_base_url(cfg_base_url):
                return LLMEndpoint(
                    provider="anthropic",
                    model=cfg_model or _default_anthropic_compat_model(cfg_base_url),
                    base_url=cfg_base_url,
                    api_key=cfg_api_key or os.environ.get(ENV_ANTHROPIC_KEY),
                    source="config",
                    adapter=cfg_adapter,
                )
            return LLMEndpoint(
                provider="openai_compat",
                model=cfg_model or _default_openai_compat_model(cfg_base_url),
                base_url=cfg_base_url,
                api_key=cfg_api_key or _placeholder_for(cfg_base_url),
                source="config",
                adapter=cfg_adapter,
            )
        if cfg_model or cfg_api_key:
            return LLMEndpoint(
                provider="anthropic",
                model=cfg_model or DEFAULT_ANTHROPIC_MODEL,
                base_url=None,
                api_key=cfg_api_key or os.environ.get(ENV_ANTHROPIC_KEY),
                source="config",
                adapter=cfg_adapter,
            )

    # 4. Default — Anthropic direct via ANTHROPIC_API_KEY
    return LLMEndpoint(
        provider="anthropic",
        model=DEFAULT_ANTHROPIC_MODEL,
        base_url=None,
        api_key=os.environ.get(ENV_ANTHROPIC_KEY),
        source="default",
    )


def _load_default_config_provider() -> dict[str, Any]:
    """Read the `provider:` section from ~/.clearwing/config.yaml.

    Returns an empty dict if the file doesn't exist or can't be
    parsed — never raises. Doesn't go through `clearwing.core.Config`
    to avoid a circular import (core → yaml is fine; providers → core
    would tangle the two packages).
    """
    from clearwing.core.config import clearwing_home

    config_path = clearwing_home() / "config.yaml"
    if not config_path.exists():
        return {}
    try:
        import yaml  # noqa: PLC0415 — deferred so env.py is still import-safe without PyYAML
    except ImportError:
        logger.debug("PyYAML not installed; skipping ~/.clearwing/config.yaml auto-load")
        return {}
    try:
        with open(config_path) as f:
            parsed = yaml.safe_load(f) or {}
    except Exception:
        logger.debug("Failed to parse %s; ignoring provider config", config_path, exc_info=True)
        return {}
    section = parsed.get("provider") if isinstance(parsed, dict) else None
    return dict(section) if isinstance(section, dict) else {}


def _resolve_config_secret(value: Any) -> str | None:
    """Expand `${ENV_VAR}` references in config secrets.

    A config file like `api_key: ${OPENROUTER_API_KEY}` should pull
    the actual secret from the environment at runtime, not bake it
    into the YAML. Also strips leading/trailing whitespace and
    returns None for empty strings.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.startswith("${") and s.endswith("}"):
        env_name = s[2:-1]
        return os.environ.get(env_name)
    return s


def _normalize_auth_flow(value: Any) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "openai-oauth": "openai_codex",
        "openai_oauth": "openai_codex",
        "openai-codex": "openai_codex",
        "openai_codex": "openai_codex",
        "codex": "openai_codex",
    }
    return aliases.get(raw, raw)


def _openai_codex_default_base_url() -> str:
    try:
        from clearwing.providers.openai_oauth import OPENAI_CODEX_DEFAULT_BASE_URL

        return OPENAI_CODEX_DEFAULT_BASE_URL
    except Exception:
        return "https://chatgpt.com/backend-api"


def _openai_codex_default_model() -> str:
    try:
        from clearwing.providers.openai_oauth import OPENAI_CODEX_DEFAULT_MODEL

        return OPENAI_CODEX_DEFAULT_MODEL
    except Exception:
        return "gpt-5.2"


def _openai_oauth_access_token() -> str | None:
    try:
        from clearwing.providers.openai_oauth import ensure_fresh_openai_oauth_credentials

        return ensure_fresh_openai_oauth_credentials().access
    except Exception:
        logger.debug("OpenAI OAuth credentials unavailable", exc_info=True)
        return None


def _is_anthropic_compat_base_url(base_url: str) -> bool:
    """Return True if *base_url* speaks Anthropic's Messages API.

    Used by `resolve_llm_endpoint` to route a custom base_url through
    the Anthropic adapter instead of OpenAI-compat. Covers MiniMax's
    `api.minimax.io/anthropic` endpoint and anthropic.com itself.
    """
    host = base_url.lower().rstrip("/")
    if "anthropic.com" in host:
        return True
    if "minimax.io" in host and host.endswith("/anthropic"):
        return True
    return False


def _default_anthropic_compat_model(base_url: str) -> str:
    """Pick a default model for an Anthropic-compat base_url."""
    host = base_url.lower()
    if "minimax.io" in host:
        return "MiniMax-M2.7"
    return DEFAULT_ANTHROPIC_MODEL


def _default_openai_compat_model(base_url: str) -> str:
    """Pick a sensible default model when only the base_url is given.

    This is a best-effort guess based on the hostname. Users who care
    about the exact model should pass `--model` explicitly; the
    guesses here just prevent the "must set --model" error for the
    common cases.
    """
    host = base_url.lower()
    if "openrouter.ai" in host:
        return "anthropic/claude-sonnet-4"
    if "localhost:11434" in host or "127.0.0.1:11434" in host:
        # Ollama default — assume a recent coder model is pulled
        return "qwen2.5-coder:32b"
    if "localhost:1234" in host or "127.0.0.1:1234" in host:
        # LM Studio default
        return "local-model"
    if "together.xyz" in host or "together.ai" in host:
        return "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
    if "groq.com" in host:
        return "llama-3.3-70b-versatile"
    if "api.openai.com" in host:
        return "gpt-4o"
    if "api.deepseek.com" in host:
        return "deepseek-chat"
    # Catch-all
    return "default"


def _placeholder_for(base_url: str) -> str:
    """Return a non-None api_key placeholder for endpoints that don't
    enforce auth.

    Ollama, LM Studio, and vLLM typically ignore the key entirely but
    the OpenAI SDK refuses to construct without *some* value. Return
    the string `"ollama"` for those (Ollama's own convention) and
    `"not-needed"` for everything else.
    """
    host = base_url.lower()
    if "11434" in host:
        return "ollama"
    return "not-needed"


__all__ = [
    "ENV_ANTHROPIC_KEY",
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "ENV_MODEL",
    "DEFAULT_ANTHROPIC_MODEL",
    "LLMEndpoint",
    "resolve_llm_endpoint",
]
