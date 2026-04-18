"""Tests for the multi-provider endpoint-resolution layer.

Covers the `resolve_llm_endpoint` precedence rules, the
`ProviderManager.for_endpoint` factory, and the env-var escape
hatches that let users point Clearwing at OpenRouter, Ollama,
LM Studio, vLLM, or any OpenAI-compatible endpoint without
editing config files.

Structured around the precedence ladder:
    1. CLI flags          (highest)
    2. CLEARWING_* env vars
    3. config.yaml provider: section
    4. Anthropic default via ANTHROPIC_API_KEY  (lowest)
"""

from __future__ import annotations

import pytest

from clearwing.llm import ChatModel
from clearwing.providers import (
    DEFAULT_ANTHROPIC_MODEL,
    ENV_ANTHROPIC_KEY,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MODEL,
    LLMEndpoint,
    ProviderManager,
    resolve_llm_endpoint,
)


@pytest.fixture
def clean_env(monkeypatch):
    """Wipe every provider-related env var so tests start from a known
    zero state regardless of the operator's shell."""
    for name in (ENV_BASE_URL, ENV_API_KEY, ENV_MODEL, ENV_ANTHROPIC_KEY, "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    yield


# --- Precedence: CLI flags win over everything ----------------------------


class TestCLIPrecedence:
    def test_cli_base_url_routes_to_openai_compat(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_ANTHROPIC_KEY, "sk-anthropic-ignored")
        ep = resolve_llm_endpoint(
            cli_base_url="https://openrouter.ai/api/v1",
            cli_api_key="sk-or-test",
            cli_model="anthropic/claude-opus-4",
            config_provider={},
        )
        assert ep.provider == "openai_compat"
        assert ep.base_url == "https://openrouter.ai/api/v1"
        assert ep.api_key == "sk-or-test"
        assert ep.model == "anthropic/claude-opus-4"
        assert ep.source == "cli"
        assert ep.is_openai_compat
        assert not ep.is_anthropic_direct

    def test_cli_model_only_stays_on_anthropic(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_ANTHROPIC_KEY, "sk-anthropic-x")
        ep = resolve_llm_endpoint(cli_model="claude-opus-4-6", config_provider={})
        assert ep.provider == "anthropic"
        assert ep.base_url is None
        assert ep.api_key == "sk-anthropic-x"
        assert ep.model == "claude-opus-4-6"
        assert ep.source == "cli"
        assert ep.is_anthropic_direct

    def test_cli_beats_env(self, clean_env, monkeypatch):
        # CLEARWING_* env vars set one endpoint, CLI another
        monkeypatch.setenv(ENV_BASE_URL, "http://localhost:11434/v1")
        monkeypatch.setenv(ENV_API_KEY, "ollama")
        monkeypatch.setenv(ENV_MODEL, "llama3:70b")
        ep = resolve_llm_endpoint(
            cli_base_url="https://api.together.xyz/v1",
            cli_api_key="sk-together",
            cli_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
            config_provider={},
        )
        assert ep.base_url == "https://api.together.xyz/v1"
        assert ep.api_key == "sk-together"
        assert ep.source == "cli"


# --- Precedence: CLEARWING_* env vars win over config + default -----------


class TestEnvPrecedence:
    def test_env_triple_routes_to_openai_compat(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_BASE_URL, "https://openrouter.ai/api/v1")
        monkeypatch.setenv(ENV_API_KEY, "sk-or-env")
        monkeypatch.setenv(ENV_MODEL, "anthropic/claude-sonnet-4")
        ep = resolve_llm_endpoint(config_provider={})
        assert ep.provider == "openai_compat"
        assert ep.base_url == "https://openrouter.ai/api/v1"
        assert ep.api_key == "sk-or-env"
        assert ep.model == "anthropic/claude-sonnet-4"
        assert ep.source == "env"

    def test_env_model_alone_with_anthropic_key(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_ANTHROPIC_KEY, "sk-anthropic-y")
        monkeypatch.setenv(ENV_MODEL, "claude-haiku-4-5-20251001")
        ep = resolve_llm_endpoint(config_provider={})
        assert ep.provider == "anthropic"
        assert ep.base_url is None
        assert ep.api_key == "sk-anthropic-y"
        assert ep.model == "claude-haiku-4-5-20251001"
        assert ep.source == "env"

    def test_env_beats_config(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_BASE_URL, "http://localhost:1234/v1")
        monkeypatch.setenv(ENV_API_KEY, "lm-studio")
        config = {
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "sk-or-from-config",
            "model": "anthropic/claude-opus-4",
        }
        ep = resolve_llm_endpoint(config_provider=config)
        assert ep.base_url == "http://localhost:1234/v1"
        assert ep.api_key == "lm-studio"
        assert ep.source == "env"

    def test_default_ollama_model_from_env_base_url(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_BASE_URL, "http://localhost:11434/v1")
        monkeypatch.setenv(ENV_API_KEY, "ollama")
        # No ENV_MODEL set — resolver guesses from the host
        ep = resolve_llm_endpoint(config_provider={})
        assert ep.base_url == "http://localhost:11434/v1"
        assert "qwen" in ep.model.lower()  # ollama default guess


# --- Precedence: config.yaml > default -------------------------------------


class TestConfigPrecedence:
    def test_config_provider_routes_to_openai_compat(self, clean_env):
        config = {
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "sk-or-config",
            "model": "anthropic/claude-opus-4",
        }
        ep = resolve_llm_endpoint(config_provider=config)
        assert ep.base_url == "https://openrouter.ai/api/v1"
        assert ep.api_key == "sk-or-config"
        assert ep.model == "anthropic/claude-opus-4"
        assert ep.source == "config"

    def test_config_secret_env_expansion(self, clean_env, monkeypatch):
        """`api_key: ${OPENROUTER_API_KEY}` should read from the
        environment at resolve time, not bake the literal into YAML."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-secret")
        config = {
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "${OPENROUTER_API_KEY}",
            "model": "anthropic/claude-opus-4",
        }
        ep = resolve_llm_endpoint(config_provider=config)
        assert ep.api_key == "sk-or-secret"

    def test_config_secret_missing_env_var_falls_back(self, clean_env):
        """If the expansion target env var is unset, the api_key
        should be None — not the literal `${NAME}` string."""
        config = {
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": "${OPENROUTER_API_KEY_NOT_SET_IN_THIS_TEST}",
            "model": "anthropic/claude-opus-4",
        }
        ep = resolve_llm_endpoint(config_provider=config)
        # Falls back to _placeholder_for() which returns "not-needed" for OpenRouter
        assert ep.api_key == "not-needed"

    def test_config_openai_oauth_routes_to_codex(self, clean_env, monkeypatch):
        import clearwing.providers.openai_oauth as openai_oauth

        monkeypatch.setattr(
            openai_oauth,
            "ensure_fresh_openai_oauth_credentials",
            lambda: openai_oauth.OpenAIOAuthCredentials(
                access="access-token",
                refresh="refresh-token",
                expires_ms=123,
                account_id="acct_123",
            ),
        )
        ep = resolve_llm_endpoint(
            config_provider={
                "auth": "openai_codex",
                "model": "gpt-5.2",
            }
        )
        assert ep.provider == "openai_codex"
        assert ep.base_url == "https://chatgpt.com/backend-api"
        assert ep.model == "gpt-5.2"
        assert ep.api_key == "access-token"
        assert not ep.is_openai_compat


# --- Default path ----------------------------------------------------------


class TestDefaultPath:
    def test_default_is_anthropic_with_env_key(self, clean_env, monkeypatch):
        monkeypatch.setenv(ENV_ANTHROPIC_KEY, "sk-anthropic-default")
        ep = resolve_llm_endpoint(config_provider={})
        assert ep.provider == "anthropic"
        assert ep.base_url is None
        assert ep.api_key == "sk-anthropic-default"
        assert ep.model == DEFAULT_ANTHROPIC_MODEL
        assert ep.source == "default"
        assert ep.is_anthropic_direct

    def test_default_with_no_env_still_returns_endpoint(self, clean_env):
        ep = resolve_llm_endpoint(config_provider={})
        assert ep.provider == "anthropic"
        assert ep.api_key is None
        assert ep.model == DEFAULT_ANTHROPIC_MODEL
        assert ep.source == "default"


# --- Default-model guessing from base_url ---------------------------------


class TestDefaultModelGuessing:
    @pytest.mark.parametrize(
        "base_url,expected_substring",
        [
            ("https://openrouter.ai/api/v1", "claude"),
            ("http://localhost:11434/v1", "qwen"),
            ("http://127.0.0.1:11434/v1", "qwen"),
            ("http://localhost:1234/v1", "local-model"),
            ("https://api.together.xyz/v1", "llama"),
            ("https://api.groq.com/openai/v1", "llama"),
            ("https://api.openai.com/v1", "gpt-4o"),
            ("https://api.deepseek.com/v1", "deepseek"),
            ("https://api.minimax.io/v1", "MiniMax"),
        ],
    )
    def test_known_hosts_get_sensible_defaults(self, clean_env, base_url, expected_substring):
        ep = resolve_llm_endpoint(cli_base_url=base_url, config_provider={})
        assert expected_substring.lower() in ep.model.lower(), (
            f"base_url={base_url} got model={ep.model!r}, "
            f"expected to contain {expected_substring!r}"
        )

    def test_unknown_host_gets_default_placeholder(self, clean_env):
        ep = resolve_llm_endpoint(cli_base_url="https://example.com/api/v1", config_provider={})
        assert ep.model == "default"


# --- api_key placeholder for key-less backends ----------------------------


class TestPlaceholderKey:
    def test_ollama_port_gets_ollama_placeholder(self, clean_env):
        ep = resolve_llm_endpoint(cli_base_url="http://localhost:11434/v1", config_provider={})
        # No cli_api_key, no env key — falls back to placeholder
        assert ep.api_key == "ollama"

    def test_non_ollama_gets_not_needed_placeholder(self, clean_env):
        ep = resolve_llm_endpoint(cli_base_url="http://localhost:1234/v1", config_provider={})
        assert ep.api_key == "not-needed"

    def test_minimax_with_cli_key(self, clean_env):
        ep = resolve_llm_endpoint(
            cli_base_url="https://api.minimax.io/v1",
            cli_api_key="sk-minimax-test",
            cli_model="MiniMax-M2.7",
            config_provider={},
        )
        assert ep.provider == "openai_compat"
        assert ep.base_url == "https://api.minimax.io/v1"
        assert ep.api_key == "sk-minimax-test"
        assert ep.model == "MiniMax-M2.7"
        assert ep.source == "cli"


# --- LLMEndpoint.describe / is_* helpers ---------------------------------


class TestLLMEndpointHelpers:
    def test_describe_anthropic(self):
        ep = LLMEndpoint(
            provider="anthropic",
            model="claude-sonnet-4-6",
            source="default",
        )
        assert "claude-sonnet-4-6" in ep.describe()
        assert "api.anthropic.com" in ep.describe()
        assert "default" in ep.describe()

    def test_describe_openrouter(self):
        ep = LLMEndpoint(
            provider="openai_compat",
            model="anthropic/claude-opus-4",
            base_url="https://openrouter.ai/api/v1",
            source="cli",
        )
        assert "anthropic/claude-opus-4" in ep.describe()
        assert "openrouter.ai" in ep.describe()
        assert "cli" in ep.describe()

    def test_is_openai_compat_flag(self):
        assert LLMEndpoint("openai_compat", "x").is_openai_compat
        assert not LLMEndpoint("anthropic", "x").is_openai_compat

    def test_is_anthropic_direct_requires_no_base_url(self):
        assert LLMEndpoint("anthropic", "x").is_anthropic_direct
        assert not LLMEndpoint(
            "anthropic", "x", base_url="https://proxy.internal/v1"
        ).is_anthropic_direct


# --- ProviderManager.for_endpoint factory --------------------------------


class TestProviderManagerForEndpoint:
    def test_for_endpoint_routes_all_tasks_to_one_llm(self, clean_env, monkeypatch):
        """When constructed via for_endpoint, every get_llm() call
        returns the same cached LLM regardless of task."""
        monkeypatch.setenv(ENV_ANTHROPIC_KEY, "sk-ant-test")
        endpoint = LLMEndpoint(
            provider="anthropic",
            model="claude-sonnet-4-6",
            api_key="sk-ant-test",
            source="cli",
        )
        pm = ProviderManager.for_endpoint(endpoint)
        ranker = pm.get_llm("ranker")
        hunter = pm.get_llm("hunter")
        verifier = pm.get_llm("verifier")

        assert isinstance(ranker, ChatModel)
        assert ranker is hunter
        assert hunter is verifier
        assert ranker.provider_name == "anthropic"
        assert ranker.model_name == "claude-sonnet-4-6"

    def test_for_endpoint_openai_compat_uses_native_chat_model(self, clean_env):
        endpoint = LLMEndpoint(
            provider="openai_compat",
            model="anthropic/claude-opus-4",
            base_url="https://openrouter.ai/api/v1",
            api_key="sk-or-test",
            source="cli",
        )
        pm = ProviderManager.for_endpoint(endpoint)
        got = pm.get_llm("hunter")
        assert isinstance(got, ChatModel)
        assert got.base_url == "https://openrouter.ai/api/v1"
        assert got.api_key == "sk-or-test"
        assert got.model_name == "anthropic/claude-opus-4"
        assert got.provider_name == "openai"

    def test_for_endpoint_get_route_info_shows_global(self, clean_env):
        endpoint = LLMEndpoint(
            provider="openai_compat",
            model="llama3:70b",
            base_url="http://localhost:11434/v1",
            api_key="ollama",
            source="env",
        )
        pm = ProviderManager.for_endpoint(endpoint)
        info = pm.get_route_info()
        assert "all tasks" in info
        assert "llama3:70b" in info
        assert "localhost:11434" in info


# --- from_config factory --------------------------------------------------


class TestProviderManagerFromConfig:
    def test_single_endpoint_from_provider_section(self, clean_env):
        cfg = {
            "provider": {
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": "sk-or-from-yaml",
                "model": "anthropic/claude-opus-4",
            }
        }
        pm = ProviderManager.from_config(cfg)
        # Should be in single-endpoint mode
        assert pm._global_endpoint is not None
        assert pm._global_endpoint.base_url == "https://openrouter.ai/api/v1"
        assert pm._global_endpoint.model == "anthropic/claude-opus-4"

    def test_multi_provider_routing(self, clean_env, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-routed")
        cfg = {
            "providers": {
                "openrouter": {
                    "base_url": "https://openrouter.ai/api/v1",
                    "api_key": "${OPENROUTER_API_KEY}",
                    "model": "anthropic/claude-opus-4",
                },
                "local_llama": {
                    "base_url": "http://localhost:11434/v1",
                    "api_key": "ollama",
                    "model": "qwen2.5-coder:32b",
                },
            },
            "routes": {
                "default": "openrouter",
                "hunter": "openrouter",
                "verifier": "local_llama",
            },
        }
        pm = ProviderManager.from_config(cfg)
        assert pm._global_endpoint is None  # multi-endpoint mode
        # Hunter route lands on openrouter
        hunter_route = pm._routes["hunter"]
        assert hunter_route.provider == "openrouter"
        # Verifier route lands on local_llama
        verifier_route = pm._routes["verifier"]
        assert verifier_route.provider == "local_llama"
        # The named provider configs were stored
        assert pm._configs["openrouter"].api_key == "sk-or-routed"
        assert pm._configs["local_llama"].api_key == "ollama"
