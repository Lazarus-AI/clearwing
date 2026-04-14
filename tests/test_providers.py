from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from clearwing.providers.manager import (
    DEFAULT_ROUTES,
    ModelRoute,
    PROVIDER_PRESETS,
    ProviderConfig,
    ProviderManager,
)


# --- ProviderConfig ---

class TestProviderConfig:
    def test_required_fields(self):
        cfg = ProviderConfig(name="anthropic", model="claude-sonnet-4-6")
        assert cfg.name == "anthropic"
        assert cfg.model == "claude-sonnet-4-6"

    def test_default_values(self):
        cfg = ProviderConfig(name="openai", model="gpt-4o")
        assert cfg.api_key == ""
        assert cfg.base_url == ""
        assert cfg.max_tokens == 4096
        assert cfg.temperature == 0.0

    def test_custom_values(self):
        cfg = ProviderConfig(
            name="ollama", model="llama3", api_key="key123",
            base_url="http://localhost:11434", max_tokens=2048, temperature=0.5,
        )
        assert cfg.api_key == "key123"
        assert cfg.base_url == "http://localhost:11434"
        assert cfg.max_tokens == 2048
        assert cfg.temperature == 0.5


# --- ModelRoute ---

class TestModelRoute:
    def test_required_fields(self):
        route = ModelRoute(task="recon", provider="anthropic", model="claude-haiku-4-5-20251001")
        assert route.task == "recon"
        assert route.provider == "anthropic"
        assert route.model == "claude-haiku-4-5-20251001"

    def test_default_reason(self):
        route = ModelRoute(task="default", provider="anthropic", model="claude-sonnet-4-6")
        assert route.reason == ""

    def test_custom_reason(self):
        route = ModelRoute(task="exploit", provider="openai", model="gpt-4o", reason="Testing")
        assert route.reason == "Testing"


# --- PROVIDER_PRESETS ---

class TestProviderPresets:
    def test_has_expected_providers(self):
        assert "anthropic" in PROVIDER_PRESETS
        assert "openai" in PROVIDER_PRESETS
        assert "google" in PROVIDER_PRESETS
        assert "ollama" in PROVIDER_PRESETS

    def test_anthropic_preset(self):
        preset = PROVIDER_PRESETS["anthropic"]
        assert "class" in preset
        assert "env_key" in preset
        assert "models" in preset
        assert preset["env_key"] == "ANTHROPIC_API_KEY"

    def test_openai_preset(self):
        preset = PROVIDER_PRESETS["openai"]
        assert preset["env_key"] == "OPENAI_API_KEY"

    def test_ollama_has_default_base_url(self):
        preset = PROVIDER_PRESETS["ollama"]
        assert preset["default_base_url"] == "http://localhost:11434"


# --- DEFAULT_ROUTES ---

class TestDefaultRoutes:
    def test_has_expected_tasks(self):
        task_names = {r.task for r in DEFAULT_ROUTES}
        assert "recon" in task_names
        assert "exploit" in task_names
        assert "report" in task_names
        assert "planning" in task_names
        assert "default" in task_names

    def test_routes_are_model_routes(self):
        for route in DEFAULT_ROUTES:
            assert isinstance(route, ModelRoute)

    def test_default_route_is_anthropic(self):
        default = [r for r in DEFAULT_ROUTES if r.task == "default"][0]
        assert default.provider == "anthropic"


# --- ProviderManager ---

class TestProviderManager:
    def test_default_routes_loaded(self):
        mgr = ProviderManager()
        routes = mgr.list_routes()
        task_names = {r.task for r in routes}
        assert "recon" in task_names
        assert "exploit" in task_names
        assert "report" in task_names
        assert "planning" in task_names
        assert "default" in task_names

    def test_custom_configs(self):
        configs = [
            ProviderConfig(name="anthropic", model="claude-sonnet-4-6", api_key="sk-test"),
            ProviderConfig(name="openai", model="gpt-4o", api_key="sk-openai"),
        ]
        mgr = ProviderManager(configs=configs)
        providers = mgr.list_providers()
        assert "anthropic" in providers
        assert "openai" in providers

    def test_custom_routes(self):
        routes = [
            ModelRoute(task="default", provider="openai", model="gpt-4o"),
        ]
        mgr = ProviderManager(routes=routes)
        route_list = mgr.list_routes()
        assert len(route_list) == 1
        assert route_list[0].provider == "openai"

    def test_get_llm_default_returns_anthropic(self):
        mgr = ProviderManager()
        llm = mgr.get_llm("default")
        from langchain_anthropic import ChatAnthropic
        assert isinstance(llm, ChatAnthropic)

    def test_get_llm_recon_returns_llm(self):
        mgr = ProviderManager()
        llm = mgr.get_llm("recon")
        from langchain_anthropic import ChatAnthropic
        assert isinstance(llm, ChatAnthropic)

    def test_get_llm_unknown_task_falls_back_to_default(self):
        mgr = ProviderManager()
        llm = mgr.get_llm("nonexistent_task")
        from langchain_anthropic import ChatAnthropic
        assert isinstance(llm, ChatAnthropic)

    def test_get_llm_no_route_raises(self):
        mgr = ProviderManager(routes=[
            ModelRoute(task="recon", provider="anthropic", model="claude-haiku-4-5-20251001"),
        ])
        with pytest.raises(ValueError, match="No route configured"):
            mgr.get_llm("nonexistent_task")

    def test_set_route(self):
        mgr = ProviderManager()
        mgr.set_route("recon", "openai", "gpt-4o", reason="Testing override")
        routes = mgr.list_routes()
        recon_route = [r for r in routes if r.task == "recon"][0]
        assert recon_route.provider == "openai"
        assert recon_route.model == "gpt-4o"
        assert recon_route.reason == "Testing override"

    def test_list_routes_returns_all(self):
        mgr = ProviderManager()
        routes = mgr.list_routes()
        assert len(routes) == len(DEFAULT_ROUTES)

    def test_get_route_info_readable(self):
        mgr = ProviderManager()
        info = mgr.get_route_info()
        assert "Model Routing:" in info
        assert "default:" in info
        assert "recon:" in info
        assert "anthropic" in info

    def test_llm_caching_same_instance(self):
        mgr = ProviderManager()
        llm1 = mgr.get_llm("default")
        llm2 = mgr.get_llm("default")
        assert llm1 is llm2

    def test_llm_caching_shared_across_tasks(self):
        """If two tasks route to the same provider/model, they share the cached instance."""
        mgr = ProviderManager()
        # exploit and planning both use claude-sonnet-4-6
        llm_exploit = mgr.get_llm("exploit")
        llm_planning = mgr.get_llm("planning")
        assert llm_exploit is llm_planning


# --- _create_llm error cases ---

class TestCreateLlmErrors:
    def test_unknown_provider_raises_value_error(self):
        mgr = ProviderManager()
        with pytest.raises(ValueError, match="Unknown provider"):
            mgr._create_llm("fakeprovider", "some-model")

    def test_openai_import_error(self):
        mgr = ProviderManager()
        with patch.dict(sys.modules, {"langchain_openai": None}):
            with pytest.raises(ImportError, match="langchain-openai"):
                mgr._create_llm("openai", "gpt-4o")

    def test_google_import_error(self):
        mgr = ProviderManager()
        with patch.dict(sys.modules, {"langchain_google_genai": None}):
            with pytest.raises(ImportError, match="langchain-google-genai"):
                mgr._create_llm("google", "gemini-2.0-flash")

    def test_ollama_import_error(self):
        mgr = ProviderManager()
        with patch.dict(sys.modules, {"langchain_ollama": None}):
            with pytest.raises(ImportError, match="langchain-ollama"):
                mgr._create_llm("ollama", "llama3")
