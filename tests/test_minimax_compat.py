"""Tests for the MiniMax provider preset and endpoint resolution.

MiniMax is routed through its Anthropic-compatible endpoint at
``https://api.minimax.io/anthropic``. That separates reasoning from
content at the protocol level (via ``reasoning_content``), so we don't
need in-band ``<think>`` tag handling.
"""

from __future__ import annotations

from clearwing.providers.catalog import preset_by_key
from clearwing.providers.env import (
    _default_anthropic_compat_model,
    _is_anthropic_compat_base_url,
    resolve_llm_endpoint,
)


class TestMiniMaxCatalog:
    def test_preset_exists(self):
        preset = preset_by_key("minimax")
        assert preset is not None
        assert preset.default_base_url == "https://api.minimax.io/anthropic"
        assert preset.default_model == "MiniMax-M2.7"
        assert preset.api_key_env_var == "MINIMAX_API_KEY"

    def test_is_anthropic_compat(self):
        preset = preset_by_key("minimax")
        assert preset is not None
        assert preset.is_openai_compat is False

    def test_alt_models(self):
        preset = preset_by_key("minimax")
        assert preset is not None
        assert "MiniMax-M2.7-highspeed" in preset.alt_models


class TestAnthropicCompatBaseUrl:
    def test_minimax_anthropic_endpoint(self):
        assert _is_anthropic_compat_base_url("https://api.minimax.io/anthropic")
        assert _is_anthropic_compat_base_url("https://api.minimax.io/anthropic/")

    def test_minimax_openai_endpoint_is_not_anthropic(self):
        assert not _is_anthropic_compat_base_url("https://api.minimax.io/v1")

    def test_anthropic_direct(self):
        assert _is_anthropic_compat_base_url("https://api.anthropic.com")

    def test_other_providers_are_not_anthropic(self):
        assert not _is_anthropic_compat_base_url("https://openrouter.ai/api/v1")
        assert not _is_anthropic_compat_base_url("https://api.openai.com/v1")


class TestMiniMaxDefaultModel:
    def test_minimax_anthropic_url(self):
        assert _default_anthropic_compat_model("https://api.minimax.io/anthropic") == "MiniMax-M2.7"


class TestMiniMaxEndpointResolution:
    def test_cli_flags_route_to_anthropic_adapter(self):
        endpoint = resolve_llm_endpoint(
            cli_base_url="https://api.minimax.io/anthropic",
            cli_api_key="test-key",
            config_provider={},
        )
        assert endpoint.provider == "anthropic"
        assert endpoint.base_url == "https://api.minimax.io/anthropic"
        assert endpoint.model == "MiniMax-M2.7"
        assert endpoint.api_key == "test-key"
        assert not endpoint.is_anthropic_direct
        assert not endpoint.is_openai_compat

    def test_config_routes_to_anthropic_adapter(self):
        endpoint = resolve_llm_endpoint(
            config_provider={
                "base_url": "https://api.minimax.io/anthropic",
                "api_key": "test-key",
                "model": "MiniMax-M2.5",
            },
        )
        assert endpoint.provider == "anthropic"
        assert endpoint.base_url == "https://api.minimax.io/anthropic"
        assert endpoint.model == "MiniMax-M2.5"
