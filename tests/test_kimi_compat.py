"""Tests for the Kimi provider preset and endpoint resolution."""

from __future__ import annotations

from clearwing.providers.catalog import preset_by_key
from clearwing.providers.env import _default_openai_compat_model, resolve_llm_endpoint


class TestKimiOpenPlatformCatalog:
    def test_preset_uses_official_api_defaults(self):
        preset = preset_by_key("kimi")

        assert preset is not None
        assert preset.display_name == "Kimi Open Platform (pay-as-you-go)"
        assert preset.default_base_url == "https://api.moonshot.ai/v1"
        assert preset.default_model == "kimi-k3"
        assert preset.api_key_env_var == "MOONSHOT_API_KEY"
        assert preset.provider_adapter == "openai"
        assert preset.is_openai_compat
        assert preset.docs_url == "https://platform.kimi.ai/console/api-keys"

    def test_preset_offers_current_coding_models(self):
        preset = preset_by_key("kimi")

        assert preset is not None
        assert "kimi-k2.7-code" in preset.alt_models
        assert "kimi-k2.7-code-highspeed" in preset.alt_models


class TestKimiCodeCatalog:
    def test_preset_uses_official_coding_api_defaults(self):
        preset = preset_by_key("kimi-code")

        assert preset is not None
        assert preset.display_name == "Kimi Code (membership)"
        assert preset.default_base_url == "https://api.kimi.com/coding/v1"
        assert preset.default_model == "k3-256k"
        assert preset.api_key_env_var == "KIMI_CODE_API_KEY"
        assert preset.provider_adapter == "openai"
        assert preset.is_openai_compat
        assert preset.docs_url == "https://www.kimi.com/code/console"

    def test_preset_offers_current_coding_model_ids(self):
        preset = preset_by_key("kimi-code")

        assert preset is not None
        assert preset.alt_models == (
            "k3",
            "kimi-for-coding",
            "kimi-for-coding-highspeed",
        )

    def test_underscore_alias_is_supported(self):
        preset = preset_by_key("kimi_code")

        assert preset is not None
        assert preset.key == "kimi-code"


class TestKimiEndpointResolution:
    def test_moonshot_url_has_kimi_default(self):
        assert _default_openai_compat_model("https://api.moonshot.ai/v1") == "kimi-k3"

    def test_kimi_code_url_has_membership_default(self):
        assert _default_openai_compat_model("https://api.kimi.com/coding/v1") == "k3-256k"

    def test_cli_flags_route_to_openai_adapter(self):
        endpoint = resolve_llm_endpoint(
            cli_base_url="https://api.moonshot.ai/v1",
            cli_api_key="test-key",
            config_provider={},
        )

        assert endpoint.provider == "openai_compat"
        assert endpoint.base_url == "https://api.moonshot.ai/v1"
        assert endpoint.model == "kimi-k3"
        assert endpoint.api_key == "test-key"
        assert endpoint.is_openai_compat

    def test_setup_style_config_preserves_explicit_adapter(self, monkeypatch):
        for name in ("CLEARWING_BASE_URL", "CLEARWING_API_KEY", "CLEARWING_MODEL"):
            monkeypatch.delenv(name, raising=False)

        endpoint = resolve_llm_endpoint(
            config_provider={
                "base_url": "https://api.moonshot.ai/v1",
                "api_key": "test-key",
                "model": "kimi-k2.7-code",
                "adapter": "openai",
            },
        )

        assert endpoint.provider == "openai_compat"
        assert endpoint.model == "kimi-k2.7-code"
        assert endpoint.adapter == "openai"
