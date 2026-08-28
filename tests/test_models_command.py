from __future__ import annotations

import argparse
import io
import json

import pytest
from rich.console import Console

from clearwing.providers.catalog import preset_by_key
from clearwing.providers.env import LLMEndpoint
from clearwing.providers.roles import ROLES, TASK_ROLES
from clearwing.ui.commands import models

# --- Fakes -----------------------------------------------------------------


class _FakeConfig:
    def __init__(self, config: dict | None = None, provider_section: dict | None = None):
        self.config = config or {}
        self._provider_section = provider_section or {}

    def get_provider_section(self) -> dict:
        return self._provider_section


class _FakeCLI:
    def __init__(self, config: dict | None = None, provider_section: dict | None = None):
        self.console = Console(file=io.StringIO(), width=200, no_color=True)
        self.config = _FakeConfig(config, provider_section)

    def output(self) -> str:
        return self.console.file.getvalue()


def _args(**kw) -> argparse.Namespace:
    base = {"provider": None, "task": None, "list_providers": False, "json": False}
    base.update(kw)
    return argparse.Namespace(**base)


# --- Pure helpers ----------------------------------------------------------


class TestHelpers:
    def test_tasks_by_role_covers_every_role_and_task(self):
        by_role = models._tasks_by_role()
        assert set(by_role) == set(ROLES)
        flat = [t for tasks in by_role.values() for t in tasks]
        assert sorted(flat) == sorted(TASK_ROLES)

    def test_key_missing_true_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert models._key_missing(preset_by_key("anthropic")) is True

    def test_key_missing_false_when_env_set(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert models._key_missing(preset_by_key("anthropic")) is False

    def test_key_missing_false_for_local_and_oauth(self):
        assert models._key_missing(preset_by_key("ollama")) is False  # is_local
        assert models._key_missing(preset_by_key("anthropic-oauth")) is False  # auth_flow

    def test_reasoning_note_flags_denylisted_family(self):
        assert models._reasoning_note("qwen2.5-coder:32b", "high") is not None
        assert models._reasoning_note("claude-sonnet-4-6", "high") is None
        assert models._reasoning_note("qwen2.5-coder:32b", "none") is None

    def test_preset_for_endpoint_matches_base_url(self):
        ep = LLMEndpoint(provider="openai_compat", model="x", base_url="https://openrouter.ai/api/v1")
        assert models._preset_for_endpoint(ep).key == "openrouter"

    def test_preset_for_endpoint_defaults_to_anthropic(self):
        ep = LLMEndpoint(provider="anthropic", model="claude-sonnet-4-6", base_url=None)
        assert models._preset_for_endpoint(ep).key == "anthropic"

    def test_presets_from_keys_rejects_unknown(self):
        console = Console(file=io.StringIO(), width=200)
        assert models._presets_from_keys(console, ["nope"]) is None


# --- handle() integration --------------------------------------------------


class TestHandle:
    def test_preview_json(self):
        cli = _FakeCLI()
        models.handle(cli, _args(provider=["deepseek", "anthropic"], json=True))
        payload = json.loads(cli.output())
        assert payload["mode"] == "preview"
        assert payload["providers"] == ["deepseek", "anthropic"]
        assert len(payload["roles"]) == len(ROLES)
        reviewer = next(r for r in payload["roles"] if r["role"] == "reviewer")
        assert reviewer["provider"] == "anthropic"  # independence -> second provider

    def test_default_recommendation_mode(self, monkeypatch):
        monkeypatch.delenv("CLEARWING_BASE_URL", raising=False)
        monkeypatch.delenv("CLEARWING_MODEL", raising=False)
        cli = _FakeCLI(config={}, provider_section={})
        models.handle(cli, _args(json=True))
        payload = json.loads(cli.output())
        assert payload["mode"] == "recommendation"

    def test_active_mode_from_model_roles(self):
        cli = _FakeCLI(config={"model_roles": {"providers": ["deepseek", "anthropic"]}})
        models.handle(cli, _args(json=True))
        payload = json.loads(cli.output())
        assert payload["mode"] == "active"
        hunter_role = next(r for r in payload["roles"] if r["role"] == "researcher")
        assert hunter_role["provider"] == "deepseek"

    def test_active_display_honors_named_model_bindings(self):
        # Regression: the command must resolve through the manager's path, not
        # a divergent parser that ignores models:/roles: bindings.
        cli = _FakeCLI(
            config={
                "model_roles": {
                    "providers": ["deepseek"],
                    "models": {
                        "a95b": {
                            "provider": "openrouter",
                            "model": "Qwen/Qwen3.8-A95B",
                            "capabilities": {"reasoning": {"levels": ["low", "high", "xhigh"]}},
                        }
                    },
                    "roles": {"reviewer": {"model": "a95b", "inference": {"reasoning": "xhigh"}}},
                }
            }
        )
        models.handle(cli, _args(json=True))
        payload = json.loads(cli.output())
        reviewer = next(r for r in payload["roles"] if r["role"] == "reviewer")
        assert reviewer["provider"] == "openrouter"
        assert reviewer["model"] == "Qwen/Qwen3.8-A95B"
        assert reviewer["reasoning"] == "xhigh"

    def test_task_json(self):
        cli = _FakeCLI(config={"model_roles": {"providers": ["anthropic"]}})
        models.handle(cli, _args(task="hunter", json=True))
        payload = json.loads(cli.output())
        assert payload["task"] == "hunter"
        assert payload["role"] == "researcher"
        assert payload["model"] == "claude-sonnet-4-6"

    def test_list_providers_json(self):
        cli = _FakeCLI()
        models.handle(cli, _args(list_providers=True, json=True))
        payload = json.loads(cli.output())
        deepseek = next(p for p in payload if p["key"] == "deepseek")
        assert deepseek["tiers"]["large"] == "deepseek-reasoner"

    def test_table_render_does_not_raise(self):
        cli = _FakeCLI(config={"model_roles": {"providers": ["ollama"]}})
        models.handle(cli, _args())
        out = cli.output()
        assert "utility" in out and "reviewer" in out
        # local Ollama needs no key, but its reasoning is dropped -> warning shown
        assert "rejects reasoning_effort" in out

    def test_unknown_provider_prints_error(self):
        cli = _FakeCLI()
        models.handle(cli, _args(provider=["bogus"]))
        assert "Unknown provider preset" in cli.output()


@pytest.mark.parametrize("task", list(TASK_ROLES))
def test_every_task_resolves_in_task_mode(task):
    cli = _FakeCLI(config={"model_roles": {"providers": ["anthropic"]}})
    models.handle(cli, _args(task=task, json=True))
    payload = json.loads(cli.output())
    assert payload["role"] in ROLES
