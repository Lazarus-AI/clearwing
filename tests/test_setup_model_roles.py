from __future__ import annotations

import io
from pathlib import Path

import yaml
from rich.console import Console

from clearwing.providers.catalog import preset_by_key
from clearwing.ui.commands import setup


class _FakeConfig:
    def __init__(self, tmp_path: Path) -> None:
        self.DEFAULT_CONFIG_PATH = tmp_path / ".clearwing" / "config.yaml"
        self.config: dict = {}

    def set(self, *keys: str, value) -> None:
        cursor = self.config
        for key in keys[:-1]:
            cursor = cursor.setdefault(key, {})
        cursor[keys[-1]] = value


class _FakeCLI:
    def __init__(self, tmp_path: Path) -> None:
        self.config = _FakeConfig(tmp_path)
        self.console = Console(file=io.StringIO(), width=200, no_color=True)


def test_write_model_roles_creates_block(tmp_path):
    cli = _FakeCLI(tmp_path)
    setup._write_model_roles(cli, ["anthropic", "openrouter"])
    data = yaml.safe_load(cli.config.DEFAULT_CONFIG_PATH.read_text())
    assert data["model_roles"] == {"providers": ["anthropic", "openrouter"]}
    assert cli.config.config["model_roles"]["providers"] == ["anthropic", "openrouter"]


def test_write_model_roles_preserves_existing_sections(tmp_path):
    cli = _FakeCLI(tmp_path)
    path = cli.config.DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"provider": {"model": "claude-sonnet-4-6"}}))
    setup._write_model_roles(cli, ["anthropic"])
    data = yaml.safe_load(path.read_text())
    assert data["provider"] == {"model": "claude-sonnet-4-6"}  # untouched
    assert data["model_roles"] == {"providers": ["anthropic"]}


def test_maybe_configure_skips_when_declined(tmp_path, monkeypatch):
    cli = _FakeCLI(tmp_path)
    monkeypatch.setattr(setup.Confirm, "ask", staticmethod(lambda *a, **k: False))
    setup._maybe_configure_model_roles(cli, cli.console, preset_by_key("anthropic"))
    # Declined -> nothing written.
    assert not cli.config.DEFAULT_CONFIG_PATH.exists()
    assert "Skipped" in cli.console.file.getvalue()


def test_maybe_configure_writes_single_provider(tmp_path, monkeypatch):
    cli = _FakeCLI(tmp_path)
    # First Confirm (configure?) -> True; second (add auditor?) -> False;
    # third (write?) -> True.
    answers = iter([True, False, True])
    monkeypatch.setattr(setup.Confirm, "ask", staticmethod(lambda *a, **k: next(answers)))
    setup._maybe_configure_model_roles(cli, cli.console, preset_by_key("anthropic"))
    data = yaml.safe_load(cli.config.DEFAULT_CONFIG_PATH.read_text())
    assert data["model_roles"] == {"providers": ["anthropic"]}
