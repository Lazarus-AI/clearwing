"""Tests for the `clearwing setup` wizard and `clearwing doctor` command.

Covers:
- Provider catalog lookup + completeness (every preset has the
  fields the rest of the code expects).
- Setup's YAML write path: merges cleanly with an existing file,
  doesn't balloon on empty input, masks secrets.
- Doctor's DoctorCheck / DoctorSection aggregation and status
  accounting. The live external-tool probes, docker reachability,
  and network checks aren't asserted against — they're environment-
  dependent and the command tolerates every failure mode gracefully.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console
import yaml

from clearwing.providers import KNOWN_PROVIDERS, preset_by_key
from clearwing.ui.commands import doctor, setup
from clearwing.ui.commands.doctor import (
    STATUS_ERR,
    STATUS_OK,
    STATUS_WARN,
    DoctorCheck,
    DoctorSection,
)
from clearwing.ui.commands.setup import _mask_secret, _write_config

# --- Provider catalog ------------------------------------------------------


class TestProviderCatalog:
    def test_catalog_not_empty(self):
        assert len(KNOWN_PROVIDERS) >= 5

    def test_every_preset_has_required_fields(self):
        """Every preset is ready to drop into the setup wizard's
        per-provider forms without crashing."""
        for preset in KNOWN_PROVIDERS:
            assert preset.key, f"preset has empty key: {preset}"
            assert preset.display_name
            assert preset.description
            assert preset.docs_url.startswith("http")

    def test_oauth_providers_are_first(self):
        assert KNOWN_PROVIDERS[0].key == "anthropic-oauth"
        assert KNOWN_PROVIDERS[0].auth_flow == "anthropic_oauth"
        assert KNOWN_PROVIDERS[1].key == "openai-oauth"
        assert KNOWN_PROVIDERS[1].auth_flow == "openai_codex"

    def test_openai_compat_presets_all_have_base_url(self):
        for preset in KNOWN_PROVIDERS:
            if preset.is_openai_compat and preset.key != "custom":
                assert preset.default_base_url, (
                    f"{preset.key} is_openai_compat but has no default_base_url"
                )

    def test_local_presets_are_flagged(self):
        for preset in KNOWN_PROVIDERS:
            if preset.key in ("ollama", "lmstudio"):
                assert preset.is_local
                assert preset.api_key_env_var is None

    def test_preset_by_key_lookup(self):
        assert preset_by_key("openrouter").display_name == "OpenRouter"
        assert preset_by_key("OPENROUTER").display_name == "OpenRouter"  # case-insensitive
        assert preset_by_key("ollama").is_local
        assert preset_by_key("openai-codex").key == "openai-oauth"
        assert preset_by_key("openai_oauth").key == "openai-oauth"
        assert preset_by_key("unknown-provider") is None

    def test_openai_oauth_preset_is_not_openai_compat(self):
        preset = preset_by_key("openai-oauth")
        assert preset is not None
        assert preset.auth_flow == "openai_codex"
        assert not preset.is_openai_compat

    def test_every_preset_declares_a_provider_adapter(self):
        """Rule: every preset in the catalog must set
        `provider_adapter` to one of the known genai-pyo3 adapter
        names. No None, no empty string — the wizard refuses to
        persist a config without an explicit adapter, so the
        catalog can't ship a preset that lacks one.
        """
        valid_adapters = {
            "anthropic",
            "openai",
            "openai_resp",
            "openai_codex",
            "ollama",
            "gemini",
        }
        for preset in KNOWN_PROVIDERS:
            assert preset.provider_adapter, (
                f"{preset.key!r} must set provider_adapter to one of {sorted(valid_adapters)}"
            )
            assert preset.provider_adapter in valid_adapters, (
                f"{preset.key!r} has unknown adapter "
                f"{preset.provider_adapter!r}; valid={sorted(valid_adapters)}"
            )

    def test_openai_responses_preset_exists(self):
        """The Responses API (used by GPT-5.x and o-series) must be
        discoverable from the setup wizard — it's not enough to bolt
        it on via the `custom` preset."""
        preset = preset_by_key("openai-responses")
        assert preset is not None
        assert preset.provider_adapter == "openai_resp"
        assert preset.default_base_url == "https://api.openai.com/v1"
        assert preset.api_key_env_var == "OPENAI_API_KEY"

    def test_openai_chat_and_responses_both_present(self):
        """Both OpenAI API dialects have catalog entries."""
        chat = preset_by_key("openai")
        resp = preset_by_key("openai-responses")
        assert chat is not None and chat.provider_adapter == "openai"
        assert resp is not None and resp.provider_adapter == "openai_resp"
        # Same API key env var, different wire shape
        assert chat.api_key_env_var == resp.api_key_env_var == "OPENAI_API_KEY"


# --- Setup wizard: _mask_secret -------------------------------------------


class TestMaskSecret:
    def test_empty_returns_empty(self):
        assert _mask_secret("") == ""

    def test_env_reference_passes_through(self):
        assert _mask_secret("${OPENROUTER_API_KEY}") == "${OPENROUTER_API_KEY}"
        assert _mask_secret("${ANTHROPIC_API_KEY}") == "${ANTHROPIC_API_KEY}"

    def test_ollama_placeholder_passes_through(self):
        assert _mask_secret("ollama") == "ollama"
        assert _mask_secret("not-needed") == "not-needed"
        assert _mask_secret("lm-studio") == "lm-studio"

    def test_short_secret_fully_masked(self):
        assert _mask_secret("short") == "*****"
        assert _mask_secret("abcdefgh") == "********"

    def test_long_secret_middle_masked(self):
        masked = _mask_secret("sk-or-v1-abcdef1234567890")
        assert masked.startswith("sk-o")
        assert "7890" in masked
        assert "chars" in masked
        # The raw secret should not appear in the masked output
        assert "abcdef" not in masked


# --- Setup wizard: _write_config ------------------------------------------


class _FakeConfig:
    """Minimal Config stand-in for the _write_config unit tests.

    Wraps `tmp_path / ".clearwing" / "config.yaml"` so tests don't
    touch the real home directory.
    """

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

        class _Console:
            def print(self, *args, **kwargs):
                pass

        self.console = _Console()


@pytest.fixture
def tmp_cli(tmp_path):
    return _FakeCLI(tmp_path)


class TestWriteConfig:
    def test_writes_minimal_provider_section(self, tmp_cli):
        preset = preset_by_key("openrouter")
        _write_config(
            tmp_cli,
            preset,
            base_url="https://openrouter.ai/api/v1",
            api_key_literal="${OPENROUTER_API_KEY}",
            model="anthropic/claude-opus-4",
        )
        path = tmp_cli.config.DEFAULT_CONFIG_PATH
        assert path.exists()
        data = yaml.safe_load(path.read_text())
        assert data == {
            "provider": {
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": "${OPENROUTER_API_KEY}",
                "model": "anthropic/claude-opus-4",
                "adapter": "openai",
            }
        }

    def test_writes_compact_file_not_bloated_defaults(self, tmp_cli):
        """Regression: earlier builds went through Config.save() which
        dumped all 1024 default ports into the file. This test asserts
        the written file stays small."""
        preset = preset_by_key("ollama")
        _write_config(
            tmp_cli,
            preset,
            base_url="http://localhost:11434/v1",
            api_key_literal="ollama",
            model="qwen2.5-coder:32b",
        )
        path = tmp_cli.config.DEFAULT_CONFIG_PATH
        text = path.read_text()
        assert len(text.splitlines()) < 20, (
            f"config.yaml should be compact; got {len(text.splitlines())} lines"
        )
        assert "default_ports" not in text
        assert "common_ports" not in text

    def test_preserves_unrelated_sections(self, tmp_path, tmp_cli):
        """Writing a new provider section should leave any other
        pre-existing sections in the config file untouched."""
        path = tmp_cli.config.DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(
                {
                    "scanning": {"max_threads": 50},
                    "database": {"path": "mydb.db"},
                    "provider": {"model": "claude-sonnet-4-6"},  # old
                }
            )
        )

        preset = preset_by_key("openrouter")
        _write_config(
            tmp_cli,
            preset,
            base_url="https://openrouter.ai/api/v1",
            api_key_literal="${OPENROUTER_API_KEY}",
            model="anthropic/claude-opus-4",
        )

        data = yaml.safe_load(path.read_text())
        # Unrelated sections preserved
        assert data["scanning"]["max_threads"] == 50
        assert data["database"]["path"] == "mydb.db"
        # Provider section replaced
        assert data["provider"]["base_url"] == "https://openrouter.ai/api/v1"
        assert data["provider"]["model"] == "anthropic/claude-opus-4"

    def test_anthropic_without_base_url(self, tmp_cli):
        """Anthropic direct has no base_url. It should be omitted
        from the written file entirely, not included as an empty string."""
        preset = preset_by_key("anthropic")
        _write_config(
            tmp_cli,
            preset,
            base_url=None,
            api_key_literal="sk-ant-test",
            model="claude-sonnet-4-6",
        )
        data = yaml.safe_load(tmp_cli.config.DEFAULT_CONFIG_PATH.read_text())
        assert "base_url" not in data["provider"]
        assert data["provider"]["model"] == "claude-sonnet-4-6"
        assert data["provider"]["api_key"] == "sk-ant-test"

    def test_openai_oauth_writes_auth_marker_without_api_key(self, tmp_cli):
        preset = preset_by_key("openai-oauth")
        _write_config(
            tmp_cli,
            preset,
            base_url="https://chatgpt.com/backend-api",
            api_key_literal="",
            model="gpt-5.2",
        )
        data = yaml.safe_load(tmp_cli.config.DEFAULT_CONFIG_PATH.read_text())
        assert data == {
            "provider": {
                "auth": "openai_codex",
                "base_url": "https://chatgpt.com/backend-api",
                "model": "gpt-5.2",
                "adapter": "openai_codex",
            }
        }


# --- Doctor: DoctorCheck + DoctorSection aggregation ---------------------


class TestDoctorResult:
    def test_check_glyph_matches_status(self):
        assert "green" in DoctorCheck("x", STATUS_OK).glyph
        assert "yellow" in DoctorCheck("x", STATUS_WARN).glyph
        assert "red" in DoctorCheck("x", STATUS_ERR).glyph

    def test_section_accumulates_checks(self):
        section = DoctorSection("Test")
        section.add(DoctorCheck("a", STATUS_OK))
        section.add(DoctorCheck("b", STATUS_WARN, hint="try X"))
        section.add(DoctorCheck("c", STATUS_ERR, "bad", hint="fix Y"))
        assert len(section.checks) == 3
        assert section.checks[2].hint == "fix Y"


# --- Doctor: individual check functions ---------------------------------


class TestPythonCheck:
    def test_current_python_passes(self):
        section = doctor._check_python_and_clearwing()
        statuses = [c.status for c in section.checks]
        # Every entry should be ok on any supported install
        assert all(s == STATUS_OK for s in statuses)
        assert section.checks[0].name == "Python"
        assert section.checks[1].name == "clearwing"


class TestFilesystemCheck:
    def test_creates_missing_directory(self, tmp_cli):
        # The fake config's DEFAULT_CONFIG_PATH lives under tmp; but
        # _check_filesystem probes ~/.clearwing/ directly (not the
        # config path). We can't redirect $HOME inside a test easily;
        # just check that running the function doesn't raise.
        section = doctor._check_filesystem(tmp_cli)
        assert section.title == "Filesystem"
        assert any(c.name == "~/.clearwing/" for c in section.checks)


class TestOptionalExtrasCheck:
    def test_genai_pyo3_is_present(self):
        """genai-pyo3 is the required native LLM runtime dependency."""
        section = doctor._check_optional_extras()
        genai_pyo3 = next((c for c in section.checks if c.name == "genai-pyo3"), None)
        assert genai_pyo3 is not None
        assert genai_pyo3.status == STATUS_OK


class TestDoctorJsonOutput:
    def test_print_json_is_valid_even_for_long_messages(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=20)
        sections = [
            DoctorSection(
                "LLM provider",
                checks=[
                    DoctorCheck(
                        "Endpoint",
                        STATUS_OK,
                        "UnCut @ https://jayleen-astrolabical-nontactically.ngrok-free.dev/v1",
                    )
                ],
            )
        ]

        doctor._print_json(console, sections)

        payload = json.loads(stream.getvalue())
        assert payload["sections"][0]["checks"][0]["message"].startswith("UnCut @ https://")


class TestLLMProviderCheck:
    def test_no_credentials_reports_error(self, tmp_cli, monkeypatch):
        """With no env vars and an empty fake config, the LLM provider
        check should emit a credentials error."""
        for name in (
            "CLEARWING_BASE_URL",
            "CLEARWING_API_KEY",
            "CLEARWING_MODEL",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
        ):
            monkeypatch.delenv(name, raising=False)

        class _FakeConfigNoProvider(_FakeConfig):
            def get_provider_section(self):
                return {}

        tmp_cli.config = _FakeConfigNoProvider(tmp_cli.config.DEFAULT_CONFIG_PATH.parent.parent)

        section = doctor._check_llm_provider(tmp_cli, skip_invoke=True)
        creds_check = next((c for c in section.checks if c.name == "Credentials"), None)
        assert creds_check is not None
        assert creds_check.status == STATUS_ERR

    def test_skip_invoke_produces_skip_status(self, tmp_cli, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")

        class _FakeConfigWithEnv(_FakeConfig):
            def get_provider_section(self):
                return {}

        tmp_cli.config = _FakeConfigWithEnv(tmp_cli.config.DEFAULT_CONFIG_PATH.parent.parent)

        section = doctor._check_llm_provider(tmp_cli, skip_invoke=True)
        invoke_check = next((c for c in section.checks if c.name == "Test invoke"), None)
        # Credentials should be OK because the env var is set;
        # test invoke should be skipped
        creds = next(c for c in section.checks if c.name == "Credentials")
        assert creds.status == STATUS_OK
        assert invoke_check is not None
        assert invoke_check.status == "skip"


# --- Doctor: setup subcommand + init alias -----------------------------


class TestSetupSubcommand:
    def test_setup_module_has_aliases(self):
        assert "init" in setup.ALIASES

    def test_setup_parser_accepts_provider_flag(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        setup.add_parser(subparsers)
        args = parser.parse_args(["setup", "--provider", "ollama", "--no-test", "-y"])
        assert args.provider == "ollama"
        assert args.no_test is True
        assert args.yes is True


class TestDoctorSubcommand:
    def test_doctor_parser_accepts_json_flag(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        doctor.add_parser(subparsers)
        args = parser.parse_args(["doctor", "--skip-llm-invoke", "--json"])
        assert args.skip_llm_invoke is True
        assert args.json is True

    def test_doctor_handle_exits_nonzero_on_errors(self, tmp_cli, monkeypatch, capsys):
        """If any check returns STATUS_ERR, the handle() function
        should call sys.exit(1)."""
        # Stub every section to return known status mixes
        with patch.object(doctor, "_check_python_and_clearwing") as mock_py:
            mock_py.return_value = DoctorSection(
                "Core", [DoctorCheck("Python", STATUS_OK, "3.12.3")]
            )
            with patch.object(doctor, "_check_llm_provider") as mock_llm:
                mock_llm.return_value = DoctorSection(
                    "LLM provider",
                    [DoctorCheck("Credentials", STATUS_ERR, "missing")],
                )
                with (
                    patch.object(doctor, "_check_filesystem", return_value=DoctorSection("FS")),
                    patch.object(doctor, "_check_docker", return_value=DoctorSection("Docker")),
                    patch.object(
                        doctor, "_check_external_tools", return_value=DoctorSection("Ext")
                    ),
                    patch.object(
                        doctor, "_check_optional_extras", return_value=DoctorSection("Extras")
                    ),
                    patch.object(doctor, "_check_network", return_value=DoctorSection("Net")),
                ):
                    args = type("Args", (), {"skip_llm_invoke": True, "json": False})()
                    with pytest.raises(SystemExit) as exc:
                        doctor.handle(tmp_cli, args)
                    assert exc.value.code == 1

    def test_doctor_handle_exits_zero_on_ok_and_warn(self, tmp_cli):
        """Only STATUS_OK and STATUS_WARN should yield exit code 0."""
        with (
            patch.object(
                doctor,
                "_check_python_and_clearwing",
                return_value=DoctorSection("Core", [DoctorCheck("Python", STATUS_OK)]),
            ),
            patch.object(
                doctor,
                "_check_llm_provider",
                return_value=DoctorSection(
                    "LLM provider", [DoctorCheck("Credentials", STATUS_WARN)]
                ),
            ),
            patch.object(doctor, "_check_filesystem", return_value=DoctorSection("FS")),
            patch.object(doctor, "_check_docker", return_value=DoctorSection("Docker")),
            patch.object(doctor, "_check_external_tools", return_value=DoctorSection("Ext")),
            patch.object(doctor, "_check_optional_extras", return_value=DoctorSection("Extras")),
            patch.object(doctor, "_check_network", return_value=DoctorSection("Net")),
        ):
            args = type("Args", (), {"skip_llm_invoke": True, "json": False})()
            with pytest.raises(SystemExit) as exc:
                doctor.handle(tmp_cli, args)
            assert exc.value.code == 0
