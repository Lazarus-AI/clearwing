"""Semgrep must be installed-capable but explicitly enabled by its caller."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.config import FeatureFlags, SourceHuntConfig, TargetConfig
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.ui.commands import sourcehunt as sourcehunt_command


def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="clearwing")
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)
    return parser.parse_args(["sourcehunt", "test-repository", *args])


def _runner(tmp_path, **overrides) -> SourceHuntRunner:
    options = {
        "repo_url": "test-repository",
        "local_path": str(tmp_path),
        "output_dir": str(tmp_path / "results"),
        "enable_calibration": False,
        "enable_knowledge_graph": False,
        "enable_mechanism_memory": False,
    }
    options.update(overrides)
    return SourceHuntRunner(**options)


def test_cli_semgrep_is_visible_and_default_off() -> None:
    assert _parse().semgrep is False
    assert _parse("--semgrep").semgrep is True


@pytest.mark.parametrize("depth", ["quick", "standard", "deep"])
def test_runner_does_not_enable_semgrep_implicitly(tmp_path, monkeypatch, depth) -> None:
    preprocessor = MagicMock()
    preprocessor.return_value.run.return_value = MagicMock()
    monkeypatch.setattr("clearwing.sourcehunt.runner.Preprocessor", preprocessor)
    monkeypatch.setattr(
        "clearwing.sourcehunt.runner.PreprocessCheckpoint.from_result",
        MagicMock(return_value=MagicMock()),
    )
    runner = _runner(tmp_path, depth=depth)
    runner._checkpoint = MagicMock(preprocess=None)
    monkeypatch.setattr(runner, "_dump_checkpoint", MagicMock())

    runner._preprocess()

    assert preprocessor.call_args.kwargs["run_semgrep"] is False


def test_runner_propagates_explicit_semgrep_even_at_quick_depth(tmp_path, monkeypatch) -> None:
    preprocessor = MagicMock()
    preprocessor.return_value.run.return_value = MagicMock()
    monkeypatch.setattr("clearwing.sourcehunt.runner.Preprocessor", preprocessor)
    monkeypatch.setattr(
        "clearwing.sourcehunt.runner.PreprocessCheckpoint.from_result",
        MagicMock(return_value=MagicMock()),
    )
    runner = _runner(tmp_path, depth="quick", enable_semgrep=True)
    runner._checkpoint = MagicMock(preprocess=None)
    monkeypatch.setattr(runner, "_dump_checkpoint", MagicMock())

    runner._preprocess()

    assert preprocessor.call_args.kwargs["run_semgrep"] is True


def test_config_can_explicitly_enable_semgrep(tmp_path) -> None:
    config = SourceHuntConfig(
        target=TargetConfig(repo_url="test-repository", local_path=str(tmp_path)),
        features=FeatureFlags(enable_semgrep=True),
    )

    runner = SourceHuntRunner(config=config, output_dir=str(tmp_path / "results"))

    assert runner._enable_semgrep is True


def test_proof_flow_rejects_semgrep_instead_of_ignoring_it(tmp_path) -> None:
    with pytest.raises(ValueError, match="Semgrep is currently supported only for legacy flow"):
        _runner(tmp_path, flow="proof", enable_semgrep=True)


def test_container_installs_sourcehunt_extra() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text()

    assert "uv pip install --system --no-cache --extra sourcehunt -r pyproject.toml" in dockerfile
