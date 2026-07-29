"""Compatibility guardrails for the opt-in sourcehunt proof flow."""

from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, Mock

import pytest

from clearwing.sourcehunt.config import ProofConfig
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.ui.commands import sourcehunt as sourcehunt_command


def _runner(tmp_path, *, flow: str = "legacy", **overrides) -> SourceHuntRunner:
    options = {
        "repo_url": "test-repository",
        "local_path": str(tmp_path),
        "output_dir": str(tmp_path / "results"),
        "flow": flow,
        "enable_calibration": False,
        "enable_knowledge_graph": False,
        "enable_mechanism_memory": False,
    }
    options.update(overrides)
    return SourceHuntRunner(**options)


def test_cli_and_config_keep_legacy_as_the_default(tmp_path) -> None:
    parser = argparse.ArgumentParser(prog="clearwing")
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)

    args = parser.parse_args(["sourcehunt", "test-repository"])
    runner = _runner(tmp_path)

    assert args.flow == "legacy"
    assert ProofConfig().flow == "legacy"
    assert runner._flow == "legacy"


@pytest.mark.asyncio
async def test_legacy_routes_without_loading_the_proof_engine(tmp_path, monkeypatch) -> None:
    class LegacyPathEntered(RuntimeError):
        pass

    runner = _runner(
        tmp_path,
        proof_compile_commands="/missing/proof-only/compile_commands.json",
        proof_validation_manifest="/missing/proof-only/validation.json",
    )
    proof_flow = AsyncMock()
    legacy_preflight = Mock(side_effect=LegacyPathEntered("legacy path entered"))
    monkeypatch.setattr(runner, "_arun_proof_flow", proof_flow)
    monkeypatch.setattr(runner, "_preflight_budget_clients", legacy_preflight)

    with pytest.raises(LegacyPathEntered, match="legacy path entered"):
        await runner.arun()

    proof_flow.assert_not_awaited()
    legacy_preflight.assert_called_once_with()


@pytest.mark.asyncio
async def test_explicit_proof_flow_routes_only_to_the_proof_engine(tmp_path, monkeypatch) -> None:
    runner = _runner(tmp_path, flow="proof")
    expected = object()
    proof_flow = AsyncMock(return_value=expected)
    legacy_preflight = Mock()
    monkeypatch.setattr(runner, "_arun_proof_flow", proof_flow)
    monkeypatch.setattr(runner, "_preflight_budget_clients", legacy_preflight)

    result = await runner.arun()

    assert result is expected
    proof_flow.assert_awaited_once_with()
    legacy_preflight.assert_not_called()


@pytest.mark.asyncio
async def test_proof_failure_does_not_fall_back_to_legacy(tmp_path, monkeypatch) -> None:
    runner = _runner(tmp_path, flow="proof")
    proof_flow = AsyncMock(side_effect=RuntimeError("proof flow failed"))
    legacy_preflight = Mock()
    monkeypatch.setattr(runner, "_arun_proof_flow", proof_flow)
    monkeypatch.setattr(runner, "_preflight_budget_clients", legacy_preflight)

    with pytest.raises(RuntimeError, match="proof flow failed"):
        await runner.arun()

    proof_flow.assert_awaited_once_with()
    legacy_preflight.assert_not_called()
