"""CyberPi managed-runtime, command-surface, and report regressions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from clearwing.bench.cyberpi import BenchmarkObservation, CyberPiBenchmarkReport
from clearwing.sourcehunt.cyberpi_runtime import (
    PI_VERSION,
    CyberPiRuntime,
    RuntimeCheck,
)
from clearwing.ui.commands import ALL_COMMANDS
from clearwing.ui.commands import cyberpi as cyberpi_command


def test_cyberpi_command_is_registered_with_cohesive_actions():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    cyberpi_command.add_parser(subparsers)

    assert cyberpi_command in ALL_COMMANDS
    assert parser.parse_args(["cyberpi", "install"]).cyberpi_action == "install"
    assert parser.parse_args(["cyberpi", "doctor", "--json"]).json is True
    benchmark = parser.parse_args(
        ["cyberpi", "benchmark", "--runs", "3", "--model", "Exact-Model-Alias"]
    )
    assert benchmark.runs == 3
    assert benchmark.model == "Exact-Model-Alias"


def test_managed_install_uses_packaged_lockfile_and_atomic_destination(tmp_path, monkeypatch):
    packaged = tmp_path / "packaged"
    packaged.mkdir()
    (packaged / "index.mjs").write_text("// sidecar\n")
    (packaged / "package.json").write_text(json.dumps({"dependencies": {}}))
    (packaged / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3}))
    runtime = CyberPiRuntime(tmp_path / "managed" / "runtime")

    monkeypatch.setattr(CyberPiRuntime, "_packaged_dir", staticmethod(lambda: packaged))
    monkeypatch.setattr(
        CyberPiRuntime,
        "_node_check",
        lambda self: RuntimeCheck("Node.js", "ok", "v22.19.0"),
    )
    monkeypatch.setattr(
        CyberPiRuntime,
        "_npm_check",
        staticmethod(lambda **_kwargs: RuntimeCheck("npm", "ok", "10.0.0")),
    )

    def fake_run(_command, *, cwd, **_kwargs):
        dependency = Path(cwd) / "node_modules" / "@earendil-works" / "pi-coding-agent"
        dependency.mkdir(parents=True)
        (dependency / "package.json").write_text(json.dumps({"version": PI_VERSION}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("clearwing.sourcehunt.cyberpi_runtime.subprocess.run", fake_run)

    installed = runtime.install()

    assert installed == runtime.runtime_dir
    assert (installed / "index.mjs").is_file()
    assert runtime.command() == (runtime.node, str(installed / "index.mjs"))
    assert not list(runtime.runtime_dir.parent.glob(f".{runtime.runtime_dir.name}-previous-*"))


def test_benchmark_report_has_machine_and_human_outputs(tmp_path):
    observations = (
        BenchmarkObservation(
            engine="native",
            fixture="heap-overflow",
            replicate=1,
            passed=False,
            findings=(),
            tokens_used=120,
            cost_usd=0.01,
            cost_basis="clearwing_estimate",
            duration_seconds=1.0,
            stop_reason="completed",
            trajectory="native.jsonl",
        ),
        BenchmarkObservation(
            engine="cyberpi",
            fixture="heap-overflow",
            replicate=1,
            passed=True,
            findings=({"cwe": "CWE-122", "line_number": 7},),
            tokens_used=80,
            cost_usd=0.005,
            cost_basis="provider_reported",
            duration_seconds=0.8,
            stop_reason="completed",
            trajectory="cyberpi.jsonl",
        ),
    )
    report = CyberPiBenchmarkReport(
        benchmark_id="cyberpi-test",
        created_at="2026-08-13T00:00:00+00:00",
        model="DeepSeek-v4-Flash-0731",
        base_url="https://example.test/v1",
        max_turns=4,
        max_output_tokens=4096,
        observations=observations,
    )

    json_path, markdown_path = report.write(tmp_path)

    payload = json.loads(json_path.read_text())
    assert payload["metrics"]["native"]["pass_rate"] == 0
    assert payload["metrics"]["cyberpi"]["pass_rate"] == 1
    assert payload["metrics"]["cyberpi"]["cost_basis"] == "provider_reported"
    assert "| cyberpi | 1 | 1 | 100% |" in markdown_path.read_text()
    assert "API" not in json_path.read_text()


def test_benchmark_scoring_normalizes_provider_cwe_spelling():
    from clearwing.bench.cyberpi import BUILTIN_FIXTURES, CyberPiBenchmark

    finding = ({"cwe": "122", "line_number": 7},)

    assert CyberPiBenchmark._passed(BUILTIN_FIXTURES[0], finding) is True
