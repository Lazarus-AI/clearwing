"""Unit tests for PoC stability verification (spec 010).

Critical assertions:
- StabilityResult defaults and construction
- Classification thresholds: stable >= 90%, flaky 50-90%, unreliable < 50%
- Race-condition CWEs use 100 runs and 70% threshold
- Failure analysis heuristics
- apply_stability_result merges fields into finding
- Hardening: LLM returns improved PoC, re-tests
- Runner integration: enabled by default, fail-open
"""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clearwing.sourcehunt.stability import (
    RACE_CWES,
    StabilityConfig,
    StabilityVerifier,
    apply_stability_result,
)
from clearwing.sourcehunt.state import StabilityResult


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "finding_type": "memory_safety",
        "cwe": "CWE-787",
        "severity": "high",
        "description": "memcpy overflow",
        "code_snippet": "memcpy(frame, input, input_len);",
        "crash_evidence": "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        "poc": "AAAA" * 100,
        "evidence_level": "crash_reproduced",
        "verified": True,
    }
    base.update(kwargs)
    return base


class _FakeExecResult:
    def __init__(self, exit_code=0, stdout="", stderr="", timed_out=False):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = 0.1
        self.timed_out = timed_out


class _FakeSandbox:
    """Fake sandbox container that scripts exec results."""

    def __init__(self, crash_rate: float = 1.0, stderr_on_crash: str = ""):
        self._crash_rate = crash_rate
        self._stderr_on_crash = stderr_on_crash
        self._call_count = 0
        self.stopped = False

    def exec(self, command, timeout=None, env=None, workdir=None):
        cmd_str = command if isinstance(command, str) else " ".join(command)
        if "randomize_va_space" in cmd_str:
            return _FakeExecResult()
        if "cc " in cmd_str or "gcc " in cmd_str:
            return _FakeExecResult(stdout="")
        self._call_count += 1
        import random
        if random.random() < self._crash_rate:
            crash_stderr = (
                self._stderr_on_crash
                or "==1==ERROR: AddressSanitizer: heap-buffer-overflow"
            )
            return _FakeExecResult(
                exit_code=1,
                stdout=f"{crash_stderr}\n__EXITCODE__1",
                stderr="",
            )
        return _FakeExecResult(
            exit_code=0,
            stdout="__EXITCODE__0",
            stderr="",
        )

    def write_file(self, path, data):
        pass

    def read_file(self, path):
        return b""

    def stop(self):
        self.stopped = True

    def copy_tree_into(self, host_path, container_path):
        pass


class _FakeSandboxManager:
    """Fake HunterSandbox that spawns _FakeSandbox instances."""

    def __init__(self, crash_rate: float = 1.0, stderr_on_crash: str = ""):
        self._crash_rate = crash_rate
        self._stderr_on_crash = stderr_on_crash
        self.spawned: list[_FakeSandbox] = []

    def spawn(self, session_id=None, **kwargs):
        sb = _FakeSandbox(
            crash_rate=self._crash_rate,
            stderr_on_crash=self._stderr_on_crash,
        )
        self.spawned.append(sb)
        return sb


# --- StabilityResult tests ----------------------------------------------------


class TestStabilityResult:
    def test_defaults(self):
        r = StabilityResult(
            finding_id="x", total_runs=0, successes=0,
            success_rate=0.0, per_container_rates=[],
            classification="unreliable",
        )
        assert r.hardened is False
        assert r.hardening_improved is False
        assert r.failure_analysis == ""
        assert r.hardened_poc is None

    def test_full_construction(self):
        r = StabilityResult(
            finding_id="f1", total_runs=60, successes=58,
            success_rate=58 / 60, per_container_rates=[1.0, 0.95, 0.95],
            classification="stable", hardened=False,
            failure_analysis="no failures",
        )
        assert r.classification == "stable"
        assert r.total_runs == 60


# --- StabilityConfig tests ----------------------------------------------------


class TestStabilityConfig:
    def test_default_thresholds(self):
        cfg = StabilityConfig()
        assert cfg.stable_threshold == 0.90
        assert cfg.flaky_threshold == 0.50
        assert cfg.runs_per_container == 20
        assert cfg.num_containers == 3

    def test_race_condition_detection(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        f_race = _make_finding(cwe="CWE-362")
        f_normal = _make_finding(cwe="CWE-787")
        assert sv._is_race_condition(f_race) is True
        assert sv._is_race_condition(f_normal) is False
        assert sv._runs_for_finding(f_race) == 100
        assert sv._runs_for_finding(f_normal) == 20
        assert sv._threshold_for_finding(f_race) == 0.70
        assert sv._threshold_for_finding(f_normal) == 0.90


# --- Classification tests ----------------------------------------------------


class TestClassification:
    def test_classify_stable(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        assert sv._classify(0.95, 0.90) == "stable"
        assert sv._classify(0.90, 0.90) == "stable"

    def test_classify_flaky(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        assert sv._classify(0.75, 0.90) == "flaky"
        assert sv._classify(0.50, 0.90) == "flaky"

    def test_classify_unreliable(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        assert sv._classify(0.49, 0.90) == "unreliable"
        assert sv._classify(0.0, 0.90) == "unreliable"


# --- Failure analysis tests ---------------------------------------------------


class TestFailureAnalysis:
    def test_timeout_analysis(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        stderrs = ["timeout expired"] * 8 + ["clean"] * 2
        analysis = sv._analyze_failures(stderrs)
        assert "timing" in analysis.lower()

    def test_address_variation_analysis(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        stderrs = [
            "crash at 0x00007fff12340000",
            "crash at 0x00007fff56780000",
            "crash at 0x00007fffabcd0000",
            "crash at 0x00007fffef010000",
        ]
        analysis = sv._analyze_failures(stderrs)
        assert "ASLR" in analysis

    def test_clean_exit_analysis(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        stderrs = ["", "", "", "", "some output"]
        analysis = sv._analyze_failures(stderrs)
        assert "environment" in analysis.lower()

    def test_empty_failures(self):
        sv = StabilityVerifier(_FakeSandboxManager())
        assert sv._analyze_failures([]) == ""


# --- apply_stability_result tests ---------------------------------------------


class TestApplyStabilityResult:
    def test_sets_classification_fields(self):
        finding = _make_finding()
        result = StabilityResult(
            finding_id="hunter-abc", total_runs=60, successes=55,
            success_rate=55 / 60, per_container_rates=[0.9, 0.95, 0.9],
            classification="stable",
        )
        apply_stability_result(finding, result)
        assert finding["stability_classification"] == "stable"
        assert finding["stability_success_rate"] == 55 / 60
        assert finding["stability_total_runs"] == 60
        assert finding["stability_hardened"] is False

    def test_hardened_poc_replaces_original(self):
        finding = _make_finding(poc="original poc")
        result = StabilityResult(
            finding_id="hunter-abc", total_runs=60, successes=55,
            success_rate=55 / 60, per_container_rates=[0.9, 0.95, 0.9],
            classification="stable", hardened=True,
            hardening_improved=True, hardened_poc="hardened poc",
        )
        apply_stability_result(finding, result)
        assert finding["poc"] == "hardened poc"

    def test_no_poc_update_if_not_hardened(self):
        finding = _make_finding(poc="original poc")
        result = StabilityResult(
            finding_id="hunter-abc", total_runs=60, successes=55,
            success_rate=55 / 60, per_container_rates=[0.9, 0.95, 0.9],
            classification="stable",
        )
        apply_stability_result(finding, result)
        assert finding.get("poc") == "original poc"


# --- StabilityVerifier integration tests --------------------------------------


class TestStabilityVerifier:
    @pytest.mark.asyncio
    async def test_stable_finding(self):
        manager = _FakeSandboxManager(crash_rate=1.0)
        config = StabilityConfig(
            runs_per_container=5, num_containers=3, enable_hardening=False,
        )
        sv = StabilityVerifier(manager, config=config)
        result = await sv.averify(_make_finding())
        assert result.classification == "stable"
        assert result.success_rate == 1.0
        assert result.total_runs == 15
        assert len(result.per_container_rates) == 3
        assert len(manager.spawned) == 3
        assert all(sb.stopped for sb in manager.spawned)

    @pytest.mark.asyncio
    async def test_flaky_finding(self):
        manager = _FakeSandboxManager(crash_rate=0.7)
        config = StabilityConfig(
            runs_per_container=20, num_containers=3, enable_hardening=False,
        )
        sv = StabilityVerifier(manager, config=config)
        result = await sv.averify(_make_finding())
        assert result.classification in ("flaky", "stable")
        assert 0.3 <= result.success_rate <= 1.0

    @pytest.mark.asyncio
    async def test_unreliable_no_hardening(self):
        manager = _FakeSandboxManager(crash_rate=0.2)
        config = StabilityConfig(
            runs_per_container=20, num_containers=3, enable_hardening=False,
        )
        sv = StabilityVerifier(manager, config=config)
        result = await sv.averify(_make_finding())
        assert result.classification == "unreliable"
        assert result.success_rate < 0.50
        assert result.hardened is False

    @pytest.mark.asyncio
    async def test_no_sandbox_spawn_failure(self):
        manager = MagicMock()
        manager.spawn.side_effect = RuntimeError("Docker not available")
        config = StabilityConfig(
            runs_per_container=5, num_containers=3, enable_hardening=False,
        )
        sv = StabilityVerifier(manager, config=config)
        result = await sv.averify(_make_finding())
        assert result.total_runs == 0
        assert result.classification == "unreliable"

    @pytest.mark.asyncio
    async def test_race_condition_runs(self):
        manager = _FakeSandboxManager(crash_rate=1.0)
        config = StabilityConfig(
            runs_per_container=20, race_runs_per_container=50,
            num_containers=2, enable_hardening=False,
        )
        sv = StabilityVerifier(manager, config=config)
        f = _make_finding(cwe="CWE-362")
        result = await sv.averify(f)
        assert result.total_runs == 100  # 50 * 2 containers


# --- Hardening tests ----------------------------------------------------------


class TestHardening:
    @pytest.mark.asyncio
    async def test_successful_hardening(self):
        call_count = 0

        class _FixingSandboxManager:
            """First round: unreliable. After hardening: stable."""

            def spawn(self, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count <= 3:
                    return _FakeSandbox(crash_rate=0.2)
                return _FakeSandbox(crash_rate=1.0)

        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text = "hardened PoC payload"
        mock_llm.aask_text = AsyncMock(return_value=mock_response)

        config = StabilityConfig(
            runs_per_container=10, num_containers=3,
            enable_hardening=True,
        )
        sv = StabilityVerifier(
            _FixingSandboxManager(), config=config,
            hardening_llm=mock_llm,
        )
        result = await sv.averify(_make_finding())
        assert result.hardened is True
        assert result.hardening_improved is True
        assert result.hardened_poc == "hardened PoC payload"

    @pytest.mark.asyncio
    async def test_failed_hardening(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text = "still bad poc"
        mock_llm.aask_text = AsyncMock(return_value=mock_response)

        manager = _FakeSandboxManager(crash_rate=0.0)
        config = StabilityConfig(
            runs_per_container=10, num_containers=3,
            enable_hardening=True,
        )
        sv = StabilityVerifier(
            manager, config=config, hardening_llm=mock_llm,
        )
        result = await sv.averify(_make_finding())
        assert result.hardened is True
        assert result.hardening_improved is False
        assert result.hardened_poc is None

    @pytest.mark.asyncio
    async def test_hardening_llm_failure(self):
        mock_llm = AsyncMock()
        mock_llm.aask_text = AsyncMock(side_effect=RuntimeError("API down"))

        manager = _FakeSandboxManager(crash_rate=0.1)
        config = StabilityConfig(
            runs_per_container=10, num_containers=3,
            enable_hardening=True,
        )
        sv = StabilityVerifier(
            manager, config=config, hardening_llm=mock_llm,
        )
        result = await sv.averify(_make_finding())
        assert result.hardened is True
        assert result.hardening_improved is False


# --- Runner integration -------------------------------------------------------


class TestRunnerIntegration:
    def test_stability_enabled_by_default(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner
        r = SourceHuntRunner(repo_url="test", depth="standard")
        assert r.enable_stability_verification is True

    def test_stability_disabled(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner
        r = SourceHuntRunner(
            repo_url="test", depth="standard",
            enable_stability_verification=False,
        )
        assert r.enable_stability_verification is False
