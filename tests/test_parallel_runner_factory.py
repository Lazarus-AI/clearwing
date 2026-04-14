"""R3 regression tests — injectable runner_factory on ParallelExecutor.

The goal: let callers swap CICDRunner for any runner that returns a
CICDResult-shaped object. Verifies that:
    - the default path (factory=None) still uses CICDRunner
    - a custom factory is called with (target, config)
    - its result flows through to TargetResult
    - existing behaviors (cost tracking, callbacks, cancellation) still work
"""
from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from clearwing.runners.parallel.executor import (
    ParallelExecutor,
    ParallelScanConfig,
    TargetResult,
)


@dataclass
class _FakeResult:
    """Minimal CICDResult-shaped stub."""
    exit_code: int = 0
    target: str = ""
    findings: list = None
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    tokens_used: int = 0

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class _FakeRunner:
    def __init__(self, target: str, config):
        self.target = target
        self.config = config

    def run(self) -> _FakeResult:
        return _FakeResult(
            exit_code=0,
            target=self.target,
            findings=[{"description": f"finding for {self.target}"}],
            duration_seconds=0.01,
            cost_usd=0.05,
            tokens_used=100,
        )


class TestDefaultRunnerFactoryPath:
    def test_default_path_uses_cicd_runner(self):
        """When factory=None, ParallelExecutor should import and use CICDRunner."""
        # Mock CICDRunner so we don't actually run a scan
        with patch("clearwing.runners.cicd.runner.CICDRunner") as MockRunner:
            mock_instance = MagicMock()
            mock_instance.run.return_value = _FakeResult(target="10.0.0.1", exit_code=0)
            MockRunner.return_value = mock_instance

            config = ParallelScanConfig(
                targets=["10.0.0.1"],
                max_parallel=1,
                timeout_minutes=1,
            )
            executor = ParallelExecutor(config)
            results = executor.run()

            assert len(results) == 1
            assert results[0].target == "10.0.0.1"
            assert results[0].status == "completed"
            # CICDRunner was instantiated
            MockRunner.assert_called_once()
            call_kwargs = MockRunner.call_args.kwargs
            assert call_kwargs["target"] == "10.0.0.1"


class TestCustomRunnerFactory:
    def test_factory_called_with_target_and_config(self):
        """A custom factory receives (target, config) and its result is used."""
        factory_calls = []

        def factory(target, config):
            factory_calls.append((target, config))
            return _FakeRunner(target, config)

        config = ParallelScanConfig(
            targets=["host-a", "host-b", "host-c"],
            max_parallel=2,
            timeout_minutes=1,
            runner_factory=factory,
        )
        executor = ParallelExecutor(config)
        results = executor.run()

        assert len(factory_calls) == 3
        assert {c[0] for c in factory_calls} == {"host-a", "host-b", "host-c"}
        # Each got the same config
        for _, cfg in factory_calls:
            assert cfg is config

        assert len(results) == 3
        for r in results:
            assert r.status == "completed"
            assert len(r.findings) == 1

    def test_factory_result_cost_tracking(self):
        """Costs from factory-produced runners flow through to TargetResult."""
        def factory(target, config):
            return _FakeRunner(target, config)

        config = ParallelScanConfig(
            targets=["a", "b", "c", "d"],
            max_parallel=2,
            runner_factory=factory,
        )
        executor = ParallelExecutor(config)
        executor.run()

        assert executor.total_cost == pytest.approx(0.20)   # 4 * 0.05

    def test_factory_respects_total_cost_limit(self):
        """total_cost_limit should still halt new runners after the limit."""
        def factory(target, config):
            return _FakeRunner(target, config)

        config = ParallelScanConfig(
            targets=["a", "b", "c", "d", "e"],
            max_parallel=1,
            runner_factory=factory,
            total_cost_limit=0.12,    # allows 2 runners at 0.05 each before tripping
        )
        executor = ParallelExecutor(config)
        results = executor.run()

        # Some targets were cancelled due to the cost cap
        cancelled = [r for r in results if r.status == "cancelled"]
        assert len(cancelled) >= 1

    def test_factory_callback_fires_per_completion(self):
        """on_target_complete should fire for every runner the factory produces."""
        seen: list[str] = []

        def factory(target, config):
            return _FakeRunner(target, config)

        config = ParallelScanConfig(
            targets=["x", "y"],
            max_parallel=2,
            runner_factory=factory,
            on_target_complete=lambda r: seen.append(r.target),
        )
        executor = ParallelExecutor(config)
        executor.run()
        assert sorted(seen) == ["x", "y"]

    def test_factory_exception_is_captured_per_target(self):
        """A runner that raises becomes a TargetResult(status='error')."""
        class ExplodingRunner:
            def __init__(self, target, config):
                self.target = target

            def run(self):
                raise RuntimeError("boom")

        def factory(target, config):
            return ExplodingRunner(target, config)

        config = ParallelScanConfig(
            targets=["a", "b"],
            max_parallel=1,
            runner_factory=factory,
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert all(r.status == "error" for r in results)
        assert all("boom" in r.error for r in results)
