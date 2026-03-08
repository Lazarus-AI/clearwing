"""Tests for the parallel agent execution system."""
from __future__ import annotations

import pytest

from vulnexploit.parallel import ParallelExecutor, ParallelScanConfig, TargetResult


class TestTargetResult:
    """Verify the TargetResult dataclass defaults."""

    def test_defaults(self):
        result = TargetResult(target="10.0.0.1", status="completed")
        assert result.target == "10.0.0.1"
        assert result.status == "completed"
        assert result.session_id == ""
        assert result.findings == []
        assert result.flags_found == []
        assert result.duration_seconds == 0.0
        assert result.cost_usd == 0.0
        assert result.tokens_used == 0
        assert result.error == ""


class TestParallelScanConfig:
    """Verify the ParallelScanConfig dataclass defaults and custom values."""

    def test_defaults(self):
        config = ParallelScanConfig(targets=["10.0.0.1"])
        assert config.targets == ["10.0.0.1"]
        assert config.max_parallel == 3
        assert config.model == "claude-sonnet-4-6"
        assert config.depth == "standard"
        assert config.timeout_minutes == 30
        assert config.cost_limit_per_target == 0.0
        assert config.total_cost_limit == 0.0
        assert config.on_target_complete is None

    def test_custom_values(self):
        callback = lambda r: None
        config = ParallelScanConfig(
            targets=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            max_parallel=5,
            model="claude-opus-4-6",
            depth="deep",
            timeout_minutes=60,
            cost_limit_per_target=1.50,
            total_cost_limit=10.0,
            on_target_complete=callback,
        )
        assert config.targets == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert config.max_parallel == 5
        assert config.model == "claude-opus-4-6"
        assert config.depth == "deep"
        assert config.timeout_minutes == 60
        assert config.cost_limit_per_target == 1.50
        assert config.total_cost_limit == 10.0
        assert config.on_target_complete is callback


class TestParallelExecutorInit:
    """Verify ParallelExecutor initialization and basic properties."""

    def test_initialization(self):
        config = ParallelScanConfig(targets=["10.0.0.1", "10.0.0.2"])
        executor = ParallelExecutor(config)
        assert executor.config is config
        assert executor._results == {}
        assert executor._total_cost == 0.0
        assert executor._cancelled is False
        assert executor._futures == {}

    def test_cancel_sets_flag(self):
        config = ParallelScanConfig(targets=["10.0.0.1"])
        executor = ParallelExecutor(config)
        assert executor.is_cancelled is False
        executor.cancel()
        assert executor.is_cancelled is True

    def test_total_count_matches_targets(self):
        config = ParallelScanConfig(targets=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        executor = ParallelExecutor(config)
        assert executor.total_count == 3

    def test_completed_count_starts_at_zero(self):
        config = ParallelScanConfig(targets=["10.0.0.1", "10.0.0.2"])
        executor = ParallelExecutor(config)
        assert executor.completed_count == 0


class TestParallelExecutorSummary:
    """Verify get_summary with empty and populated results."""

    def test_get_summary_empty_results(self):
        config = ParallelScanConfig(targets=["10.0.0.1", "10.0.0.2"])
        executor = ParallelExecutor(config)
        summary = executor.get_summary()
        assert "0/2 targets" in summary
        assert "$0.0000" in summary

    def test_get_summary_with_mixed_results(self):
        config = ParallelScanConfig(targets=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        executor = ParallelExecutor(config)

        # Manually populate results to avoid running actual scans
        executor._results["10.0.0.1"] = TargetResult(
            target="10.0.0.1",
            status="completed",
            findings=[{"description": "SQLi", "severity": "high"}],
            duration_seconds=45.0,
            cost_usd=0.05,
            tokens_used=2000,
        )
        executor._results["10.0.0.2"] = TargetResult(
            target="10.0.0.2",
            status="error",
            error="Connection refused",
            duration_seconds=2.0,
            cost_usd=0.001,
        )
        executor._results["10.0.0.3"] = TargetResult(
            target="10.0.0.3",
            status="timeout",
            error="Scan timed out after 30 minutes",
            duration_seconds=1800.0,
            cost_usd=0.50,
        )
        executor._total_cost = 0.551

        summary = executor.get_summary()

        # Check header
        assert "3/3 targets" in summary
        assert "$0.5510" in summary

        # Check individual target lines
        assert "10.0.0.1" in summary
        assert "completed" in summary
        assert "1 findings" in summary

        assert "10.0.0.2" in summary
        assert "error" in summary
        assert "Connection refused" in summary

        assert "10.0.0.3" in summary
        assert "timeout" in summary
        assert "Scan timed out" in summary


class TestParallelExecutorScanTarget:
    """Verify _scan_target behaviour without actual agent execution."""

    def test_scan_target_returns_cancelled_when_cancelled(self):
        config = ParallelScanConfig(targets=["10.0.0.1"])
        executor = ParallelExecutor(config)
        executor.cancel()
        result = executor._scan_target("10.0.0.1")
        assert result.target == "10.0.0.1"
        assert result.status == "cancelled"

    def test_scan_target_returns_cancelled_when_cost_limit_reached(self):
        config = ParallelScanConfig(
            targets=["10.0.0.1"],
            total_cost_limit=5.0,
        )
        executor = ParallelExecutor(config)
        executor._total_cost = 5.0  # Already at the limit
        result = executor._scan_target("10.0.0.1")
        assert result.target == "10.0.0.1"
        assert result.status == "cancelled"
        assert "Total cost limit reached" in result.error
