"""Tests for the Timing Side-Channel Framework (unit tests, no real network)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import clearwing.agent.tools.crypto.timing_tools as timing_mod
from clearwing.agent.tools.crypto.timing_tools import (
    get_timing_tools,
    timing_bitwise_probe,
    timing_compare,
    timing_probe,
)
from clearwing.crypto.stats import (
    apply_outlier_rejection,
    cohens_d,
    compute_extended_stats,
    compute_stats,
    confidence_interval,
    histogram,
    percentiles,
    reject_outliers_iqr,
    reject_outliers_zscore,
    welch_t_test,
)

# --- Statistical helpers (clearwing/crypto/stats.py) ---


class TestComputeStats:
    def test_basic(self):
        times = [10.0, 20.0, 30.0, 40.0, 50.0]
        result = compute_stats(times, "test")
        assert result["label"] == "test"
        assert result["mean_ms"] == 30.0
        assert result["median_ms"] == 30.0
        assert result["min_ms"] == 10.0
        assert result["max_ms"] == 50.0
        assert result["n"] == 5
        assert result["stdev_ms"] > 0

    def test_single_value(self):
        result = compute_stats([42.0], "single")
        assert result["mean_ms"] == 42.0
        assert result["stdev_ms"] == 0.0


class TestWelchTTest:
    def test_identical_distributions(self):
        a = [100.0, 101.0, 99.0, 100.5, 99.5]
        t_stat, p_value = welch_t_test(a, list(a))
        assert abs(t_stat) < 0.01
        assert p_value > 0.9

    def test_different_distributions(self):
        a = [100.0, 101.0, 99.0, 100.5, 99.5, 100.2, 99.8, 100.1, 100.3, 99.7]
        b = [200.0, 201.0, 199.0, 200.5, 199.5, 200.2, 199.8, 200.1, 200.3, 199.7]
        t_stat, p_value = welch_t_test(a, b)
        assert p_value < 0.05
        assert abs(t_stat) > 2


class TestCohensD:
    def test_identical(self):
        a = [100.0, 101.0, 99.0]
        d = cohens_d(a, list(a))
        assert d < 0.01

    def test_large_effect(self):
        a = [100.0, 101.0, 99.0, 100.5, 99.5]
        b = [200.0, 201.0, 199.0, 200.5, 199.5]
        d = cohens_d(a, b)
        assert d > 0.8


class TestPercentiles:
    def test_basic(self):
        times = list(range(1, 101))
        result = percentiles([float(t) for t in times])
        assert result["p50"] == pytest.approx(50.5, abs=0.5)
        assert result["p5"] < result["p25"] < result["p50"] < result["p75"] < result["p95"]

    def test_small_sample(self):
        result = percentiles([1.0, 2.0, 3.0])
        assert "p50" in result


class TestRejectOutliersIQR:
    def test_removes_outliers(self):
        times = [100.0, 101.0, 99.0, 100.5, 99.5, 500.0]
        cleaned = reject_outliers_iqr(times)
        assert 500.0 not in cleaned
        assert len(cleaned) < len(times)

    def test_keeps_normal_values(self):
        times = [100.0, 101.0, 99.0, 100.5, 99.5]
        cleaned = reject_outliers_iqr(times)
        assert len(cleaned) == len(times)

    def test_small_sample_unchanged(self):
        times = [1.0, 100.0]
        cleaned = reject_outliers_iqr(times)
        assert len(cleaned) == 2


class TestRejectOutliersZscore:
    def test_removes_outliers(self):
        times = [100.0] * 20 + [500.0]
        cleaned = reject_outliers_zscore(times)
        assert 500.0 not in cleaned
        assert len(cleaned) < len(times)

    def test_keeps_normal_values(self):
        times = [100.0, 101.0, 99.0, 100.5, 99.5]
        cleaned = reject_outliers_zscore(times)
        assert len(cleaned) == len(times)


class TestConfidenceInterval:
    def test_contains_mean(self):
        import statistics

        times = [100.0, 101.0, 99.0, 100.5, 99.5, 100.2, 99.8]
        lo, hi = confidence_interval(times)
        mean = statistics.mean(times)
        assert lo <= mean <= hi

    def test_wider_with_fewer_samples(self):
        import random as _rng

        _rng.seed(42)
        base = [100.0 + _rng.gauss(0, 5) for _ in range(50)]
        times_many = base
        times_few = base[:5]
        lo_m, hi_m = confidence_interval(times_many)
        lo_f, hi_f = confidence_interval(times_few)
        assert (hi_f - lo_f) > (hi_m - lo_m)

    def test_single_value(self):
        lo, hi = confidence_interval([42.0])
        assert lo == hi == 42.0


class TestHistogram:
    def test_bin_counts_sum(self):
        times = [float(i) for i in range(100)]
        bins = histogram(times)
        total = sum(b["count"] for b in bins)
        assert total == 100

    def test_default_10_bins(self):
        times = [float(i) for i in range(100)]
        bins = histogram(times)
        assert len(bins) == 10

    def test_empty_input(self):
        assert histogram([]) == []

    def test_single_value(self):
        bins = histogram([42.0])
        assert len(bins) == 1
        assert bins[0]["count"] == 1


class TestComputeExtendedStats:
    def test_has_all_keys(self):
        times = [100.0, 101.0, 99.0, 100.5, 99.5]
        result = compute_extended_stats(times, "test")
        assert "mean_ms" in result
        assert "percentiles" in result
        assert "confidence_interval_95" in result
        assert "histogram" in result
        assert "p50" in result["percentiles"]


class TestApplyOutlierRejection:
    def test_iqr_mode(self):
        times = [100.0, 101.0, 99.0, 500.0]
        cleaned = apply_outlier_rejection(times, "iqr")
        assert 500.0 not in cleaned

    def test_zscore_mode(self):
        times = [100.0, 101.0, 99.0, 100.5, 99.5, 100.2, 99.8, 100.3, 99.7, 500.0]
        cleaned = apply_outlier_rejection(times, "zscore")
        assert 500.0 not in cleaned

    def test_none_mode(self):
        times = [100.0, 101.0, 99.0, 500.0]
        cleaned = apply_outlier_rejection(times, "none")
        assert len(cleaned) == 4


# --- timing_probe ---


class TestTimingProbeValidation:
    def test_rejects_too_few_samples(self):
        result = timing_probe.invoke({"target": "http://example.com", "samples": 3})
        assert "error" in result

    def test_returns_error_when_declined(self):
        with patch.object(timing_mod, "interrupt", return_value=False):
            result = timing_probe.invoke({"target": "http://example.com", "samples": 10})
        assert "error" in result
        assert "declined" in result["error"].lower()


class TestTimingProbeWithMock:
    def _mock_request(self, *_args, **_kwargs):
        return (200, "ok", 100.0 + len(self._calls))

    @pytest.fixture(autouse=True)
    def _setup(self):
        self._calls = []
        self._call_count = 0

    def test_basic_probe_returns_stats(self):
        call_count = [0]

        def mock_request(*_args, **_kwargs):
            call_count[0] += 1
            return (200, "ok", 100.0 + call_count[0] * 0.1)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
        ):
            result = timing_probe.invoke({"target": "http://example.com", "samples": 10, "warmup": 2})

        assert "stats" in result
        assert result["stats"]["n"] <= 10
        assert result["warmup"] == 2
        assert "raw_times_ms" in result

    def test_warmup_discarded(self):
        calls = []

        def mock_request(*args, **_kwargs):
            calls.append(args)
            return (200, "ok", 100.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
        ):
            timing_probe.invoke({"target": "http://example.com", "samples": 5, "warmup": 3})

        assert len(calls) == 8  # 3 warmup + 5 samples

    def test_outlier_rejection(self):
        call_idx = [0]

        def mock_request(*_args, **_kwargs):
            call_idx[0] += 1
            if call_idx[0] == 8:  # one extreme outlier after warmup
                return (200, "ok", 9999.0)
            return (200, "ok", 100.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
        ):
            result = timing_probe.invoke({"target": "http://example.com", "samples": 10, "warmup": 2})

        assert result["outliers_removed"] >= 1
        assert result["cleaned_count"] < result["raw_count"]


# --- timing_compare ---


class TestTimingCompareValidation:
    def test_rejects_too_few_samples(self):
        result = timing_compare.invoke({"target": "http://example.com", "samples": 5})
        assert "error" in result

    def test_returns_error_when_declined(self):
        with patch.object(timing_mod, "interrupt", return_value=False):
            result = timing_compare.invoke({"target": "http://example.com", "samples": 20})
        assert "error" in result


class TestTimingCompareWithMock:
    def test_interleaved_sampling(self):
        urls_called = []

        def mock_request(url, *_args, **_kwargs):
            urls_called.append(url)
            return (200, "ok", 100.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
        ):
            timing_compare.invoke({
                "target": "http://example.com",
                "path_a": "/a",
                "path_b": "/b",
                "samples": 10,
                "warmup": 2,
            })

        # After warmup, verify interleaving: A, B, A, B pattern
        sample_urls = urls_called[2:]  # skip warmup
        for i in range(0, len(sample_urls) - 1, 2):
            assert sample_urls[i].endswith("/a")
            assert sample_urls[i + 1].endswith("/b")

    def test_significant_difference_detected(self):
        call_idx = [0]

        def mock_request(url, *_args, **_kwargs):
            call_idx[0] += 1
            if "/a" in url:
                return (200, "ok", 100.0)
            return (200, "ok", 200.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
        ):
            result = timing_compare.invoke({
                "target": "http://example.com",
                "path_a": "/a",
                "path_b": "/b",
                "samples": 20,
                "warmup": 2,
            })

        assert result["significant"] is True
        assert result["p_value"] < 0.05

    def test_no_difference_detected(self):
        def mock_request(*_args, **_kwargs):
            return (200, "ok", 100.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
        ):
            result = timing_compare.invoke({
                "target": "http://example.com",
                "path_a": "/a",
                "path_b": "/b",
                "samples": 20,
                "warmup": 2,
            })

        assert result["significant"] is False


# --- timing_bitwise_probe ---


class TestTimingBitwiseProbeValidation:
    def test_rejects_empty_charset(self):
        result = timing_bitwise_probe.invoke({
            "target": "http://example.com",
            "charset": "",
            "body_template": '{"token": "{{PROBE}}"}',
        })
        assert "error" in result

    def test_rejects_too_few_samples(self):
        result = timing_bitwise_probe.invoke({
            "target": "http://example.com",
            "charset": "abc",
            "samples_per_candidate": 1,
            "body_template": '{"token": "{{PROBE}}"}',
        })
        assert "error" in result

    def test_returns_error_when_declined(self):
        with patch.object(timing_mod, "interrupt", return_value=False):
            result = timing_bitwise_probe.invoke({
                "target": "http://example.com",
                "charset": "abc",
                "body_template": '{"token": "{{PROBE}}"}',
            })
        assert "error" in result


class TestTimingBitwiseWithMock:
    def test_identifies_correct_candidate(self):
        def mock_request(url, method, headers, body, **_kwargs):
            if body and '"a"' in body:
                return (200, "ok", 200.0)  # 'a' takes longer
            return (200, "ok", 100.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
            patch("random.shuffle"),  # disable shuffle for determinism
        ):
            result = timing_bitwise_probe.invoke({
                "target": "http://example.com",
                "charset": "abc",
                "body_template": '{"token": "{{PROBE}}"}',
                "samples_per_candidate": 5,
                "warmup": 1,
                "select": "max",
            })

        assert result["best_candidate"]["char"] == "a"
        assert result["candidates"][0]["char"] == "a"
        assert result["candidates"][0]["rank"] == 1

    def test_placeholder_substitution(self):
        bodies_seen = []

        def mock_request(url, method, headers, body, **_kwargs):
            bodies_seen.append(body)
            return (200, "ok", 100.0)

        with (
            patch.object(timing_mod, "interrupt", return_value=True),
            patch.object(timing_mod, "_timed_request", side_effect=mock_request),
            patch("random.shuffle"),
        ):
            timing_bitwise_probe.invoke({
                "target": "http://example.com",
                "charset": "x",
                "body_template": '{"token": "{{PROBE}}"}',
                "known_prefix": "abc",
                "samples_per_candidate": 3,
                "warmup": 1,
            })

        # After warmup, all sample bodies should have "abcx"
        sample_bodies = bodies_seen[1:]
        for b in sample_bodies:
            assert "abcx" in b
            assert "{{PROBE}}" not in b


# --- Tool metadata ---


class TestGetTimingTools:
    def test_returns_list(self):
        tools = get_timing_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_timing_tools()
        assert len(tools) == 3

    def test_tool_names(self):
        tools = get_timing_tools()
        names = [t.name for t in tools]
        assert names == ["timing_probe", "timing_compare", "timing_bitwise_probe"]
