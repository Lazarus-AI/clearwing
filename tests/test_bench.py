"""Tests for OSS-Fuzz crash severity ladder benchmark (spec 017)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.bench.crash_classifier import (
    CrashClassification,
    CrashClassifier,
)
from clearwing.bench.ossfuzz import (
    BENCHMARK_MODES,
    BenchmarkMode,
    BenchmarkTarget,
    OssFuzzBenchmark,
    load_corpus_dir,
    load_targets_file,
)
from clearwing.bench.results import (
    BenchmarkResult,
    ComparisonResult,
    TargetResult,
    compare_results,
    compute_mean_tier,
    compute_tier_distribution,
    format_comparison,
    load_result,
    save_result,
)


# --- CrashClassifier tests ---------------------------------------------------


class TestCrashClassifier:
    def test_tier_0_no_crash(self):
        classifier = CrashClassifier()
        result = classifier.classify_automated(exit_code=0, stdout="", stderr="")
        assert result.tier == 0
        assert result.automated_tier == 0
        assert result.sanitizer_type == "none"

    def test_tier_1_basic_crash(self):
        classifier = CrashClassifier()
        result = classifier.classify_automated(
            exit_code=139, stdout="", stderr="Segmentation fault",
        )
        assert result.tier == 1
        assert result.automated_tier == 1
        assert result.sanitizer_type == "none"

    def test_tier_2_asan_report(self):
        classifier = CrashClassifier()
        stderr = (
            "==12345== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010\n"
            "READ of size 4 at 0x602000000010 thread T0\n"
            "#0 0x4a1234 in main /src/test.c:10"
        )
        result = classifier.classify_automated(exit_code=1, stdout="", stderr=stderr)
        assert result.tier == 2
        assert result.automated_tier == 2
        assert result.sanitizer_type == "asan"
        assert result.crash_kind == "heap-buffer-overflow"

    def test_tier_2_ubsan_report(self):
        classifier = CrashClassifier()
        stderr = (
            "==999== ERROR: UndefinedBehaviorSanitizer: signed-integer-overflow\n"
            "in /src/calc.c:42"
        )
        result = classifier.classify_automated(exit_code=1, stdout="", stderr=stderr)
        assert result.tier == 2
        assert result.sanitizer_type == "ubsan"
        assert result.crash_kind == "signed-integer-overflow"

    def test_classify_returns_crash_kind(self):
        classifier = CrashClassifier()
        stderr = (
            "==1== ERROR: AddressSanitizer: use-after-free on address 0x60300000\n"
            "READ of size 8"
        )
        result = classifier.classify_automated(exit_code=1, stdout="", stderr=stderr)
        assert result.crash_kind == "use-after-free"

    @pytest.mark.asyncio
    async def test_llm_tier_3_controlled(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text = '{"tier": 3, "rationale": "user input in crash address"}'
        mock_response.cost_usd = 0.01
        mock_llm.aask_text = AsyncMock(return_value=mock_response)

        classifier = CrashClassifier(llm=mock_llm)
        stderr = (
            "==1== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\n"
            "WRITE of size 100"
        )
        result = await classifier.aclassify(exit_code=1, stdout="", stderr=stderr)
        assert result.tier == 3
        assert result.llm_tier == 3
        assert result.automated_tier == 2
        assert "user input" in result.llm_rationale

    @pytest.mark.asyncio
    async def test_llm_failure_stays_tier_2(self):
        mock_llm = AsyncMock()
        mock_llm.aask_text = AsyncMock(side_effect=RuntimeError("LLM down"))

        classifier = CrashClassifier(llm=mock_llm)
        stderr = "==1== ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 4"
        result = await classifier.aclassify(exit_code=1, stdout="", stderr=stderr)
        assert result.tier == 2
        assert result.llm_tier is None

    def test_timeout_exit_code_tier_0(self):
        classifier = CrashClassifier()
        result = classifier.classify_automated(exit_code=124, stdout="", stderr="")
        assert result.tier == 0


# --- BenchmarkResult tests ---------------------------------------------------


class TestBenchmarkResult:
    def test_result_defaults(self):
        r = BenchmarkResult()
        assert r.model == ""
        assert r.mode == "standard"
        assert r.total_cost_usd == 0.0
        assert r.targets_attempted == 0
        assert r.results == []

    def test_tier_distribution_computation(self):
        results = [
            TargetResult(project_name="a", tier=0),
            TargetResult(project_name="b", tier=1),
            TargetResult(project_name="c", tier=2),
            TargetResult(project_name="d", tier=2),
            TargetResult(project_name="e", tier=3),
            TargetResult(project_name="f", error="build failed"),
        ]
        dist = compute_tier_distribution(results)
        assert dist["0"] == 1
        assert dist["1"] == 1
        assert dist["2"] == 2
        assert dist["3"] == 1
        assert dist["4"] == 0
        assert dist["5"] == 0

    def test_json_round_trip(self):
        result = BenchmarkResult(
            model="test-model",
            mode="quick",
            timestamp="2024-01-01T00:00:00Z",
            total_cost_usd=1.23,
            targets_attempted=3,
            targets_succeeded=2,
            targets_failed=1,
            tier_distribution={"0": 1, "2": 1},
            results=[
                TargetResult(project_name="proj1", tier=0, cost_usd=0.5),
                TargetResult(project_name="proj2", tier=2, cost_usd=0.73),
            ],
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            save_result(result, f.name)
            loaded = load_result(f.name)

        assert loaded.model == "test-model"
        assert loaded.mode == "quick"
        assert loaded.total_cost_usd == 1.23
        assert loaded.targets_attempted == 3
        assert len(loaded.results) == 2
        assert loaded.results[0].project_name == "proj1"
        assert loaded.results[1].tier == 2

    def test_comparison_deltas(self):
        a = BenchmarkResult(
            model="model-a",
            tier_distribution={"0": 5, "1": 3, "2": 2},
        )
        b = BenchmarkResult(
            model="model-b",
            tier_distribution={"0": 7, "1": 2, "2": 1},
        )
        comp = compare_results(a, b)
        assert comp.tier_deltas["0"] == -2  # A has fewer tier 0 (better)
        assert comp.tier_deltas["1"] == 1
        assert comp.tier_deltas["2"] == 1

    def test_comparison_mean_tier(self):
        dist = {"0": 5, "1": 3, "2": 2}
        mean = compute_mean_tier(dist)
        expected = (0 * 5 + 1 * 3 + 2 * 2) / 10
        assert abs(mean - expected) < 0.001

    def test_comparison_empty(self):
        mean = compute_mean_tier({})
        assert mean == 0.0

    def test_format_comparison_table(self):
        comp = ComparisonResult(
            model_a="a", model_b="b",
            tier_dist_a={"0": 5}, tier_dist_b={"0": 3},
            tier_deltas={"0": 2},
            mean_tier_a=0.0, mean_tier_b=0.0,
        )
        output = format_comparison(comp, fmt="table")
        assert "a" in output
        assert "b" in output

    def test_format_comparison_json(self):
        comp = ComparisonResult(
            model_a="a", model_b="b",
            tier_dist_a={}, tier_dist_b={},
            tier_deltas={},
            mean_tier_a=0.0, mean_tier_b=0.0,
        )
        output = format_comparison(comp, fmt="json")
        data = json.loads(output)
        assert data["model_a"] == "a"

    def test_format_comparison_markdown(self):
        comp = ComparisonResult(
            model_a="a", model_b="b",
            tier_dist_a={"0": 1}, tier_dist_b={"0": 2},
            tier_deltas={"0": -1},
            mean_tier_a=0.0, mean_tier_b=0.0,
        )
        output = format_comparison(comp, fmt="markdown")
        assert "| Tier |" in output


# --- OssFuzzBenchmark tests --------------------------------------------------


class TestOssFuzzBenchmark:
    def test_mode_config_quick(self):
        mode = BENCHMARK_MODES["quick"]
        assert mode.max_targets == 100
        assert mode.budget_per_target == 5.0
        assert mode.runs_per_target == 1

    def test_mode_config_standard(self):
        mode = BENCHMARK_MODES["standard"]
        assert mode.max_targets == 1000
        assert mode.budget_per_target == 15.0

    def test_mode_config_deep(self):
        mode = BENCHMARK_MODES["deep"]
        assert mode.runs_per_target == 10
        assert mode.budget_per_target == 50.0
        assert mode.max_targets == 100

    def test_mode_config_full(self):
        mode = BENCHMARK_MODES["full"]
        assert mode.max_targets == 7000

    def test_benchmark_target_defaults(self):
        t = BenchmarkTarget()
        assert t.project_name == ""
        assert t.repo_path == ""
        assert t.entry_point == ""
        assert t.language == "c"

    def test_load_corpus_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "project_a").mkdir()
            (Path(tmpdir) / "project_b").mkdir()
            (Path(tmpdir) / ".hidden").mkdir()

            targets = load_corpus_dir(tmpdir)
            assert len(targets) == 2
            names = [t.project_name for t in targets]
            assert "project_a" in names
            assert "project_b" in names
            assert ".hidden" not in names

    def test_load_corpus_dir_nonexistent(self):
        targets = load_corpus_dir("/nonexistent/path")
        assert targets == []

    def test_load_targets_file(self):
        data = [
            {
                "project_name": "libpng",
                "repo_path": "/repos/libpng",
                "entry_points": ["fuzz_png.c", "fuzz_read.c"],
                "language": "c",
            },
            {
                "project": "libjpeg",
                "repo": "/repos/libjpeg",
            },
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False,
        ) as f:
            json.dump(data, f)
            f.flush()
            targets = load_targets_file(f.name)

        assert len(targets) == 3  # 2 entry points + 1 default
        assert targets[0].project_name == "libpng"
        assert targets[0].entry_point == "fuzz_png.c"
        assert targets[1].entry_point == "fuzz_read.c"
        assert targets[2].project_name == "libjpeg"

    def test_benchmark_prompt_has_placeholders(self):
        from clearwing.bench.ossfuzz import BENCHMARK_HUNT_PROMPT
        assert "{project_name}" in BENCHMARK_HUNT_PROMPT
        assert "{entry_point_line}" in BENCHMARK_HUNT_PROMPT


# --- CLI tests ----------------------------------------------------------------


class TestBenchCLI:
    def test_bench_ossfuzz_flag(self):
        import argparse

        from clearwing.ui.commands import bench

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        bench.add_parser(subs)
        args = parser.parse_args(["bench", "ossfuzz"])
        assert args.bench_action == "ossfuzz"

    def test_bench_ossfuzz_mode(self):
        import argparse

        from clearwing.ui.commands import bench

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        bench.add_parser(subs)
        args = parser.parse_args(["bench", "ossfuzz", "--mode", "quick"])
        assert args.mode == "quick"

    def test_bench_compare_flag(self):
        import argparse

        from clearwing.ui.commands import bench

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        bench.add_parser(subs)
        args = parser.parse_args(["bench", "compare", "a.json", "b.json"])
        assert args.bench_action == "compare"
        assert args.results == ["a.json", "b.json"]

    def test_bench_compare_format(self):
        import argparse

        from clearwing.ui.commands import bench

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        bench.add_parser(subs)
        args = parser.parse_args([
            "bench", "compare", "a.json", "b.json", "--format", "json",
        ])
        assert args.output_format == "json"

    def test_bench_no_llm_classify(self):
        import argparse

        from clearwing.ui.commands import bench

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        bench.add_parser(subs)
        args = parser.parse_args(["bench", "ossfuzz", "--no-llm-classify"])
        assert args.no_llm_classify is True
