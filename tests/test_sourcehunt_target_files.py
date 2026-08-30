"""Explicit file targeting and first-turn source-window coverage."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.agent.tools.hunt.reporting import build_reporting_tools
from clearwing.analysis.source_analyzer import AnalyzerFinding
from clearwing.runners.parallel.executor import TargetResult
from clearwing.sourcehunt.checkpoints import HuntResult
from clearwing.sourcehunt.config import SourceHuntConfig, TargetConfig
from clearwing.sourcehunt.findings_pool import FindingsPool
from clearwing.sourcehunt.hunter import _target_window_initial_message, build_hunter_agent
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig, WorkItem, _target_label
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.state import Finding
from clearwing.sourcehunt.taint import TaintPath
from clearwing.ui.commands import sourcehunt as sourcehunt_command


def _target(path: Path, relative: str, loc: int = 1) -> dict:
    return {
        "path": relative,
        "absolute_path": str(path / relative),
        "language": "c",
        "loc": loc,
        "tags": ["memory_unsafe"],
        "surface": 0,
        "influence": 0,
        "reachability": 3,
        "priority": 0.0,
        "tier": "C",
    }


def test_target_files_filter_static_results_and_expand_numbered_windows(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    selected_path = source_dir / "selected.c"
    selected_path.write_text("".join(f"line {line}\n" for line in range(1, 1002)))
    other_path = source_dir / "other.c"
    other_path.write_text("other\n")

    selected_finding = AnalyzerFinding(
        file_path=str(selected_path),
        line_number=4,
        finding_type="test",
        severity="medium",
        description="selected",
    )
    other_finding = AnalyzerFinding(
        file_path=str(other_path),
        line_number=1,
        finding_type="test",
        severity="medium",
        description="other",
    )
    selected_taint = TaintPath(
        "src/selected.c", "read", 1, "memcpy", 4, "CWE-120", "", "high", "buf"
    )
    other_taint = TaintPath("src/other.c", "read", 1, "memcpy", 1, "CWE-120", "", "high", "buf")
    result = PreprocessResult(
        repo_path=str(tmp_path),
        file_targets=[
            _target(tmp_path, "src/selected.c"),
            _target(tmp_path, "src/other.c"),
        ],
        static_findings=[selected_finding, other_finding],
        semgrep_findings=[
            {"file": "src/selected.c", "line": 4},
            {"file": "src/other.c", "line": 1},
        ],
        taint_paths=[selected_taint, other_taint],
    )
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["./src/selected.c", "src/selected.c"],
        target_window_lines=480,
    )

    filtered = runner._filter_target_files(result)
    windows = runner._expand_target_windows(filtered.file_targets)

    assert runner._target_files == ("src/selected.c",)
    assert runner._no_rank is True
    assert [item["path"] for item in filtered.file_targets] == ["src/selected.c"]
    assert filtered.file_targets[0]["loc"] == 1001
    assert [item["target_start_line"] for item in windows] == [1, 481, 961]
    assert [item["target_end_line"] for item in windows] == [480, 960, 1001]
    assert filtered.static_findings == [selected_finding]
    assert filtered.semgrep_findings == [{"file": "src/selected.c", "line": 4}]
    assert filtered.taint_paths == [selected_taint]


def test_target_files_expand_160_line_windows(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("".join(f"line {line}\n" for line in range(1, 482)))
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["target.c"],
        target_window_lines=160,
    )
    result = PreprocessResult(repo_path=str(tmp_path), file_targets=[], static_findings=[])

    windows = runner._expand_target_windows(runner._filter_target_files(result).file_targets)

    assert [item["target_start_line"] for item in windows] == [1, 161, 321, 481]
    assert [item["target_end_line"] for item in windows] == [160, 320, 480, 481]


def test_target_window_is_first_turn_numbered_source_and_unique_work(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\nbeta\ngamma\n")
    file_target = {
        **_target(tmp_path, "target.c", loc=3),
        "target_start_line": 2,
        "target_end_line": 3,
        "target_total_lines": 3,
    }

    message = _target_window_initial_message(file_target)

    assert message is not None
    assert "target.c:2-3 of 3" in message
    assert "2 | beta" in message
    assert "3 | gamma" in message
    assert "1 | alpha" not in message
    assert _target_label(file_target) == "target.c:2-3"
    assert WorkItem(file_target, "deep").stable_identifier("run") != WorkItem(
        {**file_target, "target_start_line": 1, "target_end_line": 1}, "deep"
    ).stable_identifier("run")
    assert WorkItem(
        {**file_target, "target_sha256": "old"}, "deep"
    ).stable_identifier("run") != WorkItem(
        {**file_target, "target_sha256": "new"}, "deep"
    ).stable_identifier("run")


def test_target_window_reuses_matching_work_item_cache(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\n")
    window = {
        **_target(tmp_path, "target.c"),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
        "target_sha256": "content-digest",
    }
    work_cache = MagicMock()
    work_cache.load.return_value = TargetResult(
        target="target.c:1-1",
        status="completed",
        findings=[Finding(id="cached", file="target.c", line_number=1)],
        tier="A",
        band="fast",
        stop_reason="completed",
    )
    pool = HunterPool(
        HuntPoolConfig(
            files=[window],
            repo_path=str(tmp_path),
            explicit_target_windows=True,
            session_id_prefix="hunt",
            starting_band="fast",
            max_band="fast",
            work_cache=work_cache,
            max_parallel=1,
        )
    )
    work_id = pool._expand_to_work_items(pool.config.files, "fast")[0].stable_identifier(
        "hunt", "A"
    )
    pool._run_file_task = AsyncMock(side_effect=AssertionError("cache miss"))

    findings = asyncio.run(pool.arun())

    assert findings == [Finding(id="cached", file="target.c", line_number=1)]
    work_cache.load.assert_called_once_with(work_id)
    pool._run_file_task.assert_not_awaited()
    assert pool.all_targets_completed is True


def test_target_window_uses_a_fence_longer_than_source_backticks(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("/* ``` untrusted source */\n")
    file_target = {
        **_target(tmp_path, "target.c"),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
    }

    message = _target_window_initial_message(file_target)

    assert message is not None
    assert "````c" in message
    assert "1 | /* ``` untrusted source */" in message
    assert message.rstrip().endswith(
        "Start with this window, then use source-navigation tools to follow concrete\n"
        "callers, callees, definitions, and guards outside it when needed."
    )


def test_target_window_numbers_only_lf_delimited_physical_lines(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_bytes(b"one\x0btwo\x0cstill\nthree\r\nlast")
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["target.c"],
    )
    result = PreprocessResult(repo_path=str(tmp_path), file_targets=[], static_findings=[])

    window = runner._expand_target_windows(runner._filter_target_files(result).file_targets)[0]
    message = _target_window_initial_message(window)

    assert window["target_total_lines"] == 3
    assert message is not None
    assert "1 | one\x0btwo\x0cstill\n" in message
    assert "2 | three\r\n" in message
    assert "3 | last\n" in message


def test_target_window_rejects_file_changed_after_fingerprint(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\nbeta\n")
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["target.c"],
    )
    result = PreprocessResult(repo_path=str(tmp_path), file_targets=[], static_findings=[])
    window = runner._expand_target_windows(runner._filter_target_files(result).file_targets)[0]
    source.write_text("changed\nbeta\n")

    with pytest.raises(ValueError, match="changed before hunting"):
        _target_window_initial_message(window)


def test_target_windows_run_once_without_redundancy_or_promotion(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\nbeta\n")
    windows = [
        {
            **_target(tmp_path, "target.c", loc=2),
            "priority": 5.0,
            "target_start_line": line,
            "target_end_line": line,
            "target_total_lines": 2,
        }
        for line in (1, 2)
    ]
    pool = HunterPool(
        HuntPoolConfig(
            files=windows,
            repo_path=str(tmp_path),
            explicit_target_windows=True,
            redundancy_override=5,
            shard_entry_points=True,
            entry_points_by_file={"target.c": [MagicMock(function_name="entry")]},
            starting_band="fast",
            max_band="deep",
            max_parallel=2,
        )
    )
    calls: list[str] = []

    async def fake_run(file_target, cost_limit, tier, band="", **_kwargs):
        assert cost_limit > 0
        label = _target_label(file_target)
        calls.append(label)
        return TargetResult(
            target=label,
            status="completed",
            findings=[
                {
                    "id": f"finding-{label}",
                    "file": "target.c",
                    "line_number": file_target["target_start_line"],
                    "description": "promotion signal",
                }
            ],
            tier=tier,
            band=band,
            stop_reason="completed",
        )

    pool._run_file_task = fake_run

    asyncio.run(pool.arun())

    assert sorted(calls) == ["target.c:1-1", "target.c:2-2"]
    assert pool.promotion_counts == {"fast→standard": 0, "standard→deep": 0}
    assert pool.completed_target_count == 1
    assert pool.all_targets_completed is True


def test_target_window_budget_stop_is_incomplete_but_keeps_findings(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\n")
    window = {
        **_target(tmp_path, "target.c"),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
    }
    pool = HunterPool(
        HuntPoolConfig(
            files=[window],
            repo_path=str(tmp_path),
            explicit_target_windows=True,
            max_parallel=1,
        )
    )

    async def stopped(*_args, **_kwargs):
        return TargetResult(
            target="target.c:1-1",
            status="budget_exhausted",
            findings=[{"id": "partial", "file": "target.c", "line_number": 1}],
            stop_reason="budget_exhausted",
        )

    pool._run_file_task = stopped

    findings = asyncio.run(pool.arun())

    assert [finding["id"] for finding in findings] == ["partial"]
    assert pool.all_targets_completed is False
    assert pool.completed_target_count == 0


def test_target_window_sandbox_failure_is_a_normal_incomplete_result(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\n")
    window = {
        **_target(tmp_path, "target.c"),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
    }

    def fail_sandbox():
        raise RuntimeError("daemon unavailable")

    pool = HunterPool(
        HuntPoolConfig(
            files=[window],
            repo_path=str(tmp_path),
            explicit_target_windows=True,
            sandbox_factory=fail_sandbox,
            max_parallel=1,
        )
    )

    assert asyncio.run(pool.arun()) == []
    assert pool.all_targets_completed is False
    assert pool.completed_target_count == 0


@pytest.mark.parametrize(
    ("stop_reason", "status"),
    [
        ("completed", "completed"),
        ("max_steps", "error"),
        ("budget_exhausted", "budget_exhausted"),
        ("empty_response", "error"),
        ("degenerate_loop", "error"),
    ],
)
def test_target_window_maps_hunter_stop_reason_to_coverage_status(
    tmp_path: Path, stop_reason: str, status: str
) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\n")
    window = {
        **_target(tmp_path, "target.c"),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
    }
    pool = HunterPool(
        HuntPoolConfig(
            files=[window],
            repo_path=str(tmp_path),
            explicit_target_windows=True,
        )
    )
    pool._run_one_hunter = AsyncMock(
        return_value=([Finding(id="result", file="target.c")], 0.0, 0, stop_reason)
    )

    result = asyncio.run(pool._run_file_task(window, 1.0, "A", band="fast"))

    assert result.status == status


def test_incomplete_target_window_keeps_partial_findings_in_pool(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\n")
    window = {
        **_target(tmp_path, "target.c"),
        "tier": "A",
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
    }
    pool = HunterPool(
        HuntPoolConfig(
            files=[window],
            repo_path=str(tmp_path),
            explicit_target_windows=True,
            findings_pool=FindingsPool(),
            max_parallel=1,
        )
    )
    partial = Finding(id="partial", file="target.c", line_number=1)
    pool._run_one_hunter = AsyncMock(
        return_value=([partial], 0.0, 0, "empty_response")
    )

    findings = asyncio.run(pool.arun())

    assert findings == [partial]
    assert pool.all_targets_completed is False


def test_specialist_hunter_keeps_campaign_hint_and_seeded_window(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("int target(void) { return 1; }\n")
    file_target = {
        **_target(tmp_path, "target.c", loc=1),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 1,
    }

    hunter, context = build_hunter_agent(
        file_target=file_target,
        repo_path=str(tmp_path),
        sandbox=None,
        llm=MagicMock(),
        session_id="test",
        prompt_mode="specialist",
        agent_mode="constrained",
        campaign_hint="audit target arithmetic",
    )

    assert "We are particularly interested in audit target arithmetic." in hunter.prompt
    assert "1 | int target(void)" in hunter.initial_user_message
    assert context.files_read == {"target.c"}
    assert context.read_ranges == {"target.c": [(1, 1)]}

    trace = next(tool for tool in build_reporting_tools(context) if tool.name == "record_trace_step")
    rejected = trace.handler(file="target.c", line=2, code_snippet="invented")
    assert rejected["error"]["code"] == "UNREAD_TRACE_SOURCE"


def test_target_files_can_select_preprocessor_excluded_source(tmp_path: Path) -> None:
    source = tmp_path / "bundle.min.js"
    source.write_text("function parse(value) { return value; }\n")
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["bundle.min.js"],
    )
    result = PreprocessResult(repo_path=str(tmp_path), file_targets=[], static_findings=[])

    filtered = runner._filter_target_files(result)

    assert filtered.file_targets[0]["path"] == "bundle.min.js"
    assert filtered.file_targets[0]["language"] == "javascript"


def test_target_files_reject_oversized_prompt_window(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("x" * (512 * 1024 + 1))
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["target.c"],
    )
    result = PreprocessResult(repo_path=str(tmp_path), file_targets=[], static_findings=[])

    with pytest.raises(ValueError, match="prompt bytes"):
        runner._filter_target_files(result)


def test_target_files_reject_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source.c"
    source.write_text("int value;\n")
    link = tmp_path / "link.c"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are unavailable")
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        target_files=["link.c"],
    )
    result = PreprocessResult(repo_path=str(tmp_path), file_targets=[], static_findings=[])

    with pytest.raises(ValueError, match="symbolic links"):
        runner._filter_target_files(result)


def test_target_window_cache_identity_includes_effective_prompt_context(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("alpha\nbeta\n")
    window = {
        **_target(tmp_path, "target.c", loc=2),
        "target_start_line": 1,
        "target_end_line": 1,
        "target_total_lines": 2,
        "target_size_bytes": source.stat().st_size,
        "target_sha256": "digest",
    }

    def work_id(*, hint: str, campaign: str = "audit") -> str:
        pool = HunterPool(
            HuntPoolConfig(
                files=[dict(window)],
                repo_path=str(tmp_path),
                explicit_target_windows=True,
                semgrep_hints_by_file={
                    "target.c": [{"line": 1, "description": hint}]
                },
                campaign_hint=campaign,
            )
        )
        item = pool._expand_to_work_items(pool.config.files, "fast")[0]
        return item.stable_identifier("hunt", "A")

    assert work_id(hint="first") != work_id(hint="second")
    assert work_id(hint="first") != work_id(hint="first", campaign="different")


def test_target_window_lines_respects_config_and_explicit_override() -> None:
    config = SourceHuntConfig(
        target=TargetConfig(repo_url="test", target_window_lines=160),
    )

    assert SourceHuntRunner(config=config)._target_window_lines == 160
    assert SourceHuntRunner(config=config, target_window_lines=480)._target_window_lines == 480


def test_incomplete_target_plan_skips_downstream_and_exits_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    source.write_text("int value;\n")
    runner = SourceHuntRunner(
        repo_url=str(tmp_path),
        local_path=str(tmp_path),
        target_files=["target.c"],
        output_dir=str(tmp_path / "results"),
        no_exploit=True,
        enable_findings_pool=False,
        enable_mechanism_memory=False,
        enable_behavior_monitor=False,
        enable_knowledge_graph=False,
        stop_after="hunt",
    )
    runner._ensure_sandbox_factory = MagicMock()
    runner._hunt = AsyncMock(
        return_value=HuntResult(
            findings=[],
            files_hunted=0,
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
            target_plan_completed=False,
        )
    )
    runner._verify = AsyncMock(side_effect=AssertionError("verification must not run"))
    runner._exploit = AsyncMock(side_effect=AssertionError("exploitation must not run"))

    result = runner.run()

    assert result.status == "incomplete"
    assert result.exit_code == 3
    runner._verify.assert_not_awaited()
    runner._exploit.assert_not_awaited()


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/source.c",
        "../source.c",
        "src/../../source.c",
        "",
        "src/bad\nignore.c",
        "src/bad\x7fignore.c",
        "src/bad\u2028ignore.c",
    ],
)
def test_target_files_reject_non_repository_paths(path: str) -> None:
    with pytest.raises(ValueError, match="repository-relative"):
        SourceHuntRunner(repo_url="test", target_files=[path])


def test_sourcehunt_cli_accepts_repeatable_target_files() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)

    args = parser.parse_args(
        [
            "sourcehunt",
            "repo",
            "--target-files",
            "src/a.c",
            "--target-file",
            "src/b.c",
            "--target-window-lines",
            "160",
        ]
    )

    assert args.target_files == ["src/a.c", "src/b.c"]
    assert args.target_window_lines == 160


def test_sourcehunt_cli_defers_default_window_size_to_runner() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)

    args = parser.parse_args(["sourcehunt", "repo", "--target-files", "src/a.c"])

    assert args.target_window_lines is None


def test_sourcehunt_machine_request_accepts_target_plan() -> None:
    parsed = sourcehunt_command._machine_request(
        {
            "repo_url": "https://example.test/repo.git",
            "target_files": ["src/a.c", "src/b.c"],
            "target_window_lines": 160,
        }
    )

    assert parsed["target_files"] == ["src/a.c", "src/b.c"]
    assert parsed["target_window_lines"] == 160
