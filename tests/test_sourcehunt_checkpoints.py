from __future__ import annotations

from pathlib import Path

from clearwing.analysis.source_analyzer import AnalyzerFinding
from clearwing.findings.types import Finding
from clearwing.sourcehunt.callgraph import CallGraph, FunctionInfo
from clearwing.sourcehunt.checkpoints import (
    HuntCheckpointStore,
    HuntResult,
    PreprocessCheckpointStore,
    RankCheckpointStore,
    ranked_targets_digest,
)
from clearwing.sourcehunt.findings_pool import FindingsPool
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.taint import TaintPath


def _result(repo: Path) -> PreprocessResult:
    callgraph = CallGraph()
    callgraph.functions["sample.c"].add("parse")
    callgraph.function_info["sample.c"].append(FunctionInfo("parse", 1, 4))
    return PreprocessResult(
        repo_path=str(repo),
        file_targets=[{"path": "sample.c", "absolute_path": str(repo / "sample.c")}],
        static_findings=[
            AnalyzerFinding(
                file_path="sample.c",
                line_number=2,
                finding_type="command_injection",
                severity="high",
                description="test",
            )
        ],
        callgraph=callgraph,
        taint_paths=[
            TaintPath(
                file="sample.c",
                source_function="read",
                source_line=1,
                sink_function="system",
                sink_line=2,
                sink_cwe="CWE-78",
                sink_description="test",
                severity="high",
                variable="input",
            )
        ],
    )


def test_preprocess_result_round_trips_nested_types(tmp_path: Path):
    result = _result(tmp_path)

    restored = PreprocessResult.model_validate_json(result.model_dump_json())

    assert isinstance(restored.file_targets[0], dict)
    assert isinstance(restored.static_findings[0], AnalyzerFinding)
    assert isinstance(restored.callgraph, CallGraph)
    assert isinstance(restored.callgraph.function_info["sample.c"][0], FunctionInfo)
    assert isinstance(restored.taint_paths[0], TaintPath)
    assert restored.callgraph.functions["sample.c"] == {"parse"}


def test_preprocess_checkpoint_rejects_changed_source(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    session = tmp_path / "results" / "sh-test"
    store = PreprocessCheckpointStore(session, "sh-test")
    options = {"run_taint": True}
    store.save(_result(repo), repo_url="repo", branch="main", options=options)

    assert store.load(repo_url="repo", branch="main", options=options) is not None

    source.write_text("int sample(void) { return 2; }\n", encoding="utf-8")
    assert store.load(repo_url="repo", branch="main", options=options) is None


def test_preprocess_checkpoint_rejects_corrupt_payload(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    session = tmp_path / "results" / "sh-test"
    store = PreprocessCheckpointStore(session, "sh-test")
    options = {"run_taint": False}
    store.save(_result(repo), repo_url="repo", branch="main", options=options)
    store.result_path.write_text("{}", encoding="utf-8")

    assert store.load(repo_url="repo", branch="main", options=options) is None


def test_rank_checkpoint_round_trips_exact_ranked_targets(tmp_path: Path):
    store = RankCheckpointStore(tmp_path / "sh-test", "sh-test")
    ranked = [
        {
            "path": "sample.c",
            "surface": 5,
            "influence": 4,
            "reachability": 3,
            "priority": 4.2,
            "surface_rationale": "attacker input",
        }
    ]
    options = {"model": "test-model", "max_parallel": 4}

    store.save(ranked, preprocess_digest="preprocess-sha", options=options)

    assert store.load(preprocess_digest="preprocess-sha", options=options) == ranked
    assert store.load(preprocess_digest="different", options=options) is None
    assert store.load(
        preprocess_digest="preprocess-sha",
        options={**options, "model": "other-model"},
    ) is None


def test_hunt_checkpoint_round_trips_completed_result(tmp_path: Path):
    store = HuntCheckpointStore(tmp_path / "sh-test", "sh-test")
    finding = Finding(
        id="f-test",
        file="sample.c",
        line_number=2,
        finding_type="command_injection",
        severity="high",
        evidence_level="static_corroboration",
        primitive_type="command_execution",
        cluster_id="cluster-1",
    )
    result = HuntResult(
        findings=[finding],
        files_hunted=3,
        spent_per_tier={"A": 1.25, "B": 0.0, "C": 0.0},
        band_stats={"fast_runs": 3},
        subsystems_hunted=1,
        subsystem_spent_usd=0.5,
    )
    options = {"depth": "standard", "model": "test-model"}

    store.save(
        result,
        status="completed",
        ranked_targets_digest="ranked-sha",
        options=options,
    )
    restored = store.load(
        ranked_targets_digest="ranked-sha",
        options=options,
    )

    assert restored is not None
    assert isinstance(restored.findings[0], Finding)
    assert restored.findings[0].id == "f-test"
    assert restored.files_hunted == 3
    assert store.last_status == "completed"


def test_hunt_checkpoint_restores_budget_exhausted_terminal_state(tmp_path: Path):
    store = HuntCheckpointStore(tmp_path / "sh-test", "sh-test")
    result = HuntResult(
        findings=[Finding(id="f-partial", file="sample.c")],
        files_hunted=1,
        spent_per_tier={"A": 2.0, "B": 0.0, "C": 0.0},
    )

    store.save(
        result,
        status="budget_exhausted",
        ranked_targets_digest="ranked-sha",
        options={},
    )

    assert store.load(ranked_targets_digest="ranked-sha", options={}) is not None
    assert store.last_status == "budget_exhausted"


def test_hunt_checkpoint_rejects_changed_rank_or_options(tmp_path: Path):
    store = HuntCheckpointStore(tmp_path / "sh-test", "sh-test")
    result = HuntResult(
        findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
    )
    store.save(
        result,
        status="completed",
        ranked_targets_digest="ranked-sha",
        options={"depth": "standard"},
    )

    assert (
        store.load(
            ranked_targets_digest="changed",
            options={"depth": "standard"},
        )
        is None
    )
    assert (
        store.load(
            ranked_targets_digest="ranked-sha",
            options={"depth": "deep"},
        )
        is None
    )


def test_findings_pool_restore_completed_does_not_append_checkpoint(tmp_path: Path):
    checkpoint = tmp_path / "findings.jsonl"
    pool = FindingsPool(checkpoint_path=checkpoint)
    finding = Finding(
        id="f-test",
        file="sample.c",
        description="restored",
        primitive_type="memory_corruption",
        cluster_id="cluster-1",
    )

    pool.restore_completed([finding])

    assert pool.all_findings() == [finding]
    assert pool.clusters()[0].finding_ids == ["f-test"]
    assert not checkpoint.exists()


def test_runner_uses_resume_session_id(tmp_path: Path):
    (tmp_path / "sh-existing").mkdir()
    runner = SourceHuntRunner(
        repo_url="repo",
        output_dir=str(tmp_path),
        resume_session_id="sh-existing",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    assert runner.session_id == "sh-existing"


def test_runner_restores_preprocess_checkpoint(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    first = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        parent_session_id="sh-resume",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )
    original = first._preprocess()

    resumed = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        resume_session_id="sh-resume",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("preprocessor ran instead of restoring the checkpoint")

    monkeypatch.setattr("clearwing.sourcehunt.preprocessor.Preprocessor.run", fail_if_called)
    restored = resumed._preprocess()

    assert resumed._preprocess_restored is True
    assert restored.file_targets == original.file_targets


def test_runner_rejects_unsafe_resume_session_id():
    try:
        SourceHuntRunner(repo_url="repo", resume_session_id="../outside")
    except ValueError as exc:
        assert "invalid characters" in str(exc)
    else:
        raise AssertionError("unsafe resume session ID was accepted")


def test_runner_rejects_missing_resume_session(tmp_path: Path):
    try:
        SourceHuntRunner(
            repo_url="repo",
            output_dir=str(tmp_path),
            resume_session_id="sh-missing",
            enable_mechanism_memory=False,
            enable_calibration=False,
        )
    except ValueError as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("missing resume session was accepted")


def test_runner_resumes_at_end_of_hunt_without_starting_hunters(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    output = tmp_path / "results"
    common = {
        "repo_url": str(repo),
        "local_path": str(repo),
        "output_dir": str(output),
        "depth": "standard",
        "no_rank": True,
        "no_verify": True,
        "no_exploit": True,
        "enable_findings_pool": False,
        "enable_mechanism_memory": False,
        "enable_calibration": False,
        "enable_behavior_monitor": False,
        "enable_variant_loop": False,
        "enable_knowledge_graph": False,
    }
    first = SourceHuntRunner(parent_session_id="sh-resume-hunt", **common)
    preprocessed = first._preprocess()
    for target in preprocessed.file_targets:
        target["surface"] = 3
        target["influence"] = 2
        target["reachability"] = 3
        target["priority"] = 2.8
    HuntCheckpointStore(
        output / "sh-resume-hunt", "sh-resume-hunt"
    ).save(
        HuntResult(
            findings=[Finding(id="f-restored", file="sample.c")],
            files_hunted=1,
            spent_per_tier={"A": 1.0, "B": 0.0, "C": 0.0},
        ),
        status="budget_exhausted",
        ranked_targets_digest=ranked_targets_digest(preprocessed.file_targets),
        options=first._hunt_checkpoint_options(),
    )

    resumed = SourceHuntRunner(resume_session_id="sh-resume-hunt", **common)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("hunt setup ran instead of restoring its checkpoint")

    monkeypatch.setattr(resumed, "_ensure_sandbox_factory", fail_if_called)
    result = resumed.run()

    assert [finding.id for finding in result.findings] == ["f-restored"]
    assert result.files_hunted == 1
