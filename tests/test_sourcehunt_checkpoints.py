from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from clearwing.analysis.source_analyzer import AnalyzerFinding
from clearwing.sourcehunt.callgraph import CallGraph, FunctionInfo
from clearwing.sourcehunt.checkpoints import (
    ExploitationCheckpoint,
    ExploitationResult,
    HuntCheckpoint,
    HuntResult,
    PreprocessCheckpoint,
    RankCheckpoint,
    SourceHuntCheckpoint,
    VerificationCheckpoint,
    VerificationResult,
    checkpoint_digest,
    portable_file_targets,
    portable_findings,
)
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.state import Finding, PipelineStatus, StageOutcome
from clearwing.sourcehunt.taint import TaintPath

OPTIONS = {
    "tag_files": True,
    "build_callgraph": False,
    "propagate_reachability": False,
    "run_semgrep": False,
    "run_taint": False,
    "respect_gitignore": False,
    "subsystem_paths": [],
}


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


def _commit(repo: Path, message: str = "checkpoint test") -> str:
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Clearwing Tests",
            "-c",
            "user.email=tests@clearwing.local",
            "commit",
            "-qm",
            message,
        ],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_preprocess_result_round_trips_nested_types(tmp_path: Path):
    result = _result(tmp_path)

    restored = PreprocessResult.model_validate_json(result.model_dump_json())

    assert isinstance(restored.file_targets[0], dict)
    assert isinstance(restored.static_findings[0], AnalyzerFinding)
    assert isinstance(restored.callgraph, CallGraph)
    assert isinstance(restored.callgraph.function_info["sample.c"][0], FunctionInfo)
    assert isinstance(restored.taint_paths[0], TaintPath)
    assert restored.callgraph.functions["sample.c"] == {"parse"}
    assert restored == result


def test_preprocess_checkpoint_trusts_current_source_and_rebinds_paths(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    commit_sha = _commit(repo)
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    assert checkpoint.commit_sha == commit_sha
    assert checkpoint.result["static_findings"][0]["file_path"] == "sample.c"

    restored = checkpoint.restore(repo_path=str(repo), options=OPTIONS)
    assert restored is not None
    assert restored.repo_path == str(repo.resolve())
    assert restored.file_targets[0]["absolute_path"] == str(source.resolve())
    assert restored.static_findings[0].file_path == str(source.resolve())

    source.write_text("int sample(void) { return 2; }\n", encoding="utf-8")
    assert checkpoint.restore(repo_path=str(repo), options=OPTIONS) is not None


def test_preprocess_checkpoint_rebinds_static_findings_to_a_new_checkout(tmp_path: Path):
    first_repo = tmp_path / "first"
    first_repo.mkdir()
    first_source = first_repo / "sample.c"
    first_source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    _commit(first_repo)
    result = _result(first_repo)
    result.static_findings[0].file_path = str(first_source.resolve())
    checkpoint = PreprocessCheckpoint.from_result(result, options=OPTIONS)

    second_repo = tmp_path / "second"
    subprocess.run(["git", "clone", "-q", str(first_repo), str(second_repo)], check=True)
    restored = checkpoint.restore(repo_path=str(second_repo), options=OPTIONS)

    assert restored is not None
    assert checkpoint.result["static_findings"][0]["file_path"] == "sample.c"
    assert restored.static_findings[0].file_path == str((second_repo / "sample.c").resolve())


def test_preprocess_checkpoint_rejects_different_commit(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    _commit(repo)
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)

    source.write_text("int sample(void) { return 2; }\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "sample.c"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Clearwing Tests",
            "-c",
            "user.email=tests@clearwing.local",
            "commit",
            "-qm",
            "source changed",
        ],
        check=True,
    )

    assert checkpoint.restore(repo_path=str(repo), options=OPTIONS) is None


def test_preprocess_checkpoint_rejects_corrupt_payload(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    payload = SourceHuntCheckpoint(preprocess=checkpoint).model_dump_json()
    payload = payload.replace('"schema_version":2', '"schema_version":999', 1)
    try:
        SourceHuntCheckpoint.from_input(payload)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid checkpoint schema was accepted")


def test_checkpoint_is_one_self_contained_json_blob(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    raw = checkpoint.model_dump_json()
    assert str(repo) not in raw
    assert "absolute_path" not in raw
    restored = PreprocessCheckpoint.model_validate_json(raw)
    assert restored.result["file_targets"][0]["path"] == "sample.c"
    assert restored.options == OPTIONS


def test_sourcehunt_checkpoint_rejects_flat_phase_payload(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)

    with pytest.raises(ValueError):
        SourceHuntCheckpoint.from_input(checkpoint.model_dump(mode="json"))


def test_sourcehunt_checkpoint_preserves_checkpoint_instance():
    checkpoint = SourceHuntCheckpoint()

    assert SourceHuntCheckpoint.from_input(checkpoint) is checkpoint


def test_preprocess_checkpoint_rejects_different_options(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    result = _result(repo)
    _commit(repo)
    checkpoint = PreprocessCheckpoint.from_result(result, options=OPTIONS)

    assert (
        checkpoint.restore(
            repo_path=str(repo),
            options={**OPTIONS, "run_semgrep": True},
        )
        is None
    )


def test_preprocess_checkpoint_rejects_path_traversal(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    outside = tmp_path / "outside.c"
    outside.write_text("int outside(void);\n", encoding="utf-8")
    result = _result(repo)
    result.file_targets[0]["path"] = "../outside.c"
    checkpoint = PreprocessCheckpoint.from_result(result, options=OPTIONS)

    assert checkpoint.restore(repo_path=str(repo), options=OPTIONS) is None


def test_runner_restores_preprocess_checkpoint(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
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
    checkpoint_blob = first._checkpoint.model_dump_json()

    resumed = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        checkpoint=checkpoint_blob,
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("preprocessor ran instead of restoring the checkpoint")

    monkeypatch.setattr("clearwing.sourcehunt.preprocessor.Preprocessor.run", fail_if_called)
    restored = resumed._preprocess()

    assert resumed._preprocess_restored is True
    assert restored.file_targets == original.file_targets


def test_runner_accepts_checkpoint_as_json_object(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    first = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "first"),
        depth="quick",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )
    first._preprocess()
    checkpoint = first._checkpoint.model_dump(mode="json")

    resumed = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "second"),
        depth="quick",
        checkpoint=checkpoint,
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    assert resumed._preprocess().file_targets[0]["path"] == "sample.c"
    assert resumed._preprocess_restored is True


def test_runner_rejects_incompatible_preprocess_checkpoint(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    checkpoint.commit_sha = "0" * 40
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        checkpoint=SourceHuntCheckpoint(preprocess=checkpoint).model_dump(mode="json"),
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    with pytest.raises(ValueError, match="checkpoint is invalid or incompatible"):
        runner._preprocess()


@pytest.mark.asyncio
async def test_runner_checkpoints_and_restores_ranking(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    first = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "first"),
        depth="quick",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )
    monkeypatch.setattr(first, "_get_native_client", lambda *args, **kwargs: None)
    preprocessed = first._preprocess()
    ranked = await first._rank(
        preprocessed.file_targets,
        PipelineStatus(),
        ["sample.c"],
    )

    assert isinstance(first._checkpoint, SourceHuntCheckpoint)
    assert isinstance(first._checkpoint.rank, RankCheckpoint)
    assert ranked[0]["priority"] == pytest.approx(2.8)
    assert "absolute_path" not in first._checkpoint.rank.ranked_file_targets[0]

    resumed = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "resumed"),
        depth="quick",
        checkpoint=first._checkpoint.model_dump(mode="json"),
        enable_mechanism_memory=False,
        enable_calibration=False,
    )
    restored_preprocess = resumed._preprocess()

    def fail_if_called(*args, **kwargs):
        raise AssertionError("ranker client resolved instead of restoring the checkpoint")

    monkeypatch.setattr(resumed, "_get_native_client", fail_if_called)
    restored = await resumed._rank(
        restored_preprocess.file_targets,
        PipelineStatus(),
        ["sample.c"],
    )

    assert resumed._rank_restored is True
    assert restored == ranked


@pytest.mark.asyncio
async def test_runner_restores_independent_stage_payloads(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    preprocess = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    ranked = [{"path": "sample.c", "priority": 4.2}]
    rank = RankCheckpoint.from_result(
        ranked,
        options={"preprocessing": True},
        input_digest=checkpoint_digest([{"path": "sample.c"}]),
    )
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        checkpoint={
            "schema_version": 2,
            "preprocess": preprocess.model_dump(mode="json"),
            "rank": rank.model_dump(mode="json"),
        },
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    restored_preprocess = runner._preprocess()
    monkeypatch.setattr(
        runner,
        "_get_native_client",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("ranker called")),
    )
    restored_rank = await runner._rank(
        restored_preprocess.file_targets,
        PipelineStatus(),
        ["sample.c"],
    )

    assert runner._preprocess_restored is True
    assert runner._rank_restored is True
    assert restored_rank[0]["priority"] == pytest.approx(4.2)


def test_no_rank_bypasses_ranking_and_exposes_preprocess_checkpoint(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        no_rank=True,
        enable_mechanism_memory=False,
        enable_calibration=False,
        enable_knowledge_graph=False,
    )

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("_rank ran despite --no-rank")

    monkeypatch.setattr(runner, "_rank", fail_if_called)

    result = runner.run()

    assert result.checkpoint is not None
    assert result.checkpoint["preprocess"]["result"]["file_targets"][0]["path"] == "sample.c"
    assert result.checkpoint["rank"] is None
    assert "checkpoint" not in result.output_paths


def test_runner_rejects_invalid_checkpoint_json():
    try:
        SourceHuntRunner(repo_url="repo", checkpoint="not-json")
    except ValueError as exc:
        assert "json" in str(exc).lower()
    else:
        raise AssertionError("invalid checkpoint JSON was accepted")


@pytest.mark.asyncio
async def test_runner_checkpoints_and_restores_hunt(tmp_path: Path, monkeypatch):
    first = SourceHuntRunner(
        repo_url=str(tmp_path),
        output_dir=str(tmp_path),
        enable_mechanism_memory=False,
        enable_subsystem_hunt=True,
    )
    first._checkpoint = SourceHuntCheckpoint()
    monkeypatch.setattr(first, "_get_native_client", lambda *args, **kwargs: None)

    async def complete_subsystem_hunt(result, **kwargs):
        result.findings.append(Finding(id="subsystem-1", file="sample.c", severity="high"))
        result.subsystems_hunted = 1
        result.subsystem_spent_usd = 1.25
        result.subsystem_status = "completed"
        result.status = "completed"

    monkeypatch.setattr(first, "_hunt_subsystems", complete_subsystem_hunt)
    seeded_by_file = {
        "sample.c": {
            "report": "original harness report",
            "target_function": "sample",
            "harness_source": "int fuzz(void);",
        }
    }
    mechanism_hints_by_file = {
        "sample.c": [{"source": "mechanism_memory", "description": "original hint"}]
    }
    result = await first._hunt(
        files=[],
        repo_path=str(tmp_path),
        pipeline_status=PipelineStatus(),
        stage_files=[],
        seeded_by_file=seeded_by_file,
        semgrep_hints_by_file=mechanism_hints_by_file,
        entry_points_by_file={},
        seed_corpus_by_file={},
        findings_pool=None,
        callgraph=None,
        resume_inputs={
            "seeded_by_file": seeded_by_file,
            "mechanism_hints_by_file": mechanism_hints_by_file,
        },
    )
    assert isinstance(first._checkpoint.hunt, HuntCheckpoint)
    assert first._checkpoint.hunt.result.subsystems_hunted == 1
    assert first._checkpoint.hunt.result.subsystem_spent_usd == pytest.approx(1.25)
    assert first._checkpoint.hunt.result.subsystem_status == "completed"
    assert first._checkpoint.hunt.result.findings[0].id == "subsystem-1"
    assert first._checkpoint.hunt.resume_inputs["seeded_by_file"] == seeded_by_file
    assert (
        first._checkpoint.hunt.resume_inputs["mechanism_hints_by_file"]
        == mechanism_hints_by_file
    )

    result.findings.append(Finding(id="finding-1", file="sample.c", severity="high"))
    first._checkpoint.hunt = HuntCheckpoint.from_result(
        result,
        options=first._checkpoint.hunt.options,
        input_digest=first._checkpoint.hunt.input_digest,
        resume_inputs=first._checkpoint.hunt.resume_inputs,
    )
    resumed = SourceHuntRunner(
        repo_url=str(tmp_path),
        output_dir=str(tmp_path),
        checkpoint=first._checkpoint.model_dump(mode="json"),
        enable_mechanism_memory=False,
        enable_subsystem_hunt=True,
    )
    monkeypatch.setattr(
        resumed,
        "_get_native_client",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("hunter called")),
    )
    monkeypatch.setattr(
        resumed,
        "_hunt_subsystems",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("subsystem hunt ran")),
    )
    restored_pipeline = PipelineStatus()
    restored = await resumed._hunt(
        files=[],
        repo_path=str(tmp_path),
        pipeline_status=restored_pipeline,
        stage_files=[],
        seeded_by_file=seeded_by_file,
        semgrep_hints_by_file=mechanism_hints_by_file,
        entry_points_by_file={},
        seed_corpus_by_file={},
        findings_pool=None,
        callgraph=None,
    )
    assert resumed._hunt_restored is True
    assert [finding.id for finding in restored.findings] == ["subsystem-1", "finding-1"]
    assert restored.subsystems_hunted == 1
    assert restored.per_file_status == "skipped"
    assert restored.subsystem_status == "completed"
    assert restored_pipeline.stages["hunter_pool"].outcome is StageOutcome.SKIPPED
    assert (
        restored_pipeline.stages["hunter_pool"].fallback_description
        == "Hunting was intentionally skipped"
    )
    assert restored_pipeline.stages["subsystem_hunt"].outcome is StageOutcome.SUCCEEDED


def test_static_finding_digest_is_stable_across_sessions(tmp_path: Path):
    source = tmp_path / "sample.c"
    source.write_text("int sample(void);\n", encoding="utf-8")
    preprocessed = _result(tmp_path)
    preprocessed.static_findings[0].file_path = str(source.resolve())
    first = SourceHuntRunner(
        repo_url=str(tmp_path),
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "first"),
        enable_mechanism_memory=False,
    )
    second = SourceHuntRunner(
        repo_url=str(tmp_path),
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "second"),
        enable_mechanism_memory=False,
    )

    first_findings = first._merge_static_findings([], preprocessed)
    second_findings = second._merge_static_findings([], preprocessed)

    assert first_findings[0].id != second_findings[0].id
    assert (
        first_findings[0].extra["stable_finding_id"]
        == second_findings[0].extra["stable_finding_id"]
    )
    assert checkpoint_digest(portable_findings(first_findings)) == checkpoint_digest(
        portable_findings(second_findings)
    )


def test_hunt_checkpoint_rejects_different_options():
    checkpoint = HuntCheckpoint.from_result(
        HuntResult(findings=[], spent_per_tier={}),
        options={"agent_mode": "auto"},
        input_digest="hunt-input",
    )
    assert checkpoint.restore(options={"agent_mode": "deep"}, input_digest="hunt-input") is None


def test_hunt_checkpoint_preserves_subsystem_terminal_status():
    checkpoint = HuntCheckpoint.from_result(
        HuntResult(
            findings=[],
            spent_per_tier={},
            status="budget_exhausted",
            per_file_status="skipped",
            subsystems_hunted=1,
            subsystem_status="budget_exhausted",
        ),
        options={},
        input_digest="hunt-input",
    )

    restored = checkpoint.restore(options={}, input_digest="hunt-input")

    assert restored is not None
    assert restored.status == "budget_exhausted"
    assert restored.per_file_status == "skipped"
    assert restored.subsystem_status == "budget_exhausted"


@pytest.mark.asyncio
async def test_runner_checkpoints_and_restores_verification(tmp_path: Path, monkeypatch):
    finding = Finding(id="finding-1", file="sample.c", severity="high")
    first = SourceHuntRunner(
        repo_url=str(tmp_path), output_dir=str(tmp_path), enable_mechanism_memory=False
    )
    first._checkpoint = SourceHuntCheckpoint()
    monkeypatch.setattr(first, "_get_native_client", lambda *args, **kwargs: None)
    result = await first._verify(
        [finding], repo_path=str(tmp_path), pipeline_status=PipelineStatus()
    )
    assert isinstance(first._checkpoint.verification, VerificationCheckpoint)
    assert result.verified[0].id == "finding-1"

    resumed = SourceHuntRunner(
        repo_url=str(tmp_path),
        output_dir=str(tmp_path),
        checkpoint=first._checkpoint.model_dump(mode="json"),
        enable_mechanism_memory=False,
    )
    monkeypatch.setattr(
        resumed,
        "_get_native_client",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("verifier called")),
    )
    restored = await resumed._verify(
        [Finding(id="finding-1", file="sample.c", severity="high")],
        repo_path=str(tmp_path),
        pipeline_status=PipelineStatus(),
    )
    assert resumed._verification_restored is True
    assert restored.verified[0].id == "finding-1"
    assert restored.status == "degraded"

    with pytest.raises(ValueError, match="verification checkpoint is invalid"):
        await resumed._verify(
            [Finding(id="different-finding", file="different.c", severity="high")],
            repo_path=str(tmp_path),
            pipeline_status=PipelineStatus(),
        )


def test_verification_checkpoint_rejects_different_options():
    checkpoint = VerificationCheckpoint.from_result(
        VerificationResult(verified=[], rejected=[]),
        options={"validator_mode": "v2"},
        input_digest="verification-input",
    )
    assert (
        checkpoint.restore(options={"validator_mode": "v1"}, input_digest="verification-input")
        is None
    )


@pytest.mark.asyncio
async def test_runner_checkpoints_and_restores_exploitation(tmp_path: Path, monkeypatch):
    finding = Finding(
        id="finding-1", file="sample.c", severity="high", evidence_level="crash_reproduced"
    )
    first = SourceHuntRunner(
        repo_url=str(tmp_path), output_dir=str(tmp_path), enable_mechanism_memory=False
    )
    first._checkpoint = SourceHuntCheckpoint()
    monkeypatch.setattr(first, "_get_native_client", lambda *args, **kwargs: None)
    result = await first._exploit([finding], findings_pool=None)
    assert isinstance(first._checkpoint.exploitation, ExploitationCheckpoint)
    assert result.verified[0].id == "finding-1"
    assert first._checkpoint.exploitation.resume_verified[0].id == "finding-1"

    saved = ExploitationResult(verified=[finding], exploited=[finding])
    supplemental = [
        Finding(
            id="variant-1",
            file="sample.c",
            severity="medium",
            extra={"stable_finding_id": "variant-stable"},
        )
    ]
    supplemental[0]["stability_classification"] = "unreliable"
    supplemental[0]["stability_success_rate"] = 0.0
    first._checkpoint.exploitation = ExploitationCheckpoint.from_result(
        saved,
        options=first._checkpoint.exploitation.options,
        input_digest=first._checkpoint.exploitation.input_digest,
        resume_verified=[finding],
        resume_all_findings=[finding, *supplemental],
    )
    resumed = SourceHuntRunner(
        repo_url=str(tmp_path),
        output_dir=str(tmp_path),
        checkpoint=first._checkpoint.model_dump(mode="json"),
        enable_mechanism_memory=False,
    )
    monkeypatch.setattr(
        resumed,
        "_get_native_client",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("exploiter called")),
    )
    restored = await resumed._exploit([finding], findings_pool=None)
    assert resumed._exploitation_restored is True
    assert restored.exploited[0].id == "finding-1"
    assert resumed._checkpoint.exploitation.resume_verified[0].id == "finding-1"
    assert (
        resumed._checkpoint.exploitation.resume_all_findings[1].id == "variant-1"
    )
    assert (
        resumed._checkpoint.exploitation.resume_all_findings[1]["stability_classification"]
        == "unreliable"
    )


def test_exploitation_checkpoint_rejects_different_options():
    checkpoint = ExploitationCheckpoint.from_result(
        ExploitationResult(verified=[], exploited=[]),
        options={
            "no_exploit": False,
            "enable_stability_verification": True,
            "enable_variant_loop": True,
        },
        input_digest="exploitation-input",
    )
    assert (
        checkpoint.restore(
            options={
                "no_exploit": False,
                "enable_stability_verification": False,
                "enable_variant_loop": True,
            },
            input_digest="exploitation-input",
        )
        is None
    )


STAGE_STATUSES = ("completed", "skipped", "budget_exhausted", "degraded")


def _finding(path: str | None = "src/sample.c") -> Finding:
    return Finding(
        id="finding-1",
        file=path,
        description="original",
        vulnerability_trace={"steps": [{"file": "src/sample.c", "line": 3, "function": "parse"}]},
    )


def _stage_checkpoint(
    stage: str,
    finding: Finding,
    *,
    status: str = "completed",
    input_digest: str = "input-a",
) -> HuntCheckpoint | VerificationCheckpoint | ExploitationCheckpoint:
    if stage == "hunt":
        result = HuntResult(findings=[finding], spent_per_tier={}, status=status)
        return HuntCheckpoint.from_result(result, options={}, input_digest=input_digest)
    if stage == "verification":
        result = VerificationResult(verified=[finding], rejected=[finding], status=status)
        return VerificationCheckpoint.from_result(result, options={}, input_digest=input_digest)
    result = ExploitationResult(verified=[finding], exploited=[finding], status=status)
    return ExploitationCheckpoint.from_result(result, options={}, input_digest=input_digest)


@pytest.mark.parametrize("stage", ["hunt", "verification", "exploitation"])
@pytest.mark.parametrize("status", STAGE_STATUSES)
def test_stage_checkpoint_preserves_every_explicit_status(stage: str, status: str):
    checkpoint = _stage_checkpoint(stage, _finding(), status=status)

    restored = checkpoint.restore(options={}, input_digest="input-a")

    assert restored is not None
    assert restored.status == status


@pytest.mark.parametrize("stage", ["hunt", "verification", "exploitation"])
def test_stage_checkpoint_binds_exact_input(stage: str):
    checkpoint = _stage_checkpoint(stage, _finding())

    assert checkpoint.restore(options={}, input_digest="input-b") is None


def test_rank_checkpoint_binds_exact_input_and_copies_nested_values(tmp_path: Path):
    inputs: list[dict[str, Any]] = [
        {
            "path": "sample.c",
            "absolute_path": str(tmp_path / "sample.c"),
            "loc": 4,
            "tags": ["parser"],
        }
    ]
    ranked = [{**inputs[0], "priority": 4.2}]
    input_digest = checkpoint_digest(portable_file_targets(inputs))
    checkpoint = RankCheckpoint.from_result(
        ranked,
        options={"preprocessing": True},
        input_digest=input_digest,
    )
    ranked[0]["tags"].append("mutated")

    assert (
        checkpoint.restore(
            inputs,
            options={"preprocessing": True},
            input_digest="different-input",
        )
        is None
    )
    restored = checkpoint.restore(
        inputs,
        options={"preprocessing": True},
        input_digest=input_digest,
    )
    assert restored is not None
    assert restored[0]["tags"] == ["parser"]
    assert restored[0]["absolute_path"] == str(tmp_path / "sample.c")
    restored[0]["tags"].append("restore-mutation")
    assert checkpoint.ranked_file_targets[0]["tags"] == ["parser"]


@pytest.mark.parametrize("stage", ["hunt", "verification", "exploitation"])
def test_stage_checkpoint_snapshots_are_deep_copied(stage: str):
    finding = _finding()
    checkpoint = _stage_checkpoint(stage, finding)
    finding.description = "live mutation"
    finding.vulnerability_trace["steps"][0]["file"] = "src/live-mutation.c"

    restored = checkpoint.restore(options={}, input_digest="input-a")
    assert restored is not None
    saved = restored.findings[0] if isinstance(restored, HuntResult) else restored.verified[0]
    assert saved.description == "original"
    assert saved.vulnerability_trace["steps"][0]["file"] == "src/sample.c"

    saved.description = "restore mutation"
    checkpoint_saved = (
        checkpoint.result.findings[0]
        if isinstance(checkpoint.result, HuntResult)
        else checkpoint.result.verified[0]
    )
    assert checkpoint_saved.description == "original"


@pytest.mark.parametrize("stage", ["hunt", "verification", "exploitation"])
@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../secret.c",
        "src/../../secret.c",
        r"src\..\secret.c",
        r"C:\secret.c",
        r"\\server\share\secret.c",
        r"\rooted\secret.c",
        "src/evil\x00.c",
    ],
)
def test_checkpoint_rejects_nonportable_finding_paths(stage: str, path: str):
    with pytest.raises(ValueError, match="finding.file"):
        _stage_checkpoint(stage, _finding(path))


@pytest.mark.parametrize("stage", ["hunt", "verification", "exploitation"])
@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "../secret.c", r"src\..\secret.c", r"C:\secret.c", "bad\x00.c"],
)
def test_checkpoint_rejects_nonportable_trace_step_paths(stage: str, path: str):
    finding = _finding()
    finding.vulnerability_trace["steps"][0]["file"] = path

    with pytest.raises(ValueError, match="vulnerability_trace"):
        _stage_checkpoint(stage, finding)


@pytest.mark.parametrize("path", [None, ""])
def test_checkpoint_allows_findings_without_source_paths(path: str | None):
    checkpoint = _stage_checkpoint("hunt", _finding(path))

    assert isinstance(checkpoint, HuntCheckpoint)
    assert checkpoint.result.findings[0].file == path


def test_exploitation_checkpoint_strips_transcript_path_without_mutating_live_result():
    finding = _finding()
    finding.extra["exploit_transcript_path"] = "/tmp/worker/transcript.jsonl"
    finding.extra["portable"] = "kept"
    result = ExploitationResult(verified=[finding], exploited=[finding])

    checkpoint = ExploitationCheckpoint.from_result(
        result,
        options={},
        input_digest="input-a",
    )
    restored = checkpoint.restore(options={}, input_digest="input-a")

    assert finding.extra["exploit_transcript_path"] == "/tmp/worker/transcript.jsonl"
    assert "exploit_transcript_path" not in checkpoint.result.verified[0].extra
    assert restored is not None
    assert "exploit_transcript_path" not in restored.exploited[0].extra
    assert restored.exploited[0].extra["portable"] == "kept"


def test_static_finding_digest_uses_stable_id_after_serialization():
    first = Finding(
        id="static-random-a",
        file="sample.c",
        discovered_by="source_analyzer",
        extra={"stable_finding_id": "static-stable"},
    )
    second = Finding(
        id="static-random-b",
        file="sample.c",
        discovered_by="source_analyzer",
        extra={"stable_finding_id": "static-stable"},
    )

    checkpoint = HuntCheckpoint.from_result(
        HuntResult(findings=[first], spent_per_tier={}),
        options={},
        input_digest=checkpoint_digest(portable_findings([first])),
    )
    resumed = HuntCheckpoint.model_validate_json(checkpoint.model_dump_json())

    assert resumed.input_digest == checkpoint_digest(portable_findings([second]))
