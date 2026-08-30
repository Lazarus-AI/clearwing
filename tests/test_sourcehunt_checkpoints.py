from __future__ import annotations

import subprocess
from pathlib import Path

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
)
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.state import Finding, PipelineStatus
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


def test_hunt_checkpoint_round_trips_unresolved_potentials() -> None:
    potentials = [
        {
            "id": "lead-1",
            "file": "sample.c",
            "line": 2,
            "note": "unchecked length",
            "hypothesis": "CWE-787",
            "priority": "high",
        }
    ]
    result = HuntResult(
        findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        potentials=potentials,
    )
    checkpoint = HuntCheckpoint.from_result(result, options={"depth": "deep"})

    restored = HuntCheckpoint.model_validate_json(checkpoint.model_dump_json()).restore(
        options={"depth": "deep"}
    )

    assert restored is not None
    assert restored.potentials == potentials
    restored.potentials[0]["note"] = "changed"
    assert checkpoint.result.potentials[0]["note"] == "unchecked length"


def test_preprocess_checkpoint_trusts_current_source_and_rebinds_paths(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    commit_sha = _commit(repo)
    checkpoint = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    assert checkpoint.commit_sha == commit_sha

    restored = checkpoint.restore(repo_path=str(repo), options=OPTIONS)
    assert restored is not None
    assert restored.repo_path == str(repo.resolve())
    assert restored.file_targets[0]["absolute_path"] == str(source.resolve())

    source.write_text("int sample(void) { return 2; }\n", encoding="utf-8")
    assert checkpoint.restore(repo_path=str(repo), options=OPTIONS) is not None


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
    payload = payload.replace('"schema_version":1', '"schema_version":999', 1)
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


def test_sourcehunt_checkpoint_dumps_one_atomic_aggregate_file(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    preprocess = PreprocessCheckpoint.from_result(_result(repo), options=OPTIONS)
    checkpoint = SourceHuntCheckpoint(preprocess=preprocess)
    target = tmp_path / "workspace" / "sourcehunt" / "pipeline" / "checkpoint.json"

    assert checkpoint.dump(target) == target
    restored = SourceHuntCheckpoint.model_validate_json(target.read_text(encoding="utf-8"))
    assert restored.preprocess == preprocess
    assert restored.rank is None

    checkpoint.rank = RankCheckpoint.from_result(
        [{"path": "sample.c", "priority": 4.2}], options={"preprocessing": True}
    )
    checkpoint.dump(target)
    restored = SourceHuntCheckpoint.model_validate_json(target.read_text(encoding="utf-8"))
    assert restored.rank == checkpoint.rank
    assert list(target.parent.glob("*.tmp")) == []


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
    checkpoint_path = tmp_path / "results" / "sh-resume" / "checkpoint.json"
    assert (
        SourceHuntCheckpoint.model_validate_json(checkpoint_path.read_text(encoding="utf-8"))
        == first._checkpoint
    )

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


def test_runner_loads_and_updates_bridge_checkpoint_path(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    checkpoint_path = tmp_path / "workspace" / "pipeline" / "checkpoint.json"
    output_dir = tmp_path / "workspace" / "sourcehunt"
    first = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(output_dir),
        parent_session_id="bridge-session",
        checkpoint_path=checkpoint_path,
        depth="quick",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    original = first._preprocess()

    assert checkpoint_path.is_file()
    assert not (output_dir / "bridge-session" / "checkpoint.json").exists()
    resumed = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(output_dir),
        parent_session_id="another-session",
        checkpoint_path=checkpoint_path,
        depth="quick",
        enable_mechanism_memory=False,
        enable_calibration=False,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("preprocessor ran instead of loading checkpoint_path")

    monkeypatch.setattr("clearwing.sourcehunt.preprocessor.Preprocessor.run", fail_if_called)
    restored = resumed._preprocess()

    assert resumed._preprocess_restored is True
    assert restored.file_targets == original.file_targets


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
    )
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        depth="quick",
        checkpoint={
            "schema_version": 1,
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

    monkeypatch.setattr(first, "_hunt_subsystems", complete_subsystem_hunt)
    result = await first._hunt(
        files=[],
        repo_path=str(tmp_path),
        pipeline_status=PipelineStatus(),
        stage_files=[],
        seeded_by_file={},
        semgrep_hints_by_file={},
        entry_points_by_file={},
        seed_corpus_by_file={},
        findings_pool=None,
        callgraph=None,
    )
    assert isinstance(first._checkpoint.hunt, HuntCheckpoint)
    assert first._checkpoint.hunt.result.subsystems_hunted == 1
    assert first._checkpoint.hunt.result.subsystem_spent_usd == pytest.approx(1.25)
    assert first._checkpoint.hunt.result.findings[0].id == "subsystem-1"

    result.findings.append(Finding(id="finding-1", file="sample.c", severity="high"))
    first._checkpoint.hunt = HuntCheckpoint.from_result(
        result,
        options=first._checkpoint.hunt.options,
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
    restored = await resumed._hunt(
        files=[],
        repo_path=str(tmp_path),
        pipeline_status=PipelineStatus(),
        stage_files=[],
        seeded_by_file={},
        semgrep_hints_by_file={},
        entry_points_by_file={},
        seed_corpus_by_file={},
        findings_pool=None,
        callgraph=None,
    )
    assert resumed._hunt_restored is True
    assert [finding.id for finding in restored.findings] == ["subsystem-1", "finding-1"]
    assert restored.subsystems_hunted == 1


def test_hunt_checkpoint_rejects_different_options():
    checkpoint = HuntCheckpoint.from_result(
        HuntResult(findings=[], spent_per_tier={}), options={"agent_mode": "auto"}
    )
    assert checkpoint.restore(options={"agent_mode": "deep"}) is None


def test_hunt_checkpoint_preserves_subsystem_budget_exhaustion():
    checkpoint = HuntCheckpoint.from_result(
        HuntResult(
            findings=[],
            spent_per_tier={},
            subsystem_status="budget_exhausted",
        ),
        options={},
    )

    restored = checkpoint.restore(options={})

    assert restored is not None
    assert restored.subsystem_status == "budget_exhausted"


def test_legacy_hunt_checkpoint_defaults_subsystem_status_to_completed():
    checkpoint = HuntCheckpoint.model_validate(
        {
            "schema_version": 1,
            "options": {},
            "result": {
                "findings": [],
                "spent_per_tier": {},
                "subsystems_hunted": 1,
            },
        }
    )

    restored = checkpoint.restore(options={})

    assert restored is not None
    assert restored.subsystem_status == "completed"


def test_stop_after_hunt_returns_accumulated_hunt_result(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        stop_after="hunt",
        no_rank=True,
        enable_mechanism_memory=False,
        enable_calibration=False,
        enable_knowledge_graph=False,
        enable_subsystem_hunt=False,
    )
    monkeypatch.setattr(runner, "_ensure_sandbox_factory", lambda *args, **kwargs: None)

    hunt_finding = Finding(id="hunt-1", file="sample.c", severity="high")

    async def fake_hunt(**kwargs):
        return HuntResult(
            findings=[hunt_finding],
            files_hunted=1,
            spent_per_tier={"A": 1.25, "B": 0.0, "C": 0.0},
        )

    monkeypatch.setattr(runner, "_hunt", fake_hunt)

    result = runner.run()

    assert [finding.id for finding in result.findings] == ["hunt-1"]
    assert result.verified_findings == []
    assert result.exploited_findings == []
    assert result.files_hunted == 1
    assert result.spent_per_tier == {"A": 1.25, "B": 0.0, "C": 0.0}


def test_stop_after_verify_returns_accumulated_verification_result(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(tmp_path / "results"),
        stop_after="verify",
        no_rank=True,
        enable_mechanism_memory=False,
        enable_calibration=False,
        enable_knowledge_graph=False,
        enable_subsystem_hunt=False,
    )
    monkeypatch.setattr(runner, "_ensure_sandbox_factory", lambda *args, **kwargs: None)

    hunt_finding = Finding(id="hunt-1", file="sample.c", severity="high")
    verified_finding = Finding(id="verified-1", file="sample.c", severity="high")

    async def fake_hunt(**kwargs):
        return HuntResult(
            findings=[hunt_finding],
            files_hunted=1,
            spent_per_tier={"A": 1.25, "B": 0.0, "C": 0.0},
        )

    async def fake_verify(*args, **kwargs):
        return VerificationResult(verified=[verified_finding], rejected=[])

    monkeypatch.setattr(runner, "_hunt", fake_hunt)
    monkeypatch.setattr(runner, "_verify", fake_verify)

    result = runner.run()

    assert [finding.id for finding in result.findings] == ["hunt-1"]
    assert [finding.id for finding in result.verified_findings] == ["verified-1"]
    assert result.exploited_findings == []
    assert result.files_hunted == 1


@pytest.mark.asyncio
async def test_runner_checkpoints_and_restores_verification(tmp_path: Path, monkeypatch):
    finding = Finding(id="finding-1", file="sample.c", severity="high")
    verifier_client = type(
        "VerifierClient",
        (),
        {"provider_name": "test-provider", "model_name": "test-model"},
    )()
    first = SourceHuntRunner(
        repo_url=str(tmp_path),
        output_dir=str(tmp_path),
        validator_mode="v1",
        enable_mechanism_memory=False,
    )
    first._checkpoint = SourceHuntCheckpoint()
    monkeypatch.setattr(first, "_get_native_client", lambda *args, **kwargs: verifier_client)

    async def verify_once(*args, **kwargs):
        return [finding]

    monkeypatch.setattr(first, "_verify_v1", verify_once)
    result = await first._verify(
        [finding], repo_path=str(tmp_path), pipeline_status=PipelineStatus()
    )
    assert isinstance(first._checkpoint.verification, VerificationCheckpoint)
    assert result.verified[0].id == "finding-1"

    resumed = SourceHuntRunner(
        repo_url=str(tmp_path),
        output_dir=str(tmp_path),
        checkpoint=first._checkpoint.model_dump(mode="json"),
        validator_mode="v1",
        enable_mechanism_memory=False,
    )
    monkeypatch.setattr(resumed, "_get_native_client", lambda *args, **kwargs: verifier_client)

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("verifier called")

    monkeypatch.setattr(resumed, "_verify_v1", fail_if_called)
    restored = await resumed._verify(
        [finding], repo_path=str(tmp_path), pipeline_status=PipelineStatus()
    )
    assert resumed._verification_restored is True
    assert restored.verified[0].id == "finding-1"


def test_verification_checkpoint_rejects_different_options():
    checkpoint = VerificationCheckpoint.from_result(
        VerificationResult(verified=[], rejected=[]), options={"validator_mode": "v2"}
    )
    assert checkpoint.restore(options={"validator_mode": "v1"}) is None


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

    saved = ExploitationResult(verified=[finding], exploited=[finding])
    first._checkpoint.exploitation = ExploitationCheckpoint.from_result(
        saved, options=first._checkpoint.exploitation.options
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


def test_exploitation_checkpoint_rejects_different_options():
    checkpoint = ExploitationCheckpoint.from_result(
        ExploitationResult(verified=[], exploited=[]), options={"no_exploit": False}
    )
    assert checkpoint.restore(options={"no_exploit": True}) is None
