from __future__ import annotations

import subprocess
from pathlib import Path

from clearwing.analysis.source_analyzer import AnalyzerFinding
from clearwing.sourcehunt.callgraph import CallGraph, FunctionInfo
from clearwing.sourcehunt.checkpoints import (
    CheckpointBundle,
    CheckpointBundleStore,
    PreprocessCheckpointStore,
    parse_checkpoint,
)
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.runner import SourceHuntRunner
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


def test_preprocess_checkpoint_trusts_current_source_and_rebinds_paths(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    commit_sha = _commit(repo)
    session = tmp_path / "results" / "sh-test"
    bundle_store = CheckpointBundleStore(session)
    store = PreprocessCheckpointStore(bundle_store)
    store.save(_result(repo), options=OPTIONS)
    assert bundle_store.bundle.preprocess is not None
    assert bundle_store.bundle.preprocess.commit_sha == commit_sha

    restored = store.load(repo_path=str(repo), options=OPTIONS)
    assert restored is not None
    assert restored.repo_path == str(repo.resolve())
    assert restored.file_targets[0]["absolute_path"] == str(source.resolve())

    source.write_text("int sample(void) { return 2; }\n", encoding="utf-8")
    assert store.load(repo_path=str(repo), options=OPTIONS) is not None


def test_preprocess_checkpoint_rejects_different_commit(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    _commit(repo)
    bundle_store = CheckpointBundleStore(tmp_path / "results" / "sh-test")
    store = PreprocessCheckpointStore(bundle_store)
    store.save(_result(repo), options=OPTIONS)

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

    assert store.load(repo_path=str(repo), options=OPTIONS) is None


def test_preprocess_checkpoint_rejects_corrupt_payload(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    session = tmp_path / "results" / "sh-test"
    bundle_store = CheckpointBundleStore(session)
    store = PreprocessCheckpointStore(bundle_store)
    store.save(_result(repo), options=OPTIONS)
    payload = bundle_store.path.read_text(encoding="utf-8").replace(
        '"schema_version": 1', '"schema_version": 999', 1
    )
    try:
        parse_checkpoint(payload)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid checkpoint schema was accepted")


def test_checkpoint_is_one_self_contained_json_blob(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    bundle_store = CheckpointBundleStore(tmp_path / "sh-test")
    preprocess = PreprocessCheckpointStore(bundle_store)
    preprocess.save(_result(repo), options=OPTIONS)

    assert bundle_store.path == tmp_path / "sh-test" / "checkpoint.json"
    assert not (tmp_path / "sh-test" / "checkpoints").exists()
    raw = bundle_store.path.read_text()
    assert str(repo) not in raw
    assert "absolute_path" not in raw
    restored = CheckpointBundle.model_validate_json(bundle_store.path.read_text())
    assert restored.preprocess is not None
    assert restored.preprocess.result["file_targets"][0]["path"] == "sample.c"
    assert restored.preprocess.options == OPTIONS


def test_preprocess_checkpoint_rejects_different_options(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    result = _result(repo)
    _commit(repo)
    bundle_store = CheckpointBundleStore(tmp_path / "sh-test")
    store = PreprocessCheckpointStore(bundle_store)
    store.save(result, options=OPTIONS)

    assert store.load(
        repo_path=str(repo),
        options={**OPTIONS, "run_semgrep": True},
    ) is None


def test_preprocess_checkpoint_rejects_path_traversal(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.c").write_text("int sample(void);\n", encoding="utf-8")
    _commit(repo)
    outside = tmp_path / "outside.c"
    outside.write_text("int outside(void);\n", encoding="utf-8")
    bundle_store = CheckpointBundleStore(tmp_path / "sh-test")
    result = _result(repo)
    result.file_targets[0]["path"] = "../outside.c"
    PreprocessCheckpointStore(bundle_store).save(result, options=OPTIONS)

    assert PreprocessCheckpointStore(bundle_store).load(
        repo_path=str(repo), options=OPTIONS
    ) is None


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
    checkpoint_blob = first._checkpoint_store.path.read_text(encoding="utf-8")

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
    checkpoint = first._checkpoint_store.bundle.model_dump(mode="json")

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


def test_runner_result_exposes_checkpoint_for_bridge_response(tmp_path: Path):
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

    result = runner.run()

    assert result.checkpoint is not None
    assert result.checkpoint["preprocess"]["result"]["file_targets"][0]["path"] == "sample.c"
    assert Path(result.output_paths["checkpoint"]).read_text(encoding="utf-8")


def test_runner_rejects_invalid_checkpoint_json():
    try:
        SourceHuntRunner(repo_url="repo", checkpoint="not-json")
    except ValueError as exc:
        assert "json" in str(exc).lower()
    else:
        raise AssertionError("invalid checkpoint JSON was accepted")
