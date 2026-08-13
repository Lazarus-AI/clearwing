from __future__ import annotations

import json
import time

import pytest

from clearwing.findings.types import Finding
from clearwing.sourcehunt.config import SourceHuntConfig
from clearwing.sourcehunt.resume import (
    SourceHuntResumeError,
    SourceHuntResumeStore,
    deterministic_work_id,
    source_input_identity,
)


def _target(path, absolute_path):
    return {
        "path": path,
        "absolute_path": str(absolute_path),
        "surface": 5,
        "influence": 4,
        "reachability": 3,
        "priority": 4.1,
        "tier": "A",
        "tags": [],
        "language": "python",
        "loc": 1,
        "surface_rationale": "ranked",
        "influence_rationale": "ranked",
        "reachability_rationale": "default",
        "static_hint": 0,
        "semgrep_hint": 0,
        "taint_hits": 0,
        "imports_by": 0,
        "transitive_callers": 0,
        "defines_constants": False,
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
    }


def _store(tmp_path, *, session_id="sh-store"):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    source = repo / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    target = _target("app.py", source)
    store = SourceHuntResumeStore(tmp_path / session_id)
    store.create_session(
        repository={"url": str(repo), "branch": "main", "resolved_commit": None},
        config={
            "target": {
                "repo_url": str(repo),
                "local_path": str(repo),
                "branch": "main",
                "depth": "standard",
            },
            "budget": {"budget_usd": 10.0},
            "output": {"output_formats": ["json"]},
            "proof": {"flow": "legacy"},
        },
        source_identity=source_input_identity(repo, [target]),
    )
    return store, target


def _work_id(store, *, band="fast", seed_transcript=None):
    return deterministic_work_id(
        store.session_id,
        file="app.py",
        tier="A",
        band=band,
        attempt=0,
        entry_point=None,
        seed_context=None,
        seed_transcript=seed_transcript,
    )


def _work_payload(store, *, findings=(), work_id=None):
    work_id = work_id or _work_id(store)
    return {
        "schema_version": 1,
        "work_id": work_id,
        "work": {
            "file": "app.py",
            "tier": "A",
            "band": "fast",
            "attempt": 0,
            "entry_point": None,
            "seed_context": None,
            "seed_transcript": None,
        },
        "result": {
            "status": "completed",
            "findings": list(findings),
            "clusters": [],
        },
    }


def _save_work(store, *, findings=(), attempt=0, **overrides):
    work_id = deterministic_work_id(
        store.session_id,
        file="app.py",
        tier="A",
        band="fast",
        attempt=attempt,
        entry_point=None,
        seed_context=None,
        seed_transcript=None,
    )
    options = {
        "work_id": work_id,
        "file": "app.py",
        "tier": "A",
        "band": "fast",
        "attempt": attempt,
        "entry_point": None,
        "seed_context": None,
        "seed_transcript": None,
        "findings": findings,
        "clusters": [],
        "cost_usd": 0,
        "tokens_used": 0,
        "stop_reason": "completed",
        "promotion_transcript": None,
    }
    options.update(overrides)
    return store.save_work_result(**options)


def test_session_rank_and_work_results_round_trip(tmp_path):
    store, target = _store(tmp_path)
    ranked = [{key: value for key, value in target.items() if key != "absolute_path"}]
    store.save_rank_plan(ranked)
    finding = Finding(
        id="f-1",
        file="app.py",
        description="bug",
        primitive_type="memory_corruption",
        cluster_id="cluster-1",
    )
    _save_work(
        store,
        findings=[finding],
        cost_usd=1.25,
        tokens_used=30,
        promotion_transcript="previous work",
    )

    loaded = SourceHuntResumeStore.load(store.session_dir)

    assert loaded.load_rank_plan() == ranked
    result = loaded.load_completed_work()[_work_id(store)]
    assert result.findings == [finding]
    assert result.promotion_transcript == "previous work"


def test_effective_config_round_trips_behavior_options():
    config = SourceHuntConfig.from_options(
        {
            "repo_url": "repo",
            "branch": "feature",
            "local_path": "/repo",
            "depth": "deep",
            "budget_usd": 12.5,
            "max_parallel": 3,
            "output_dir": "/results",
            "output_formats": ["json"],
            "no_verify": True,
            "mechanism_store_path": "/mechanisms",
            "respect_gitignore": True,
            "flow": "legacy",
            "proof_compile_commands": "/repo/compile_commands.json",
            "retain_incomplete_certificates": False,
            "emit_rejection_certificates": False,
            "falsify": False,
        }
    )

    restored = SourceHuntConfig.from_dict(config.to_dict())

    assert restored == config
    assert restored.target.branch == "feature"
    assert restored.features.no_verify is True
    assert restored.tuning.mechanism_store_path == "/mechanisms"
    assert restored.tuning.respect_gitignore is True
    assert restored.proof.compile_commands == "/repo/compile_commands.json"
    assert restored.proof.retain_incomplete_certificates is False


@pytest.mark.parametrize("invalid", ["truncated", "malformed_finding", "wrong_id"])
def test_invalid_work_results_are_ignored(tmp_path, invalid):
    store, _target_value = _store(tmp_path, session_id=f"sh-{invalid}")
    store.work_results_dir.mkdir()
    work_id = _work_id(store)
    if invalid == "truncated":
        path = store.work_results_dir / f"{work_id}.json"
        path.write_text('{"schema_version":1,"work_id":', encoding="utf-8")
    else:
        if invalid == "wrong_id":
            work_id = "work-0123456789abcdef"
        payload = _work_payload(store, work_id=work_id)
        if invalid == "malformed_finding":
            payload["result"]["findings"] = [{}]
        (store.work_results_dir / f"{work_id}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    assert store.load_completed_work() == {}


def test_existing_valid_work_result_is_immutable(tmp_path):
    store, _target_value = _store(tmp_path)
    work_id = _work_id(store)
    first = Finding(id="first", file="app.py", description="first")
    second = Finding(id="second", file="app.py", description="second")
    _save_work(store, findings=[first])
    path = store.work_results_dir / f"{work_id}.json"
    original = path.read_bytes()

    result = _save_work(store, findings=[second])

    assert result.findings == [first]
    assert path.read_bytes() == original


def test_small_result_persistence_benchmark(tmp_path):
    store, _target_value = _store(tmp_path)
    started = time.perf_counter()
    for attempt in range(100):
        _save_work(store, attempt=attempt)
    loaded = SourceHuntResumeStore.load(store.session_dir).load_completed_work()

    assert len(loaded) == 100
    assert time.perf_counter() - started < 5


def test_partial_or_invalid_rank_plan_is_ignored(tmp_path):
    store, _target_value = _store(tmp_path)
    store.rank_plan_path.write_text('{"schema_version":1,"targets":', encoding="utf-8")
    assert store.load_rank_plan() is None

    store.rank_plan_path.write_text(
        json.dumps({"schema_version": 1, "targets": [{"path": "other.py"}]}),
        encoding="utf-8",
    )
    assert store.load_rank_plan() is None

    store.rank_plan_path.write_text(
        json.dumps({"schema_version": 1, "targets": [{"path": "app.py"}]}),
        encoding="utf-8",
    )
    assert store.load_rank_plan() is None


def test_selected_path_changes_reject_resume(tmp_path):
    store, target = _store(tmp_path)
    extra = tmp_path / "repo" / "extra.py"
    extra.write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(SourceHuntResumeError, match="source inputs changed"):
        store.validate_source_identity(
            source_input_identity(
                tmp_path / "repo",
                [target, _target("extra.py", extra)],
            )
        )
