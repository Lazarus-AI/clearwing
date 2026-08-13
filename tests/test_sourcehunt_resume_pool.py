from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from clearwing.findings.types import Finding
from clearwing.sourcehunt.findings_pool import FindingsPool
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig, TierBudget, WorkItem
from clearwing.sourcehunt.resume import SourceHuntResumeStore


def _target(path):
    return {
        "path": path,
        "absolute_path": f"/repo/{path}",
        "surface": 5,
        "influence": 5,
        "reachability": 3,
        "priority": 4.4,
        "tier": "A",
        "tags": [],
        "language": "python",
        "loc": 10,
    }


def _store(tmp_path, session_id="sh-pool"):
    store = SourceHuntResumeStore(tmp_path / session_id)
    paths = ["done.py", "interrupted.py", "new.py"]
    store.create_session(
        repository={"url": "repo", "branch": "main"},
        config={"test": True},
        source_identity={
            "algorithm": "sha256-path-content-v1",
            "fingerprint": "0" * 64,
            "paths": paths,
        },
    )
    return store


def _save(store, item, *, findings=(), stop_reason="completed", transcript=None):
    store.save_work_result(
        work_id=item.stable_identifier(store.session_id, "A"),
        file=item.file_target["path"],
        tier="A",
        band=item.band,
        attempt=item.attempt,
        entry_point=None,
        seed_context=item.seed_context,
        seed_transcript=item.seed_transcript,
        findings=findings,
        cost_usd=0,
        tokens_used=0,
        stop_reason=stop_reason,
        promotion_transcript=transcript,
    )


def _pool(store, files, calls, *, findings_pool=None, max_band="fast"):
    def factory(file_target, sandbox, session_id):
        calls.append(file_target["path"])

        class Hunter:
            async def arun(self):
                return SimpleNamespace(
                    findings=[], cost_usd=0, tokens_used=0, stop_reason="completed"
                )

        return Hunter(), MagicMock(cleanup_variants=MagicMock())

    return HunterPool(
        HuntPoolConfig(
            files=files,
            repo_path="/repo",
            hunter_factory=factory,
            max_parallel=1,
            tier_budget=TierBudget(1, 0, 0),
            session_id_prefix=store.session_id,
            starting_band="fast",
            max_band=max_band,
            redundancy_override=1,
            findings_pool=findings_pool,
            resume_store=store,
        )
    )


def test_completed_zero_finding_work_is_skipped_and_missing_work_runs(tmp_path):
    store = _store(tmp_path)
    files = [_target("done.py"), _target("interrupted.py"), _target("new.py")]
    _save(store, WorkItem(files[0], "fast"))
    calls = []

    pool = _pool(store, files, calls)
    asyncio.run(pool.arun())

    assert calls == ["interrupted.py", "new.py"]
    assert pool.completed_target_count == 3


def test_restored_findings_and_clusters_are_live_before_dispatch(tmp_path):
    store = _store(tmp_path)
    done = _target("done.py")
    finding = Finding(
        id="f-restored",
        file="done.py",
        description="restored",
        primitive_type="memory_corruption",
        cluster_id="cluster-restored",
    )
    _save(store, WorkItem(done, "fast"), findings=[finding])
    pool_state = FindingsPool()
    calls = []
    pool = _pool(store, [done, _target("new.py")], calls, findings_pool=pool_state)

    async def observe_restored_state(file_target, *_args, **_kwargs):
        calls.append(file_target["path"])
        assert file_target["path"] == "new.py"
        assert [item.id for item in pool_state.all_findings()] == ["f-restored"]
        assert pool_state.clusters()[0].finding_ids == ["f-restored"]
        return [], 0, 0, "completed"

    pool._run_one_hunter = observe_restored_state

    asyncio.run(pool.arun())

    assert calls == ["new.py"]
    assert [item.id for item in pool_state.all_findings()] == ["f-restored"]
    assert pool_state.clusters()[0].finding_ids == ["f-restored"]


def test_restored_cluster_descriptor_is_available_before_dispatch(tmp_path):
    store = _store(tmp_path)
    done = _target("done.py")
    finding = Finding(
        id="f-clustered",
        file="done.py",
        description="member",
        primitive_type="memory_corruption",
        cluster_id="cluster-restored",
    )
    item = WorkItem(done, "fast")
    store.save_work_result(
        work_id=item.stable_identifier(store.session_id, "A"),
        file="done.py",
        tier="A",
        band="fast",
        attempt=0,
        entry_point=None,
        seed_context=None,
        seed_transcript=None,
        findings=[finding],
        clusters=[
            {
                "cluster_id": "cluster-restored",
                "root_cause_summary": "original root cause",
                "primitive_type": "memory_corruption",
                "cwe": "CWE-787",
            }
        ],
        cost_usd=0,
        tokens_used=0,
        stop_reason="completed",
        promotion_transcript=None,
    )
    pool_state = FindingsPool()
    pool = _pool(store, [done], [], findings_pool=pool_state)

    asyncio.run(pool.arun())

    cluster = pool_state.clusters()[0]
    assert cluster.root_cause_summary == "original root cause"
    assert cluster.cwe == "CWE-787"


def test_completed_result_reconstructs_promotion(tmp_path):
    store = _store(tmp_path)
    target = _target("done.py")
    finding = Finding(id="f-promote", file="done.py", description="promote")
    fast = WorkItem(target, "fast")
    _save(store, fast, findings=[finding], transcript="seed transcript")
    pool = _pool(store, [target], [], max_band="standard")
    observed = []

    async def run_one(file_target, cost_limit, seed_transcript=None, **kwargs):
        observed.append(("standard", seed_transcript))
        return [], 0, 0, "completed"

    pool._run_one_hunter = run_one
    asyncio.run(pool.arun())

    assert observed == [("standard", "seed transcript")]


def test_completed_promoted_work_is_not_duplicated(tmp_path):
    store = _store(tmp_path)
    target = _target("done.py")
    finding = Finding(id="f-promote", file="done.py", description="promote")
    fast = WorkItem(target, "fast")
    standard = WorkItem(target, "standard", seed_transcript="seed transcript")
    _save(store, fast, findings=[finding], transcript="seed transcript")
    _save(store, standard)
    calls = []

    asyncio.run(_pool(store, [target], calls, max_band="standard").arun())

    assert calls == []


def test_interrupted_and_resumed_pool_matches_uninterrupted_result(tmp_path):
    files = [_target("done.py"), _target("new.py")]
    full_store = _store(tmp_path / "full", "sh-full")
    resumed_store = _store(tmp_path / "resumed", "sh-resumed")
    full_calls = []
    resumed_calls = []

    full_pool = _pool(full_store, files, full_calls)
    resumed_pool = _pool(resumed_store, files, resumed_calls)

    async def deterministic_hunt(file_target, *_args, **_kwargs):
        finding = Finding(
            id=f"finding-{file_target['path']}",
            file=file_target["path"],
            description="deterministic",
            primitive_type="memory_corruption",
        )
        return [finding], 0, 0, "completed"

    full_pool._run_one_hunter = deterministic_hunt
    resumed_pool._run_one_hunter = deterministic_hunt
    asyncio.run(full_pool.arun())
    done = WorkItem(files[0], "fast")
    _save(
        resumed_store,
        done,
        findings=[
            Finding(
                id="finding-done.py",
                file="done.py",
                description="deterministic",
                primitive_type="memory_corruption",
            )
        ],
        transcript="seed transcript",
    )
    asyncio.run(resumed_pool.arun())

    assert {(item.file, item.band) for item in full_store.load_completed_work().values()} == {
        (item.file, item.band) for item in resumed_store.load_completed_work().values()
    }
    assert full_store.completed_findings() == resumed_store.completed_findings()
