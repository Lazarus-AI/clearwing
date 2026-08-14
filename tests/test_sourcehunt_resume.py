from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from clearwing.findings.types import Finding
from clearwing.llm.budget import BudgetConfigurationError, SpendLedger
from clearwing.runners.parallel.executor import TargetResult
from clearwing.sourcehunt.entry_points import EntryPoint
from clearwing.sourcehunt.findings_pool import FindingsPool
from clearwing.sourcehunt.pool import (
    HunterPool,
    HuntPoolConfig,
    WorkItem,
    _extract_transcript,
)
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.resume import (
    SourceHuntCheckpoint,
    SourceHuntResumeError,
    SourceHuntSessionLock,
    fingerprint_invocation,
    fingerprint_source,
    session_directory,
)
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.ui.commands import sourcehunt as sourcehunt_command


def _target(repo: Path, **overrides):
    target = {
        "path": "app.py",
        "absolute_path": str(repo / "app.py"),
        "surface": 4,
        "influence": 4,
        "reachability": 3,
        "priority": 3.7,
        "tier": "C",
        "tags": ["attacker_reachable"],
        "language": "python",
        "loc": 1,
        "surface_rationale": "ranked",
        "influence_rationale": "ranked",
        "reachability_rationale": "reachable",
        "static_hint": 0,
        "semgrep_hint": 0,
        "taint_hits": 0,
        "imports_by": 0,
        "transitive_callers": 0,
        "defines_constants": False,
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
    }
    target.update(overrides)
    return target


def _prepared_store(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('safe')\n", encoding="utf-8")
    target = _target(repo)
    invocation = fingerprint_invocation({"depth": "standard"})
    source = fingerprint_source(repo, [target])
    store = SourceHuntCheckpoint(tmp_path / "out" / "sh-test", resuming=False)
    assert (
        store.prepare(
            invocation_fingerprint=invocation,
            source_fingerprint=source,
            source_paths=["app.py"],
        )
        is None
    )
    return repo, target, invocation, source, store


def test_checkpoint_restores_only_a_complete_compatible_rank_plan(tmp_path):
    repo, target, invocation, source, store = _prepared_store(tmp_path)
    store.save_rank_plan([target])

    resumed = SourceHuntCheckpoint(store.session_dir, resuming=True)
    plan = resumed.prepare(
        invocation_fingerprint=invocation,
        source_fingerprint=source,
        source_paths=["app.py"],
    )
    assert plan is not None
    fresh_target = _target(repo, surface=0, priority=0.0, surface_rationale="")
    resumed.apply_rank_plan([fresh_target], plan)
    assert fresh_target["surface"] == 4
    assert fresh_target["priority"] == 3.7

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    payload["rank_plan"] = [{"path": "app.py"}]
    store.path.write_text(json.dumps(payload), encoding="utf-8")
    assert (
        SourceHuntCheckpoint(store.session_dir, resuming=True).prepare(
            invocation_fingerprint=invocation,
            source_fingerprint=source,
            source_paths=["app.py"],
        )
        is None
    )


def test_checkpoint_rejects_changed_options_or_source(tmp_path):
    repo, target, invocation, source, store = _prepared_store(tmp_path)
    with pytest.raises(SourceHuntResumeError, match="options"):
        SourceHuntCheckpoint(store.session_dir, resuming=True).prepare(
            invocation_fingerprint=fingerprint_invocation({"depth": "deep"}),
            source_fingerprint=source,
            source_paths=["app.py"],
        )

    (repo / "app.py").write_text("print('changed')\n", encoding="utf-8")
    with pytest.raises(SourceHuntResumeError, match="source inputs changed"):
        SourceHuntCheckpoint(store.session_dir, resuming=True).prepare(
            invocation_fingerprint=invocation,
            source_fingerprint=fingerprint_source(repo, [target]),
            source_paths=["app.py"],
        )


def test_completed_work_round_trips_and_corruption_is_a_cache_miss(tmp_path):
    _repo, _target_value, _invocation, _source, store = _prepared_store(tmp_path)
    work_id = "work-" + "a" * 16
    result = TargetResult(
        target="app.py",
        status="completed",
        findings=[
            Finding(
                id="finding-1",
                file="app.py",
                line_number=1,
                severity="high",
                description="unsafe input",
            )
        ],
        cost_usd=0.25,
        tokens_used=20,
        tier="A",
        band="fast",
    )
    store.save(work_id, result)

    restored = store.load(work_id)
    assert restored is not None
    assert restored.cost_usd == 0.25
    assert isinstance(restored.findings[0], Finding)

    zero_id = "work-" + "b" * 16
    store.save(
        zero_id,
        TargetResult(
            target="app.py", status="completed", findings=[], tier="A", band="fast"
        ),
    )
    assert store.load(zero_id) is not None

    (store.work_dir / f"{work_id}.json").write_text('{"result":', encoding="utf-8")
    assert store.load(work_id) is None


def test_session_ids_and_concurrent_writers_are_rejected(tmp_path):
    with pytest.raises(SourceHuntResumeError, match="Invalid"):
        session_directory(tmp_path, "../escape")

    session = tmp_path / "sh-test"
    first = SourceHuntSessionLock(session)
    second = SourceHuntSessionLock(session)
    first.acquire()
    try:
        with pytest.raises(SourceHuntResumeError, match="already running"):
            second.acquire()
    finally:
        first.release()


class _MemoryCheckpoint:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.loaded = []
        self.saved = []

    def load(self, work_id):
        self.loaded.append(work_id)
        return self.values.get(work_id)

    def save(self, work_id, result):
        self.saved.append((work_id, result))
        self.values[work_id] = result


@pytest.mark.asyncio
async def test_cached_findings_and_promotions_follow_the_normal_pool_path(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = _target(repo)
    finding = Finding(
        id="cached-finding",
        file="app.py",
        line_number=1,
        severity="high",
        description="cached bug",
    )
    base_result = TargetResult(
        target="app.py",
        status="completed",
        findings=[finding],
        cost_usd=1.0,
        tier="A",
        band="fast",
        stop_reason="completed",
    )
    base = WorkItem(target, "fast")
    promoted = WorkItem(
        target,
        "standard",
        seed_transcript=_extract_transcript(base_result),
    )
    checkpoint = _MemoryCheckpoint(
        {
            base.stable_identifier("sh-test", "A"): base_result,
            promoted.stable_identifier("sh-test", "A"): TargetResult(
                target="app.py",
                status="completed",
                findings=[],
                tier="A",
                band="standard",
            ),
        }
    )
    findings_pool = FindingsPool()
    pool = HunterPool(
        HuntPoolConfig(
            files=[target],
            repo_path=str(repo),
            checkpoint=checkpoint,
            findings_pool=findings_pool,
            session_id_prefix="sh-test",
            redundancy_override=1,
            max_parallel=1,
            starting_band="fast",
            max_band="standard",
        )
    )
    pool._run_file_task = AsyncMock(side_effect=AssertionError("cached work reran"))

    findings = await pool.arun()

    pool._run_file_task.assert_not_awaited()
    assert [item.id for item in findings] == ["cached-finding"]
    assert pool.promotion_counts == {"fast→standard": 1, "standard→deep": 0}
    assert pool.total_spent == 1.0


@pytest.mark.asyncio
async def test_findings_pool_replay_is_idempotent(tmp_path):
    path = tmp_path / "findings-pool.jsonl"
    original = Finding(
        id="cached-finding",
        file="app.py",
        line_number=1,
        finding_type="command_injection",
        severity="critical",
        description="cached bug",
    )
    pool = FindingsPool(checkpoint_path=path)
    await pool.add(original)
    cluster_id = original.cluster_id

    resumed = FindingsPool.from_checkpoint(path)
    restored = await resumed.add(
        Finding(
            id="cached-finding",
            file="app.py",
            line_number=1,
            finding_type="command_injection",
            severity="critical",
            description="cached bug",
        )
    )

    assert resumed.count == 1
    assert restored.cluster_id == cluster_id
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.asyncio
async def test_missing_work_runs_and_is_saved_even_with_zero_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = _target(repo)
    checkpoint = _MemoryCheckpoint()
    pool = HunterPool(
        HuntPoolConfig(
            files=[target],
            repo_path=str(repo),
            checkpoint=checkpoint,
            session_id_prefix="sh-test",
            redundancy_override=1,
            max_parallel=1,
            starting_band="fast",
            max_band="fast",
        )
    )
    pool._run_file_task = AsyncMock(
        return_value=TargetResult(
            target="app.py",
            status="completed",
            findings=[],
            cost_usd=0.2,
            tier="A",
            band="fast",
        )
    )

    assert await pool.arun() == []
    pool._run_file_task.assert_awaited_once()
    assert len(checkpoint.saved) == 1
    assert checkpoint.saved[0][1].findings == []


@pytest.mark.asyncio
async def test_mismatched_cached_work_is_a_cache_miss(tmp_path):
    target = _target(tmp_path)
    item = WorkItem(target, "fast")
    checkpoint = _MemoryCheckpoint(
        {
            item.stable_identifier("sh-test", "A"): TargetResult(
                target="other.py",
                status="completed",
                findings=[],
                tier="A",
                band="fast",
            )
        }
    )
    pool = HunterPool(
        HuntPoolConfig(
            files=[target],
            repo_path=str(tmp_path),
            checkpoint=checkpoint,
            session_id_prefix="sh-test",
            redundancy_override=1,
            max_parallel=1,
            starting_band="fast",
            max_band="fast",
        )
    )
    pool._run_file_task = AsyncMock(
        return_value=TargetResult(
            target="app.py", status="completed", findings=[], tier="A", band="fast"
        )
    )

    await pool.arun()

    pool._run_file_task.assert_awaited_once()


def _ledger(tmp_path: Path, session_id: str, *, resume: bool = False) -> SpendLedger:
    return SpendLedger(
        limit_usd=10.0,
        session_id=session_id,
        repo_url="repo",
        output_dir=tmp_path,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
        resume=resume,
    )


def test_spend_resume_restores_settlements_and_ignores_a_truncated_tail(tmp_path):
    ledger = _ledger(tmp_path, "settled")
    reservation = ledger.reserve_call(
        model="test",
        provider="test",
        stage="hunt",
        input_token_upper_bound=0,
        requested_max_output_tokens=2,
        supports_output_limit=True,
    )
    ledger.settle_call(reservation, input_tokens=2, output_tokens=1)
    ledger.finalize("failed")
    with ledger.ledger_path.open("a", encoding="utf-8") as stream:
        stream.write('{"event":')

    resumed = _ledger(tmp_path, "settled", resume=True)
    assert resumed.spent_usd == pytest.approx(1.0)
    assert resumed.snapshot()["total_tokens"] == 3


def test_spend_resume_charges_an_orphaned_reservation_only_once(tmp_path):
    ledger = _ledger(tmp_path, "orphan")
    reservation = ledger.reserve_call(
        model="test",
        provider="test",
        stage="hunt",
        input_token_upper_bound=0,
        requested_max_output_tokens=2,
        supports_output_limit=True,
    )
    first_resume = _ledger(tmp_path, "orphan", resume=True)
    assert first_resume.spent_usd == pytest.approx(reservation.reserved_usd)
    first_resume.finalize("failed")

    second_resume = _ledger(tmp_path, "orphan", resume=True)
    assert second_resume.spent_usd == pytest.approx(reservation.reserved_usd)


def test_spend_resume_refuses_a_missing_or_corrupt_ledger(tmp_path):
    with pytest.raises(BudgetConfigurationError, match="ledger is missing"):
        _ledger(tmp_path, "missing", resume=True)

    ledger = _ledger(tmp_path, "corrupt")
    ledger.ledger_path.write_text("not-json\n{}\n", encoding="utf-8")
    with pytest.raises(BudgetConfigurationError, match="ledger is corrupt"):
        _ledger(tmp_path, "corrupt", resume=True)


def test_work_ids_distinguish_overloaded_entry_points(tmp_path):
    target = _target(tmp_path)
    first = WorkItem(
        target,
        "fast",
        entry_point=EntryPoint("app.py", "parse", 1, 10, "parser", "first"),
    )
    second = WorkItem(
        target,
        "fast",
        entry_point=EntryPoint("app.py", "parse", 20, 30, "parser", "second"),
    )

    assert first.stable_identifier("sh-test", "A") != second.stable_identifier(
        "sh-test", "A"
    )


def test_runner_reruns_preprocessing_and_restores_rank_plan(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('safe')\n", encoding="utf-8")
    output = tmp_path / "out"
    preprocess_calls = 0
    rank_calls = 0

    def preprocess():
        nonlocal preprocess_calls
        preprocess_calls += 1
        return PreprocessResult(
            repo_path=str(repo),
            file_targets=[_target(repo, surface=0, influence=0, priority=0.0)],
            static_findings=[],
        )

    async def rank(_self, files):
        nonlocal rank_calls
        rank_calls += 1
        files[0].update(
            surface=5,
            influence=4,
            priority=4.2,
            surface_rationale="paid rank",
            influence_rationale="paid rank",
        )
        return files

    monkeypatch.setattr("clearwing.sourcehunt.runner.Ranker.arank", rank)
    common = {
        "repo_url": str(repo),
        "local_path": str(repo),
        "depth": "quick",
        "output_dir": str(output),
        "ranker_llm": AsyncMock(provider_name="test"),
        "enable_mechanism_memory": False,
        "enable_knowledge_graph": False,
    }
    first = SourceHuntRunner(**common)
    first._preprocess = preprocess
    first.run()
    assert rank_calls == 1

    resumed = SourceHuntRunner(**common, resume_session_id=first.session_id)
    resumed._preprocess = preprocess
    resumed.run()
    assert preprocess_calls == 2
    assert rank_calls == 1

    (repo / "app.py").write_text("print('changed')\n", encoding="utf-8")
    incompatible = SourceHuntRunner(**common, resume_session_id=first.session_id)
    incompatible._preprocess = preprocess
    with pytest.raises(SourceHuntResumeError, match="source inputs changed"):
        incompatible.run()


def test_invocation_compatibility_excludes_models_and_replayed_later_stages(tmp_path):
    common = {
        "repo_url": "repo",
        "output_dir": str(tmp_path),
        "enable_calibration": False,
        "enable_mechanism_memory": False,
    }
    original = SourceHuntRunner(**common, model_override="model-a")
    replacement = SourceHuntRunner(
        **common,
        model_override="model-b",
        no_verify=True,
        no_exploit=True,
    )
    changed_hunt = SourceHuntRunner(**common, prompt_mode="specialist")
    changed_parallelism = SourceHuntRunner(**common, max_parallel=2)

    assert original._invocation_fingerprint() == replacement._invocation_fingerprint()
    assert original._invocation_fingerprint() != changed_hunt._invocation_fingerprint()
    assert original._invocation_fingerprint() != changed_parallelism._invocation_fingerprint()


def test_cli_keeps_repo_required_and_accepts_normal_options_with_resume():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)
    args = parser.parse_args(
        ["sourcehunt", "repo", "--resume", "sh-test", "--no-verify", "--depth", "deep"]
    )
    assert args.repo == "repo"
    assert args.resume == "sh-test"
    assert args.no_verify is True
    assert args.depth == "deep"

    missing_repo = parser.parse_args(["sourcehunt", "--resume", "sh-test"])
    with pytest.raises(SystemExit):
        sourcehunt_command.handle(None, missing_repo)
