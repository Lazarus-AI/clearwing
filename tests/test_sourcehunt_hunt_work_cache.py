"""Work-item-granular hunt resume folded into the checkpoint architecture.

Covers the ``HuntWorkCache`` store, its wiring into ``HunterPool`` (reuse
completed work, save new work, ignore mismatched/corrupt entries), the
idempotent findings-pool replay, the spend-ledger lifetime-budget resume, and
the runner's ``--resume`` session validation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from clearwing.findings.types import Finding
from clearwing.llm.budget import BudgetConfigurationError, SpendLedger
from clearwing.runners.parallel.executor import TargetResult
from clearwing.sourcehunt.entry_points import EntryPoint
from clearwing.sourcehunt.findings_pool import FindingsPool
from clearwing.sourcehunt.hunt_work_cache import HuntWorkCache
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig, WorkItem, _extract_transcript


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


class _MemoryWorkCache:
    """In-memory HuntWorkCache stand-in that records loads and saves."""

    def __init__(self, values=None):
        self.values = dict(values or {})
        self.loaded: list[str] = []
        self.saved: list[tuple[str, TargetResult]] = []

    def load(self, work_id):
        self.loaded.append(work_id)
        return self.values.get(work_id)

    def save(self, work_id, result):
        self.saved.append((work_id, result))
        self.values[work_id] = result


# --- HuntWorkCache store ----------------------------------------------------


def test_completed_work_round_trips_and_corruption_is_a_cache_miss(tmp_path):
    cache = HuntWorkCache(tmp_path / "hunt-work")
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
    cache.save(work_id, result)

    # A fresh cache over the same directory reads the persisted result back —
    # this is exactly what a resumed process does.
    restored = HuntWorkCache(tmp_path / "hunt-work").load(work_id)
    assert restored is not None
    assert restored.cost_usd == 0.25
    assert isinstance(restored.findings[0], Finding)

    # Zero-finding completed work is still cached (it is real, finished work).
    zero_id = "work-" + "b" * 16
    cache.save(zero_id, TargetResult(target="app.py", status="completed", findings=[], tier="A", band="fast"))
    assert cache.load(zero_id) is not None

    # A torn file is a cache miss, not a crash — the work simply re-runs.
    (cache.work_dir / f"{work_id}.json").write_text('{"result":', encoding="utf-8")
    assert cache.load(work_id) is None


def test_only_completed_work_is_cached(tmp_path):
    cache = HuntWorkCache(tmp_path / "hunt-work")
    work_id = "work-" + "c" * 16
    cache.save(work_id, TargetResult(target="app.py", status="error", findings=[], tier="A", band="fast"))
    assert cache.load(work_id) is None
    assert not (cache.work_dir / f"{work_id}.json").exists()
    # A malformed id is never written or read.
    assert cache.load("not-a-work-id") is None


def test_save_is_write_once(tmp_path):
    cache = HuntWorkCache(tmp_path / "hunt-work")
    work_id = "work-" + "d" * 16
    first = TargetResult(target="app.py", status="completed", findings=[], cost_usd=1.0, tier="A", band="fast")
    second = TargetResult(target="app.py", status="completed", findings=[], cost_usd=9.0, tier="A", band="fast")
    cache.save(work_id, first)
    cache.save(work_id, second)  # ignored — first result is authoritative
    assert cache.load(work_id).cost_usd == 1.0


# --- HunterPool wiring ------------------------------------------------------


@pytest.mark.asyncio
async def test_cached_work_is_reused_and_promotions_follow_normal_path(tmp_path):
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
    promoted = WorkItem(target, "standard", seed_transcript=_extract_transcript(base_result))
    work_cache = _MemoryWorkCache(
        {
            base.stable_identifier("sh-test", "A"): base_result,
            promoted.stable_identifier("sh-test", "A"): TargetResult(
                target="app.py", status="completed", findings=[], tier="A", band="standard"
            ),
        }
    )
    findings_pool = FindingsPool()
    pool = HunterPool(
        HuntPoolConfig(
            files=[target],
            repo_path=str(repo),
            work_cache=work_cache,
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
async def test_missing_work_runs_and_is_saved_even_with_zero_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = _target(repo)
    work_cache = _MemoryWorkCache()
    pool = HunterPool(
        HuntPoolConfig(
            files=[target],
            repo_path=str(repo),
            work_cache=work_cache,
            session_id_prefix="sh-test",
            redundancy_override=1,
            max_parallel=1,
            starting_band="fast",
            max_band="fast",
        )
    )
    pool._run_file_task = AsyncMock(
        return_value=TargetResult(
            target="app.py", status="completed", findings=[], cost_usd=0.2, tier="A", band="fast"
        )
    )

    assert await pool.arun() == []
    pool._run_file_task.assert_awaited_once()
    assert len(work_cache.saved) == 1
    assert work_cache.saved[0][1].findings == []


@pytest.mark.asyncio
async def test_mismatched_cached_work_is_a_cache_miss(tmp_path):
    target = _target(tmp_path)
    item = WorkItem(target, "fast")
    work_cache = _MemoryWorkCache(
        {
            item.stable_identifier("sh-test", "A"): TargetResult(
                target="other.py", status="completed", findings=[], tier="A", band="fast"
            )
        }
    )
    pool = HunterPool(
        HuntPoolConfig(
            files=[target],
            repo_path=str(tmp_path),
            work_cache=work_cache,
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


@pytest.mark.asyncio
async def test_findings_pool_add_is_idempotent(tmp_path):
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


# --- Work-item identity -----------------------------------------------------


def test_work_ids_distinguish_overloaded_entry_points(tmp_path):
    target = _target(tmp_path)
    first = WorkItem(target, "fast", entry_point=EntryPoint("app.py", "parse", 1, 10, "parser", "first"))
    second = WorkItem(target, "fast", entry_point=EntryPoint("app.py", "parse", 20, 30, "parser", "second"))
    assert first.stable_identifier("sh-test", "A") != second.stable_identifier("sh-test", "A")


def test_work_ids_vary_with_tier_and_context(tmp_path):
    target = _target(tmp_path)
    item = WorkItem(target, "fast")
    assert item.stable_identifier("sh-test", "A") != item.stable_identifier("sh-test", "B")
    with_context = WorkItem(target, "fast", context_id="ctx-1")
    assert item.stable_identifier("sh-test", "A") != with_context.stable_identifier("sh-test", "A")


# --- Spend ledger lifetime-budget resume ------------------------------------


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


# --- Runner --resume validation ---------------------------------------------


def test_runner_resume_requires_an_existing_session(tmp_path):
    from clearwing.sourcehunt.runner import SourceHuntRunner

    with pytest.raises(ValueError, match="does not exist"):
        SourceHuntRunner(
            repo_url="x", output_dir=str(tmp_path), resume_session_id="sh-nope"
        )


def test_runner_resume_conflicts_with_parent_session(tmp_path):
    from clearwing.sourcehunt.runner import SourceHuntRunner

    (Path(tmp_path) / "sh-a").mkdir()
    with pytest.raises(ValueError, match="cannot be combined"):
        SourceHuntRunner(
            repo_url="x",
            output_dir=str(tmp_path),
            resume_session_id="sh-a",
            parent_session_id="sh-b",
        )
