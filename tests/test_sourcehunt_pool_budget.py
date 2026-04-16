"""Pool budget allocation and rollover tests.

Uses a hunter_factory stub that returns synthetic findings + a fake cost,
so we can exercise the budget math without any LLM or sandbox calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.pool import (
    HunterPool,
    HuntPoolConfig,
    TierBudget,
)


def _ft(path: str, surface: int, influence: int) -> dict:
    priority = surface * 0.5 + influence * 0.2 + 3 * 0.3  # reach=3
    return {
        "path": path,
        "absolute_path": f"/abs/{path}",
        "surface": surface,
        "influence": influence,
        "reachability": 3,
        "priority": priority,
        "tier": "C",  # overwritten by HunterPool.__init__
        "tags": [],
        "language": "c",
        "loc": 100,
        "static_hint": 0,
        "imports_by": 0,
        "defines_constants": False,
        "semgrep_hint": 0,
        "transitive_callers": 0,
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
        "surface_rationale": "",
        "influence_rationale": "",
        "reachability_rationale": "",
    }


def _stub_hunter_factory(per_call_cost: float, finding_per_file: bool = True):
    """Return a hunter_factory that fakes a native hunter + ctx with a fixed cost."""

    def factory(file_target, sandbox, session_id):
        ctx = MagicMock()
        # Stub finding
        if finding_per_file:
            ctx.findings = [
                {
                    "id": f"f-{file_target['path']}",
                    "file": file_target["path"],
                    "line_number": 1,
                    "evidence_level": "suspicion",
                    "severity": "low",
                    "description": "stub",
                }
            ]
        else:
            ctx.findings = []
        ctx.session_id = session_id
        ctx.cleanup_variants = MagicMock()

        class _StubHunter:
            async def arun(self):
                return list(ctx.findings), per_call_cost, 0

        return _StubHunter(), ctx

    return factory


def _make_pool(files, budget=10.0, tier_split=(0.7, 0.25, 0.05), per_call_cost=0.5, max_parallel=4):
    config = HuntPoolConfig(
        files=files,
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(per_call_cost),
        max_parallel=max_parallel,
        budget_usd=budget,
        tier_budget=TierBudget(*tier_split),
        cost_limit_per_file_a=10.0,  # disable per-file caps for these tests
        cost_limit_per_file_b=10.0,
        cost_limit_per_file_c=10.0,
    )
    return HunterPool(config)


# --- Tier assignment in __init__ -------------------------------------------


class TestTierAssignmentOnInit:
    def test_files_get_assigned_tiers(self):
        files = [
            _ft("a_high.c", 5, 5),  # priority 4.4 → A
            _ft("b_mid.c", 2, 2),  # priority 2.3 → B
            _ft("c_low.c", 1, 1),  # priority 1.6 → C
            _ft("ffmpeg.h", 1, 5),  # priority 2.4 → B (NOT C!)
        ]
        _make_pool(files)
        # Tiers were written in __init__
        assert files[0]["tier"] == "A"
        assert files[1]["tier"] == "B"
        assert files[2]["tier"] == "C"
        assert files[3]["tier"] == "B"  # critical regression — must be B not C


# --- Tier A spending --------------------------------------------------------


class TestTierASpend:
    def test_tier_a_spends_within_allocation(self):
        # 10 Tier A files at $0.50 each = $5.00; budget allows $7 for A
        files = [_ft(f"a{i}.c", 5, 5) for i in range(10)]
        pool = _make_pool(files, budget=10.0, per_call_cost=0.5)
        findings = pool.run()
        # All 10 should run because $5 < $7 budget
        assert len(findings) == 10
        spent = pool.spent_per_tier
        assert spent["A"] == pytest.approx(5.0)

    def test_tier_a_stops_at_budget(self):
        # 100 Tier A files at $1 each, budget $10 → $7 for A → max 7 files
        files = [_ft(f"a{i}.c", 5, 5) for i in range(100)]
        pool = _make_pool(files, budget=10.0, per_call_cost=1.0, max_parallel=1)
        pool.run()
        spent = pool.spent_per_tier
        # Note: with max_parallel=1 the budget gate runs between submissions,
        # but submitted hunters always complete (we don't kill running work).
        # Expect spending to stay close to $7 — within one extra file's cost.
        assert spent["A"] <= 7.5
        assert spent["A"] >= 6.0  # at least 6 files completed


# --- Rollover ---------------------------------------------------------------


class TestRollover:
    def test_unused_a_rolls_into_b(self):
        # 1 Tier A file at $0.50 (budget $7) → leaves ~$6.5 unused
        # 4 Tier B files at $0.50 each → total cost $2 (budget $2.5 + $6.5 rollover)
        files = [
            _ft("a.c", 5, 5),  # Tier A
            _ft("b1.c", 2, 2),
            _ft("b2.c", 2, 2),
            _ft("b3.c", 2, 2),
            _ft("b4.c", 2, 2),
        ]
        pool = _make_pool(files, budget=10.0, per_call_cost=0.5)
        findings = pool.run()
        # All 5 files should run (well within rollover-augmented budget)
        assert len(findings) == 5
        # B tier should NOT have stopped early
        spent = pool.spent_per_tier
        assert spent["A"] == pytest.approx(0.5)
        assert spent["B"] == pytest.approx(2.0)

    def test_unused_b_rolls_into_c(self):
        # No A files, lots of B and C
        files = [
            _ft("b1.c", 2, 2),
            _ft("c1.c", 1, 1),
            _ft("c2.c", 1, 1),
            _ft("c3.c", 1, 1),
            _ft("c4.c", 1, 1),
        ]
        pool = _make_pool(files, budget=10.0, per_call_cost=0.2)
        findings = pool.run()
        # With $7 + $2.5 + $0.5 budgets and rollover, all 5 fit easily
        assert len(findings) == 5
        spent = pool.spent_per_tier
        assert spent["C"] == pytest.approx(0.8)


# --- Skip-tier-c -----------------------------------------------------------


class TestSkipTierC:
    def test_zero_tier_c_fraction_skips_phase_c(self):
        files = [_ft("c1.c", 1, 1), _ft("c2.c", 1, 1)]
        pool = _make_pool(files, tier_split=(0.75, 0.25, 0.0), per_call_cost=0.5)
        findings = pool.run()
        # No findings because Tier C is disabled
        assert findings == []
        assert pool.spent_per_tier["C"] == 0.0


# --- spent_per_tier reflects all phases ------------------------------------


class TestSpentPerTier:
    def test_three_tier_distribution(self):
        files = [
            _ft("a.c", 5, 5),  # A
            _ft("b.c", 2, 2),  # B
            _ft("ffmpeg.h", 1, 5),  # B (propagation)
            _ft("c.c", 1, 1),  # C
        ]
        pool = _make_pool(files, budget=10.0, per_call_cost=0.5)
        pool.run()
        spent = pool.spent_per_tier
        assert spent["A"] == pytest.approx(0.5)
        assert spent["B"] == pytest.approx(1.0)
        assert spent["C"] == pytest.approx(0.5)
        # Total
        assert pool.total_spent == pytest.approx(2.0)
