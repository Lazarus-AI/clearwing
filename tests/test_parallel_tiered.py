"""Production tests for the v0.4 tiered execution mode on ParallelExecutor.

Covers:
    - dispatch to _run_tiered when tier_budget + item_tier_fn are set
    - three-phase A/B/C execution with rollover
    - per-tier cost caps via item_cost_limits
    - spent_per_tier tracking
    - sliding-window submission under budget pressure
    - tier="" stays in flat mode (backwards compat)
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from clearwing.runners.parallel.executor import (
    ParallelExecutor,
    ParallelScanConfig,
    TierBudget,
)


@dataclass
class _FakeResult:
    exit_code: int = 0
    target: str = ""
    findings: list = None
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    tokens_used: int = 0

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class _FixedCostRunner:
    """A runner with a fixed per-call cost and one-finding-per-run."""

    def __init__(self, item, config, cost: float = 0.5):
        self.item = item
        self.cost = cost

    def run(self) -> _FakeResult:
        return _FakeResult(
            exit_code=0,
            target=str(self.item),
            findings=[{"description": f"finding for {self.item}"}],
            cost_usd=self.cost,
        )


def _item(name: str, tier: str, priority: float = 1.0) -> dict:
    return {"path": name, "tier": tier, "priority": priority}


# --- Dispatch: flat vs tiered ----------------------------------------------


class TestDispatch:
    def test_no_tier_budget_runs_flat(self):
        """Legacy path — no tier_budget set → flat execution."""
        config = ParallelScanConfig(
            targets=["a", "b"],
            max_parallel=2,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.1),
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert len(results) == 2
        assert executor.spent_per_tier == {"A": 0.0, "B": 0.0, "C": 0.0}

    def test_tier_budget_without_tier_fn_runs_flat(self):
        """Partial config — tier_budget set but no item_tier_fn → flat."""
        config = ParallelScanConfig(
            targets=["a", "b"],
            max_parallel=2,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.1),
            tier_budget=TierBudget(),
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert len(results) == 2
        # spent_per_tier stays at zero in flat mode
        assert executor.spent_per_tier == {"A": 0.0, "B": 0.0, "C": 0.0}

    def test_tier_budget_and_tier_fn_runs_tiered(self):
        items = [
            _item("a.c", "A"),
            _item("b.c", "B"),
            _item("c.c", "C"),
        ]
        config = ParallelScanConfig(
            items=items,
            max_parallel=3,
            total_cost_limit=10.0,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.5),
            tier_budget=TierBudget(),
            item_tier_fn=lambda f: f["tier"],
            item_key_fn=lambda f: f["path"],
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert len(results) == 3
        # Every TargetResult has its tier stamped on
        tiers = {r.target: r.tier for r in results}
        assert tiers == {"a.c": "A", "b.c": "B", "c.c": "C"}
        spent = executor.spent_per_tier
        assert spent["A"] == pytest.approx(0.5)
        assert spent["B"] == pytest.approx(0.5)
        assert spent["C"] == pytest.approx(0.5)


# --- Budget enforcement ----------------------------------------------------


class TestTierBudgetEnforcement:
    def test_tier_a_stops_at_budget(self):
        # 100 items, $1 each, $7 for tier A → max ~7 items complete
        items = [_item(f"a{i}.c", "A") for i in range(100)]
        config = ParallelScanConfig(
            items=items,
            max_parallel=1,
            total_cost_limit=10.0,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=1.0),
            tier_budget=TierBudget(),
            item_tier_fn=lambda f: f["tier"],
            item_key_fn=lambda f: f["path"],
        )
        executor = ParallelExecutor(config)
        executor.run()
        spent_a = executor.spent_per_tier["A"]
        # Sliding-window: at most $7 + one extra in-flight → 8
        assert 6.0 <= spent_a <= 8.0

    def test_rollover_a_to_b(self):
        # 1 item in A ($0.5) + 4 items in B ($0.5 each) = $2.5
        # Budget: $10 total → A gets $7, B gets $2.5. After A spends $0.5,
        # $6.5 rolls over to B → B has $9. All 4 B items fit.
        items = [
            _item("a.c", "A"),
            _item("b1.c", "B"),
            _item("b2.c", "B"),
            _item("b3.c", "B"),
            _item("b4.c", "B"),
        ]
        config = ParallelScanConfig(
            items=items,
            max_parallel=1,
            total_cost_limit=10.0,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.5),
            tier_budget=TierBudget(),
            item_tier_fn=lambda f: f["tier"],
            item_key_fn=lambda f: f["path"],
        )
        executor = ParallelExecutor(config)
        executor.run()
        spent = executor.spent_per_tier
        assert spent["A"] == pytest.approx(0.5)
        assert spent["B"] == pytest.approx(2.0)  # all 4 B items completed

    def test_skip_tier_c(self):
        """tier_c_fraction=0 → no Tier C items run."""
        items = [_item("c1.c", "C"), _item("c2.c", "C")]
        config = ParallelScanConfig(
            items=items,
            max_parallel=1,
            total_cost_limit=10.0,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.5),
            tier_budget=TierBudget(
                tier_a_fraction=0.75,
                tier_b_fraction=0.25,
                tier_c_fraction=0.0,
            ),
            item_tier_fn=lambda f: f["tier"],
            item_key_fn=lambda f: f["path"],
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert results == []  # no C items ran
        assert executor.spent_per_tier["C"] == 0.0


# --- Tier stamping on results ----------------------------------------------


class TestTierStamping:
    def test_tier_field_on_target_result(self):
        items = [_item("x.c", "A"), _item("y.c", "B"), _item("z.c", "C")]
        config = ParallelScanConfig(
            items=items,
            max_parallel=3,
            total_cost_limit=10.0,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.1),
            tier_budget=TierBudget(),
            item_tier_fn=lambda f: f["tier"],
            item_key_fn=lambda f: f["path"],
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        for r in results:
            assert r.tier in ("A", "B", "C")
            assert r.tier != ""  # flat mode would leave it blank

    def test_flat_mode_leaves_tier_blank(self):
        config = ParallelScanConfig(
            targets=["a", "b"],
            max_parallel=2,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.1),
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        for r in results:
            assert r.tier == ""


# --- Invalid tier handling -------------------------------------------------


class TestInvalidTierFallback:
    def test_unknown_tier_falls_back_to_c(self):
        """An item with an unknown tier string should land in Tier C."""
        items = [{"path": "weird.c", "tier": "Z"}]
        config = ParallelScanConfig(
            items=items,
            max_parallel=1,
            total_cost_limit=10.0,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.1),
            tier_budget=TierBudget(),
            item_tier_fn=lambda f: f["tier"],
            item_key_fn=lambda f: f["path"],
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert len(results) == 1
        assert results[0].tier == "C"


# --- items list takes precedence over targets -----------------------------


class TestItemsOverridesTargets:
    def test_items_wins(self):
        """When both targets and items are set, items wins."""
        items = [{"path": "x.c"}]
        config = ParallelScanConfig(
            targets=["not-used"],
            items=items,
            max_parallel=1,
            runner_factory=lambda i, c: _FixedCostRunner(i, c, cost=0.1),
        )
        executor = ParallelExecutor(config)
        results = executor.run()
        assert len(results) == 1
        # The key comes from the items list, not the targets list
        assert results[0].target != "not-used"
