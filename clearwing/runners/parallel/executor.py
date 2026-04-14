from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import (
    FIRST_COMPLETED,
    Future,
    ThreadPoolExecutor,
    wait,
)
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TargetResult:
    """Result from scanning a single target (or item, for tiered runs)."""

    target: str
    status: str  # completed, error, timeout, cancelled
    session_id: str = ""
    findings: list[dict] = field(default_factory=list)
    flags_found: list[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    tokens_used: int = 0
    error: str = ""
    # v0.4: which tier this result came from (A/B/C or "" for flat runs).
    # Used by tiered callers to build a spent_per_tier breakdown.
    tier: str = ""


@dataclass
class TierBudget:
    """Fractional budget split across tiers. Must sum to ~1.0.

    v0.4: lives in the executor module so both network-pentest and
    source-hunt pools can share it without duplication.
    """

    tier_a_fraction: float = 0.70
    tier_b_fraction: float = 0.25
    tier_c_fraction: float = 0.05

    def __post_init__(self):
        total = self.tier_a_fraction + self.tier_b_fraction + self.tier_c_fraction
        if not (0.95 <= total <= 1.05):
            raise ValueError(f"TierBudget fractions must sum to ~1.0, got {total:.3f}")


@dataclass
class ParallelScanConfig:
    """Configuration for a parallel scan.

    Supports two execution modes:
        flat  — submit every target to a ThreadPoolExecutor, wait for all.
                Used by the network-pentest CICDRunner path.
        tiered — split items into Tier A/B/C, run three phases with
                 sliding-window submission and budget rollover. Used by
                 the sourcehunt HunterPool via the factory seam.

    Tiered mode is enabled by setting `tier_budget` AND `item_tier_fn`.
    Otherwise the executor runs in flat mode (backwards compatible).
    """

    # Legacy network-pentest field. Still accepted — copied into `items`
    # at run time when `items` is not set explicitly.
    targets: list[str] = field(default_factory=list)
    # Generic item list — takes precedence over `targets` when set. Items
    # can be anything the runner_factory accepts (e.g. FileTarget dicts).
    items: list[Any] | None = None
    max_parallel: int = 3
    model: str = "claude-sonnet-4-6"
    depth: str = "standard"
    timeout_minutes: int = 30
    cost_limit_per_target: float = 0.0  # 0 = no limit
    total_cost_limit: float = 0.0  # 0 = no limit
    on_target_complete: Callable | None = None
    base_url: str | None = None
    api_key: str | None = None
    # R3: injectable runner factory. Receives (item, config) and returns
    # an object with a `.run()` method that yields a CICDResult-shaped
    # result (exit_code, findings, cost_usd, tokens_used).
    runner_factory: Callable | None = None
    # v0.4 tiered execution
    tier_budget: TierBudget | None = None
    item_tier_fn: Callable[[Any], str] | None = None  # item → "A"|"B"|"C"
    item_key_fn: Callable[[Any], str] | None = None  # item → str (for logging)
    # Per-tier cost-per-item caps. Keys: "A"|"B"|"C". Missing tiers fall
    # back to cost_limit_per_target.
    item_cost_limits: dict[str, float] = field(default_factory=dict)


class ParallelExecutor:
    """Execute penetration testing against multiple targets in parallel.

    Each target runs in its own thread with its own agent instance.
    Memory is shared across targets via the EpisodicMemory and SemanticMemory
    SQLite databases (WAL mode ensures concurrent access).
    """

    def __init__(self, config: ParallelScanConfig):
        self.config = config
        self._results: dict[str, TargetResult] = {}
        self._lock = threading.Lock()
        self._total_cost = 0.0
        self._spent_per_tier: dict[str, float] = {"A": 0.0, "B": 0.0, "C": 0.0}
        self._cancelled = False
        self._futures: dict[str, Future] = {}

    # ------------------------------------------------------------------
    # Item resolution — items takes precedence over legacy `targets`
    # ------------------------------------------------------------------

    @property
    def _effective_items(self) -> list[Any]:
        """Return the actual list of items to execute.

        - If `items` is set, use that.
        - Else use `targets` (legacy network-pentest path).
        """
        if self.config.items is not None:
            return list(self.config.items)
        return list(self.config.targets)

    def _item_key(self, item: Any) -> str:
        """Return a stable string key for an item (for result dict indexing)."""
        if self.config.item_key_fn is not None:
            try:
                return str(self.config.item_key_fn(item))
            except Exception:
                pass
        if isinstance(item, str):
            return item
        if isinstance(item, dict) and "path" in item:
            return str(item["path"])
        return str(item)

    def _item_tier(self, item: Any) -> str:
        """Return 'A'|'B'|'C' for an item using the configured tier function."""
        if self.config.item_tier_fn is None:
            return ""
        try:
            return str(self.config.item_tier_fn(item))
        except Exception:
            return "C"

    # ------------------------------------------------------------------
    # run() — dispatch flat vs tiered
    # ------------------------------------------------------------------

    def run(self) -> list[TargetResult]:
        """Execute scans against all items with bounded parallelism.

        Dispatches to _run_tiered() when tier_budget + item_tier_fn are
        configured, else to _run_flat() (backwards-compatible legacy path).
        """
        if self.config.tier_budget is not None and self.config.item_tier_fn is not None:
            return self._run_tiered()
        return self._run_flat()

    # ------------------------------------------------------------------
    # _run_flat: the legacy path. Submits everything, waits for all.
    # ------------------------------------------------------------------

    def _run_flat(self) -> list[TargetResult]:
        items = self._effective_items
        with ThreadPoolExecutor(max_workers=self.config.max_parallel) as pool:
            for item in items:
                if self._cancelled:
                    break
                key = self._item_key(item)
                future = pool.submit(self._scan_item, item)
                self._futures[key] = future

            for key, future in self._futures.items():
                try:
                    result = future.result(timeout=self.config.timeout_minutes * 60)
                    with self._lock:
                        self._results[key] = result
                except TimeoutError:
                    with self._lock:
                        self._results[key] = TargetResult(
                            target=key,
                            status="timeout",
                            error=f"Scan timed out after {self.config.timeout_minutes} minutes",
                        )
                except Exception as e:
                    with self._lock:
                        self._results[key] = TargetResult(
                            target=key,
                            status="error",
                            error=str(e),
                        )

        return list(self._results.values())

    # ------------------------------------------------------------------
    # _run_tiered: three-phase tiered execution with budget rollover
    # ------------------------------------------------------------------

    def _run_tiered(self) -> list[TargetResult]:
        """Run items in three phases (A → B → C) with budget rollover.

        Sliding-window submission — submit up to max_parallel, wait for at
        least one to complete, check the tier budget, submit more. This is
        the only way to enforce a real per-tier spend cap when item costs
        aren't known until the runner completes.
        """
        items = self._effective_items
        by_tier: dict[str, list[Any]] = {"A": [], "B": [], "C": []}
        for item in items:
            tier = self._item_tier(item) or "C"
            if tier not in by_tier:
                tier = "C"
            by_tier[tier].append(item)

        total_budget = self.config.total_cost_limit
        tb = self.config.tier_budget
        budget_a = total_budget * tb.tier_a_fraction
        budget_b = total_budget * tb.tier_b_fraction
        budget_c = total_budget * tb.tier_c_fraction

        spent_a = self._run_tier_phase(
            by_tier["A"],
            "A",
            budget_a,
            cost_per_item=self.config.item_cost_limits.get("A", 0.0),
        )
        # Roll over unused A budget into B
        budget_b += max(0.0, budget_a - spent_a)

        spent_b = self._run_tier_phase(
            by_tier["B"],
            "B",
            budget_b,
            cost_per_item=self.config.item_cost_limits.get("B", 0.0),
        )
        # Roll over unused B budget into C
        budget_c += max(0.0, budget_b - spent_b)

        # Skip Tier C entirely if its fraction is zero (or no items)
        if by_tier["C"] and tb.tier_c_fraction > 0:
            self._run_tier_phase(
                by_tier["C"],
                "C",
                budget_c,
                cost_per_item=self.config.item_cost_limits.get("C", 0.0),
            )

        return list(self._results.values())

    def _run_tier_phase(
        self,
        items: list[Any],
        tier: str,
        budget: float,
        cost_per_item: float,
    ) -> float:
        """Execute one tier's items with sliding-window submission.

        Returns the amount actually spent in this tier.
        """
        if not items or budget <= 0:
            return 0.0

        max_parallel = max(1, self.config.max_parallel)
        timeout = self.config.timeout_minutes * 60
        spent = 0.0

        with ThreadPoolExecutor(max_workers=max_parallel) as pool:
            in_flight: dict[Future, tuple[str, Any]] = {}
            item_iter = iter(items)

            def _submit_next() -> bool:
                nonlocal spent
                with self._lock:
                    if self._cancelled:
                        return False
                if spent >= budget:
                    return False
                try:
                    nxt = next(item_iter)
                except StopIteration:
                    return False
                key = self._item_key(nxt)
                future = pool.submit(
                    self._scan_item,
                    nxt,
                    cost_limit_override=cost_per_item or None,
                    tier_label=tier,
                )
                in_flight[future] = (key, nxt)
                return True

            # Prime the window
            for _ in range(max_parallel):
                if not _submit_next():
                    break

            while in_flight:
                done, _pending = wait(
                    list(in_flight.keys()),
                    timeout=timeout,
                    return_when=FIRST_COMPLETED,
                )
                for future in done:
                    key, _item = in_flight.pop(future)
                    try:
                        result = future.result(timeout=0)
                    except Exception as e:
                        logger.warning("tier %s runner for %s failed: %s", tier, key, e)
                        with self._lock:
                            self._results[key] = TargetResult(
                                target=key,
                                status="error",
                                error=str(e),
                                tier=tier,
                            )
                        continue
                    # Stamp the tier onto the result
                    result.tier = tier
                    with self._lock:
                        self._results[key] = result
                        self._spent_per_tier[tier] += result.cost_usd
                    spent += result.cost_usd
                    # Submit one more if there's room and budget
                    _submit_next()

        return spent

    # ------------------------------------------------------------------
    # _scan_item — formerly _scan_target. Handles both flat and tiered.
    # ------------------------------------------------------------------

    def _scan_item(
        self,
        item: Any,
        cost_limit_override: float | None = None,
        tier_label: str = "",
    ) -> TargetResult:
        """Run one item through the configured runner factory.

        `item` may be a string target (legacy path) or any object the
        factory accepts (tiered path).
        """
        key = self._item_key(item)
        return self._scan_target_legacy(item, key, cost_limit_override, tier_label)

    def _scan_target_legacy(
        self,
        item: Any,
        key: str,
        cost_limit_override: float | None,
        tier_label: str,
    ) -> TargetResult:
        """Run one item's runner and produce a TargetResult.

        Accepts arbitrary items (targets or FileTarget dicts) and dispatches
        via `runner_factory` when set, else falls back to CICDRunner (legacy).
        """
        start = time.time()

        if self._cancelled:
            return TargetResult(target=key, status="cancelled", tier=tier_label)

        # Check total cost limit (belt-and-suspenders with the per-tier gate)
        if self.config.total_cost_limit > 0:
            with self._lock:
                if self._total_cost >= self.config.total_cost_limit:
                    return TargetResult(
                        target=key,
                        status="cancelled",
                        error="Total cost limit reached",
                        tier=tier_label,
                    )

        try:
            if self.config.runner_factory is not None:
                runner = self.config.runner_factory(item, self.config)
            else:
                # Legacy CICDRunner path — item must be a target string
                from clearwing.runners.cicd.runner import CICDRunner

                runner = CICDRunner(
                    target=str(item),
                    depth=self.config.depth,
                    model=self.config.model,
                    cost_limit=(cost_limit_override or self.config.cost_limit_per_target or None),
                    timeout_minutes=self.config.timeout_minutes,
                    base_url=self.config.base_url,
                    api_key=self.config.api_key,
                )
            cicd_result = runner.run()

            duration = time.time() - start

            result = TargetResult(
                target=key,
                status="completed" if cicd_result.exit_code >= 0 else "error",
                session_id=getattr(runner, "_session_id", ""),
                findings=cicd_result.findings,
                duration_seconds=duration,
                cost_usd=cicd_result.cost_usd,
                tokens_used=cicd_result.tokens_used,
                tier=tier_label,
            )

            # Update total cost
            with self._lock:
                self._total_cost += result.cost_usd

            # Callback
            if self.config.on_target_complete:
                try:
                    self.config.on_target_complete(result)
                except Exception:
                    logger.debug("on_target_complete callback failed", exc_info=True)

            return result

        except Exception as e:
            return TargetResult(
                target=key,
                status="error",
                error=str(e),
                duration_seconds=time.time() - start,
                tier=tier_label,
            )

    # Backwards-compat alias — preserve the old name for any external callers
    # that reach into the private method.
    _scan_target = _scan_item

    def cancel(self):
        """Cancel all pending scans."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    @property
    def total_cost(self) -> float:
        with self._lock:
            return self._total_cost

    @property
    def completed_count(self) -> int:
        with self._lock:
            return len(self._results)

    @property
    def total_count(self) -> int:
        return len(self._effective_items)

    @property
    def spent_per_tier(self) -> dict[str, float]:
        """Per-tier spend breakdown. Only meaningful in tiered mode.

        Returns {"A": usd, "B": usd, "C": usd}. In flat mode, all three
        stay at 0.0.
        """
        with self._lock:
            return dict(self._spent_per_tier)

    def get_summary(self) -> str:
        """Human-readable summary of all results."""
        lines = [f"Parallel Scan Summary ({self.completed_count}/{self.total_count} targets)"]
        lines.append(f"Total cost: ${self._total_cost:.4f}")
        lines.append("")

        for result in self._results.values():
            finding_count = len(result.findings)
            status_icon = {
                "completed": "OK",
                "error": "ERR",
                "timeout": "T/O",
                "cancelled": "---",
            }.get(result.status, "?")
            lines.append(
                f"  [{status_icon}] {result.target}: {result.status} "
                f"({finding_count} findings, ${result.cost_usd:.4f}, {result.duration_seconds:.0f}s)"
            )
            if result.error:
                lines.append(f"    Error: {result.error}")

        return "\n".join(lines)
