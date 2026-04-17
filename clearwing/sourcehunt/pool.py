"""HunterPool: tiered parallel fan-out with budget rollover.

v0.4: HunterPool is now a thin adapter over clearwing/runners/parallel/executor.py
— the generalized ParallelExecutor handles both network-pentest (flat) and
sourcehunt (tiered) execution. HunterPool's job is:

    1. Convert a HuntPoolConfig into a ParallelScanConfig with the right
       sourcehunt seams (file tier function, per-tier cost caps, etc.)
    2. Wrap each file in a runner that spawns a sandbox + hunter graph
       and streams it to completion
    3. Extract Finding objects from the resulting TargetResults

The existing HunterPool API (run() → list[Finding], spent_per_tier,
total_spent, cancel, assign_tier) is preserved.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from clearwing.runners.parallel.executor import (
    TargetResult,
)
from clearwing.runners.parallel.executor import (
    TierBudget as _ExecutorTierBudget,
)

from .state import FileTarget, Finding

logger = logging.getLogger(__name__)
_DEFAULT_HUNTER_FACTORY = None


# Re-export so existing callers that import from pool.py still work
TierBudget = _ExecutorTierBudget


# --- Tier assignment --------------------------------------------------------


def assign_tier(file_target: FileTarget) -> Literal["A", "B", "C"]:
    """Return 'A', 'B', or 'C' from the file's priority.

    Thresholds:
        priority >= 3.0 → A
        priority >= 2.0 → B
        otherwise       → C

    Calibrated so:
      - (surface=4, influence=2, reach=3) → 0.5*4 + 0.2*2 + 0.3*3 = 3.3 → A
      - (surface=2, influence=2, reach=3) → 0.5*2 + 0.2*2 + 0.3*3 = 2.3 → B
      - (surface=1, influence=1, reach=3) → 0.5*1 + 0.2*1 + 0.3*3 = 1.6 → C
      - (surface=1, influence=5, reach=3) → 0.5*1 + 0.2*5 + 0.3*3 = 2.4 → B
        (the FFmpeg-style propagation case lands in Tier B, never Tier C)
    """
    p = file_target.get("priority", 0.0)
    if p >= 3.0:
        return "A"
    if p >= 2.0:
        return "B"
    return "C"


# --- Config -----------------------------------------------------------------


@dataclass
class HuntPoolConfig:
    files: list[FileTarget]
    repo_path: str
    sandbox_factory: Callable | None = None
    # Callable[[], SandboxContainer] — a fresh
    # container per hunter. None → host-fallback.
    hunter_factory: Callable | None = None
    # Callable[[FileTarget, sandbox, session_id], (graph, ctx)]
    # If None, the pool will import build_hunter_agent
    # at run time and require an llm in the config.
    llm: object | None = None  # Required if hunter_factory is None
    max_parallel: int = 8
    budget_usd: float = 0.0
    tier_budget: TierBudget = field(default_factory=TierBudget)
    cost_limit_per_file_a: float = 0.25
    cost_limit_per_file_b: float = 0.15
    cost_limit_per_file_c: float = 0.04
    timeout_minutes_per_file: int = 0
    on_finding: Callable | None = None
    session_id_prefix: str = "hunt"
    sandbox_manager: Any = None
    # v0.2 seeded-crash lookup: {repo_relative_file_path: {report, target_function, ...}}
    seeded_crashes_by_file: dict = field(default_factory=dict)
    # v0.2 Semgrep hints: {repo_relative_file_path: [semgrep_finding_dicts]}
    semgrep_hints_by_file: dict = field(default_factory=dict)
    agent_mode: str = "constrained"  # "constrained" | "deep"
    prompt_mode: str = "unconstrained"  # "unconstrained" | "specialist"
    campaign_hint: str | None = None
    exploit_mode: bool = False


# --- HunterPool -------------------------------------------------------------


class HunterPool:
    """Tiered parallel hunter executor with native async LLM scheduling."""

    def __init__(self, config: HuntPoolConfig):
        self.config = config
        for ft in self.config.files:
            ft["tier"] = assign_tier(ft)
        self._results: dict[str, TargetResult] = {}
        self._spent_per_tier: dict[str, float] = {"A": 0.0, "B": 0.0, "C": 0.0}
        self._cancelled = False

    def run(self) -> list[Finding]:
        return asyncio.run(self.arun())

    async def arun(self) -> list[Finding]:
        """Run the full A → B → C pipeline. Returns merged findings."""
        logger.info("HunterPool dispatching %d tiered file tasks", len(self.config.files))
        by_tier: dict[str, list[FileTarget]] = {"A": [], "B": [], "C": []}
        for item in self.config.files:
            by_tier[item.get("tier", "C")].append(item)

        total_budget = self.config.budget_usd
        tb = self.config.tier_budget
        if total_budget <= 0:
            budget_a = budget_b = budget_c = float("inf")
        else:
            budget_a = total_budget * tb.tier_a_fraction
            budget_b = total_budget * tb.tier_b_fraction
            budget_c = total_budget * tb.tier_c_fraction

        spent_a = await self._run_tier_phase(
            by_tier["A"],
            "A",
            budget_a,
            self.config.cost_limit_per_file_a,
        )
        budget_b += max(0.0, budget_a - spent_a)

        spent_b = await self._run_tier_phase(
            by_tier["B"],
            "B",
            budget_b,
            self.config.cost_limit_per_file_b,
        )
        budget_c += max(0.0, budget_b - spent_b)

        if by_tier["C"] and tb.tier_c_fraction > 0:
            await self._run_tier_phase(
                by_tier["C"],
                "C",
                budget_c,
                self.config.cost_limit_per_file_c,
            )

        target_results = list(self._results.values())
        status_counts = Counter(tr.status for tr in target_results)
        if status_counts:
            logger.info("HunterPool result statuses: %s", dict(status_counts))
        error_results = [tr for tr in target_results if tr.status == "error"]
        for tr in error_results[:10]:
            logger.warning("HunterPool error for %s: %s", tr.target, tr.error or "(no error text)")
        all_findings: list[Finding] = []
        for tr in target_results:
            if tr.status == "completed":
                # TargetResult.findings is typed as list[dict] by the
                # ParallelExecutor contract, but hunter_tools stashes real
                # `Finding` dataclass instances. Cast at the boundary.
                for f in cast(list[Finding], tr.findings):
                    all_findings.append(f)
                if self.config.on_finding:
                    for f in cast(list[Finding], tr.findings):
                        try:
                            self.config.on_finding(f)
                        except Exception:
                            logger.debug("on_finding callback failed", exc_info=True)
        logger.info(
            "HunterPool finished: completed=%d findings=%d spent=%s",
            sum(1 for tr in target_results if tr.status == "completed"),
            len(all_findings),
            self.spent_per_tier,
        )
        return all_findings

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def spent_per_tier(self) -> dict[str, float]:
        return dict(self._spent_per_tier)

    @property
    def total_spent(self) -> float:
        return sum(self._spent_per_tier.values())

    async def _run_tier_phase(
        self,
        items: list[FileTarget],
        tier: str,
        budget: float,
        cost_per_item: float,
    ) -> float:
        if not items or budget <= 0:
            return 0.0

        timeout = (
            self.config.timeout_minutes_per_file * 60
            if self.config.timeout_minutes_per_file > 0
            else None
        )
        spent = 0.0
        in_flight: dict[asyncio.Task[TargetResult], str] = {}
        item_iter = iter(items)

        def _submit_next() -> bool:
            nonlocal spent
            if self._cancelled or spent >= budget:
                return False
            try:
                nxt = next(item_iter)
            except StopIteration:
                return False
            key = nxt.get("path", "")
            task = asyncio.create_task(
                self._run_file_task(
                    nxt,
                    cost_limit=(cost_per_item or 0.0),
                    tier=tier,
                )
            )
            in_flight[task] = key
            return True

        for _ in range(max(1, self.config.max_parallel)):
            if not _submit_next():
                break

        while in_flight:
            done, _pending = await asyncio.wait(
                list(in_flight.keys()),
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if timeout is not None and not done:
                logger.warning(
                    "tier %s had no completed hunters within %ss; marking %d in-flight items as timeout",
                    tier,
                    timeout,
                    len(in_flight),
                )
                for task, key in list(in_flight.items()):
                    task.cancel()
                    self._results[key] = TargetResult(
                        target=key,
                        status="timeout",
                        error=f"Hunter did not complete within {timeout}s",
                        tier=tier,
                    )
                for pending_item in item_iter:
                    pending_key = pending_item.get("path", "")
                    self._results[pending_key] = TargetResult(
                        target=pending_key,
                        status="timeout",
                        error=f"Tier {tier} aborted after no completions within {timeout}s",
                        tier=tier,
                    )
                return spent

            for task in done:
                key = in_flight.pop(task)
                try:
                    result = await task
                except asyncio.CancelledError:
                    result = TargetResult(
                        target=key,
                        status="cancelled",
                        tier=tier,
                    )
                except Exception as exc:
                    logger.warning("tier %s hunter for %s failed: %s", tier, key, exc)
                    result = TargetResult(
                        target=key,
                        status="error",
                        error=str(exc),
                        tier=tier,
                    )
                self._results[key] = result
                self._spent_per_tier[tier] += result.cost_usd
                spent += result.cost_usd
                _submit_next()

        return spent

    # --- Internals: hunter-specific logic the runner delegates back to ----

    async def _run_file_task(
        self,
        file_target: FileTarget,
        cost_limit: float,
        tier: str,
    ) -> TargetResult:
        findings, cost, tokens = await self._run_one_hunter(file_target, cost_limit)
        return TargetResult(
            target=file_target.get("path", ""),
            status="completed",
            findings=cast(list[dict], findings),
            cost_usd=cost,
            tokens_used=tokens,
            tier=tier,
        )

    async def _run_one_hunter(
        self,
        file_target: FileTarget,
        cost_limit: float,
    ) -> tuple[list[Finding], float, int]:
        """Run a single hunter. Returns (findings, cost_usd, tokens_used)."""
        logger.info(
            "Hunter starting for %s (tier=%s cost_limit=%.2f)",
            file_target.get("path"),
            file_target.get("tier"),
            cost_limit,
        )

        # Spawn a fresh sandbox if a factory is provided
        sandbox = None
        if self.config.sandbox_factory is not None:
            try:
                sandbox = await asyncio.to_thread(self.config.sandbox_factory)
            except Exception as e:
                logger.warning("sandbox_factory failed for %s: %s", file_target.get("path"), e)

        try:
            hunter, ctx = self._build_hunter_for_file(file_target, sandbox)
            findings, cost_used, tokens_used = await hunter.arun()

            logger.info(
                "Hunter completed for %s findings=%d cost=%.4f",
                file_target.get("path"),
                len(findings),
                cost_used,
            )
            return list(findings), cost_used, tokens_used
        finally:
            try:
                if "ctx" in locals():
                    ctx.cleanup_variants()
            except Exception:
                logger.debug("Variant sandbox cleanup failed", exc_info=True)
            if sandbox is not None:
                try:
                    await asyncio.to_thread(sandbox.stop)
                except Exception:
                    pass

    def _build_hunter_for_file(self, file_target: FileTarget, sandbox: Any) -> Any:
        """Either invoke the user-supplied hunter_factory or import build_hunter_agent."""
        session_id = f"{self.config.session_id_prefix}-{uuid.uuid4().hex[:8]}"

        if self.config.hunter_factory is not None:
            return self.config.hunter_factory(file_target, sandbox, session_id)

        # Default: use build_hunter_agent + the configured llm
        global _DEFAULT_HUNTER_FACTORY
        if _DEFAULT_HUNTER_FACTORY is None:
            from .hunter import build_hunter_agent

            _DEFAULT_HUNTER_FACTORY = build_hunter_agent

        if self.config.llm is None:
            raise ValueError("HuntPoolConfig.llm is required when hunter_factory is None")

        # Pull seeded crash / semgrep hints for this file if available
        file_path = file_target.get("path", "")
        seeded_crash = self.config.seeded_crashes_by_file.get(file_path)
        semgrep_hints = self.config.semgrep_hints_by_file.get(file_path)

        return _DEFAULT_HUNTER_FACTORY(
            file_target=file_target,
            repo_path=self.config.repo_path,
            sandbox=sandbox,
            llm=self.config.llm,  # type: ignore[arg-type]
            session_id=session_id,
            seeded_crash=seeded_crash,
            semgrep_hints=semgrep_hints,
            sandbox_manager=self.config.sandbox_manager,
            agent_mode=self.config.agent_mode,
            prompt_mode=self.config.prompt_mode,
            campaign_hint=self.config.campaign_hint,
            exploit_mode=self.config.exploit_mode,
        )
