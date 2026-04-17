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

# --- Band promotion (spec 003) ---------------------------------------------

BAND_ORDER = ("fast", "standard", "deep")


@dataclass
class BandBudget:
    """Per-band cost caps in USD."""

    fast_usd: float = 5.0
    standard_usd: float = 25.0
    deep_usd: float = 100.0

    def for_band(self, band: str) -> float:
        return {"fast": self.fast_usd, "standard": self.standard_usd, "deep": self.deep_usd}[band]


@dataclass
class WorkItem:
    """A single (file, band, attempt) unit of work."""

    file_target: FileTarget
    band: str  # "fast" | "standard" | "deep"
    attempt: int = 0
    seed_transcript: str | None = None


def _file_rank(file_target: FileTarget) -> int:
    p = file_target.get("priority", 0.0)
    if p >= 4.0:
        return 5
    if p >= 3.0:
        return 4
    if p >= 2.0:
        return 3
    if p >= 1.0:
        return 2
    return 1


def _redundancy_for_rank(rank: int, override: int | None = None) -> int:
    if override is not None:
        return min(override, 5)
    if rank >= 5:
        return 3
    if rank >= 4:
        return 2
    return 1


def promotion_decision(
    findings: list,
    stop_reason: str,
    current_band: str,
    max_band: str,
) -> str | None:
    """Return the next band to promote to, or None."""
    if current_band == max_band:
        return None
    idx = BAND_ORDER.index(current_band)
    max_idx = BAND_ORDER.index(max_band)
    if idx >= max_idx:
        return None
    next_band = BAND_ORDER[idx + 1]

    if current_band == "fast":
        if findings or stop_reason == "budget_exhausted":
            return next_band
    elif current_band == "standard":
        confirmed_levels = {
            "static_corroboration",
            "crash_reproduced",
            "root_cause_explained",
            "exploit_demonstrated",
        }
        has_confirmed = any(f.get("evidence_level") in confirmed_levels for f in findings)
        if has_confirmed and stop_reason == "budget_exhausted":
            return next_band
    return None


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
    starting_band: str = "fast"  # "fast" | "standard" | "deep"
    max_band: str = "standard"  # highest band promotion can reach
    band_budget: BandBudget = field(default_factory=BandBudget)
    redundancy_override: int | None = None


def _extract_transcript(result: TargetResult) -> str:
    """Build a brief transcript summary from a TargetResult for seeding promoted runs."""
    parts: list[str] = []
    for f in result.findings:
        desc = f.get("description", "") if isinstance(f, dict) else str(f)
        parts.append(f"Finding: {desc[:200]}")
    if not parts:
        parts.append(f"Run completed with status={result.status}, stop_reason={result.stop_reason}")
    return "\n".join(parts)[:500]


# --- HunterPool -------------------------------------------------------------


class HunterPool:
    """Tiered parallel hunter executor with native async LLM scheduling."""

    def __init__(self, config: HuntPoolConfig):
        self.config = config
        for ft in self.config.files:
            ft["tier"] = assign_tier(ft)
        self._results: dict[str, TargetResult] = {}
        self._spent_per_tier: dict[str, float] = {"A": 0.0, "B": 0.0, "C": 0.0}
        self._spent_per_band: dict[str, float] = {"fast": 0.0, "standard": 0.0, "deep": 0.0}
        self._runs_per_band: dict[str, int] = {"fast": 0, "standard": 0, "deep": 0}
        self._promotion_counts: dict[str, int] = {"fast→standard": 0, "standard→deep": 0}
        self._cancelled = False

    def run(self) -> list[Finding]:
        return asyncio.run(self.arun())

    def _expand_to_work_items(self, files: list[FileTarget], band: str) -> list[WorkItem]:
        """Expand files into WorkItems respecting redundancy policy."""
        items: list[WorkItem] = []
        for ft in files:
            rank = _file_rank(ft)
            n = _redundancy_for_rank(rank, self.config.redundancy_override)
            for attempt in range(n):
                items.append(WorkItem(file_target=ft, band=band, attempt=attempt))
        return items

    async def arun(self) -> list[Finding]:
        """Run the full A → B → C pipeline with band promotion. Returns merged findings."""
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

        starting_band = self.config.starting_band

        work_items_a = self._expand_to_work_items(by_tier["A"], starting_band)
        spent_a = await self._run_tier_phase(work_items_a, "A", budget_a)
        budget_b += max(0.0, budget_a - spent_a)

        work_items_b = self._expand_to_work_items(by_tier["B"], starting_band)
        spent_b = await self._run_tier_phase(work_items_b, "B", budget_b)
        budget_c += max(0.0, budget_b - spent_b)

        if by_tier["C"] and tb.tier_c_fraction > 0:
            work_items_c = self._expand_to_work_items(by_tier["C"], starting_band)
            await self._run_tier_phase(work_items_c, "C", budget_c)

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
                for f in cast(list[Finding], tr.findings):
                    all_findings.append(f)
                if self.config.on_finding:
                    for f in cast(list[Finding], tr.findings):
                        try:
                            self.config.on_finding(f)
                        except Exception:
                            logger.debug("on_finding callback failed", exc_info=True)
        logger.info(
            "HunterPool finished: completed=%d findings=%d spent_tier=%s spent_band=%s promotions=%s",
            sum(1 for tr in target_results if tr.status == "completed"),
            len(all_findings),
            self.spent_per_tier,
            self.spent_per_band,
            self.promotion_counts,
        )
        return all_findings

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def spent_per_band(self) -> dict[str, float]:
        return dict(self._spent_per_band)

    @property
    def runs_per_band(self) -> dict[str, int]:
        return dict(self._runs_per_band)

    @property
    def promotion_counts(self) -> dict[str, int]:
        return dict(self._promotion_counts)

    @property
    def spent_per_tier(self) -> dict[str, float]:
        return dict(self._spent_per_tier)

    @property
    def total_spent(self) -> float:
        return sum(self._spent_per_tier.values())

    async def _run_tier_phase(
        self,
        work_items: list[WorkItem],
        tier: str,
        budget: float,
    ) -> float:
        if not work_items or budget <= 0:
            return 0.0

        timeout = (
            self.config.timeout_minutes_per_file * 60
            if self.config.timeout_minutes_per_file > 0
            else None
        )
        spent = 0.0
        in_flight: dict[asyncio.Task[TargetResult], WorkItem] = {}
        item_iter = iter(work_items)
        promotion_queue: list[WorkItem] = []

        def _submit_next() -> bool:
            nonlocal spent
            if self._cancelled or spent >= budget:
                return False
            wi: WorkItem | None = None
            try:
                wi = next(item_iter)
            except StopIteration:
                if promotion_queue:
                    wi = promotion_queue.pop(0)
            if wi is None:
                return False
            band_cost = self.config.band_budget.for_band(wi.band)
            key = f"{wi.file_target.get('path', '')}:{wi.band}:{wi.attempt}"
            task = asyncio.create_task(
                self._run_file_task(
                    wi.file_target,
                    cost_limit=band_cost,
                    tier=tier,
                    band=wi.band,
                    seed_transcript=wi.seed_transcript,
                )
            )
            in_flight[task] = wi
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
                for task, wi in list(in_flight.items()):
                    task.cancel()
                    key = wi.file_target.get("path", "")
                    self._results[key] = TargetResult(
                        target=key,
                        status="timeout",
                        error=f"Hunter did not complete within {timeout}s",
                        tier=tier,
                        band=wi.band,
                    )
                return spent

            for task in done:
                wi = in_flight.pop(task)
                key = wi.file_target.get("path", "")
                try:
                    result = await task
                except asyncio.CancelledError:
                    result = TargetResult(
                        target=key,
                        status="cancelled",
                        tier=tier,
                        band=wi.band,
                    )
                except Exception as exc:
                    logger.warning("tier %s hunter for %s failed: %s", tier, key, exc)
                    result = TargetResult(
                        target=key,
                        status="error",
                        error=str(exc),
                        tier=tier,
                        band=wi.band,
                    )
                self._results[f"{key}:{wi.band}:{wi.attempt}"] = result
                self._spent_per_tier[tier] += result.cost_usd
                self._spent_per_band[wi.band] = self._spent_per_band.get(wi.band, 0.0) + result.cost_usd
                self._runs_per_band[wi.band] = self._runs_per_band.get(wi.band, 0) + 1
                spent += result.cost_usd

                if result.status == "completed":
                    next_band = promotion_decision(
                        cast(list[Finding], result.findings),
                        result.stop_reason,
                        wi.band,
                        self.config.max_band,
                    )
                    if next_band:
                        promo_key = f"{wi.band}→{next_band}"
                        self._promotion_counts[promo_key] = self._promotion_counts.get(promo_key, 0) + 1
                        logger.info(
                            "Promoting %s from %s to %s band",
                            key, wi.band, next_band,
                        )
                        promotion_queue.append(WorkItem(
                            file_target=wi.file_target,
                            band=next_band,
                            attempt=wi.attempt,
                            seed_transcript=_extract_transcript(result),
                        ))

                _submit_next()

        return spent

    # --- Internals: hunter-specific logic the runner delegates back to ----

    async def _run_file_task(
        self,
        file_target: FileTarget,
        cost_limit: float,
        tier: str,
        band: str = "",
        seed_transcript: str | None = None,
    ) -> TargetResult:
        findings, cost, tokens, stop_reason = await self._run_one_hunter(
            file_target, cost_limit, seed_transcript=seed_transcript,
        )
        return TargetResult(
            target=file_target.get("path", ""),
            status="completed",
            findings=cast(list[dict], findings),
            cost_usd=cost,
            tokens_used=tokens,
            tier=tier,
            band=band,
            stop_reason=stop_reason,
        )

    async def _run_one_hunter(
        self,
        file_target: FileTarget,
        cost_limit: float,
        seed_transcript: str | None = None,
    ) -> tuple[list[Finding], float, int, str]:
        """Run a single hunter. Returns (findings, cost_usd, tokens_used, stop_reason)."""
        logger.info(
            "Hunter starting for %s (tier=%s cost_limit=%.2f)",
            file_target.get("path"),
            file_target.get("tier"),
            cost_limit,
        )

        sandbox = None
        if self.config.sandbox_factory is not None:
            try:
                sandbox = await asyncio.to_thread(self.config.sandbox_factory)
            except Exception as e:
                logger.warning("sandbox_factory failed for %s: %s", file_target.get("path"), e)

        try:
            hunter, ctx = self._build_hunter_for_file(
                file_target, sandbox, budget_usd=cost_limit, seed_transcript=seed_transcript,
            )
            run_result = await hunter.arun()

            logger.info(
                "Hunter completed for %s findings=%d cost=%.4f stop=%s",
                file_target.get("path"),
                len(run_result.findings),
                run_result.cost_usd,
                run_result.stop_reason,
            )
            return (
                list(run_result.findings),
                run_result.cost_usd,
                run_result.tokens_used,
                run_result.stop_reason,
            )
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

    def _build_hunter_for_file(
        self,
        file_target: FileTarget,
        sandbox: Any,
        budget_usd: float = 0.0,
        seed_transcript: str | None = None,
    ) -> Any:
        """Either invoke the user-supplied hunter_factory or import build_hunter_agent."""
        session_id = f"{self.config.session_id_prefix}-{uuid.uuid4().hex[:8]}"

        if self.config.hunter_factory is not None:
            return self.config.hunter_factory(file_target, sandbox, session_id)

        global _DEFAULT_HUNTER_FACTORY
        if _DEFAULT_HUNTER_FACTORY is None:
            from .hunter import build_hunter_agent

            _DEFAULT_HUNTER_FACTORY = build_hunter_agent

        if self.config.llm is None:
            raise ValueError("HuntPoolConfig.llm is required when hunter_factory is None")

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
            budget_usd=budget_usd,
            seed_transcript=seed_transcript,
        )
