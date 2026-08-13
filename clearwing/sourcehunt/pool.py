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
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from clearwing.core.event_payloads import HuntProgressPayload
from clearwing.core.events import EventBus
from clearwing.llm import ProviderExhaustedError, ProviderExhaustionState
from clearwing.llm.budget import BudgetExceeded, spend_metadata
from clearwing.runners.parallel.executor import (
    TargetResult,
)
from clearwing.runners.parallel.executor import (
    TierBudget as _ExecutorTierBudget,
)

from .instrumentation import stable_run_id
from .resume import CompletedWork, SourceHuntResumeStore, deterministic_work_id
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
    entry_point: Any = None  # EntryPoint | None — spec 004
    seed_context: str | None = None  # spec 004 seed corpus

    def stable_identifier(self, run_id: str, tier: str) -> str:
        return deterministic_work_id(
            run_id,
            file=str(self.file_target.get("path") or ""),
            tier=tier,
            band=self.band,
            attempt=self.attempt,
            entry_point=HunterPool._entry_point_payload(self),
            seed_context=self.seed_context,
            seed_transcript=self.seed_transcript,
        )


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
    entry_points_by_file: dict = field(default_factory=dict)  # {path: [EntryPoint]}
    seed_corpus_by_file: dict = field(default_factory=dict)  # {path: [SeedCorpusEntry]}
    shard_entry_points: bool = False
    findings_pool: Any = None  # FindingsPool | None — spec 005
    trajectory_root: str | Path | None = None
    instrumentation: Any = None  # SourceHuntInstrumentation | None
    resume_store: SourceHuntResumeStore | None = None
    prior_spend_per_tier: dict[str, float] = field(default_factory=dict)
    provider_exhaustion_state: ProviderExhaustionState | None = None


def _format_seed_context(entries: list) -> str | None:
    """Format seed corpus entries for prompt injection. Returns None if empty."""
    if not entries:
        return None
    try:
        from .seed_corpus import format_seed_context

        return format_seed_context(entries) or None
    except ImportError:
        return None


MAX_TRANSCRIPT_FINDINGS = 25


def _extract_transcript(result: TargetResult) -> str:
    """Build a transcript summary from a TargetResult for seeding promoted runs.

    Must surface every finding from the previous pass, not just the first
    couple: the promoted hunter's prompt explicitly says "a previous
    investigation found the following ... do not repeat analysis already
    done," so any finding silently dropped here just gets rediscovered and
    re-reported as if it were new.
    """
    findings = result.findings
    if not findings:
        return f"Run completed with status={result.status}, stop_reason={result.stop_reason}"

    parts: list[str] = []
    for f in findings[:MAX_TRANSCRIPT_FINDINGS]:
        # result.findings is annotated list[dict] but the real runtime objects
        # flowing through here are Finding dataclass instances (the cast() at
        # the call site is a no-op) — Finding implements dict-mimicking
        # __getitem__/.get() specifically so callers don't need to branch on
        # dict vs. Finding, matching the existing pattern a few dozen lines
        # above this function. An isinstance(f, dict) guard here would always
        # be False in production, silently degrading every entry to "?:?".
        file = f.get("file", "?")
        line = f.get("line_number", "?")
        desc = f.get("description", "") or ""
        parts.append(f"- {file}:{line} — {desc[:200]}")
    if len(findings) > MAX_TRANSCRIPT_FINDINGS:
        parts.append(
            f"... and {len(findings) - MAX_TRANSCRIPT_FINDINGS} more findings "
            "from the previous pass."
        )
    return "Previously found in this file (do not re-report these):\n" + "\n".join(parts)


# --- HunterPool -------------------------------------------------------------


class HunterPool:
    """Tiered parallel hunter executor with native async LLM scheduling."""

    def __init__(self, config: HuntPoolConfig):
        self.config = config
        for ft in self.config.files:
            ft["tier"] = assign_tier(ft)
        self._results: dict[str, TargetResult] = {}
        self._spent_per_tier: dict[str, float] = {
            tier: max(0.0, float(self.config.prior_spend_per_tier.get(tier, 0.0)))
            for tier in ("A", "B", "C")
        }
        self._spent_per_band: dict[str, float] = {"fast": 0.0, "standard": 0.0, "deep": 0.0}
        self._runs_per_band: dict[str, int] = {"fast": 0, "standard": 0, "deep": 0}
        self._promotion_counts: dict[str, int] = {"fast→standard": 0, "standard→deep": 0}
        self._state_lock = asyncio.Lock()
        self._cancelled = False

    def run(self) -> list[Finding]:
        return asyncio.run(self.arun())

    def _expand_to_work_items(self, files: list[FileTarget], band: str) -> list[WorkItem]:
        """Expand files into WorkItems respecting redundancy and entry-point sharding."""
        items: list[WorkItem] = []
        for ft in files:
            rank = _file_rank(ft)
            n = _redundancy_for_rank(rank, self.config.redundancy_override)
            file_path = ft.get("path", "")
            entry_points = (
                self.config.entry_points_by_file.get(file_path, [])
                if self.config.shard_entry_points and rank >= 4
                else []
            )
            seed_entries = self.config.seed_corpus_by_file.get(file_path, [])

            if entry_points:
                for ep in entry_points:
                    ep_seeds = [
                        s
                        for s in seed_entries
                        if s.function_name is None or s.function_name == ep.function_name
                    ]
                    seed_ctx = _format_seed_context(ep_seeds) if ep_seeds else None
                    for attempt in range(n):
                        items.append(
                            WorkItem(
                                file_target=ft,
                                band=band,
                                attempt=attempt,
                                entry_point=ep,
                                seed_context=seed_ctx,
                            )
                        )
            else:
                seed_ctx = _format_seed_context(seed_entries) if seed_entries else None
                for attempt in range(n):
                    items.append(
                        WorkItem(
                            file_target=ft,
                            band=band,
                            attempt=attempt,
                            seed_context=seed_ctx,
                        )
                    )
        return items

    @staticmethod
    def _entry_point_payload(item: WorkItem) -> dict[str, Any] | None:
        entry_point = item.entry_point
        if entry_point is None:
            return None
        return {
            "file_path": getattr(entry_point, "file_path", ""),
            "function_name": getattr(entry_point, "function_name", ""),
            "start_line": getattr(entry_point, "start_line", 0),
            "end_line": getattr(entry_point, "end_line", 0),
            "entry_type": getattr(entry_point, "entry_type", ""),
            "description": getattr(entry_point, "description", ""),
        }

    def _pending_work_items(
        self,
        initial: list[WorkItem],
        tier: str,
    ) -> list[WorkItem]:
        store = self.config.resume_store
        if store is None:
            return initial
        completed = store.load_completed_work()
        pending: list[WorkItem] = []
        queue = deque(initial)
        seen: set[str] = set()
        while queue:
            item = queue.popleft()
            work_id = item.stable_identifier(self.config.session_id_prefix, tier)
            if work_id in seen:
                continue
            seen.add(work_id)
            result = completed.get(work_id)
            if result is None:
                pending.append(item)
                continue
            self._restore_result(result)
            next_band = promotion_decision(
                result.findings,
                result.stop_reason,
                item.band,
                self.config.max_band,
            )
            if next_band:
                self._promotion_counts[f"{item.band}→{next_band}"] += 1
                queue.append(
                    WorkItem(
                        file_target=item.file_target,
                        band=next_band,
                        attempt=item.attempt,
                        seed_transcript=result.promotion_transcript,
                        entry_point=item.entry_point,
                        seed_context=item.seed_context,
                    )
                )
        return pending

    def _restore_result(self, result: CompletedWork) -> None:
        key = result.work_id
        if key in self._results:
            return
        self._results[key] = TargetResult(
            target=result.file,
            status="completed",
            findings=cast(list[dict], result.findings),
            cost_usd=0.0,
            tokens_used=0,
            tier=result.tier,
            band=result.band,
            stop_reason=result.stop_reason,
        )

    async def arun(self) -> list[Finding]:
        """Run the full A → B → C pipeline with band promotion. Returns merged findings."""
        logger.info("HunterPool dispatching %d tiered file tasks", len(self.config.files))
        if self.config.provider_exhaustion_state is not None:
            self.config.provider_exhaustion_state.raise_if_exhausted()
        if self.config.resume_store is not None and self.config.findings_pool is not None:
            self.config.findings_pool.restore(
                self.config.resume_store.completed_findings(),
                self.config.resume_store.completed_clusters(),
            )
        by_tier: dict[str, list[FileTarget]] = {"A": [], "B": [], "C": []}
        for item in self.config.files:
            by_tier[item.get("tier", "C")].append(item)

        # The ranker computes a per-file priority but returns files in
        # enumeration order; it does not sort. Without this, hunters within a
        # tier run in filesystem (roughly alphabetical) order, so the most
        # suspicious files are not hunted first and can be starved when a tier
        # budget is exhausted. Sort each tier by priority descending (stable,
        # so equal-priority files keep their enumeration order) to make the
        # ranker's scores actually drive hunt order.
        for _tier_files in by_tier.values():
            _tier_files.sort(key=lambda ft: ft.get("priority", 0.0), reverse=True)

        total_budget = self.config.budget_usd
        tb = self.config.tier_budget
        prior_spend = dict(self._spent_per_tier)
        if total_budget <= 0:
            budget_a = budget_b = budget_c = float("inf")
        else:
            allocation_a = total_budget * tb.tier_a_fraction
            allocation_b = total_budget * tb.tier_b_fraction
            budget_a = max(0.0, allocation_a - prior_spend["A"])
            # Rollover is based on lifetime spend, including completed work
            # restored from an earlier invocation.
            budget_b = max(
                0.0,
                allocation_a + allocation_b - prior_spend["A"] - prior_spend["B"],
            )
            budget_c = max(
                0.0,
                total_budget - sum(prior_spend.values()),
            )

        starting_band = self.config.starting_band

        work_items_a = self._pending_work_items(
            self._expand_to_work_items(by_tier["A"], starting_band), "A"
        )
        spent_a = await self._run_tier_phase(work_items_a, "A", budget_a)

        work_items_b = self._pending_work_items(
            self._expand_to_work_items(by_tier["B"], starting_band), "B"
        )
        budget_b = max(0.0, budget_b - spent_a)
        spent_b = await self._run_tier_phase(work_items_b, "B", budget_b)
        budget_c = max(0.0, budget_c - spent_a - spent_b)

        if by_tier["C"] and tb.tier_c_fraction > 0:
            work_items_c = self._pending_work_items(
                self._expand_to_work_items(by_tier["C"], starting_band), "C"
            )
            await self._run_tier_phase(work_items_c, "C", budget_c)

        target_results = list(self._results.values())
        status_counts = Counter(tr.status for tr in target_results)
        if status_counts:
            logger.info("HunterPool result statuses: %s", dict(status_counts))
        error_results = [tr for tr in target_results if tr.status == "error"]
        for tr in error_results[:10]:
            logger.warning("HunterPool error for %s: %s", tr.target, tr.error or "(no error text)")
        all_findings: list[Finding] = []
        if self.config.findings_pool is not None:
            all_findings = self.config.findings_pool.all_findings()
        elif self.config.resume_store is not None:
            all_findings = self.config.resume_store.completed_findings()
        else:
            for tr in target_results:
                if tr.status == "completed":
                    for f in cast(list[Finding], tr.findings):
                        all_findings.append(f)
        if self.config.on_finding:
            for f in all_findings:
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

    @property
    def budget_exhausted(self) -> bool:
        return any(result.status == "budget_exhausted" for result in self._results.values())

    @property
    def provider_exhausted(self) -> bool:
        state = self.config.provider_exhaustion_state
        return bool(state is not None and state.exhausted) or any(
            result.status == "provider_exhausted" for result in self._results.values()
        )

    @property
    def completed_target_count(self) -> int:
        if self.config.resume_store is not None:
            return self.config.resume_store.completed_target_count()
        return len(
            {result.target for result in self._results.values() if result.status == "completed"}
        )

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
        promotion_queue: deque[WorkItem] = deque()

        def _submit_next() -> bool:
            nonlocal spent
            if (
                self._cancelled
                or spent >= budget
                or (
                    self.config.provider_exhaustion_state is not None
                    and self.config.provider_exhaustion_state.exhausted
                )
            ):
                return False
            wi: WorkItem | None = None
            try:
                wi = next(item_iter)
            except StopIteration:
                if promotion_queue:
                    wi = promotion_queue.popleft()
            if wi is None:
                return False
            band_cost = self.config.band_budget.for_band(wi.band)
            work_item_id = wi.stable_identifier(self.config.session_id_prefix, tier)
            task = asyncio.create_task(
                self._run_file_task(
                    wi.file_target,
                    cost_limit=band_cost,
                    tier=tier,
                    band=wi.band,
                    seed_transcript=wi.seed_transcript,
                    entry_point=wi.entry_point,
                    seed_context=wi.seed_context,
                    work_item_id=work_item_id,
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
                    async with self._state_lock:
                        self._results[key] = TargetResult(
                            target=key,
                            status="timeout",
                            error=f"Hunter did not complete within {timeout}s",
                            tier=tier,
                            band=wi.band,
                        )
                await asyncio.gather(*in_flight, return_exceptions=True)
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
                except BudgetExceeded as exc:
                    logger.info("tier %s hunter for %s stopped at budget", tier, key)
                    self._cancelled = True
                    result = TargetResult(
                        target=key,
                        status="budget_exhausted",
                        error=str(exc),
                        tier=tier,
                        band=wi.band,
                        stop_reason="budget_exhausted",
                    )
                except ProviderExhaustedError as exc:
                    logger.warning("tier %s hunter for %s exhausted provider quota", tier, key)
                    self._cancelled = True
                    result = TargetResult(
                        target=key,
                        status="provider_exhausted",
                        error=str(exc),
                        tier=tier,
                        band=wi.band,
                        stop_reason="provider_exhausted",
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
                ep_suffix = f":{wi.entry_point.function_name}" if wi.entry_point else ""
                next_band = None
                promoted_item = None
                if result.status == "completed":
                    next_band = promotion_decision(
                        cast(list[Finding], result.findings),
                        result.stop_reason,
                        wi.band,
                        self.config.max_band,
                    )
                    if next_band:
                        promoted_item = WorkItem(
                            file_target=wi.file_target,
                            band=next_band,
                            attempt=wi.attempt,
                            seed_transcript=_extract_transcript(result),
                            entry_point=wi.entry_point,
                            seed_context=wi.seed_context,
                        )
                if result.status == "completed":
                    try:
                        if self.config.findings_pool is not None:
                            for finding in cast(list[Finding], result.findings):
                                await self.config.findings_pool.add(finding)
                        if self.config.resume_store is not None:
                            self.config.resume_store.save_work_result(
                                work_id=wi.stable_identifier(self.config.session_id_prefix, tier),
                                file=str(wi.file_target.get("path") or ""),
                                tier=tier,
                                band=wi.band,
                                attempt=wi.attempt,
                                entry_point=self._entry_point_payload(wi),
                                seed_context=wi.seed_context,
                                seed_transcript=wi.seed_transcript,
                                findings=cast(list[Finding], result.findings),
                                clusters=(
                                    self.config.findings_pool.cluster_state(
                                        {
                                            finding.cluster_id
                                            for finding in cast(list[Finding], result.findings)
                                            if finding.cluster_id
                                        }
                                    )
                                    if self.config.findings_pool is not None
                                    else []
                                ),
                                cost_usd=result.cost_usd,
                                tokens_used=result.tokens_used,
                                stop_reason=result.stop_reason,
                                promotion_transcript=(
                                    promoted_item.seed_transcript
                                    if promoted_item is not None
                                    else None
                                ),
                            )
                    except ProviderExhaustedError as exc:
                        self._cancelled = True
                        result = TargetResult(
                            target=key,
                            status="provider_exhausted",
                            error=str(exc),
                            tier=tier,
                            band=wi.band,
                            stop_reason="provider_exhausted",
                        )
                async with self._state_lock:
                    self._results[f"{key}{ep_suffix}:{wi.band}:{wi.attempt}"] = result
                    self._spent_per_tier[tier] += result.cost_usd
                    self._spent_per_band[wi.band] = (
                        self._spent_per_band.get(wi.band, 0.0) + result.cost_usd
                    )
                    self._runs_per_band[wi.band] = self._runs_per_band.get(wi.band, 0) + 1
                    spent += result.cost_usd

                completed_count = sum(
                    1
                    for r in self._results.values()
                    if r.status in ("completed", "error", "timeout")
                )
                total_files = len(self.config.files)
                findings_count = sum(
                    len(r.findings) for r in self._results.values() if r.status == "completed"
                )
                EventBus().emit_hunt_progress(
                    HuntProgressPayload(
                        session_id=self.config.session_id_prefix,
                        tier=tier,
                        band=wi.band,
                        files_completed=completed_count,
                        files_total=total_files,
                        findings_this_tier=findings_count,
                        cost_usd=spent,
                        budget_remaining=max(0.0, budget - spent),
                    )
                )

                if result.status == "completed" and result.findings:
                    for f in cast(list[Finding], result.findings):
                        trace = f.get("vulnerability_trace")
                        trace_chain = ""
                        if trace and trace.get("steps"):
                            trace_chain = " | " + " -> ".join(
                                f"{s.get('file', '?')}:{s.get('function') or '?'}"
                                for s in trace["steps"]
                            )
                        logger.info(
                            "Finding: %s:%s [%s] %.40s%s",
                            f.get("file", "?"),
                            f.get("line_number", "?"),
                            f.get("severity", "?"),
                            f.get("description", "") or "",
                            trace_chain,
                        )
                if result.status == "completed":
                    if next_band and promoted_item is not None:
                        promo_key = f"{wi.band}→{next_band}"
                        async with self._state_lock:
                            self._promotion_counts[promo_key] = (
                                self._promotion_counts.get(promo_key, 0) + 1
                            )
                        logger.info(
                            "Promoting %s from %s to %s band",
                            key,
                            wi.band,
                            next_band,
                        )
                        promotion_queue.append(promoted_item)

                if result.status == "provider_exhausted":
                    for active_task in in_flight:
                        if not active_task.done():
                            active_task.cancel()

                _submit_next()

        if self.provider_exhausted:
            raise ProviderExhaustedError("Provider quota exhausted during hunt")
        return spent

    # --- Internals: hunter-specific logic the runner delegates back to ----

    async def _run_file_task(
        self,
        file_target: FileTarget,
        cost_limit: float,
        tier: str,
        band: str = "",
        seed_transcript: str | None = None,
        entry_point: Any = None,
        seed_context: str | None = None,
        work_item_id: str = "",
    ) -> TargetResult:
        if not work_item_id:
            work_item_id = stable_run_id(
                "work",
                {
                    "run_id": self.config.session_id_prefix,
                    "file": file_target.get("path", ""),
                    "band": band,
                    "entry_point": (
                        getattr(entry_point, "function_name", "") if entry_point is not None else ""
                    ),
                },
            )
        instrumentation = self.config.instrumentation
        entry_symbol = (
            str(getattr(entry_point, "function_name", "") or "") if entry_point is not None else ""
        )
        if instrumentation is not None:
            instrumentation.record(
                "work_item",
                stage="hunt",
                status="started",
                files=[file_target.get("path", "")],
                symbols=[entry_symbol] if entry_symbol else [],
                work_item_id=work_item_id,
                metadata={"tier": tier, "band": band},
            )
        with spend_metadata(
            tier=tier,
            band=band,
            target=file_target.get("path", ""),
            entry_point=(entry_point.function_name if entry_point else None),
            work_item_id=work_item_id,
        ):
            try:
                findings, cost, tokens, stop_reason = await self._run_one_hunter(
                    file_target,
                    cost_limit,
                    seed_transcript=seed_transcript,
                    entry_point=entry_point,
                    seed_context=seed_context,
                    work_item_id=work_item_id,
                )
            except BaseException as exc:
                status = (
                    "provider_exhausted" if isinstance(exc, ProviderExhaustedError) else "failed"
                )
                if instrumentation is not None:
                    instrumentation.record(
                        "work_item",
                        stage="hunt",
                        status=status,
                        files=[file_target.get("path", "")],
                        symbols=[entry_symbol] if entry_symbol else [],
                        work_item_id=work_item_id,
                        error={"type": type(exc).__name__, "message": str(exc)},
                    )
                raise
        if instrumentation is not None:
            instrumentation.record(
                "work_item",
                stage="hunt",
                status=stop_reason,
                files=[file_target.get("path", "")],
                symbols=[entry_symbol] if entry_symbol else [],
                work_item_id=work_item_id,
                finding_ids=[finding.id for finding in findings],
                metadata={"tier": tier, "band": band, "cost_usd": cost, "tokens": tokens},
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
        entry_point: Any = None,
        seed_context: str | None = None,
        work_item_id: str = "",
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
                file_target,
                sandbox,
                budget_usd=cost_limit,
                seed_transcript=seed_transcript,
                entry_point=entry_point,
                seed_context=seed_context,
                work_item_id=work_item_id,
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
        entry_point: Any = None,
        seed_context: str | None = None,
        work_item_id: str = "",
    ) -> Any:
        """Either invoke the user-supplied hunter_factory or import build_hunter_agent."""
        if not work_item_id:
            work_item_id = stable_run_id(
                "work",
                {
                    "run_id": self.config.session_id_prefix,
                    "file": file_target.get("path", ""),
                    "entry_point": (
                        getattr(entry_point, "function_name", "") if entry_point is not None else ""
                    ),
                },
            )
        session_id = f"{self.config.session_id_prefix}-{uuid.uuid4().hex[:8]}"

        if self.config.hunter_factory is not None:
            result = self.config.hunter_factory(file_target, sandbox, session_id)
            self._configure_hunter_context(result, work_item_id)
            return result

        global _DEFAULT_HUNTER_FACTORY
        from .hunter import build_hunter_agent

        if (
            _DEFAULT_HUNTER_FACTORY is None
            or _DEFAULT_HUNTER_FACTORY.__module__ != build_hunter_agent.__module__
        ):
            _DEFAULT_HUNTER_FACTORY = build_hunter_agent

        if self.config.llm is None:
            raise ValueError("HuntPoolConfig.llm is required when hunter_factory is None")

        file_path = file_target.get("path", "")
        seeded_crash = self.config.seeded_crashes_by_file.get(file_path)
        semgrep_hints = self.config.semgrep_hints_by_file.get(file_path)

        result = _DEFAULT_HUNTER_FACTORY(
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
            entry_point=entry_point,
            seed_context=seed_context,
            findings_pool=self.config.findings_pool,
        )
        self._configure_hunter_context(result, work_item_id)
        return result

    def _configure_hunter_context(self, result: Any, work_item_id: str) -> None:
        """Attach durable evaluation joins without changing factory contracts."""

        try:
            _hunter, context = result
        except (TypeError, ValueError):
            return
        context.work_item_id = work_item_id
        context.instrumentation = self.config.instrumentation
        if self.config.trajectory_root is not None:
            context.trajectory_dir = Path(self.config.trajectory_root) / work_item_id
