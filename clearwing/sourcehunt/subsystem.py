"""Subsystem identification and cross-subsystem hunt runner (spec 006).

Provides:
    - Auto-detection of subsystems from ranked file targets
    - Manual subsystem specification from directory paths
    - SubsystemHuntRunner for parallel subsystem-level hunts
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.llm.budget import BudgetExceeded, spend_metadata
from clearwing.sourcehunt.state import FileTarget, Finding, SubsystemTarget

from .instrumentation import stable_run_id

logger = logging.getLogger(__name__)

# Default caps for auto-detected subsystems. These bound how much a single
# auto-detected subsystem (and how many subsystems) get hunted, to keep spend
# predictable. They are DEFAULTS, not hard limits — callers may raise them or
# pass None to disable the cap. NOTE: under ``--no-rank`` every file has the
# same priority, so a cap here degenerates to keeping os.walk order and can drop
# the ground-truth file out of scope (observed in CVE-2026-5747). That is why
# every drop below is logged at WARNING rather than performed silently.
DEFAULT_MAX_FILES_PER_SUBSYSTEM = 50
DEFAULT_MAX_SUBSYSTEMS = 10


def _warn_files_dropped(
    context: str,
    *,
    kept: int,
    dropped: list[FileTarget],
    explicit: bool = False,
) -> None:
    """Emit a WARNING naming files dropped from a subsystem's scope.

    Silent truncation reads downstream as "covered everything", so every drop
    is surfaced with a count and a sample of the dropped paths. *explicit* marks
    a drop from an operator-named scope, which is worded more loudly because it
    overrides a deliberate choice.
    """
    total = kept + len(dropped)
    sample = ", ".join(f.get("path", "") for f in dropped[:10])
    more = "" if len(dropped) <= 10 else f" (+{len(dropped) - 10} more)"
    if explicit:
        logger.warning(
            "Explicit scope %s matched %d file(s) but max_files=%d caps it — "
            "DROPPING %d file(s) from a deliberately-named scope: %s%s. Pass "
            "max_files=None (or raise it) to hunt the full scope.",
            context, total, kept, len(dropped), sample, more,
        )
    else:
        logger.warning(
            "%s: kept top %d file(s) by priority, DROPPED %d out of scope: %s%s. "
            "Under --no-rank all priorities are equal, so this keeps os.walk "
            "order and can drop the ground-truth file. Raise the cap "
            "(or set it to None) to widen scope.",
            context, kept, len(dropped), sample, more,
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


def _dir_prefix(path: str, depth: int = 2) -> str:
    """Extract the first `depth` directory components of a path."""
    parts = path.split("/")
    if len(parts) <= depth:
        return "/".join(parts[:-1]) if len(parts) > 1 else parts[0]
    return "/".join(parts[:depth])


def identify_subsystems_auto(
    file_targets: list[FileTarget],
    callgraph: Any = None,
    entry_points_by_file: dict | None = None,
    min_high_rank_files: int = 3,
    min_file_rank: int = 4,
    max_files_per_subsystem: int | None = DEFAULT_MAX_FILES_PER_SUBSYSTEM,
    max_subsystems: int | None = DEFAULT_MAX_SUBSYSTEMS,
) -> list[SubsystemTarget]:
    """Identify subsystems by grouping ranked files by directory prefix.

    Directories with >= min_high_rank_files files at rank >= min_file_rank
    are promoted to subsystem targets.
    """
    by_dir: dict[str, list[FileTarget]] = {}
    for ft in file_targets:
        path = ft.get("path", "")
        if not path:
            continue
        prefix = _dir_prefix(path)
        by_dir.setdefault(prefix, []).append(ft)

    subsystems: list[SubsystemTarget] = []
    for prefix, files in by_dir.items():
        high_rank_count = sum(1 for f in files if _file_rank(f) >= min_file_rank)
        if high_rank_count < min_high_rank_files:
            continue

        sorted_files = sorted(files, key=lambda f: f.get("priority", 0.0), reverse=True)
        if (
            max_files_per_subsystem is not None
            and len(sorted_files) > max_files_per_subsystem
        ):
            _warn_files_dropped(
                f"auto subsystem {prefix!r}",
                kept=max_files_per_subsystem,
                dropped=sorted_files[max_files_per_subsystem:],
            )
            capped_files = sorted_files[:max_files_per_subsystem]
        else:
            capped_files = sorted_files
        priority = max(f.get("priority", 0.0) for f in capped_files)

        eps: list = []
        if entry_points_by_file:
            for f in capped_files:
                fp = f.get("path", "")
                eps.extend(entry_points_by_file.get(fp, []))

        subsystems.append(
            SubsystemTarget(
                name=prefix.replace("/", "_"),
                root_path=prefix,
                files=capped_files,
                entry_points=eps,
                priority=priority,
                source="auto",
            )
        )

    subsystems.sort(key=lambda s: s.priority, reverse=True)
    if max_subsystems is not None and len(subsystems) > max_subsystems:
        dropped = subsystems[max_subsystems:]
        logger.warning(
            "Auto-detection kept the top %d of %d subsystems by priority; "
            "DROPPED %d: %s. Raise max_subsystems (or set it to None) to widen "
            "scope.",
            max_subsystems,
            len(subsystems),
            len(dropped),
            ", ".join(s.root_path for s in dropped[:10]),
        )
        subsystems = subsystems[:max_subsystems]
    return subsystems


def subsystem_from_path(
    path: str,
    file_targets: list[FileTarget],
    callgraph: Any = None,
    entry_points_by_file: dict | None = None,
    max_files: int | None = None,
) -> SubsystemTarget:
    """Build a SubsystemTarget from a directory path or glob pattern.

    Raises ValueError if no files match.

    An explicit path is a deliberate operator scope, so *max_files* defaults to
    ``None`` (no cap) — the full matched set is hunted. If a cap is supplied and
    exceeded, files are dropped with a loud WARNING rather than silently.
    """
    normalized = path.rstrip("/")
    is_glob = "*" in normalized or "?" in normalized

    matched: list[FileTarget] = []
    for ft in file_targets:
        fp = ft.get("path", "")
        if is_glob:
            if fnmatch.fnmatch(fp, normalized) or fnmatch.fnmatch(fp, normalized + "/*"):
                matched.append(ft)
        else:
            if fp.startswith(normalized + "/") or fp == normalized:
                matched.append(ft)

    if not matched:
        raise ValueError(f"No files match subsystem path: {path}")

    matched.sort(key=lambda f: f.get("priority", 0.0), reverse=True)
    if max_files is not None and len(matched) > max_files:
        _warn_files_dropped(
            f"{path!r}",
            kept=max_files,
            dropped=matched[max_files:],
            explicit=True,
        )
        capped = matched[:max_files]
    else:
        capped = matched
    priority = max(f.get("priority", 0.0) for f in capped)

    eps: list = []
    if entry_points_by_file:
        for f in capped:
            fp = f.get("path", "")
            eps.extend(entry_points_by_file.get(fp, []))

    name = normalized.replace("/", "_").strip("_")
    return SubsystemTarget(
        name=name,
        root_path=normalized,
        files=capped,
        entry_points=eps,
        priority=priority,
        source="manual",
    )


# ---------------------------------------------------------------------------
# SubsystemHuntRunner
# ---------------------------------------------------------------------------


@dataclass
class SubsystemHuntConfig:
    """Configuration for subsystem-level hunts."""

    subsystems: list[SubsystemTarget]
    repo_path: str
    sandbox_factory: Callable | None = None
    llm: Any = None
    max_parallel: int = 4
    budget_per_subsystem_usd: float = 100.0
    total_budget_usd: float = 0.0  # 0 = unlimited
    timeout_seconds: int = 14400  # 4 hours
    findings_pool: Any = None
    session_id_prefix: str = "subsys"
    sandbox_manager: Any = None
    campaign_hint: str | None = None
    callgraph: Any = None
    project_name: str = "target"
    trajectory_root: str | Path | None = None
    instrumentation: Any = None
    # Max files enumerated in each subsystem hunt prompt. None = list every file
    # (correct for an explicit scope so the ground-truth file is never hidden).
    max_files_in_prompt: int | None = None
    semantic_tools: list[Any] = field(default_factory=list)


class SubsystemHuntRunner:
    """Run subsystem-level hunts in parallel."""

    def __init__(self, config: SubsystemHuntConfig):
        self.config = config
        self._spent: float = 0.0
        self._subsystems_completed: int = 0
        self._budget_exhausted = False
        self.all_potentials: list[dict] = []

    @property
    def total_spent(self) -> float:
        return self._spent

    @property
    def subsystems_completed(self) -> int:
        return self._subsystems_completed

    @property
    def budget_exhausted(self) -> bool:
        """Whether any subsystem stopped before completion at its budget limit."""
        return self._budget_exhausted

    async def arun(self) -> list[Finding]:
        """Run all subsystem hunts. Returns merged findings."""
        if not self.config.subsystems or self.config.llm is None:
            return []

        sem = asyncio.Semaphore(self.config.max_parallel)
        all_findings: list[Finding] = []

        async def _guarded_run(subsystem: SubsystemTarget) -> list[Finding]:
            async with sem:
                if self.config.total_budget_usd > 0 and self._spent >= self.config.total_budget_usd:
                    self._budget_exhausted = True
                    logger.info(
                        "Subsystem %s skipped: total budget exhausted",
                        subsystem.name,
                    )
                    return []
                work_item_id = stable_run_id(
                    "work",
                    {
                        "run_id": self.config.session_id_prefix,
                        "subsystem": subsystem.name,
                        "files": sorted(str(item.get("path") or "") for item in subsystem.files),
                    },
                )
                with spend_metadata(
                    subsystem=subsystem.name,
                    work_item_id=work_item_id,
                ):
                    findings, cost, tokens, stop, potentials = await self._run_one_subsystem(
                        subsystem,
                        self.config.budget_per_subsystem_usd,
                        work_item_id=work_item_id,
                    )
                self._spent += cost
                self._subsystems_completed += 1
                if stop == "budget_exhausted":
                    self._budget_exhausted = True
                self.all_potentials.extend(potentials)
                logger.info(
                    "Subsystem %s finished: %d findings, $%.4f, stop=%s",
                    subsystem.name,
                    len(findings),
                    cost,
                    stop,
                )
                if self.config.findings_pool is not None:
                    for f in findings:
                        try:
                            await self.config.findings_pool.add(f)
                        except Exception:
                            logger.debug("findings_pool.add failed", exc_info=True)
                return findings

        tasks = [asyncio.create_task(_guarded_run(s)) for s in self.config.subsystems]

        for coro in asyncio.as_completed(tasks):
            try:
                findings = await coro
                all_findings.extend(findings)
            except BudgetExceeded:
                self._budget_exhausted = True
                logger.info("Subsystem hunt stopped because the run budget is exhausted")
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                break
            except Exception:
                logger.warning("Subsystem hunt task failed", exc_info=True)

        return all_findings

    async def _run_one_subsystem(
        self,
        subsystem: SubsystemTarget,
        budget_usd: float,
        *,
        work_item_id: str,
    ) -> tuple[list[Finding], float, int, str, list[dict]]:
        """Spawn sandbox, build agent, run, collect findings."""
        from .hunter import build_subsystem_hunter_agent

        sandbox = None
        if self.config.sandbox_factory is not None:
            try:
                sandbox = await asyncio.to_thread(self.config.sandbox_factory)
            except Exception as e:
                logger.error(
                    "sandbox_factory failed for subsystem %s: %s",
                    subsystem.name,
                    e,
                )
                raise SystemExit(1) from e

        session_id = f"{self.config.session_id_prefix}-{uuid.uuid4().hex[:8]}"
        files = [str(item.get("path") or "") for item in subsystem.files]
        symbols = sorted(
            {
                str(getattr(entry_point, "function_name", "") or "")
                for entry_point in subsystem.entry_points
                if getattr(entry_point, "function_name", "")
            }
        )
        instrumentation = self.config.instrumentation
        if instrumentation is not None:
            instrumentation.record(
                "work_item",
                stage="hunt",
                status="started",
                files=files,
                symbols=symbols,
                work_item_id=work_item_id,
                metadata={"subsystem": subsystem.name},
            )
        try:
            hunter, ctx = build_subsystem_hunter_agent(
                subsystem=subsystem,
                repo_path=self.config.repo_path,
                sandbox=sandbox,
                llm=self.config.llm,
                session_id=session_id,
                project_name=self.config.project_name,
                budget_usd=budget_usd,
                findings_pool=self.config.findings_pool,
                campaign_hint=self.config.campaign_hint,
                callgraph=self.config.callgraph,
                max_files_in_prompt=self.config.max_files_in_prompt,
                semantic_tools=self.config.semantic_tools,
            )
            ctx.work_item_id = work_item_id
            ctx.instrumentation = instrumentation
            if self.config.trajectory_root is not None:
                ctx.trajectory_dir = Path(self.config.trajectory_root) / work_item_id
            result = await asyncio.wait_for(
                hunter.arun(),
                timeout=self.config.timeout_seconds,
            )
            findings = list(result.findings)
            if instrumentation is not None:
                instrumentation.record(
                    "work_item",
                    stage="hunt",
                    status=result.stop_reason,
                    files=files,
                    symbols=symbols,
                    work_item_id=work_item_id,
                    finding_ids=[finding.id for finding in findings],
                    metadata={
                        "subsystem": subsystem.name,
                        "cost_usd": result.cost_usd,
                        "tokens": result.tokens_used,
                    },
                )
            return (
                findings,
                result.cost_usd,
                result.tokens_used,
                result.stop_reason,
                list(result.potentials),
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Subsystem %s timed out after %ds", subsystem.name, self.config.timeout_seconds
            )
            if instrumentation is not None:
                instrumentation.record(
                    "work_item",
                    stage="hunt",
                    status="timeout",
                    files=files,
                    symbols=symbols,
                    work_item_id=work_item_id,
                )
            if "ctx" in locals():
                return (list(ctx.findings), 0.0, 0, "timeout", list(ctx.potentials))
            return ([], 0.0, 0, "timeout", [])
        except BudgetExceeded:
            raise
        except Exception as exc:
            logger.warning("Subsystem %s failed", subsystem.name, exc_info=True)
            if instrumentation is not None:
                instrumentation.record(
                    "work_item",
                    stage="hunt",
                    status="failed",
                    files=files,
                    symbols=symbols,
                    work_item_id=work_item_id,
                    error={"type": type(exc).__name__, "message": str(exc)},
                )
            return ([], 0.0, 0, "error", [])
        finally:
            if sandbox is not None:
                try:
                    await asyncio.to_thread(sandbox.stop)
                except Exception:
                    pass
