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
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from clearwing.llm.budget import BudgetExceeded, spend_metadata
from clearwing.sourcehunt.state import FileTarget, Finding, SubsystemTarget

from .instrumentation import stable_run_id

logger = logging.getLogger(__name__)


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
    max_files_per_subsystem: int = 50,
    max_subsystems: int = 10,
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
        capped_files = sorted_files[:max_files_per_subsystem]
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
    return subsystems[:max_subsystems]


def _normalize_repo_rel(path: str) -> str:
    """POSIX-ish repo-relative path: strip ``./``, trailing slash, backslashes."""
    text = (path or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/")


def file_matches_subsystem_pin(file_path: str, pin: str) -> bool:
    """True when *file_path* is the pin or lives under it (glob-aware)."""
    fp = _normalize_repo_rel(file_path)
    pin_n = _normalize_repo_rel(pin)
    if not fp or not pin_n:
        return False
    if "*" in pin_n or "?" in pin_n:
        return fnmatch.fnmatch(fp, pin_n) or fnmatch.fnmatch(fp, pin_n + "/*")
    return fp == pin_n or fp.startswith(pin_n + "/")


def files_for_prompt_listing(
    subsystem: SubsystemTarget,
    limit: int = 50,
) -> list[FileTarget]:
    """File listing for the hunter prompt: exact ``--subsystem`` pin first.

    Under ``--no-rank`` dummy scores, a 50-file cap used to drop the pinned
    file when tag-boosted neighbors sorted first. Exact pin paths always
    survive the listing window.
    """
    files = list(subsystem.files or [])
    pin = _normalize_repo_rel(subsystem.root_path)
    exact: list[FileTarget] = []
    rest: list[FileTarget] = []
    for ft in files:
        fp = _normalize_repo_rel(str(ft.get("path") or ""))
        if fp == pin:
            exact.append(ft)
        else:
            rest.append(ft)
    ordered = exact + rest
    if limit is None or limit <= 0:
        return ordered
    kept = list(ordered[:limit])
    kept_paths = {_normalize_repo_rel(str(ft.get("path") or "")) for ft in kept}
    for ft in exact:
        fp = _normalize_repo_rel(str(ft.get("path") or ""))
        if fp and fp not in kept_paths:
            kept.insert(0, ft)
            kept_paths.add(fp)
    return kept[: max(limit, len(exact))] or kept


def _file_target_from_disk(rel_path: str, abs_path: Path) -> FileTarget:
    from clearwing.sourcehunt.preprocessor import _SOURCE_EXTS_TO_LANG

    ext = abs_path.suffix.lower()
    language = _SOURCE_EXTS_TO_LANG.get(ext, "unknown")
    try:
        loc = sum(1 for _ in abs_path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        loc = 0
    return FileTarget(
        path=rel_path,
        absolute_path=str(abs_path),
        language=language,
        loc=loc,
        tags=[],
        priority=2.8,
        surface=3,
        influence=2,
        reachability=3,
        tier="C",
        surface_rationale="",
        influence_rationale="",
        reachability_rationale="",
        static_hint=0,
        semgrep_hint=0,
        taint_hits=0,
        imports_by=0,
        transitive_callers=0,
        defines_constants=False,
        has_fuzz_entry_point=False,
        fuzz_harness_path=None,
    )


def _pin_file_targets_from_disk(repo_path: str, pin: str) -> list[FileTarget]:
    """Enumerate the pin on disk when the preprocessor walk missed it.

    Covers MAX_DEPTH / language-filter / gitignore holes for ``--subsystem``.
    """
    from clearwing.sourcehunt.preprocessor import _SOURCE_EXTS_TO_LANG

    root = Path(repo_path)
    if not root.is_dir():
        return []
    pin_n = _normalize_repo_rel(pin)
    if not pin_n:
        return []
    target = root / pin_n
    candidates: list[Path] = []
    if target.is_file():
        candidates = [target]
    elif target.is_dir():
        candidates = [p for p in target.rglob("*") if p.is_file()]
    else:
        candidates = [p for p in root.glob(pin_n) if p.is_file()]

    matched: list[FileTarget] = []
    for abs_path in candidates:
        ext = abs_path.suffix.lower()
        if ext not in _SOURCE_EXTS_TO_LANG:
            continue
        try:
            rel = Path(os.path.relpath(abs_path, root)).as_posix()
        except ValueError:
            continue
        matched.append(_file_target_from_disk(_normalize_repo_rel(rel), abs_path))
    return matched


def subsystem_from_path(
    path: str,
    file_targets: list[FileTarget],
    callgraph: Any = None,
    entry_points_by_file: dict | None = None,
    max_files: int = 50,
    repo_path: str | None = None,
    no_rank: bool = False,
) -> SubsystemTarget:
    """Build a SubsystemTarget from a directory path, file path, or glob.

    Raises ValueError if no files match. When *repo_path* is set and the
    preprocessor list is empty for this pin, files are collected from disk
    so ``--subsystem`` still hunts. Under *no_rank*, dummy scores do not
    shuffle the exact pin out of the cap window.
    """
    normalized = _normalize_repo_rel(path)
    matched: list[FileTarget] = []
    seen: set[str] = set()
    for ft in file_targets:
        fp = _normalize_repo_rel(str(ft.get("path") or ""))
        if not fp or fp in seen:
            continue
        if file_matches_subsystem_pin(fp, normalized):
            matched.append(ft)
            seen.add(fp)

    if not matched and repo_path:
        for ft in _pin_file_targets_from_disk(repo_path, normalized):
            fp = _normalize_repo_rel(str(ft.get("path") or ""))
            if fp and fp not in seen:
                matched.append(ft)
                seen.add(fp)
        if matched:
            logger.info(
                "subsystem pin %s: preprocessor missed it; loaded %d files from disk",
                normalized,
                len(matched),
            )

    if not matched:
        raise ValueError(f"No files match subsystem path: {path}")

    def _sort_key(ft: FileTarget) -> tuple:
        fp = _normalize_repo_rel(str(ft.get("path") or ""))
        exact = 0 if fp == normalized else 1
        if no_rank:
            return (exact, fp)
        return (exact, -float(ft.get("priority") or 0.0), fp)

    matched.sort(key=_sort_key)
    exact = [
        ft
        for ft in matched
        if _normalize_repo_rel(str(ft.get("path") or "")) == normalized
    ]
    cap = max_files if max_files and max_files > 0 else len(matched)
    capped = matched[:cap]
    kept_paths = {_normalize_repo_rel(str(ft.get("path") or "")) for ft in capped}
    for ft in exact:
        fp = _normalize_repo_rel(str(ft.get("path") or ""))
        if fp and fp not in kept_paths:
            capped.insert(0, ft)
            kept_paths.add(fp)
    if exact:
        capped = capped[: max(cap, len(exact))]

    priority = max((float(f.get("priority") or 0.0) for f in capped), default=0.0)

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


class EmptySubsystemSelectorError(ValueError):
    """One or more intended ``--subsystem`` pins resolved to zero files.

    An explicit selector that matches nothing is a harness/config error
    (wrong pin path, wrong repo checkout), not a legitimately empty result.
    Raising instead of silently proceeding keeps a mis-pinned hunt from
    reporting a clean "0 findings" success.
    """

    def __init__(self, unmatched: list[str]):
        self.unmatched = list(unmatched)
        joined = ", ".join(self.unmatched) or "(none)"
        super().__init__(
            "subsystem selector(s) matched zero files: "
            f"{joined} — check the pin path against the repo tree "
            "(a zero-match intended selector is a harness/config error, "
            "not an empty result)"
        )


def resolve_subsystem_targets(
    subsystem_paths: list[str],
    file_targets: list[FileTarget],
    *,
    callgraph: Any = None,
    entry_points_by_file: dict | None = None,
    repo_path: str | None = None,
    no_rank: bool = False,
    max_files: int = 50,
) -> list[SubsystemTarget]:
    """Resolve every intended ``--subsystem`` pin or fail visibly.

    Each pin is resolved via :func:`subsystem_from_path` (which already falls
    back to a disk walk when the preprocessor missed the pin). Any pin that
    still resolves to zero files is collected and raised together as an
    :class:`EmptySubsystemSelectorError`, so the caller can surface a visible
    failure rather than dropping the pin with a log line and proceeding.
    """
    targets: list[SubsystemTarget] = []
    unmatched: list[str] = []
    for sp in subsystem_paths:
        try:
            targets.append(
                subsystem_from_path(
                    sp,
                    file_targets,
                    callgraph=callgraph,
                    entry_points_by_file=entry_points_by_file,
                    repo_path=repo_path,
                    no_rank=no_rank,
                    max_files=max_files,
                )
            )
        except ValueError:
            logger.error("No files match subsystem path: %s", sp)
            unmatched.append(sp)
    if unmatched:
        raise EmptySubsystemSelectorError(unmatched)
    return targets


# ---------------------------------------------------------------------------
# SubsystemHuntRunner
# ---------------------------------------------------------------------------


class InvalidHarnessError(RuntimeError):
    """Hunt refused because execute/read_file cannot access the source tree."""


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
    hunter_max_steps: int = 2000


class SubsystemHuntRunner:
    """Run subsystem-level hunts in parallel."""

    def __init__(self, config: SubsystemHuntConfig):
        self.config = config
        self._spent: float = 0.0
        self._subsystems_completed: int = 0

    @property
    def total_spent(self) -> float:
        return self._spent

    @property
    def subsystems_completed(self) -> int:
        return self._subsystems_completed

    async def arun(self) -> list[Finding]:
        """Run all subsystem hunts. Returns merged findings."""
        if not self.config.subsystems or self.config.llm is None:
            return []

        sem = asyncio.Semaphore(self.config.max_parallel)
        all_findings: list[Finding] = []

        async def _guarded_run(subsystem: SubsystemTarget) -> list[Finding]:
            async with sem:
                if self.config.total_budget_usd > 0 and self._spent >= self.config.total_budget_usd:
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
                    findings, cost, tokens, stop = await self._run_one_subsystem(
                        subsystem,
                        self.config.budget_per_subsystem_usd,
                        work_item_id=work_item_id,
                    )
                self._spent += cost
                self._subsystems_completed += 1
                logger.info(
                    "Subsystem %s completed: %d findings, $%.4f, stop=%s",
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
                logger.info("Subsystem hunt stopped because the run budget is exhausted")
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                break
            except InvalidHarnessError:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            except Exception:
                logger.warning("Subsystem hunt task failed", exc_info=True)

        return all_findings

    async def _run_one_subsystem(
        self,
        subsystem: SubsystemTarget,
        budget_usd: float,
        *,
        work_item_id: str,
    ) -> tuple[list[Finding], float, int, str]:
        """Spawn sandbox, build agent, run, collect findings."""
        from .hunter import build_subsystem_hunter_agent

        sandbox = None
        if self.config.sandbox_factory is not None:
            try:
                sandbox = await asyncio.to_thread(self.config.sandbox_factory)
            except Exception as e:
                logger.warning(
                    "sandbox_factory failed for subsystem %s: %s",
                    subsystem.name,
                    e,
                )

        if sandbox is None:
            raise InvalidHarnessError(
                f"invalid_harness: subsystem {subsystem.name} has no sandbox; "
                "refusing to hunt blind (execute/read_file would return "
                "'no sandbox available' while the prompt claims /workspace)"
            )

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
                max_steps=self.config.hunter_max_steps,
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
                return (list(ctx.findings), 0.0, 0, "timeout")
            return ([], 0.0, 0, "timeout")
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
            return ([], 0.0, 0, "error")
        finally:
            if sandbox is not None:
                try:
                    await asyncio.to_thread(sandbox.stop)
                except Exception:
                    pass
