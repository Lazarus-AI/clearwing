"""Campaign-scale orchestration — spec 012.

Orchestrates multiple SourceHuntRunner instances across projects with
shared FindingsPool for cross-project dedup, budget tracking, stopping
rules, and checkpointing for pause/resume.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from clearwing.core.event_payloads import CampaignProgressPayload
from clearwing.core.events import EventBus

from .campaign_config import CampaignConfig, CampaignTargetConfig

logger = logging.getLogger(__name__)


# --- State dataclasses --------------------------------------------------------


@dataclass
class ProjectState:
    repo: str
    status: str = "queued"
    session_id: str = ""
    cost_usd: float = 0.0
    runs_completed: int = 0
    findings_count: int = 0
    verified_count: int = 0
    start_time: float | None = None
    end_time: float | None = None
    error: str = ""


@dataclass
class CampaignCheckpoint:
    campaign_name: str
    campaign_session_id: str
    timestamp: float
    completed_projects: list[str]
    per_project_state: dict[str, ProjectState]
    budget_spent: float
    findings_pool_path: str
    recent_runs_count: int = 0
    recent_new_findings: int = 0
    paused: bool = False


@dataclass
class CampaignResult:
    campaign_name: str
    campaign_session_id: str
    status: str
    total_cost_usd: float
    duration_seconds: float
    projects_completed: int
    projects_total: int
    total_findings: int
    total_verified: int
    per_project_results: dict[str, ProjectState]
    output_paths: dict[str, str]
    findings_pool_stats: dict[str, int]
    stopping_reason: str | None = None


# --- Checkpoint I/O -----------------------------------------------------------


def save_checkpoint(
    checkpoint: CampaignCheckpoint,
    checkpoint_dir: Path,
) -> None:
    """Atomic JSON write: temp file + rename."""
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    target = checkpoint_dir / "checkpoint.json"

    data = {
        "campaign_name": checkpoint.campaign_name,
        "campaign_session_id": checkpoint.campaign_session_id,
        "timestamp": checkpoint.timestamp,
        "completed_projects": checkpoint.completed_projects,
        "per_project_state": {
            repo: asdict(ps)
            for repo, ps in checkpoint.per_project_state.items()
        },
        "budget_spent": checkpoint.budget_spent,
        "findings_pool_path": checkpoint.findings_pool_path,
        "recent_runs_count": checkpoint.recent_runs_count,
        "recent_new_findings": checkpoint.recent_new_findings,
        "paused": checkpoint.paused,
    }

    fd, tmp_path = tempfile.mkstemp(
        dir=str(checkpoint_dir), suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, str(target))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_checkpoint(
    checkpoint_dir: Path,
    campaign_name: str | None = None,
) -> CampaignCheckpoint | None:
    """Load checkpoint from JSON. Returns None if not found."""
    target = checkpoint_dir / "checkpoint.json"
    if not target.exists():
        return None

    try:
        with open(target, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    per_project = {}
    for repo, ps_data in data.get("per_project_state", {}).items():
        per_project[repo] = ProjectState(**ps_data)

    return CampaignCheckpoint(
        campaign_name=data.get("campaign_name", ""),
        campaign_session_id=data.get("campaign_session_id", ""),
        timestamp=data.get("timestamp", 0.0),
        completed_projects=data.get("completed_projects", []),
        per_project_state=per_project,
        budget_spent=data.get("budget_spent", 0.0),
        findings_pool_path=data.get("findings_pool_path", ""),
        recent_runs_count=data.get("recent_runs_count", 0),
        recent_new_findings=data.get("recent_new_findings", 0),
        paused=data.get("paused", False),
    )


# --- CampaignRunner ----------------------------------------------------------


class CampaignRunner:
    """Orchestrate multiple SourceHuntRunner instances across projects."""

    def __init__(
        self,
        config: CampaignConfig,
        session_id: str | None = None,
    ):
        self.config = config
        self._session_id = session_id or f"campaign-{uuid.uuid4().hex[:8]}"
        self._findings_pool: Any = None
        self._historical_db: Any = None
        self._project_states: dict[str, ProjectState] = {}
        self._budget_spent: float = 0.0
        self._budget_lock = asyncio.Lock()
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # start running (not paused)
        self._recent_runs: int = 0
        self._recent_new_findings: int = 0
        self._start_time: float = 0.0
        self._checkpoint_dir = Path(
            config.output_dir,
        ) / self._session_id

        for target in config.targets:
            self._project_states[target.repo] = ProjectState(repo=target.repo)

    def _emit_progress(
        self, current_project: str = "", status: str = "running",
    ) -> None:
        total_findings = sum(ps.findings_count for ps in self._project_states.values())
        total_verified = sum(ps.verified_count for ps in self._project_states.values())
        projects_completed = sum(
            1 for ps in self._project_states.values() if ps.status == "completed"
        )
        EventBus().emit_campaign_progress(CampaignProgressPayload(
            campaign_name=self.config.name,
            projects_completed=projects_completed,
            projects_total=len(self.config.targets),
            current_project=current_project,
            status=status,
            cost_usd=self._budget_spent,
            findings_total=total_findings,
            verified_total=total_verified,
        ))

    async def arun(self) -> CampaignResult:
        """Run the full campaign."""
        self._start_time = time.time()

        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        pool_path = self._checkpoint_dir / "findings_pool.jsonl"

        try:
            from .findings_pool import FindingsPool
            self._findings_pool = FindingsPool(checkpoint_path=pool_path)
        except Exception:
            logger.warning("FindingsPool init failed", exc_info=True)

        try:
            from .historical_findings_db import HistoricalFindingsDB
            self._historical_db = HistoricalFindingsDB()
        except Exception:
            logger.warning("HistoricalFindingsDB init failed", exc_info=True)

        checkpoint_task = asyncio.create_task(self._checkpoint_loop())

        pending_targets = [
            t for t in self.config.targets
            if self._project_states[t.repo].status == "queued"
        ]
        pending_targets.sort(
            key=lambda t: (not bool(t.focus), -(t.budget or 0)),
        )

        semaphore = asyncio.Semaphore(self.config.max_concurrent_containers)
        tasks: dict[asyncio.Task, CampaignTargetConfig] = {}
        stopping_reason: str | None = None

        for target in pending_targets:
            task = asyncio.create_task(
                self._run_project(target, semaphore),
            )
            tasks[task] = target

        completed_count = 0
        for coro in asyncio.as_completed(list(tasks.keys())):
            try:
                result = await coro
                target = tasks[
                    [t for t in tasks if t.done() and not t.cancelled()][
                        -1
                    ]
                ]
            except Exception:
                completed_count += 1
                continue

            completed_count += 1

            stopping_reason = self._check_stopping_rules()
            if stopping_reason:
                self._emit_progress(status="stopped")
                logger.info(
                    "Campaign stopping: %s", stopping_reason,
                )
                for t in tasks:
                    if not t.done():
                        t.cancel()
                break

        checkpoint_task.cancel()
        try:
            await checkpoint_task
        except asyncio.CancelledError:
            pass

        if self._historical_db is not None and self._findings_pool is not None:
            try:
                all_findings = list(self._findings_pool._findings.values())
                for target in self.config.targets:
                    ps = self._project_states[target.repo]
                    if ps.status == "completed":
                        self._historical_db.ingest_campaign(
                            [
                                f for f in all_findings
                                if target.repo in f.get("id", "")
                                or f.get("_repo_url") == target.repo
                            ],
                            repo_url=target.repo,
                            session_id=ps.session_id,
                        )
            except Exception:
                logger.warning("Campaign historical DB ingest failed", exc_info=True)
            finally:
                try:
                    self._historical_db.close()
                except Exception:
                    pass

        self._save_checkpoint()

        duration = time.time() - self._start_time
        total_findings = sum(
            ps.findings_count for ps in self._project_states.values()
        )
        total_verified = sum(
            ps.verified_count for ps in self._project_states.values()
        )
        projects_completed = sum(
            1 for ps in self._project_states.values()
            if ps.status == "completed"
        )

        pool_stats = {}
        if self._findings_pool is not None:
            try:
                pool_stats = self._findings_pool.pool_stats()
            except Exception:
                pass

        status = stopping_reason or "completed"
        self._emit_progress(status=status)

        return CampaignResult(
            campaign_name=self.config.name,
            campaign_session_id=self._session_id,
            status=status,
            total_cost_usd=self._budget_spent,
            duration_seconds=duration,
            projects_completed=projects_completed,
            projects_total=len(self.config.targets),
            total_findings=total_findings,
            total_verified=total_verified,
            per_project_results=dict(self._project_states),
            output_paths={"checkpoint": str(self._checkpoint_dir)},
            findings_pool_stats=pool_stats,
            stopping_reason=stopping_reason,
        )

    def run(self) -> CampaignResult:
        """Sync wrapper."""
        return asyncio.run(self.arun())

    async def _run_project(
        self,
        target: CampaignTargetConfig,
        semaphore: asyncio.Semaphore,
    ) -> Any:
        """Run one project within campaign context."""
        await self._pause_event.wait()

        async with semaphore:
            ps = self._project_states[target.repo]
            ps.status = "running"
            ps.start_time = time.time()
            ps.session_id = f"{self._session_id}-{_safe_name(target.repo)}"
            self._emit_progress(current_project=target.repo)

            project_budget = target.budget
            if project_budget <= 0:
                async with self._budget_lock:
                    remaining = self.config.budget - self._budget_spent
                project_budget = max(remaining / max(1, self._queued_count()), 0)

            try:
                from clearwing.providers import ProviderManager, resolve_llm_endpoint

                from .runner import SourceHuntRunner

                endpoint = resolve_llm_endpoint()
                provider_manager = ProviderManager.for_endpoint(endpoint)
                max_par = target.max_parallel or 8
                runner = SourceHuntRunner(
                    repo_url=target.repo,
                    branch=target.branch,
                    depth=target.depth or self.config.depth,
                    budget_usd=project_budget,
                    max_parallel=max_par,
                    campaign_hint=target.campaign_hint or self.config.campaign_hint,
                    parent_session_id=ps.session_id,
                    prompt_mode=self.config.prompt_mode,
                    output_dir=str(self._checkpoint_dir),
                    enable_findings_pool=True,
                    enable_subsystem_hunt=bool(target.focus),
                    subsystem_paths=target.focus or None,
                    redundancy_override=target.redundancy,
                    provider_manager=provider_manager,
                )

                if self._findings_pool is not None:
                    runner._inject_campaign_pool(
                        self._findings_pool,
                        self._historical_db,
                    )

                result = await runner.arun()

                async with self._budget_lock:
                    self._budget_spent += result.cost_usd
                    self._recent_runs += result.files_hunted
                    self._recent_new_findings += len(result.findings)

                ps.cost_usd = result.cost_usd
                ps.runs_completed = result.files_hunted
                ps.findings_count = len(result.findings)
                ps.verified_count = len(result.verified_findings)
                ps.status = "completed"
                ps.end_time = time.time()
                self._emit_progress(current_project=target.repo)

                return result

            except Exception as e:
                ps.status = "error"
                ps.error = str(e)
                ps.end_time = time.time()
                logger.warning(
                    "Campaign project %s failed: %s",
                    target.repo, e, exc_info=True,
                )
                return None

    async def _checkpoint_loop(self) -> None:
        """Save checkpoint periodically and check for PAUSE signal."""
        pause_file = self._checkpoint_dir / "PAUSE"
        while True:
            try:
                await asyncio.sleep(self.config.checkpoint_interval_seconds)
            except asyncio.CancelledError:
                return

            if pause_file.exists():
                self._pause_event.clear()
                logger.info("Campaign paused via signal file")
            elif not self._pause_event.is_set():
                self._pause_event.set()
                logger.info("Campaign resumed — PAUSE file removed")

            self._save_checkpoint()
            self._emit_progress(status="paused" if not self._pause_event.is_set() else "running")

    def _save_checkpoint(self) -> None:
        pool_path = str(self._checkpoint_dir / "findings_pool.jsonl")
        checkpoint = CampaignCheckpoint(
            campaign_name=self.config.name,
            campaign_session_id=self._session_id,
            timestamp=time.time(),
            completed_projects=[
                repo for repo, ps in self._project_states.items()
                if ps.status == "completed"
            ],
            per_project_state=dict(self._project_states),
            budget_spent=self._budget_spent,
            findings_pool_path=pool_path,
            recent_runs_count=self._recent_runs,
            recent_new_findings=self._recent_new_findings,
            paused=not self._pause_event.is_set(),
        )
        try:
            save_checkpoint(checkpoint, self._checkpoint_dir)
        except Exception:
            logger.warning("Checkpoint save failed", exc_info=True)

    def _check_stopping_rules(self) -> str | None:
        if self.config.budget > 0 and self._budget_spent >= self.config.budget:
            return "budget_exhausted"

        window = self.config.diminishing_returns_window
        if self._recent_runs >= window:
            rate = self._recent_new_findings / self._recent_runs
            if rate < self.config.diminishing_returns_threshold:
                return f"diminishing_returns (rate={rate:.3f})"

        if (
            self.config.triage_backlog_limit > 0
            and self._findings_pool is not None
        ):
            try:
                stats = self._findings_pool.pool_stats()
                if stats.get("unique_findings", 0) > self.config.triage_backlog_limit:
                    return "triage_backlog"
            except Exception:
                pass

        return None

    def pause(self) -> None:
        self._pause_event.clear()

    def resume(self) -> None:
        self._pause_event.set()

    def _queued_count(self) -> int:
        return sum(
            1 for ps in self._project_states.values()
            if ps.status == "queued"
        )

    @classmethod
    async def from_checkpoint(
        cls,
        config: CampaignConfig,
    ) -> CampaignRunner:
        """Reconstruct runner state from checkpoint for resume."""
        checkpoint_dir = Path(config.output_dir)
        session_dirs = sorted(checkpoint_dir.glob("campaign-*"))
        if not session_dirs:
            raise ValueError("No campaign checkpoint found")

        latest = session_dirs[-1]
        cp = load_checkpoint(latest)
        if cp is None:
            raise ValueError(f"Could not load checkpoint from {latest}")

        runner = cls(config, session_id=cp.campaign_session_id)
        runner._budget_spent = cp.budget_spent
        runner._recent_runs = cp.recent_runs_count
        runner._recent_new_findings = cp.recent_new_findings

        for repo, ps in cp.per_project_state.items():
            runner._project_states[repo] = ps

        pool_path = Path(cp.findings_pool_path)
        if pool_path.exists():
            try:
                from .findings_pool import FindingsPool
                runner._findings_pool = FindingsPool.from_checkpoint(pool_path)
            except Exception:
                logger.warning("Pool reconstruction failed", exc_info=True)

        return runner


def _safe_name(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in tail) or "project"
