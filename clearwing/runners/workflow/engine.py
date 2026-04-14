from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    SKIPPED = "skipped"


@dataclass
class RetryPolicy:
    """Configurable retry policy for workflow steps."""

    max_retries: int = 3
    backoff_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    max_backoff_seconds: float = 60.0
    retry_on_exceptions: tuple = (Exception,)

    def get_delay(self, attempt: int) -> float:
        """Calculate backoff delay for a given attempt number."""
        delay = self.backoff_seconds * (self.backoff_multiplier**attempt)
        return min(delay, self.max_backoff_seconds)


@dataclass
class WorkflowStep:
    """A single step in a workflow."""

    id: str
    name: str
    description: str = ""
    status: StepStatus = StepStatus.PENDING
    result: str | None = None
    error: str | None = None
    attempts: int = 0
    max_retries: int = 3
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float = 0.0
    dependencies: list[str] = field(default_factory=list)  # step IDs that must complete first
    metadata: dict = field(default_factory=dict)


@dataclass
class WorkflowState:
    """Persistent state of a workflow execution."""

    workflow_id: str
    name: str
    target: str = ""
    status: str = "running"  # running, paused, completed, failed, recovered
    steps: list[WorkflowStep] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    checkpoint_path: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(tz=timezone.utc).isoformat()
        self.updated_at = self.created_at


class WorkflowEngine:
    """Durable workflow execution with crash recovery and retry policies.

    Features:
    - Checkpoint-based crash recovery
    - Configurable retry policies with exponential backoff
    - Step dependencies (DAG execution)
    - Progress tracking and queryable state
    """

    CHECKPOINT_DIR = Path("~/.clearwing/workflows").expanduser()

    def __init__(
        self,
        workflow_id: str = None,
        name: str = "pentest",
        target: str = "",
        retry_policy: RetryPolicy = None,
    ):
        self._retry_policy = retry_policy or RetryPolicy()
        self._lock = threading.Lock()
        self._step_handlers: dict[str, Callable] = {}

        if workflow_id:
            # Try to recover existing workflow
            self._state = self._load_checkpoint(workflow_id)
            if self._state is None:
                self._state = WorkflowState(
                    workflow_id=workflow_id,
                    name=name,
                    target=target,
                )
        else:
            import uuid

            self._state = WorkflowState(
                workflow_id=uuid.uuid4().hex[:12],
                name=name,
                target=target,
            )

        self.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    @property
    def state(self) -> WorkflowState:
        return self._state

    @property
    def workflow_id(self) -> str:
        return self._state.workflow_id

    def add_step(
        self,
        step_id: str,
        name: str,
        handler: Callable = None,
        description: str = "",
        dependencies: list[str] = None,
        max_retries: int = None,
    ) -> WorkflowStep:
        """Add a step to the workflow."""
        step = WorkflowStep(
            id=step_id,
            name=name,
            description=description,
            dependencies=dependencies or [],
            max_retries=max_retries if max_retries is not None else self._retry_policy.max_retries,
        )
        with self._lock:
            self._state.steps.append(step)
            if handler:
                self._step_handlers[step_id] = handler
        return step

    def run(self) -> WorkflowState:
        """Execute the workflow, respecting dependencies and retry policies."""
        self._state.status = "running"
        self._checkpoint()

        while True:
            runnable = self._get_runnable_steps()
            if not runnable:
                break

            for step in runnable:
                self._execute_step(step)
                self._checkpoint()

        # Determine final status
        all_done = all(
            s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED) for s in self._state.steps
        )
        self._state.status = "completed" if all_done else "failed"
        self._checkpoint()

        return self._state

    def _execute_step(self, step: WorkflowStep):
        """Execute a single step with retry logic."""
        handler = self._step_handlers.get(step.id)
        if handler is None:
            step.status = StepStatus.SKIPPED
            step.error = "No handler registered"
            return

        step.status = StepStatus.RUNNING
        step.started_at = datetime.now(tz=timezone.utc).isoformat()

        for attempt in range(step.max_retries + 1):
            step.attempts = attempt + 1
            try:
                result = handler(step, self._state)
                step.status = StepStatus.COMPLETED
                step.result = str(result) if result is not None else ""
                step.completed_at = datetime.now(tz=timezone.utc).isoformat()
                if step.started_at:
                    start = datetime.fromisoformat(step.started_at)
                    end = datetime.fromisoformat(step.completed_at)
                    step.duration_seconds = (end - start).total_seconds()
                return
            except Exception as e:
                step.error = str(e)
                if attempt < step.max_retries:
                    step.status = StepStatus.RETRYING
                    delay = self._retry_policy.get_delay(attempt)
                    time.sleep(delay)
                else:
                    step.status = StepStatus.FAILED
                    step.completed_at = datetime.now(tz=timezone.utc).isoformat()

    def _get_runnable_steps(self) -> list[WorkflowStep]:
        """Get steps whose dependencies are all completed."""
        runnable = []
        for step in self._state.steps:
            if step.status != StepStatus.PENDING:
                continue
            # Check all dependencies are completed
            deps_met = all(
                self._get_step(dep_id) and self._get_step(dep_id).status == StepStatus.COMPLETED
                for dep_id in step.dependencies
            )
            # Check no dependency has failed
            deps_failed = any(
                self._get_step(dep_id) and self._get_step(dep_id).status == StepStatus.FAILED
                for dep_id in step.dependencies
            )
            if deps_failed:
                step.status = StepStatus.SKIPPED
                step.error = "Dependency failed"
                continue
            if deps_met:
                runnable.append(step)
        return runnable

    def _get_step(self, step_id: str) -> WorkflowStep | None:
        for step in self._state.steps:
            if step.id == step_id:
                return step
        return None

    # --- Checkpoint / Recovery ---

    def _checkpoint(self):
        """Save current state to disk."""
        path = self.CHECKPOINT_DIR / f"{self._state.workflow_id}.json"
        self._state.updated_at = datetime.now(tz=timezone.utc).isoformat()
        self._state.checkpoint_path = str(path)

        # Serialize
        data = {
            "workflow_id": self._state.workflow_id,
            "name": self._state.name,
            "target": self._state.target,
            "status": self._state.status,
            "created_at": self._state.created_at,
            "updated_at": self._state.updated_at,
            "checkpoint_path": self._state.checkpoint_path,
            "metadata": self._state.metadata,
            "steps": [],
        }
        for step in self._state.steps:
            step_data = {
                "id": step.id,
                "name": step.name,
                "description": step.description,
                "status": step.status.value if isinstance(step.status, StepStatus) else step.status,
                "result": step.result,
                "error": step.error,
                "attempts": step.attempts,
                "max_retries": step.max_retries,
                "started_at": step.started_at,
                "completed_at": step.completed_at,
                "duration_seconds": step.duration_seconds,
                "dependencies": step.dependencies,
                "metadata": step.metadata,
            }
            data["steps"].append(step_data)

        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_checkpoint(self, workflow_id: str) -> WorkflowState | None:
        """Load workflow state from a checkpoint file."""
        path = self.CHECKPOINT_DIR / f"{workflow_id}.json"
        if not path.exists():
            return None

        data = json.loads(path.read_text(encoding="utf-8"))
        steps = []
        for sd in data.get("steps", []):
            steps.append(
                WorkflowStep(
                    id=sd["id"],
                    name=sd["name"],
                    description=sd.get("description", ""),
                    status=StepStatus(sd.get("status", "pending")),
                    result=sd.get("result"),
                    error=sd.get("error"),
                    attempts=sd.get("attempts", 0),
                    max_retries=sd.get("max_retries", 3),
                    started_at=sd.get("started_at"),
                    completed_at=sd.get("completed_at"),
                    duration_seconds=sd.get("duration_seconds", 0.0),
                    dependencies=sd.get("dependencies", []),
                    metadata=sd.get("metadata", {}),
                )
            )

        state = WorkflowState(
            workflow_id=data["workflow_id"],
            name=data.get("name", ""),
            target=data.get("target", ""),
            status=data.get("status", "running"),
            steps=steps,
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            checkpoint_path=str(path),
            metadata=data.get("metadata", {}),
        )
        # Mark as recovered
        if state.status == "running":
            state.status = "recovered"
        return state

    def get_progress(self) -> dict:
        """Get current progress as a queryable dict."""
        total = len(self._state.steps)
        completed = sum(1 for s in self._state.steps if s.status == StepStatus.COMPLETED)
        failed = sum(1 for s in self._state.steps if s.status == StepStatus.FAILED)
        running = sum(1 for s in self._state.steps if s.status == StepStatus.RUNNING)
        pending = sum(1 for s in self._state.steps if s.status == StepStatus.PENDING)

        return {
            "workflow_id": self._state.workflow_id,
            "status": self._state.status,
            "total_steps": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "pending": pending,
            "progress_pct": (completed / total * 100) if total > 0 else 0.0,
        }

    @classmethod
    def list_workflows(cls) -> list[dict]:
        """List all saved workflow checkpoints."""
        results = []
        cls.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        for path in sorted(cls.CHECKPOINT_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                results.append(
                    {
                        "workflow_id": data["workflow_id"],
                        "name": data.get("name", ""),
                        "target": data.get("target", ""),
                        "status": data.get("status", ""),
                        "created_at": data.get("created_at", ""),
                        "step_count": len(data.get("steps", [])),
                    }
                )
            except Exception:
                logger.debug("Failed to read workflow file %s", path, exc_info=True)
                continue
        return results
