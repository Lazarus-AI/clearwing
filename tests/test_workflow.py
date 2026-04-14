"""Tests for the durable workflow execution module."""

from __future__ import annotations

import json

import pytest

from clearwing.runners.workflow import (
    RetryPolicy,
    StepStatus,
    WorkflowEngine,
    WorkflowState,
    WorkflowStep,
)

# ---------------------------------------------------------------------------
# StepStatus
# ---------------------------------------------------------------------------


class TestStepStatus:
    """Verify StepStatus enum values."""

    def test_enum_values(self):
        assert StepStatus.PENDING == "pending"
        assert StepStatus.RUNNING == "running"
        assert StepStatus.COMPLETED == "completed"
        assert StepStatus.FAILED == "failed"
        assert StepStatus.RETRYING == "retrying"
        assert StepStatus.SKIPPED == "skipped"


# ---------------------------------------------------------------------------
# RetryPolicy
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    """Verify RetryPolicy defaults and backoff calculation."""

    def test_defaults(self):
        policy = RetryPolicy()
        assert policy.max_retries == 3
        assert policy.backoff_seconds == 1.0
        assert policy.backoff_multiplier == 2.0
        assert policy.max_backoff_seconds == 60.0
        assert policy.retry_on_exceptions == (Exception,)

    def test_get_delay_exponential_backoff(self):
        policy = RetryPolicy(backoff_seconds=1.0, backoff_multiplier=2.0)
        assert policy.get_delay(0) == 1.0  # 1 * 2^0 = 1
        assert policy.get_delay(1) == 2.0  # 1 * 2^1 = 2
        assert policy.get_delay(2) == 4.0  # 1 * 2^2 = 4

    def test_get_delay_respects_max_backoff(self):
        policy = RetryPolicy(
            backoff_seconds=1.0,
            backoff_multiplier=2.0,
            max_backoff_seconds=3.0,
        )
        # attempt 2 would give 4.0 but capped at 3.0
        assert policy.get_delay(2) == 3.0
        assert policy.get_delay(10) == 3.0


# ---------------------------------------------------------------------------
# WorkflowStep
# ---------------------------------------------------------------------------


class TestWorkflowStep:
    """Verify WorkflowStep dataclass defaults."""

    def test_defaults(self):
        step = WorkflowStep(id="s1", name="scan")
        assert step.id == "s1"
        assert step.name == "scan"
        assert step.description == ""
        assert step.status == StepStatus.PENDING
        assert step.result is None
        assert step.error is None
        assert step.attempts == 0
        assert step.max_retries == 3
        assert step.started_at is None
        assert step.completed_at is None
        assert step.duration_seconds == 0.0
        assert step.dependencies == []
        assert step.metadata == {}


# ---------------------------------------------------------------------------
# WorkflowState
# ---------------------------------------------------------------------------


class TestWorkflowState:
    """Verify WorkflowState defaults and auto-generated timestamps."""

    def test_defaults_and_auto_created_at(self):
        state = WorkflowState(workflow_id="wf1", name="pentest")
        assert state.workflow_id == "wf1"
        assert state.name == "pentest"
        assert state.target == ""
        assert state.status == "running"
        assert state.steps == []
        assert state.created_at != ""
        assert state.updated_at == state.created_at
        assert state.checkpoint_path == ""
        assert state.metadata == {}


# ---------------------------------------------------------------------------
# WorkflowEngine – initialisation
# ---------------------------------------------------------------------------


class TestWorkflowEngineInit:
    """Verify WorkflowEngine initialization creates state."""

    def test_initialization_creates_state(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        engine = WorkflowEngine(workflow_id="test1", name="scan", target="10.0.0.1")
        assert engine.workflow_id == "test1"
        assert engine.state.name == "scan"
        assert engine.state.target == "10.0.0.1"
        assert engine.state.status == "running"


# ---------------------------------------------------------------------------
# WorkflowEngine.add_step
# ---------------------------------------------------------------------------


class TestWorkflowEngineAddStep:
    """Verify add_step registers step and handler."""

    def test_add_step_adds_step_and_handler(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        engine = WorkflowEngine(workflow_id="test2", name="scan")

        def handler(step, state):
            return "ok"

        engine.add_step("s1", "recon", handler=handler, description="do recon")

        assert len(engine.state.steps) == 1
        assert engine.state.steps[0].id == "s1"
        assert engine.state.steps[0].name == "recon"
        assert engine.state.steps[0].description == "do recon"
        assert engine._step_handlers["s1"] is handler


# ---------------------------------------------------------------------------
# WorkflowEngine.run – basic execution
# ---------------------------------------------------------------------------


class TestWorkflowEngineRun:
    """Verify workflow execution in order."""

    def test_run_executes_steps_in_order(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0)
        engine = WorkflowEngine(workflow_id="test3", name="scan", retry_policy=policy)

        execution_order = []

        def handler_a(step, state):
            execution_order.append("a")
            return "done_a"

        def handler_b(step, state):
            execution_order.append("b")
            return "done_b"

        engine.add_step("a", "step_a", handler=handler_a)
        engine.add_step("b", "step_b", handler=handler_b)

        result = engine.run()

        assert execution_order == ["a", "b"]
        assert result.steps[0].status == StepStatus.COMPLETED
        assert result.steps[0].result == "done_a"
        assert result.steps[1].status == StepStatus.COMPLETED
        assert result.steps[1].result == "done_b"


# ---------------------------------------------------------------------------
# WorkflowEngine.run – dependencies
# ---------------------------------------------------------------------------


class TestWorkflowEngineDependencies:
    """Verify step dependency handling."""

    def test_run_with_dependencies(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0)
        engine = WorkflowEngine(workflow_id="test4", name="scan", retry_policy=policy)

        execution_order = []

        def handler_a(step, state):
            execution_order.append("a")
            return "done_a"

        def handler_b(step, state):
            execution_order.append("b")
            return "done_b"

        engine.add_step("a", "step_a", handler=handler_a)
        engine.add_step("b", "step_b", handler=handler_b, dependencies=["a"])

        result = engine.run()

        assert execution_order == ["a", "b"]
        assert result.steps[0].status == StepStatus.COMPLETED
        assert result.steps[1].status == StepStatus.COMPLETED

    def test_run_skips_step_when_dependency_fails(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0, max_retries=0)
        engine = WorkflowEngine(workflow_id="test5", name="scan", retry_policy=policy)

        def failing_handler(step, state):
            raise RuntimeError("boom")

        def success_handler(step, state):
            return "done"

        engine.add_step("a", "step_a", handler=failing_handler, max_retries=0)
        engine.add_step("b", "step_b", handler=success_handler, dependencies=["a"])

        result = engine.run()

        assert result.steps[0].status == StepStatus.FAILED
        assert result.steps[1].status == StepStatus.SKIPPED
        assert result.steps[1].error == "Dependency failed"


# ---------------------------------------------------------------------------
# WorkflowEngine.run – retry logic
# ---------------------------------------------------------------------------


class TestWorkflowEngineRetry:
    """Verify retry policies during step execution."""

    def test_run_retries_failed_step_then_succeeds(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0, max_retries=3)
        engine = WorkflowEngine(workflow_id="test6", name="scan", retry_policy=policy)

        call_count = 0

        def flaky_handler(step, state):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("temporary error")
            return "recovered"

        engine.add_step("s1", "flaky", handler=flaky_handler)

        result = engine.run()

        assert call_count == 3
        assert result.steps[0].status == StepStatus.COMPLETED
        assert result.steps[0].result == "recovered"
        assert result.steps[0].attempts == 3

    def test_run_marks_step_failed_after_max_retries(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0, max_retries=2)
        engine = WorkflowEngine(workflow_id="test7", name="scan", retry_policy=policy)

        def always_fails(step, state):
            raise RuntimeError("permanent error")

        engine.add_step("s1", "doomed", handler=always_fails)

        result = engine.run()

        assert result.steps[0].status == StepStatus.FAILED
        assert result.steps[0].error == "permanent error"
        # max_retries=2 means 3 total attempts (0, 1, 2)
        assert result.steps[0].attempts == 3


# ---------------------------------------------------------------------------
# WorkflowEngine – checkpoint and recovery
# ---------------------------------------------------------------------------


class TestWorkflowEngineCheckpoint:
    """Verify checkpoint persistence and recovery round-trip."""

    def test_checkpoint_and_recovery_round_trip(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0)
        engine = WorkflowEngine(
            workflow_id="ckpt1", name="scan", target="10.0.0.1", retry_policy=policy
        )

        def success_handler(step, state):
            return "done"

        engine.add_step("s1", "recon", handler=success_handler, description="recon step")
        engine.run()

        # Verify checkpoint file was written
        ckpt_file = tmp_path / "ckpt1.json"
        assert ckpt_file.exists()

        data = json.loads(ckpt_file.read_text(encoding="utf-8"))
        assert data["workflow_id"] == "ckpt1"
        assert data["name"] == "scan"
        assert data["target"] == "10.0.0.1"
        assert len(data["steps"]) == 1
        assert data["steps"][0]["id"] == "s1"
        assert data["steps"][0]["status"] == "completed"

    def test_recovery_marks_status_as_recovered(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)

        # Simulate a checkpoint file that was left in "running" state (crash)
        crash_data = {
            "workflow_id": "crash1",
            "name": "scan",
            "target": "10.0.0.1",
            "status": "running",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "checkpoint_path": "",
            "metadata": {},
            "steps": [
                {
                    "id": "s1",
                    "name": "recon",
                    "description": "",
                    "status": "completed",
                    "result": "done",
                    "error": None,
                    "attempts": 1,
                    "max_retries": 3,
                    "started_at": "2026-01-01T00:00:00+00:00",
                    "completed_at": "2026-01-01T00:00:01+00:00",
                    "duration_seconds": 1.0,
                    "dependencies": [],
                    "metadata": {},
                },
                {
                    "id": "s2",
                    "name": "exploit",
                    "description": "",
                    "status": "pending",
                    "result": None,
                    "error": None,
                    "attempts": 0,
                    "max_retries": 3,
                    "started_at": None,
                    "completed_at": None,
                    "duration_seconds": 0.0,
                    "dependencies": ["s1"],
                    "metadata": {},
                },
            ],
        }
        ckpt_file = tmp_path / "crash1.json"
        ckpt_file.write_text(json.dumps(crash_data), encoding="utf-8")

        # Recover the workflow
        engine = WorkflowEngine(workflow_id="crash1")

        assert engine.state.status == "recovered"
        assert engine.state.workflow_id == "crash1"
        assert len(engine.state.steps) == 2
        assert engine.state.steps[0].status == StepStatus.COMPLETED
        assert engine.state.steps[1].status == StepStatus.PENDING


# ---------------------------------------------------------------------------
# WorkflowEngine.get_progress
# ---------------------------------------------------------------------------


class TestWorkflowEngineProgress:
    """Verify get_progress returns correct counts."""

    def test_get_progress_returns_correct_counts(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0, max_retries=0)
        engine = WorkflowEngine(workflow_id="prog1", name="scan", retry_policy=policy)

        def success_handler(step, state):
            return "ok"

        def failing_handler(step, state):
            raise RuntimeError("fail")

        engine.add_step("s1", "step1", handler=success_handler, max_retries=0)
        engine.add_step("s2", "step2", handler=failing_handler, max_retries=0)
        engine.add_step("s3", "step3", handler=success_handler, max_retries=0)

        engine.run()

        progress = engine.get_progress()
        assert progress["workflow_id"] == "prog1"
        assert progress["total_steps"] == 3
        assert progress["completed"] == 2
        assert progress["failed"] == 1
        assert progress["running"] == 0
        assert progress["pending"] == 0
        assert progress["progress_pct"] == pytest.approx(200.0 / 3.0)


# ---------------------------------------------------------------------------
# WorkflowEngine.list_workflows
# ---------------------------------------------------------------------------


class TestWorkflowEngineListWorkflows:
    """Verify list_workflows finds saved workflow checkpoints."""

    def test_list_workflows_finds_saved_workflows(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0)

        # Create two workflows
        engine1 = WorkflowEngine(workflow_id="list1", name="scan1", retry_policy=policy)
        engine1.add_step("s1", "step1", handler=lambda s, st: "ok")
        engine1.run()

        engine2 = WorkflowEngine(workflow_id="list2", name="scan2", retry_policy=policy)
        engine2.add_step("s1", "step1", handler=lambda s, st: "ok")
        engine2.run()

        workflows = WorkflowEngine.list_workflows()
        ids = [w["workflow_id"] for w in workflows]

        assert "list1" in ids
        assert "list2" in ids
        assert all("name" in w for w in workflows)
        assert all("step_count" in w for w in workflows)


# ---------------------------------------------------------------------------
# WorkflowEngine – final status
# ---------------------------------------------------------------------------


class TestWorkflowEngineFinalStatus:
    """Verify completed and failed final workflow statuses."""

    def test_completed_workflow_has_status_completed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0)
        engine = WorkflowEngine(workflow_id="fin1", name="scan", retry_policy=policy)

        engine.add_step("s1", "step1", handler=lambda s, st: "ok")
        engine.add_step("s2", "step2", handler=lambda s, st: "ok")

        result = engine.run()
        assert result.status == "completed"

    def test_failed_workflow_has_status_failed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(WorkflowEngine, "CHECKPOINT_DIR", tmp_path)
        policy = RetryPolicy(backoff_seconds=0, max_retries=0)
        engine = WorkflowEngine(workflow_id="fin2", name="scan", retry_policy=policy)

        def failing_handler(step, state):
            raise RuntimeError("fatal")

        engine.add_step("s1", "step1", handler=failing_handler, max_retries=0)

        result = engine.run()
        assert result.status == "failed"
