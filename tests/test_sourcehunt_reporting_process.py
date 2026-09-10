"""Inert process/filesystem reporting regression, portable to Linux containers.

No model, discovery, verification, exploitation, or sandbox is executed.
Run with PYTHONPATH=. python -m pytest tests/test_sourcehunt_reporting_process.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from clearwing.runners.parallel.executor import TargetResult
from clearwing.sourcehunt import runner as runner_module
from clearwing.sourcehunt.checkpoints import (
    ExploitationCheckpoint,
    ExploitationResult,
    PreprocessCheckpoint,
    SourceHuntCheckpoint,
    VerificationCheckpoint,
    VerificationResult,
)
from clearwing.sourcehunt.pool import HunterPool
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.runner import SourceHuntRunner


class InertProcessPool(HunterPool):
    async def _run_file_task(self, file_target, *, tier, band, **kwargs):
        path = file_target["path"]
        failed = PROCESS_OUTCOME == "worker" or (
            PROCESS_OUTCOME == "partial" and path == "failed.c"
        )
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", f"raise SystemExit({42 if failed else 0})"
        )
        returncode = await asyncio.wait_for(process.wait(), timeout=15)
        with (PROCESS_ROOT / "workers.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "path": path,
                        "pid": process.pid,
                        "parent_pid": os.getpid(),
                        "returncode": returncode,
                    }
                )
                + "\n"
            )
        if returncode:
            raise RuntimeError(f"Inert worker exited {returncode}")
        return TargetResult(
            target=path,
            status="completed",
            tier=tier,
            band=band,
            stop_reason="max_steps" if PROCESS_OUTCOME == "stopped" else "completed",
        )


class FailedProcessPool(InertProcessPool):
    async def arun(self):
        process = await asyncio.create_subprocess_exec(sys.executable, "-c", "raise SystemExit(43)")
        returncode = await asyncio.wait_for(process.wait(), timeout=15)
        raise RuntimeError(f"Inert pool exited {returncode}")


class InertReportingRunner(SourceHuntRunner):
    def _preflight_budget_clients(self):
        pass

    def _ensure_sandbox_factory(self, *args, **kwargs):
        pass

    def _get_native_client(self, task, *args, **kwargs):
        if task == "ranker" or PROCESS_OUTCOME == "no_model":
            return None
        if task != "hunter":
            raise AssertionError(f"Unexpected provider route: {task}")
        return object()

    def _preprocess(self):
        if PROCESS_OUTCOME == "fatal":
            raise RuntimeError("Inert preprocessing failed")
        self._preprocess_restored = False
        options = {"inert_reporting_fixture": True}
        if self._checkpoint is not None and self._checkpoint.preprocess is not None:
            result = self._checkpoint.preprocess.restore(
                repo_path=self.local_path,
                options=options,
            )
            assert result is not None
            self._preprocess_restored = True
            return result
        result = PreprocessResult(
            repo_path=self.local_path,
            file_targets=[
                {"path": path.name, "tier": "A"}
                for path in sorted(Path(self.local_path).glob("*.c"))
            ],
            static_findings=[],
        )
        self._checkpoint = SourceHuntCheckpoint(
            preprocess=PreprocessCheckpoint.from_result(result, options=options),
        )
        self._dump_checkpoint()
        return result

    async def _verify(self, *args, **kwargs):
        raise AssertionError("Verification must never run")

    async def _exploit(self, *args, **kwargs):
        raise AssertionError("Exploitation must never run")


def _process_main(root: Path, outcome: str, resume: bool) -> None:
    global PROCESS_ROOT, PROCESS_OUTCOME
    PROCESS_ROOT, PROCESS_OUTCOME = root, outcome

    def deny_network(event, args):
        if event in {"socket.connect", "socket.getaddrinfo"}:
            raise AssertionError("Network access is forbidden in this inert fixture")

    sys.addaudithook(deny_network)
    runner_module.HunterPool = FailedProcessPool if outcome == "pool" else InertProcessPool
    runner = InertReportingRunner(
        repo_url=str(root / "repo"),
        local_path=str(root / "repo"),
        output_dir=str(root / "results"),
        parent_session_id=None if resume else "inert-reporting",
        resume_session_id="inert-reporting" if resume else None,
        output_formats=["json", "markdown", "sarif"],
        stop_after="hunt",
        max_parallel=1,
        enable_mechanism_memory=False,
        enable_calibration=False,
        enable_knowledge_graph=False,
        enable_subsystem_hunt=False,
        enable_findings_pool=False,
        preprocessing=False,
    )
    result = runner.run()
    (root / "result.json").write_text(
        json.dumps(
            {
                "status": result.status,
                "exit_code": result.exit_code,
                "files_hunted": result.files_hunted,
                "checkpoint": result.checkpoint,
                "preprocess_restored": runner._preprocess_restored,
                "rank_restored": runner._rank_restored,
                "hunt_restored": runner._hunt_restored,
            }
        ),
        encoding="utf-8",
    )
    raise SystemExit(result.exit_code)


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _run_process(root: Path, outcome: str, *, resume: bool = False):
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            "OTEL_SDK_DISABLED": "true",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "commit.gpgsign",
            "GIT_CONFIG_VALUE_0": "false",
        }
    )
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), str(root), outcome, str(int(resume))],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
    )


@pytest.fixture
def inert_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "completed.c").write_text("int fixture(void) { return 0; }\n", encoding="utf-8")
    (repo / "failed.c").write_text("int other(void) { return 0; }\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Inert Tests",
            "-c",
            "user.email=inert@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "inert fixture",
        ],
        check=True,
    )
    return tmp_path


@pytest.mark.parametrize(
    "outcome",
    ["worker", "partial", "pool", "no_model", "stopped", "complete"],
)
def test_process_reports_and_checkpoint_reuse(inert_repository, outcome):
    root = inert_repository
    session = root / "results" / "inert-reporting"
    complete = outcome == "complete"
    expected_status = "completed" if complete else "incomplete"
    expected_exit = 0 if complete else 3
    first_checkpoint = None
    first_workers = []
    for resume in (False, True):
        process = _run_process(root, outcome, resume=resume)
        assert process.returncode == expected_exit, process.stdout + process.stderr
        result = _read_json(root / "result.json")
        assert result["status"] == expected_status
        assert result["exit_code"] == expected_exit
        assert result["files_hunted"] == (
            2 if outcome in {"complete", "stopped"} else int(outcome == "partial")
        )
        assert result["preprocess_restored"] is resume
        assert result["rank_restored"] is resume
        assert result["hunt_restored"] is (resume and complete)
        checkpoint = _read_json(session / "checkpoint.json")
        assert checkpoint == result["checkpoint"]
        assert checkpoint["preprocess"] is not None
        assert checkpoint["rank"] is not None
        assert (checkpoint["hunt"] is not None) is complete
        assert checkpoint["verification"] is None
        assert checkpoint["exploitation"] is None
        if resume:
            assert checkpoint["preprocess"] == first_checkpoint["preprocess"]
            assert checkpoint["rank"] == first_checkpoint["rank"]
        first_checkpoint = checkpoint
        report = _read_json(session / "findings.json")
        assert report["findings"] == []
        assert report["budget"]["status"] == expected_status
        hunter = report["pipeline_status"]["hunter_pool"]
        assert hunter["outcome"] == ("succeeded" if complete else "degraded")
        if outcome == "pool":
            assert hunter["error"] == "RuntimeError: Inert pool exited 43"
        assert _read_json(session / "manifest.json")["status"] == expected_status
        assert f"**Run status:** {expected_status}" in (session / "report.md").read_text()
        events = [
            json.loads(line)
            for line in (session / "instrumentation" / "events.jsonl").read_text().splitlines()
        ]
        hunt_events = [event["status"] for event in events if event["stage"] == "hunt"]
        assert ("completed" in hunt_events) is complete
        if not complete:
            assert "degraded" in hunt_events
        for stage in ("verify", "exploit"):
            assert {event["status"] for event in events if event["stage"] == stage} == {"skipped"}
        worker_log = root / "workers.jsonl"
        workers = (
            [json.loads(line) for line in worker_log.read_text().splitlines()]
            if worker_log.exists()
            else []
        )
        if outcome in {"worker", "partial", "complete", "stopped"}:
            assert workers
            assert all(
                worker["pid"] > 0 and worker["pid"] != worker["parent_pid"] for worker in workers
            )
            assert {worker["returncode"] for worker in workers} == (
                {0}
                if outcome in {"complete", "stopped"}
                else {0, 42}
                if outcome == "partial"
                else {42}
            )
        else:
            assert workers == []
        if resume:
            if outcome in {"complete", "stopped"}:
                assert workers == first_workers
            elif outcome in {"worker", "partial"}:
                assert len(workers) > len(first_workers)
                assert all(worker["returncode"] == 42 for worker in workers[len(first_workers) :])
        first_workers = workers
        if not resume and not complete:
            stale = SourceHuntCheckpoint.from_file(session / "checkpoint.json")
            stale.verification = VerificationCheckpoint.from_result(
                VerificationResult(verified=[], rejected=[]),
                options={},
            )
            stale.exploitation = ExploitationCheckpoint.from_result(
                ExploitationResult(verified=[], exploited=[]),
                options={},
            )
            stale.dump(session / "checkpoint.json")


def test_process_fatal_failure_persists_failed_status(inert_repository):
    root = inert_repository
    process = _run_process(root, "fatal")
    assert process.returncode == 1, process.stdout + process.stderr
    assert "Inert preprocessing failed" in process.stderr
    session = root / "results" / "inert-reporting"
    assert _read_json(session / "manifest.json")["status"] == "failed"
    events = [
        json.loads(line)
        for line in (session / "instrumentation" / "events.jsonl").read_text().splitlines()
    ]
    assert any(event["stage"] == "run" and event["status"] == "failed" for event in events)
    assert not any(event["stage"] == "run" and event["status"] == "completed" for event in events)
    assert not (session / "checkpoint.json").exists()
    assert not (root / "workers.jsonl").exists()


if __name__ == "__main__":
    _process_main(Path(sys.argv[1]), sys.argv[2], bool(int(sys.argv[3])))
