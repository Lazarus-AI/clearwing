"""Durable Phase-0 sourcehunt instrumentation tests."""

from __future__ import annotations

import json

from clearwing.sourcehunt.hunter import HunterTrajectoryLogger
from clearwing.sourcehunt.instrumentation import (
    SourceHuntInstrumentation,
    stable_run_id,
)


def test_instrumentation_joins_stable_entities_and_materializes_summary(tmp_path) -> None:
    instrumentation = SourceHuntInstrumentation(tmp_path / "session", "run-1")
    work_id = stable_run_id("work", {"run": "run-1", "file": "src/a.c"})
    model_id = stable_run_id("modelcall", {"work": work_id, "step": 1})
    tool_id = stable_run_id("toolaction", {"work": work_id, "call": "read-1"})

    first = instrumentation.record(
        "work_item",
        stage="hunt",
        status="started",
        files=["src/a.c", "src/a.c"],
        symbols=["decode"],
        work_item_id=work_id,
    )
    instrumentation.record(
        "model_call",
        stage="hunt",
        status="completed",
        work_item_id=work_id,
        model_call_id=model_id,
    )
    instrumentation.record(
        "tool_action",
        stage="hunt",
        status="completed",
        work_item_id=work_id,
        tool_action_id=tool_id,
        finding_ids=["finding-1"],
    )
    instrumentation.reporting_failure(
        "disk full",
        error_type="OSError",
        finding_ids=["finding-1"],
    )
    instrumentation.finalize("completed")

    summary = json.loads(instrumentation.summary_path.read_text(encoding="utf-8"))
    assert first["id"] == stable_run_id(
        "instrument",
        {
            "run_id": "run-1",
            "sequence": 1,
            "event": "work_item",
            "stage": "hunt",
            "work_item_id": work_id,
            "model_call_id": None,
            "tool_action_id": None,
        },
    )
    assert summary["files_by_stage"]["hunt"] == ["src/a.c"]
    assert summary["symbols_by_stage"]["hunt"] == ["decode"]
    assert summary["work_item_ids"] == [work_id]
    assert summary["model_call_ids"] == [model_id]
    assert summary["tool_action_ids"] == [tool_id]
    assert summary["finding_ids"] == ["finding-1"]
    assert summary["reporting_failure_count"] == 1
    assert instrumentation.reporting_failures_path.is_file()


def test_instrumentation_tolerates_only_a_truncated_final_event(tmp_path) -> None:
    instrumentation = SourceHuntInstrumentation(tmp_path / "session", "run-1")
    instrumentation.stage("preprocess", "completed", files=["a.py"])
    with instrumentation.events_path.open("a", encoding="utf-8") as stream:
        stream.write('{"truncated":')

    events = instrumentation.read_events()

    assert len(events) == 1
    assert events[0]["stage"] == "preprocess"

    recovered = SourceHuntInstrumentation(tmp_path / "session", "run-1")
    recovered.finalize("failed")
    assert [event["sequence"] for event in recovered.read_events()] == [1, 2]


def test_hunter_trajectory_persists_model_and_tool_join_ids(tmp_path) -> None:
    instrumentation = SourceHuntInstrumentation(tmp_path / "session", "run-1")
    trajectory_path = tmp_path / "session" / "trajectories" / "work-1.jsonl"
    trajectory_path.parent.mkdir(parents=True)
    trajectory = HunterTrajectoryLogger(
        path=trajectory_path,
        run_id="run-1",
        work_item_id="work-1",
        file_path="decoder.py",
        instrumentation=instrumentation,
    )
    trajectory.log(
        "message",
        {
            "step": 1,
            "message": {"role": "assistant", "content": "inspect"},
            "usage": {"input_tokens": 10, "output_tokens": 2},
            "model": "local-model",
        },
    )
    tool_call = {
        "call_id": "call-1",
        "fn_name": "read_source_file",
        "fn_arguments": {"path": "decoder.py"},
    }
    trajectory.log("tool_call", {"step": 1, "tool_call": tool_call})
    trajectory.log(
        "tool_result",
        {"step": 1, "tool_call": tool_call, "tool_output": "source"},
    )

    records = [
        json.loads(line) for line in trajectory_path.read_text(encoding="utf-8").splitlines()
    ]
    assert records[0]["model_call_id"].startswith("modelcall-")
    assert records[1]["tool_action_id"].startswith("toolaction-")
    assert records[1]["tool_action_id"] == records[2]["tool_action_id"]
    assert all(record["work_item_id"] == "work-1" for record in records)
    summary = json.loads(instrumentation.summary_path.read_text(encoding="utf-8"))
    assert summary["model_call_ids"] == [records[0]["model_call_id"]]
    assert summary["tool_action_ids"] == [records[1]["tool_action_id"]]


def test_spend_ledger_calls_join_without_overwriting_stage_status(tmp_path) -> None:
    instrumentation = SourceHuntInstrumentation(tmp_path / "session", "run-1")
    instrumentation.stage("hunt", "started", files=["decoder.py"])
    ledger = tmp_path / "session" / "spend-ledger.jsonl"
    stable_model_id = stable_run_id(
        "modelcall",
        {"run_id": "run-1", "work_item_id": "work-1", "step": 1},
    )
    ledger.write_text(
        json.dumps(
            {
                "event": "call_settled",
                "call_id": "physical-call-1",
                "stage": "hunt",
                "model": "local-model",
                "provider": "test",
                "status": "success",
                "cost_usd": 0.01,
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 2,
                "metadata": {
                    "model_call_id": stable_model_id,
                    "work_item_id": "work-1",
                    "target": "decoder.py",
                    "entry_point": "decode",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert instrumentation.ingest_spend_ledger(ledger) == 1
    assert instrumentation.ingest_spend_ledger(ledger) == 0
    instrumentation.stage("hunt", "completed", files=["decoder.py"])

    summary = json.loads(instrumentation.summary_path.read_text(encoding="utf-8"))
    assert summary["model_call_ids"] == [stable_model_id]
    assert summary["stages"]["hunt"]["status"] == "completed"
    assert summary["symbols_by_stage"]["hunt"] == ["decode"]
