"""CyberPi hunt-engine and sidecar boundary regressions."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.findings.types import Finding
from clearwing.llm import AsyncLLMClient, NativeToolSpec
from clearwing.llm.budget import BudgetExceeded, SpendLedger
from clearwing.sourcehunt.config import FeatureFlags
from clearwing.sourcehunt.hunt_engine import HuntAssignment, HuntOutcome
from clearwing.sourcehunt.native_hunt_engine import NativeHuntEngine
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig
from clearwing.ui.commands import sourcehunt as sourcehunt_command

_FAKE_SIDECAR = r"""
import json
import os
import sys
import time

def read():
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("protocol closed")
    return json.loads(line)

def send(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()

mode = os.environ.get("FAKE_MODE", "happy")
secret = os.environ.pop("CLEARWING_CYBERPI_API_KEY")
start = read()
assert secret not in repr(sys.argv)
assert secret not in json.dumps(start)

if mode == "malformed_json":
    sys.stdout.write("{not-json\n")
    sys.stdout.flush()
    raise SystemExit(0)
if mode == "unexpected":
    send({"type": "unexpected"})
    time.sleep(60)
if mode == "exit":
    raise SystemExit(7)

if mode != "prose_only":
    send({"type": "tool_call", "id": "read-1", "name": "read_file", "arguments": {"path": "/repo/src/app.c"}})
    assert read() == {"type": "tool_result", "id": "read-1", "ok": True, "result": "source"}
    send({
        "type": "tool_call",
        "id": "finding-1",
        "name": "record_finding",
        "arguments": {
            "file": "src/app.c",
            "line_number": 7,
            "finding_type": "buffer_overflow",
            "severity": "high",
            "description": "attacker-controlled length reaches memcpy",
        },
    })
    result = read()
    assert result["type"] == "tool_result" and result["ok"] is True

send({"type": "model_call", "id": "model-1", "input_bytes": 1, "max_tokens": start["model"]["max_output_tokens"] or 4096})
authorization = read()
if os.environ.get("AUTH_MARKER"):
    Path = __import__("pathlib").Path
    Path(os.environ["AUTH_MARKER"]).write_text(str(authorization["max_tokens"]))

if mode == "cancel":
    Path = __import__("pathlib").Path
    Path(os.environ["PID_FILE"]).write_text(str(os.getpid()))
    time.sleep(60)

if mode == "malformed_usage":
    usage = {"input_tokens": 1}
else:
    usage = {
        "input_tokens": 1,
        "output_tokens": 1,
        "cached_input_tokens": 0,
        "total_tokens": 2,
        "cost_usd": 0.01,
    }
send({"type": "model_result", "id": "model-1", "ok": mode != "model_error", "error": "provider failed" if mode == "model_error" else None, "usage": usage})
ack = read()
assert ack == {"type": "model_result_ack", "id": "model-1"}
send({
    "type": "trajectory",
    "step": 1,
    "message": {
        "role": "assistant",
        "content": "I inspected the bounded fixture.",
        "tool_calls": [],
        "tool_response_call_id": None,
    },
    "reasoning_content": "The length reaches memcpy without a bound.",
    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    "model": start["model"]["id"],
})
send({
    "type": "complete",
    "stop_reason": "stop",
    "turns": 1,
    "model_calls": 1,
    "final_text": "Invented prose-only CVE that Clearwing must ignore",
})
"""


def _schema(properties: dict, required: list[str]) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _client(ledger: SpendLedger | None = None) -> AsyncLLMClient:
    client = AsyncLLMClient(
        model_name="deepseek-v4-flash-0731",
        provider_name="openai",
        api_key="secret-value",
        base_url=("https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"),
    )
    return client.with_spend_ledger(ledger, stage="hunt") if ledger else client


def _runtime(tmp_path: Path, *, mode: str = "happy", ledger: SpendLedger | None = None):
    from clearwing.sourcehunt.cyberpi import CyberPiHuntEngine

    script = tmp_path / "fake_sidecar.py"
    script.write_text(_FAKE_SIDECAR, encoding="utf-8")
    context = HunterContext(
        repo_path="/repo",
        file_path="src/app.c",
        session_id="cyberpi-test",
        trajectory_dir=tmp_path / "trajectory",
        work_item_id="work-1",
    )
    context.cleanup_variants = MagicMock()

    async def text_result(**_kwargs):
        return "source"

    async def record_finding(**arguments):
        context.findings.append(Finding(**arguments))
        return "recorded"

    tools = [
        NativeToolSpec(
            name="execute",
            description="execute",
            schema=_schema({"command": {"type": "string"}}, ["command"]),
            handler=text_result,
        ),
        NativeToolSpec(
            name="read_file",
            description="read",
            schema=_schema({"path": {"type": "string"}}, ["path"]),
            handler=text_result,
        ),
        NativeToolSpec(
            name="write_file",
            description="write",
            schema=_schema(
                {"path": {"type": "string"}, "contents": {"type": "string"}},
                ["path", "contents"],
            ),
            handler=text_result,
        ),
        NativeToolSpec(
            name="record_trace_step",
            description="trace",
            schema=_schema(
                {"file": {"type": "string"}, "line": {"type": "integer"}},
                ["file", "line"],
            ),
            handler=text_result,
        ),
        NativeToolSpec(
            name="record_finding",
            description="finding",
            schema=_schema(
                {
                    "file": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "finding_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "description": {"type": "string"},
                },
                ["file", "line_number", "finding_type", "severity", "description"],
            ),
            handler=record_finding,
        ),
    ]
    hunter = SimpleNamespace(
        llm=_client(ledger),
        tools=tools,
        prompt="Find real vulnerabilities. Record findings through the tool.",
        initial_user_message="Audit src/app.c",
        max_steps=4,
    )
    engine = CyberPiHuntEngine(
        lambda _assignment, _sandbox: (hunter, context),
        command=(sys.executable, os.fspath(script)),
        environ={"FAKE_MODE": mode},
    )
    assignment = HuntAssignment(
        file_target={"path": "src/app.c"},
        session_id="cyberpi-test",
        work_item_id="work-1",
        budget_usd=2.0,
    )
    return engine, assignment, context


def _ledger(tmp_path: Path, limit: float = 2.0) -> SpendLedger:
    return SpendLedger(
        limit_usd=limit,
        session_id="cyberpi-ledger",
        repo_url="/repo",
        output_dir=tmp_path,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
    )


@pytest.mark.asyncio
async def test_sidecar_routes_tools_and_accepts_findings_only_from_context(tmp_path):
    engine, assignment, context = _runtime(tmp_path)

    outcome = await engine.hunt(assignment, object())

    assert [finding.finding_type for finding in outcome.findings] == ["buffer_overflow"]
    assert outcome.cost_usd == pytest.approx(0.01)
    assert outcome.tokens_used == 2
    context.cleanup_variants.assert_called_once_with()
    records = [
        json.loads(line)
        for line in (Path(context.trajectory_dir) / "transcript.jsonl").read_text().splitlines()
    ]
    assert [record["event"] for record in records] == [
        "start",
        "message",
        "tool_call",
        "tool_result",
        "message",
        "tool_call",
        "tool_result",
        "message",
        "message",
        "finish",
    ]
    assert records[0]["tools"] == [
        "execute",
        "read_file",
        "write_file",
        "record_trace_step",
        "record_finding",
    ]
    assert records[0]["tool_definitions"][1] == {
        "name": "read_file",
        "description": "read",
        "schema": _schema({"path": {"type": "string"}}, ["path"]),
    }
    assistant = records[-2]
    assert assistant["reasoning_content"] == "The length reaches memcpy without a bound."
    assert assistant["usage"]["total_tokens"] == 2


@pytest.mark.asyncio
async def test_final_prose_cannot_create_a_finding(tmp_path):
    engine, assignment, _context = _runtime(tmp_path, mode="prose_only")

    outcome = await engine.hunt(assignment, object())

    assert outcome.findings == ()


@pytest.mark.asyncio
async def test_model_calls_reserve_and_settle_the_clearwing_ledger(tmp_path):
    ledger = _ledger(tmp_path)
    engine, assignment, _context = _runtime(tmp_path, ledger=ledger)

    outcome = await engine.hunt(assignment, object())

    assert ledger.spent_usd == pytest.approx(1.0)
    assert ledger.remaining_usd == pytest.approx(1.0)
    assert outcome.cost_usd == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_budget_refusal_happens_before_provider_dispatch(tmp_path):
    ledger = _ledger(tmp_path, limit=0.5)
    engine, assignment, context = _runtime(tmp_path, ledger=ledger)
    marker = tmp_path / "authorized"
    engine._environ["AUTH_MARKER"] = os.fspath(marker)

    with pytest.raises(BudgetExceeded):
        await engine.hunt(assignment, object())

    assert not marker.exists()
    assert ledger.spent_usd == 0.0
    context.cleanup_variants.assert_called_once_with()


@pytest.mark.asyncio
async def test_packaged_pi_sdk_reaches_the_budget_gate_without_dispatch(tmp_path):
    from clearwing.sourcehunt.cyberpi import CyberPiHuntEngine

    command = CyberPiHuntEngine.default_command()
    dependency = Path(command[1]).parent / "node_modules" / "@earendil-works" / "pi-coding-agent"
    if not dependency.is_dir():
        pytest.skip("CyberPi npm dependencies are not installed")
    ledger = _ledger(tmp_path, limit=0.5)
    engine, assignment, context = _runtime(tmp_path, ledger=ledger)
    engine._command = command
    engine._environ = None

    with pytest.raises(BudgetExceeded):
        await engine.hunt(assignment, object())

    assert ledger.spent_usd == 0.0
    context.cleanup_variants.assert_called_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["malformed_usage", "model_error"])
async def test_ambiguous_model_failures_charge_the_reservation(tmp_path, mode):
    from clearwing.sourcehunt.cyberpi import CyberPiError

    ledger = _ledger(tmp_path)
    engine, assignment, _context = _runtime(tmp_path, mode=mode, ledger=ledger)

    with pytest.raises(CyberPiError):
        await engine.hunt(assignment, object())

    assert ledger.spent_usd == pytest.approx(2.0)
    assert ledger.remaining_usd == pytest.approx(0.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["malformed_json", "unexpected", "exit"])
async def test_protocol_violations_fail_closed(tmp_path, mode):
    from clearwing.sourcehunt.cyberpi import CyberPiError

    engine, assignment, context = _runtime(tmp_path, mode=mode)

    with pytest.raises(CyberPiError):
        await engine.hunt(assignment, object())

    context.cleanup_variants.assert_called_once_with()


@pytest.mark.asyncio
async def test_cancellation_kills_child_and_conservatively_settles(tmp_path):
    ledger = _ledger(tmp_path)
    engine, assignment, context = _runtime(tmp_path, mode="cancel", ledger=ledger)
    pid_file = tmp_path / "pid"
    engine._environ["PID_FILE"] = os.fspath(pid_file)
    task = asyncio.create_task(engine.hunt(assignment, object()))
    for _ in range(100):
        if pid_file.exists():
            break
        await asyncio.sleep(0.01)
    assert pid_file.exists()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)
    assert ledger.spent_usd == pytest.approx(2.0)
    context.cleanup_variants.assert_called_once_with()


@pytest.mark.asyncio
async def test_tool_boundary_rejects_unknown_malformed_and_unsafe_calls():
    from clearwing.sourcehunt.cyberpi import CyberPiHuntEngine

    async def handler(**_kwargs):
        return "ok"

    tool = NativeToolSpec(
        name="write_file",
        description="write",
        schema=_schema(
            {"path": {"type": "string"}, "contents": {"type": "string"}},
            ["path", "contents"],
        ),
        handler=handler,
    )
    cases = [
        {"id": "1", "name": "unknown", "arguments": {}},
        {"id": "2", "name": "write_file", "arguments": []},
        {"id": "3", "name": "write_file", "arguments": {"path": "/scratch/a"}},
        {
            "id": "4",
            "name": "write_file",
            "arguments": {"path": 7, "contents": "x"},
        },
        {
            "id": "5",
            "name": "write_file",
            "arguments": {"path": "/scratch/a", "contents": "x", "extra": True},
        },
        {
            "id": "6",
            "name": "write_file",
            "arguments": {"path": "/etc/passwd", "contents": "x"},
        },
    ]

    results = [await CyberPiHuntEngine._invoke_tool([tool], case) for case in cases]

    assert all(result["ok"] is False for result in results)
    allowed = await CyberPiHuntEngine._invoke_tool(
        [tool],
        {
            "id": "7",
            "name": "write_file",
            "arguments": {"path": "/scratch/poc.py", "contents": "x"},
        },
    )
    assert allowed["ok"] is True
    assert CyberPiHuntEngine._is_scratch_path("/scratch/../etc/passwd") is False


def test_deepseek_v4_flash_uses_the_pi_token_plan_adapter():
    from clearwing.sourcehunt.cyberpi import CyberPiHuntEngine

    model = CyberPiHuntEngine._model_from_client(_client())

    assert model.provider == "qwen-token-plan-individual"
    assert model.model == "deepseek-v4-flash-0731"
    assert model.api == "openai-completions"


def test_native_is_default_and_does_not_import_cyberpi():
    sys.modules.pop("clearwing.sourcehunt.cyberpi", None)
    pool = HunterPool(
        HuntPoolConfig(
            files=[],
            repo_path="/repo",
            hunter_factory=lambda *_args: None,
        )
    )

    assert isinstance(pool._hunt_engine, NativeHuntEngine)
    assert "clearwing.sourcehunt.cyberpi" not in sys.modules
    assert FeatureFlags().hunt_engine == "native"


def test_engine_injection_uses_the_domain_contract():
    finding = Finding(file="src/app.c", finding_type="test", description="test")

    class Engine:
        async def hunt(self, assignment, sandbox):
            assert assignment.file_target["path"] == "src/app.c"
            assert sandbox is None
            return HuntOutcome((finding,), 0.25, 11, "completed")

    pool = HunterPool(
        HuntPoolConfig(
            files=[{"path": "src/app.c", "priority": 4.0}],
            repo_path="/repo",
            hunt_engine=Engine(),
            starting_band="deep",
            max_band="deep",
            redundancy_override=1,
        )
    )

    assert pool.run() == [finding]


def test_cli_and_machine_mode_expose_engine_selection():
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)

    assert parser.parse_args(["sourcehunt", "repo"]).hunt_engine == "native"
    assert (
        parser.parse_args(["sourcehunt", "repo", "--hunt-engine", "cyberpi"]).hunt_engine
        == "cyberpi"
    )
    parsed = sourcehunt_command._machine_request(
        {"repo_url": "https://example.test/repo", "hunt_engine": "cyberpi"}
    )
    assert parsed["hunt_engine"] == "cyberpi"
