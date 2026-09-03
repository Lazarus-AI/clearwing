"""Machine-mode CLI protocol tests."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from clearwing.agent.operator import OperatorResult
from clearwing.providers import (
    ProviderManager,
    install_runtime_routing,
    resolve_llm_endpoint,
    runtime_routing,
)
from clearwing.providers import runtime as provider_runtime
from clearwing.ui.commands import operate, sourcehunt, tool
from clearwing.ui.machine import MAX_RECORD_BYTES, MachineChannel, MachineProtocolError


def _routing(value: dict | None = None) -> dict:
    config = value or {
        "provider": {
            "base_url": "https://llm.example/v1",
            "model": "host-model",
            "api_key": "host-secret",
        }
    }
    encoded = base64.urlsafe_b64encode(json.dumps(config).encode()).decode().rstrip("=")
    return {"encoding": "base64url", "value": encoded}


def _channel(
    operation: str,
    request: dict,
    routing: dict | None = None,
    workspace: dict | None = None,
):
    parent, child = socket.socketpair()
    record = {
        "v": 1,
        "type": f"{operation}.start",
        "request": request,
        "provider_routing": routing or _routing(),
    }
    if workspace is not None:
        record["workspace"] = workspace
    parent.sendall(json.dumps(record).encode() + b"\n")
    return parent, MachineChannel(child.detach(), operation)


def _records(sock: socket.socket) -> list[dict]:
    with sock.makefile("rb") as stream:
        return [json.loads(line) for line in stream]


def test_channel_rejects_unknown_and_oversized_start_records():
    parent, child = socket.socketpair()
    parent.sendall(
        json.dumps(
            {
                "v": 1,
                "type": "operate.start",
                "request": {},
                "provider_routing": _routing(),
                "api_key": "guest-secret",
            }
        ).encode()
        + b"\n"
    )
    channel = MachineChannel(child.detach(), "operate")
    with pytest.raises(MachineProtocolError, match="unknown start"):
        channel.read_start()
    channel.close()
    parent.close()


def test_channel_accepts_host_selected_workspace_paths():
    workspace = {
        "local_path": "/workspaces/run/source",
        "output_dir": "/workspaces/run/sourcehunt",
        "checkpoint_path": "/workspaces/run/sourcehunt/pipeline/checkpoint.json",
    }
    parent, channel = _channel(
        "sourcehunt",
        {"repo_url": "https://example.test/repo"},
        workspace=workspace,
    )

    channel.read_start()

    assert channel.workspace == workspace
    channel.close()
    parent.close()


def test_operate_request_rejects_provider_and_transport_fields():
    with pytest.raises(ValueError, match="unknown request field.*api_key"):
        operate._machine_request(
            {"target": "host", "goals": ["scan"], "api_key": "guest-secret"}
        )
    with pytest.raises(ValueError, match="unknown request field.*model"):
        operate._machine_request(
            {"target": "host", "goals": ["scan"], "model": "guest-model"}
        )


def test_operate_request_accepts_bounded_callback_route():
    parsed = operate._machine_request(
        {
            "target": "host",
            "goals": ["prove RCE"],
            "lhost": "host.docker.internal",
            "lport": 8989,
        }
    )
    assert parsed["lhost"] == "host.docker.internal"
    assert parsed["lport"] == 8989

    with pytest.raises(ValueError, match="lport"):
        operate._machine_request(
            {"target": "host", "goals": ["prove RCE"], "lport": 80}
        )


def test_sourcehunt_request_rejects_paths_credentials_and_provider_fields():
    with pytest.raises(ValueError, match="credentials"):
        sourcehunt._machine_request(
            {"repo_url": "https://user:secret@example.test/repo"}
        )
    with pytest.raises(ValueError, match="unknown request field.*local_path"):
        sourcehunt._machine_request(
            {"repo_url": "https://example.test/repo", "local_path": "/host"}
        )
    with pytest.raises(ValueError, match="unknown request field.*model"):
        sourcehunt._machine_request(
            {"repo_url": "https://example.test/repo", "model": "guest-model"}
        )
    with pytest.raises(ValueError, match="unknown request field.*stage"):
        sourcehunt._machine_request(
            {
                "repo_url": "https://example.test/repo",
                "stage": "hunt",
            }
        )


def test_sourcehunt_machine_request_accepts_checkpoint_object():
    checkpoint = {"schema_version": 1, "commit_sha": None, "options": {}, "result": {}}

    parsed = sourcehunt._machine_request(
        {"repo_url": "https://example.test/repo", "checkpoint": checkpoint}
    )

    assert parsed["checkpoint"] == checkpoint
    with pytest.raises(ValueError, match="checkpoint must be a JSON object"):
        sourcehunt._machine_request(
            {"repo_url": "https://example.test/repo", "checkpoint": "serialized-json"}
        )


def test_sourcehunt_machine_request_semgrep_is_strict_and_default_off():
    assert sourcehunt._machine_request({"repo_url": "https://example.test/repo"})["semgrep"] is False
    assert (
        sourcehunt._machine_request(
            {"repo_url": "https://example.test/repo", "semgrep": True}
        )["semgrep"]
        is True
    )
    with pytest.raises(ValueError, match="semgrep must be a boolean"):
        sourcehunt._machine_request(
            {"repo_url": "https://example.test/repo", "semgrep": "true"}
        )


def test_sourcehunt_machine_handler_propagates_semgrep(monkeypatch):
    captured = {}

    class FakeChannel:
        workspace = {
            "local_path": "/workspace/source",
            "output_dir": "/workspace/results",
            "checkpoint_path": "/workspace/results/checkpoint.json",
        }

        def __init__(self, descriptor, operation):
            assert descriptor == 7
            assert operation == "sourcehunt"

        def read_start(self):
            return (
                {
                    "repo_url": "https://example.test/repo",
                    "semgrep": True,
                    "campaign_hint": "Audit the parser's length arithmetic.",
                },
                {"provider": {"model": "test-model"}},
            )

        def emit(self, *_args):
            pass

        def result(self, value):
            captured["result"] = value

        def error(self, error):
            raise AssertionError(f"unexpected machine error: {error}")

        def close(self):
            pass

    class FakeRunner:
        def __init__(self, **kwargs):
            captured["runner"] = kwargs

        async def arun(self):
            return _SourceResult()

    monkeypatch.setattr("clearwing.ui.machine.MachineChannel", FakeChannel)
    monkeypatch.setattr("clearwing.providers.install_runtime_routing", lambda routing: None)
    monkeypatch.setattr(
        "clearwing.providers.ProviderManager.from_config",
        lambda routing: SimpleNamespace(),
    )
    monkeypatch.setattr("clearwing.sourcehunt.runner.SourceHuntRunner", FakeRunner)

    assert sourcehunt._handle_machine(7) == 0
    assert captured["runner"]["enable_semgrep"] is True
    assert captured["runner"]["campaign_hint"] == "Audit the parser's length arithmetic."


def test_sourcehunt_machine_request_bounds_campaign_hint():
    parsed = sourcehunt._machine_request(
        {
            "repo_url": "https://example.test/repo",
            "campaign_hint": "Audit the parser's length arithmetic.",
        }
    )
    assert parsed["campaign_hint"] == "Audit the parser's length arithmetic."

    with pytest.raises(ValueError, match="campaign_hint"):
        sourcehunt._machine_request(
            {"repo_url": "https://example.test/repo", "campaign_hint": "x" * 4097}
        )


def test_sourcehunt_machine_handler_honors_visible_cli_semgrep(monkeypatch):
    captured = {}

    class FakeChannel:
        workspace = {}

        def __init__(self, _descriptor, _operation):
            pass

        def read_start(self):
            return (
                {"repo_url": "https://example.test/repo"},
                {"provider": {"model": "test-model"}},
            )

        def emit(self, *_args):
            pass

        def result(self, _value):
            pass

        def error(self, error):
            raise AssertionError(f"unexpected machine error: {error}")

        def close(self):
            pass

    class FakeRunner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def arun(self):
            return _SourceResult()

    monkeypatch.setattr("clearwing.ui.machine.MachineChannel", FakeChannel)
    monkeypatch.setattr("clearwing.providers.install_runtime_routing", lambda routing: None)
    monkeypatch.setattr(
        "clearwing.providers.ProviderManager.from_config",
        lambda routing: SimpleNamespace(),
    )
    monkeypatch.setattr("clearwing.sourcehunt.runner.SourceHuntRunner", FakeRunner)

    assert sourcehunt._handle_machine(7, enable_semgrep=True) == 0
    assert captured["enable_semgrep"] is True


def test_operate_machine_uses_host_routing_and_emits_typed_records():
    parent, channel = _channel("operate", {"target": "host", "goals": ["scan"]})
    request, routing = channel.read_start()
    parsed = operate._machine_request(request)
    manager = ProviderManager.from_config(routing)
    endpoint = manager._global_endpoint
    assert endpoint is not None
    assert endpoint.model == "host-model"
    assert endpoint.api_key == "host-secret"
    assert "host-secret" not in repr(parsed)

    channel.emit("progress", {"role": "agent", "content": "working"})
    channel.result(
        OperatorResult(goals=["scan"], target="host", status="completed", turns=1)
    )
    channel.close()
    records = _records(parent)
    assert [record["type"] for record in records] == [
        "operate.progress",
        "operate.result",
    ]
    assert [record["seq"] for record in records] == [1, 2]
    assert records[-1]["data"]["status"] == "completed"


def test_machine_channel_compacts_oversized_progress_records():
    parent, channel = _channel("sourcehunt", {"repo_url": "https://example.test/repo"})
    channel.read_start()
    channel.emit(
        "progress",
        {
            "event": "hunter_status",
            "hunter_target": "app.py",
            "text": "x" * MAX_RECORD_BYTES,
        },
    )
    channel.result({"status": "completed"})
    channel.close()

    records = _records(parent)
    compacted = records[0]["data"]
    assert compacted["event"] == "hunter_status"
    assert compacted["hunter_target"] == "app.py"
    assert compacted["truncated"] is True
    assert compacted["original_bytes"] > MAX_RECORD_BYTES
    assert len(json.dumps(records[0], separators=(",", ":")).encode()) < MAX_RECORD_BYTES


def test_machine_channel_compacts_oversized_terminal_and_keeps_summary():
    parent, channel = _channel("sourcehunt", {"repo_url": "https://example.test/repo"})
    channel.read_start()
    channel.result(
        {
            "status": "completed",
            "files_ranked": 120,
            "findings": [{"description": "x" * MAX_RECORD_BYTES}],
            "checkpoint": {"result": {"files": "y" * MAX_RECORD_BYTES}},
        }
    )
    channel.close()

    record = _records(parent)[0]
    compacted = record["data"]
    assert compacted["status"] == "completed"
    assert compacted["files_ranked"] == 120
    assert compacted["findings_count"] == 1
    assert compacted["checkpoint_keys"] == ["result"]
    assert compacted["truncated"] is True
    assert compacted["original_bytes"] > MAX_RECORD_BYTES
    assert len(json.dumps(record, separators=(",", ":")).encode()) < MAX_RECORD_BYTES


@dataclass
class _Stage:
    outcome: object
    error: str | None = None
    fallback_description: str | None = None


@dataclass
class _Outcome:
    value: str


@dataclass
class _Pipeline:
    stages: dict = field(default_factory=lambda: {"rank": _Stage(_Outcome("succeeded"))})


@dataclass
class _SourceResult:
    status: str = "completed"
    exit_code: int = 2
    repo_url: str = "https://example.test/repo"
    repo_path: str = "/private/repo"
    findings: list = field(
        default_factory=lambda: [
            {"file": "/private/repo/app.py", "extra": {"artifact": "/private/proof"}}
        ]
    )
    verified_findings: list = field(default_factory=list)
    exploited_findings: list = field(default_factory=list)
    files_ranked: int = 1
    files_hunted: int = 1
    duration_seconds: float = 1.0
    cost_usd: float = 0.1
    tokens_used: int = 10
    budget_usd: float = 1.0
    output_paths: dict = field(default_factory=lambda: {"report": "/private/report"})
    session_id: str = "source-test"
    pipeline_status: _Pipeline = field(default_factory=_Pipeline)
    checkpoint: dict = field(
        default_factory=lambda: {
            "schema_version": 1,
            "commit_sha": None,
            "options": {},
            "result": {},
        }
    )


def test_sourcehunt_public_result_is_bounded_and_removes_workspace_state():
    def _bucket(prefix: str, count: int) -> list[dict]:
        return [
            {
                "file": f"/private/repo/{prefix}-{index}.py",
                "description": "x" * 10_000,
                "extra": {"artifact": "/private/proof"},
            }
            for index in range(count)
        ]

    source = _SourceResult(
        findings=_bucket("file", 20),
        verified_findings=_bucket("verified", 30),
        exploited_findings=_bucket("exploited", 18),
    )
    result = sourcehunt._public_result(source)

    # Every finding bucket is capped, but its true total is preserved alongside.
    assert len(result["findings"]) == 16
    assert result["finding_count"] == 20
    assert len(result["verified_findings"]) == 16
    assert result["verified_finding_count"] == 30
    assert len(result["exploited_findings"]) == 16
    assert result["exploited_finding_count"] == 18

    assert result["findings"][0]["file"] == "file-0.py"
    assert result["exploited_findings"][0]["file"] == "exploited-0.py"
    assert len(result["findings"][0]["description"].encode("utf-8")) == 4096

    assert set(result) == {
        "status",
        "findings",
        "verified_findings",
        "exploited_findings",
        "finding_count",
        "verified_finding_count",
        "exploited_finding_count",
        "files_ranked",
        "files_hunted",
        "duration_seconds",
        "cost_usd",
        "tokens_used",
    }
    assert "extra" not in result["findings"][0]
    assert "extra" not in result["exploited_findings"][0]
    assert "checkpoint" not in result
    assert "pipeline" not in result
    assert "session_id" not in result
    assert "repo_url" not in result
    assert "/private" not in repr(result)


def test_sourcehunt_public_progress_keeps_counts_out_of_bulk_event_state():
    result = sourcehunt._public_progress(
        {
            "type": "stage",
            "stage": "preprocess",
            "status": "completed",
            "detail": "x" * 10_000,
            "findings_so_far": 3,
            "cost_usd": 1.25,
            "files": [f"file-{index}.py" for index in range(1000)],
            "symbols": [f"symbol-{index}" for index in range(500)],
            "finding_ids": [f"finding-{index}" for index in range(25)],
            "error": {"code": "partial", "message": "bounded message", "raw": "private"},
            "checkpoint": {"bulk": "must not cross progress"},
        }
    )

    assert result == {
        "type": "stage",
        "stage": "preprocess",
        "status": "completed",
        "detail": "x" * 2048,
        "findings_so_far": 3,
        "cost_usd": 1.25,
        "file_count": 1000,
        "symbol_count": 500,
        "finding_id_count": 25,
        "error_code": "partial",
        "error_message": "bounded message",
    }


def test_sourcehunt_machine_request_preserves_deep_depth():
    result = sourcehunt._machine_request(
        {"repo_url": "https://example.test/repo", "depth": "deep"}
    )

    assert result["depth"] == "deep"


def test_machine_fd_is_not_secret_bearing_argv(monkeypatch):
    monkeypatch.setattr(os, "environ", {"PATH": os.environ.get("PATH", "")})
    argv = ["clearwing", "operate", "--machine-fd", "3"]
    assert "host-secret" not in repr(argv)
    assert "host-secret" not in repr(os.environ)


def test_process_routing_is_install_once_immutable_and_precedes_guest_model(monkeypatch):
    monkeypatch.setattr(provider_runtime, "_routing", None)
    config = {
        "provider": {
            "base_url": "https://llm.example/v1",
            "model": "host-model",
            "api_key": "host-secret",
        }
    }
    install_runtime_routing(config)
    config["provider"]["api_key"] = "mutated"

    endpoint = resolve_llm_endpoint(cli_model="guest-model")
    assert endpoint.model == "host-model"
    assert endpoint.api_key == "host-secret"
    copy = runtime_routing()
    assert copy is not None
    copy["provider"]["api_key"] = "changed-copy"
    assert runtime_routing()["provider"]["api_key"] == "host-secret"
    with pytest.raises(RuntimeError, match="already installed"):
        install_runtime_routing({"provider": {"model": "second"}})


def test_real_cli_reads_secret_only_from_inherited_descriptor():
    parent, child = socket.socketpair()
    executable = Path(sys.executable).with_name("clearwing")
    argv = [str(executable), "operate", "--machine-fd", str(child.fileno())]
    process = subprocess.Popen(
        argv,
        pass_fds=(child.fileno(),),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child.close()
    parent.sendall(
        json.dumps(
            {
                "v": 1,
                "type": "operate.start",
                "request": {"goals": ["scan"]},
                "provider_routing": _routing(),
            }
        ).encode()
        + b"\n"
    )
    parent.shutdown(socket.SHUT_WR)
    with parent.makefile("rb") as stream:
        records = [json.loads(line) for line in stream]
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 1
    assert records == [
        {
            "v": 1,
            "type": "operate.error",
            "seq": 1,
            "error": "target must be a non-empty string",
        }
    ]
    assert "host-secret" not in repr(process.args)
    assert "host-secret" not in stdout
    assert "host-secret" not in stderr


def test_tool_catalog_channel_allows_absent_provider_routing():
    parent, child = socket.socketpair()
    parent.sendall(
        json.dumps(
            {
                "v": 1,
                "type": "tools.catalog.start",
                "request": {},
            }
        ).encode()
        + b"\n"
    )
    channel = MachineChannel(
        child.detach(),
        "tools.catalog",
        require_provider_routing=False,
    )
    assert channel.read_start() == ({}, None)
    channel.result([])
    channel.close()
    assert _records(parent)[0]["type"] == "tools.catalog.result"


@pytest.mark.asyncio
async def test_tool_catalog_and_call_use_canonical_registry(monkeypatch):
    invoke = AsyncMock(return_value={"ok": True})
    item = SimpleNamespace(
        name="example",
        description="Example tool",
        input_schema={"type": "object"},
        ainvoke=invoke,
    )
    monkeypatch.setattr(tool, "_load_tools", lambda: {"example": item})

    assert tool._catalog() == [
        {
            "name": "example",
            "description": "Example tool",
            "input_schema": {"type": "object"},
        }
    ]
    assert await tool._invoke("example", {"value": 1}) == {"ok": True}
    invoke.assert_awaited_once_with({"value": 1})
