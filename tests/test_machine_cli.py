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
from clearwing.ui.machine import MachineChannel, MachineProtocolError


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


def _channel(operation: str, request: dict, routing: dict | None = None):
    parent, child = socket.socketpair()
    parent.sendall(
        json.dumps(
            {
                "v": 1,
                "type": f"{operation}.start",
                "request": request,
                "provider_routing": routing or _routing(),
            }
        ).encode()
        + b"\n"
    )
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


def test_sourcehunt_public_result_removes_host_paths():
    result = sourcehunt._public_result(_SourceResult())
    assert result["findings"] == [{"file": "app.py"}]
    assert "repo_path" not in result
    assert "output_paths" not in result
    assert "/private" not in repr(result)


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
