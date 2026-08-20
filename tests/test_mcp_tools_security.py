"""Security tests for connect_mcp_server (c15 command allowlist)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import clearwing.agent.tools.ops.mcp_tools as mcp_mod
from clearwing.agent.tools.ops.mcp_tools import (
    _MCP_CLIENTS,
    _allowed_commands,
    _servers_dir,
    _validate_launch_spec,
    connect_mcp_server,
)


@pytest.fixture(autouse=True)
def _reset_clients():
    _MCP_CLIENTS.clear()
    yield
    _MCP_CLIENTS.clear()


@pytest.fixture
def approve():
    with patch.object(mcp_mod, "interrupt", return_value=True):
        yield


@pytest.fixture
def servers_dir(tmp_path, monkeypatch):
    d = tmp_path / "mcp_servers"
    d.mkdir()
    monkeypatch.setenv("CLEARWING_MCP_SERVERS_DIR", str(d))
    return d


class TestInterruptGate:
    def test_denied(self, servers_dir):
        with patch.object(mcp_mod, "interrupt", return_value=False):
            result = connect_mcp_server.invoke(
                {"name": "x", "command": "python3", "args": [str(servers_dir / "s.py")]}
            )
        assert result["status"] == "error"
        assert "not approved" in result["message"].lower()


class TestCommandAllowlist:
    def test_default_allowlist(self, monkeypatch):
        monkeypatch.delenv("CLEARWING_MCP_ALLOWED_COMMANDS", raising=False)
        assert _allowed_commands() == {"python", "python3", "node", "npx", "bun"}

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("CLEARWING_MCP_ALLOWED_COMMANDS", "deno, python3 ")
        assert _allowed_commands() == {"deno", "python3"}

    def test_rejects_disallowed_command(self, approve, servers_dir):
        result = connect_mcp_server.invoke(
            {"name": "x", "command": "bash", "args": [str(servers_dir / "s.sh")]}
        )
        assert result["status"] == "error"
        assert "allowlist" in result["message"]

    def test_basename_is_checked(self, approve, servers_dir):
        # /usr/bin/bash -> basename 'bash' still rejected
        result = connect_mcp_server.invoke(
            {"name": "x", "command": "/usr/bin/bash", "args": [str(servers_dir / "s.sh")]}
        )
        assert result["status"] == "error"


class TestServersDirConfinement:
    def test_default_dir(self, monkeypatch):
        monkeypatch.delenv("CLEARWING_MCP_SERVERS_DIR", raising=False)
        assert _servers_dir() == (Path.home() / ".clearwing" / "mcp_servers").resolve()

    def test_rejects_script_outside_dir(self, approve, servers_dir, tmp_path):
        outside = tmp_path / "elsewhere.py"
        outside.write_text("")
        result = connect_mcp_server.invoke(
            {"name": "x", "command": "python3", "args": [str(outside)]}
        )
        assert result["status"] == "error"
        assert "outside the permitted directory" in result["message"]

    def test_rejects_traversal(self, approve, servers_dir):
        err = _validate_launch_spec("python3", [str(servers_dir / ".." / "evil.py")])
        assert err is not None

    def test_requires_first_arg(self, approve, servers_dir):
        result = connect_mcp_server.invoke({"name": "x", "command": "python3", "args": []})
        assert result["status"] == "error"
        assert "server script path" in result["message"]


class TestMinimalEnvPassedToPopen:
    def test_happy_path_passes_minimal_env(self, approve, servers_dir):
        script = servers_dir / "server.py"
        script.write_text("")

        fake_client = MagicMock()
        fake_client.list_tools.return_value = [{"name": "t"}]
        with patch.object(mcp_mod, "MCPClient", return_value=fake_client) as mock_cls:
            result = connect_mcp_server.invoke(
                {"name": "srv", "command": "python3", "args": [str(script)]}
            )
        assert result["status"] == "connected"
        _, kwargs = mock_cls.call_args
        assert set(kwargs["env"].keys()) == {"PATH", "HOME"}

    def test_client_forwards_env_to_popen(self):
        from clearwing.mcp.client import MCPClient

        with patch("clearwing.mcp.client.subprocess.Popen") as mock_popen:
            mock_popen.return_value.stdout = iter([])
            client = MCPClient("python3", ["x.py"], env={"PATH": "/usr/bin", "HOME": "/tmp"})
            with patch.object(client, "call", return_value={}):
                client.connect()
        _, kwargs = mock_popen.call_args
        assert kwargs["env"] == {"PATH": "/usr/bin", "HOME": "/tmp"}
