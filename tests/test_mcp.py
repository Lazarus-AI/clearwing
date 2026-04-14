from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from clearwing.mcp.server import MCPServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_tool(name: str, description: str, schema: dict | None = None):
    """Create a minimal mock that behaves like a langchain @tool."""
    tool = MagicMock()
    tool.name = name
    tool.description = description
    if schema is None:
        schema = {
            "type": "object",
            "properties": {"ip_or_cidr": {"type": "string"}},
        }
    # Simulate args_schema with a .schema() method
    args_schema = MagicMock()
    args_schema.schema.return_value = schema
    tool.args_schema = args_schema
    return tool


def _build_server(tools: list | None = None):
    """Build an MCPServer with mocked tool loading."""
    if tools is None:
        tools = [
            _make_fake_tool(
                "validate_target",
                "Validate an IP address or CIDR range.",
                {
                    "type": "object",
                    "properties": {"ip_or_cidr": {"type": "string"}},
                },
            ),
            _make_fake_tool(
                "calculate_severity",
                "Calculate severity level from a CVSS score.",
                {
                    "type": "object",
                    "properties": {"cvss_score": {"type": "number"}},
                },
            ),
        ]
    with patch("clearwing.mcp.server.MCPServer._register_tools"):
        server = MCPServer()
    # Manually populate _tools from the mocks
    for t in tools:
        name = t.name
        desc = t.description
        schema = t.args_schema.schema()
        server._tools[name] = {
            "description": desc,
            "input_schema": schema,
            "func": t,
        }
    return server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMCPServerInit:
    """MCPServer initialization registers tools."""

    def test_registers_tools(self):
        server = _build_server()
        assert len(server._tools) > 0

    def test_registered_tool_has_expected_keys(self):
        server = _build_server()
        for name, info in server._tools.items():
            assert "description" in info
            assert "input_schema" in info
            assert "func" in info


class TestHandleInitialize:
    """handle_request with 'initialize' returns correct protocol version."""

    def test_initialize_protocol_version(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        response = server.handle_request(request)
        assert response["id"] == 1
        assert response["result"]["protocolVersion"] == MCPServer.PROTOCOL_VERSION

    def test_initialize_server_info(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
        response = server.handle_request(request)
        info = response["result"]["serverInfo"]
        assert info["name"] == "clearwing"
        assert info["version"] == "1.0.0"

    def test_initialize_capabilities(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}}
        response = server.handle_request(request)
        assert "tools" in response["result"]["capabilities"]


class TestHandleToolsList:
    """handle_request with 'tools/list' returns non-empty tool list."""

    def test_tools_list_non_empty(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
        response = server.handle_request(request)
        tools = response["result"]["tools"]
        assert len(tools) > 0

    def test_each_tool_has_required_keys(self):
        """Each tool in tools/list has name, description, inputSchema keys."""
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 11, "method": "tools/list"}
        response = server.handle_request(request)
        for tool in response["result"]["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_tool_names_match(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 12, "method": "tools/list"}
        response = server.handle_request(request)
        names = {t["name"] for t in response["result"]["tools"]}
        assert "validate_target" in names
        assert "calculate_severity" in names


class TestHandleToolsCall:
    """handle_request with 'tools/call' on 'validate_target' with valid args returns result."""

    def test_call_validate_target(self):
        server = _build_server()
        # Mock invoke to return a dict
        server._tools["validate_target"]["func"].invoke.return_value = {
            "valid": True,
            "is_cidr": False,
            "ips": ["192.168.1.1"],
        }
        request = {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "validate_target",
                "arguments": {"ip_or_cidr": "192.168.1.1"},
            },
        }
        response = server.handle_request(request)
        assert response["result"]["isError"] is False
        content_text = response["result"]["content"][0]["text"]
        parsed = json.loads(content_text)
        assert parsed["valid"] is True

    def test_call_returns_string_result(self):
        server = _build_server()
        server._tools["calculate_severity"]["func"].invoke.return_value = "HIGH"
        request = {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "calculate_severity",
                "arguments": {"cvss_score": 8.5},
            },
        }
        response = server.handle_request(request)
        assert response["result"]["isError"] is False
        assert response["result"]["content"][0]["text"] == "HIGH"

    def test_call_tool_exception(self):
        server = _build_server()
        server._tools["validate_target"]["func"].invoke.side_effect = RuntimeError("boom")
        request = {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "validate_target",
                "arguments": {"ip_or_cidr": "bad"},
            },
        }
        response = server.handle_request(request)
        assert response["result"]["isError"] is True
        assert "boom" in response["result"]["content"][0]["text"]


class TestUnknownMethod:
    """handle_request with unknown method returns error."""

    def test_unknown_method_error(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "id": 30, "method": "bogus/method"}
        response = server.handle_request(request)
        assert "error" in response
        assert response["error"]["code"] == -32601
        assert "bogus/method" in response["error"]["message"]


class TestUnknownTool:
    """handle_request with unknown tool returns error."""

    def test_unknown_tool_error(self):
        server = _build_server()
        request = {
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {"name": "nonexistent_tool", "arguments": {}},
        }
        response = server.handle_request(request)
        assert "error" in response
        assert response["error"]["code"] == -32602
        assert "nonexistent_tool" in response["error"]["message"]


class TestToolToMCP:
    """_tool_to_mcp extracts name and description."""

    def test_extracts_name(self):
        server = _build_server([])
        fake = _make_fake_tool("my_tool", "Does things")
        name, desc, schema = server._tool_to_mcp(fake)
        assert name == "my_tool"

    def test_extracts_description(self):
        server = _build_server([])
        fake = _make_fake_tool("my_tool", "Does things")
        name, desc, schema = server._tool_to_mcp(fake)
        assert desc == "Does things"

    def test_extracts_schema(self):
        server = _build_server([])
        fake = _make_fake_tool(
            "my_tool",
            "Does things",
            {"type": "object", "properties": {"x": {"type": "integer"}}},
        )
        name, desc, schema = server._tool_to_mcp(fake)
        assert schema["type"] == "object"
        assert "x" in schema["properties"]

    def test_fallback_schema_when_no_args_schema(self):
        server = _build_server([])
        fake = MagicMock()
        fake.name = "bare_tool"
        fake.description = "No schema"
        fake.args_schema = None
        name, desc, schema = server._tool_to_mcp(fake)
        assert schema == {"type": "object", "properties": {}}


class TestNotificationsInitialized:
    """notifications/initialized returns None (no response)."""

    def test_returns_none(self):
        server = _build_server()
        request = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        response = server.handle_request(request)
        assert response is None
