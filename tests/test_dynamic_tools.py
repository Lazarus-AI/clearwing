"""Tests for dynamic tool creator."""
import pytest
import shutil
from pathlib import Path


CUSTOM_TOOLS_DIR = Path(__file__).parent.parent / "clearwing" / "agent" / "custom_tools"


class TestDynamicToolCreator:
    @pytest.fixture(autouse=True)
    def cleanup_custom_tools(self):
        """Remove any test-created tool files after each test."""
        yield
        for name in ("test_greeting", "test_adder"):
            path = CUSTOM_TOOLS_DIR / f"{name}.py"
            if path.exists():
                path.unlink()
        # Clear registry
        from clearwing.agent.tools.dynamic_tool_creator import _CUSTOM_TOOL_REGISTRY
        _CUSTOM_TOOL_REGISTRY.clear()

    def test_create_simple_tool(self):
        from clearwing.agent.tools.dynamic_tool_creator import (
            create_custom_tool,
            _CUSTOM_TOOL_REGISTRY,
        )

        result = create_custom_tool.invoke({
            "tool_name": "test_greeting",
            "description": "Returns a greeting message.",
            "parameters": [{"name": "name", "type": "str"}],
            "python_code": "return f'Hello, {name}!'",
        })

        assert result["success"] is True
        assert result["tool_name"] == "test_greeting"

        # Verify file was written
        tool_file = CUSTOM_TOOLS_DIR / "test_greeting.py"
        assert tool_file.exists()
        content = tool_file.read_text()
        assert "test_greeting" in content
        assert "@tool" in content

        # Verify registered
        assert "test_greeting" in _CUSTOM_TOOL_REGISTRY

    def test_create_tool_with_multiple_params(self):
        from clearwing.agent.tools.dynamic_tool_creator import (
            create_custom_tool,
            _CUSTOM_TOOL_REGISTRY,
        )

        result = create_custom_tool.invoke({
            "tool_name": "test_adder",
            "description": "Adds two numbers.",
            "parameters": [
                {"name": "a", "type": "int"},
                {"name": "b", "type": "int"},
            ],
            "python_code": "return str(a + b)",
        })

        assert result["success"] is True
        assert "test_adder" in _CUSTOM_TOOL_REGISTRY

    def test_name_validation_rejects_path_traversal(self):
        from clearwing.agent.tools.dynamic_tool_creator import create_custom_tool

        result = create_custom_tool.invoke({
            "tool_name": "../../../etc/evil",
            "description": "Evil tool",
            "parameters": [],
            "python_code": "return 'evil'",
        })
        assert result["success"] is False

    def test_name_validation_rejects_special_chars(self):
        from clearwing.agent.tools.dynamic_tool_creator import create_custom_tool

        result = create_custom_tool.invoke({
            "tool_name": "my-tool",
            "description": "Hyphenated name",
            "parameters": [],
            "python_code": "return 'nope'",
        })
        assert result["success"] is False

    def test_name_validation_rejects_starting_digit(self):
        from clearwing.agent.tools.dynamic_tool_creator import create_custom_tool

        result = create_custom_tool.invoke({
            "tool_name": "1tool",
            "description": "Starts with digit",
            "parameters": [],
            "python_code": "return 'nope'",
        })
        assert result["success"] is False

    def test_list_custom_tools(self):
        from clearwing.agent.tools.dynamic_tool_creator import (
            create_custom_tool,
            list_custom_tools,
        )

        create_custom_tool.invoke({
            "tool_name": "test_greeting",
            "description": "Returns a greeting.",
            "parameters": [{"name": "name", "type": "str"}],
            "python_code": "return f'Hi {name}'",
        })

        result = list_custom_tools.invoke({})
        assert len(result) == 1
        assert result[0]["name"] == "test_greeting"

    def test_get_custom_tools(self):
        from clearwing.agent.tools.dynamic_tool_creator import (
            create_custom_tool,
            get_custom_tools,
        )

        create_custom_tool.invoke({
            "tool_name": "test_greeting",
            "description": "Returns a greeting.",
            "parameters": [{"name": "name", "type": "str"}],
            "python_code": "return f'Hi {name}'",
        })

        tools = get_custom_tools()
        assert len(tools) == 1
        assert tools[0].name == "test_greeting"
