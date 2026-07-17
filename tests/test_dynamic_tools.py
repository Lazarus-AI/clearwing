"""Tests for dynamic tool creator."""

import json
from unittest.mock import patch

import pytest

import clearwing.agent.tools.ops.dynamic_tool_creator as dtc_mod
from clearwing.agent.tools.ops.dynamic_tool_creator import (
    _CUSTOM_TOOL_REGISTRY,
    CUSTOM_TOOLS_DIR,
    _validate_parameters,
    _validate_tool_name,
    create_custom_tool,
    get_custom_tools,
    list_custom_tools,
)


@pytest.fixture
def approve():
    """Auto-approve the human-in-the-loop gate for tests that exercise the happy path."""
    with patch.object(dtc_mod, "interrupt", return_value=True):
        yield


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
        _CUSTOM_TOOL_REGISTRY.clear()

    def test_create_simple_tool(self, approve):
        result = create_custom_tool.invoke(
            {
                "tool_name": "test_greeting",
                "description": "Returns a greeting message.",
                "parameters": [{"name": "name", "type": "str"}],
                "python_code": "return f'Hello, {name}!'",
            }
        )

        assert result["success"] is True
        assert result["tool_name"] == "test_greeting"

        # Verify file was written to the ephemeral temp dir, not the package tree
        tool_file = CUSTOM_TOOLS_DIR / "test_greeting.py"
        assert tool_file.exists()
        content = tool_file.read_text()
        assert "test_greeting" in content

        # Verify registered
        assert "test_greeting" in _CUSTOM_TOOL_REGISTRY

    def test_create_tool_with_multiple_params(self, approve):
        result = create_custom_tool.invoke(
            {
                "tool_name": "test_adder",
                "description": "Adds two numbers.",
                "parameters": [
                    {"name": "a", "type": "int"},
                    {"name": "b", "type": "int"},
                ],
                "python_code": "return str(a + b)",
            }
        )

        assert result["success"] is True
        assert "test_adder" in _CUSTOM_TOOL_REGISTRY

    def test_name_validation_rejects_path_traversal(self, approve):
        result = create_custom_tool.invoke(
            {
                "tool_name": "../../../etc/evil",
                "description": "Evil tool",
                "parameters": [],
                "python_code": "return 'evil'",
            }
        )
        assert result["success"] is False

    def test_name_validation_rejects_special_chars(self, approve):
        result = create_custom_tool.invoke(
            {
                "tool_name": "my-tool",
                "description": "Hyphenated name",
                "parameters": [],
                "python_code": "return 'nope'",
            }
        )
        assert result["success"] is False

    def test_name_validation_rejects_starting_digit(self, approve):
        result = create_custom_tool.invoke(
            {
                "tool_name": "1tool",
                "description": "Starts with digit",
                "parameters": [],
                "python_code": "return 'nope'",
            }
        )
        assert result["success"] is False

    def test_list_custom_tools(self, approve):
        create_custom_tool.invoke(
            {
                "tool_name": "test_greeting",
                "description": "Returns a greeting.",
                "parameters": [{"name": "name", "type": "str"}],
                "python_code": "return f'Hi {name}'",
            }
        )

        result = list_custom_tools.invoke({})
        assert len(result) == 1
        assert result[0]["name"] == "test_greeting"

    def test_get_custom_tools(self, approve):
        create_custom_tool.invoke(
            {
                "tool_name": "test_greeting",
                "description": "Returns a greeting.",
                "parameters": [{"name": "name", "type": "str"}],
                "python_code": "return f'Hi {name}'",
            }
        )

        tools = get_custom_tools()
        assert len(tools) == 1
        assert tools[0].name == "test_greeting"


class TestSecurityHardening:
    """Regression tests for the c14 sandbox hardening."""

    @pytest.fixture(autouse=True)
    def cleanup(self):
        yield
        _CUSTOM_TOOL_REGISTRY.clear()

    def test_interrupt_gate_blocks_when_denied(self):
        with patch.object(dtc_mod, "interrupt", return_value=False):
            result = create_custom_tool.invoke(
                {
                    "tool_name": "denied_tool",
                    "description": "d",
                    "parameters": [],
                    "python_code": "return 'x'",
                }
            )
        assert result["success"] is False
        assert "not approved" in result["message"].lower()
        assert "denied_tool" not in _CUSTOM_TOOL_REGISTRY

    def test_name_regex_rejects_uppercase(self):
        assert _validate_tool_name("MyTool") is False

    def test_name_regex_rejects_over_length(self):
        assert _validate_tool_name("a" * 42) is False
        assert _validate_tool_name("a" * 41) is True

    def test_parameter_name_validated(self):
        err = _validate_parameters([{"name": "x; import os", "type": "str"}])
        assert err is not None
        assert "Invalid parameter name" in err

    def test_parameter_type_allowlist(self):
        err = _validate_parameters([{"name": "x", "type": "__import__('os')"}])
        assert err is not None
        assert "Invalid parameter type" in err
        assert _validate_parameters([{"name": "x", "type": "int"}]) is None

    def test_rejects_invalid_parameter_via_tool(self, approve):
        result = create_custom_tool.invoke(
            {
                "tool_name": "bad_param_tool",
                "description": "d",
                "parameters": [{"name": "x)", "type": "str"}],
                "python_code": "return 'x'",
            }
        )
        assert result["success"] is False

    def test_description_is_escaped(self, approve):
        # A description that would otherwise close the docstring and inject code.
        result = create_custom_tool.invoke(
            {
                "tool_name": "test_greeting",
                "description": '"""\nimport os; os.system("id")\n"""',
                "parameters": [],
                "python_code": "return 'ok'",
            }
        )
        assert result["success"] is True
        content = (CUSTOM_TOOLS_DIR / "test_greeting.py").read_text()
        # The raw triple-quote sequence must not survive into the generated file.
        assert '"""\nimport os' not in content
        (CUSTOM_TOOLS_DIR / "test_greeting.py").unlink()

    def test_temp_dir_outside_package_tree(self):
        import clearwing

        pkg_root = str(clearwing.__path__[0])
        assert not str(CUSTOM_TOOLS_DIR).startswith(pkg_root)

    def test_stub_shells_to_isolated_subprocess(self, approve):
        create_custom_tool.invoke(
            {
                "tool_name": "test_greeting",
                "description": "d",
                "parameters": [{"name": "name", "type": "str"}],
                "python_code": "return name",
            }
        )
        stub = _CUSTOM_TOOL_REGISTRY["test_greeting"]
        with patch.object(dtc_mod, "subprocess") as mock_sub:
            mock_sub.run.return_value.returncode = 0
            mock_sub.run.return_value.stdout = json.dumps("hi")
            out = stub.invoke({"name": "hi"})
        assert out == json.dumps("hi")
        args, kwargs = mock_sub.run.call_args
        argv = args[0]
        assert argv[1] == "-I"
        assert kwargs["capture_output"] is True
        assert set(kwargs["env"].keys()) == {"PATH"}
