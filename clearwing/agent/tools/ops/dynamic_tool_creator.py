import importlib
import importlib.util
import re
from pathlib import Path

from clearwing.agent.tooling import tool

_CUSTOM_TOOL_REGISTRY: dict = {}

CUSTOM_TOOLS_DIR = Path(__file__).parent.parent.parent / "custom_tools"

TOOL_TEMPLATE = '''"""Auto-generated custom tool: {tool_name}"""
import asyncio
import json
import re
import socket
import subprocess

from clearwing.agent.tooling import tool


@tool
async def {tool_name}({param_signature}) -> str:
    """{description}"""
{code}
'''


def _validate_tool_name(name: str) -> bool:
    return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name))


@tool
def create_custom_tool(
    tool_name: str,
    description: str,
    parameters: list[dict],
    python_code: str,
) -> dict:
    """Create a new tool at runtime by writing a Python file.

    The tool will be a @tool-decorated async function. It has access to:
    asyncio, json, re, socket, subprocess.

    Args:
        tool_name: Name for the tool (alphanumeric and underscores only).
        description: Description of what the tool does.
        parameters: List of parameter dicts with keys: name, type, description.
        python_code: Python code for the function body (will be indented).

    Returns:
        Dict with keys: success, tool_name, message.
    """
    if not _validate_tool_name(tool_name):
        return {
            "success": False,
            "tool_name": tool_name,
            "message": "Invalid tool name. Use only alphanumeric characters and underscores.",
        }

    # Build parameter signature
    param_parts = []
    for p in parameters:
        ptype = p.get("type", "str")
        param_parts.append(f"{p['name']}: {ptype}")
    param_signature = ", ".join(param_parts)

    # Indent code body
    indented_code = "\n".join(f"    {line}" for line in python_code.strip().splitlines())

    file_content = TOOL_TEMPLATE.format(
        tool_name=tool_name,
        description=description,
        param_signature=param_signature,
        code=indented_code,
    )

    CUSTOM_TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    file_path = CUSTOM_TOOLS_DIR / f"{tool_name}.py"
    file_path.write_text(file_content)

    # Load the module
    spec = importlib.util.spec_from_file_location(
        f"clearwing.agent.custom_tools.{tool_name}", str(file_path)
    )
    if spec is None or spec.loader is None:
        return {
            "success": False,
            "tool_name": tool_name,
            "message": f"Failed to build import spec for {file_path}",
        }
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    tool_func = getattr(module, tool_name)
    _CUSTOM_TOOL_REGISTRY[tool_name] = tool_func

    return {
        "success": True,
        "tool_name": tool_name,
        "message": f"Tool '{tool_name}' created and registered.",
    }


@tool
def list_custom_tools() -> list[dict]:
    """List all runtime-created custom tools.

    Returns:
        List of dicts with keys: name, description.
    """
    result = []
    for name, func in _CUSTOM_TOOL_REGISTRY.items():
        result.append(
            {
                "name": name,
                "description": getattr(func, "description", ""),
            }
        )
    return result


def get_custom_tools() -> list:
    return list(_CUSTOM_TOOL_REGISTRY.values())
