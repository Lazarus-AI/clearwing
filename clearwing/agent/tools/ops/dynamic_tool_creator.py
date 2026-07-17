import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from clearwing.agent.tooling import interrupt, tool

_CUSTOM_TOOL_REGISTRY: dict = {}

# Generated tool source is written to an ephemeral temp directory rather than
# the installed package tree so an attacker cannot persist code on disk or
# poison the import path.
CUSTOM_TOOLS_DIR = Path(tempfile.mkdtemp(prefix="clearwing_custom_tools_"))

_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,40}$")
_ALLOWED_PARAM_TYPES = frozenset({"str", "int", "float", "bool", "dict", "list"})

TOOL_TEMPLATE = '''"""Auto-generated custom tool: {tool_name}"""
import asyncio
import json
import re
import socket
import subprocess


async def {tool_name}({param_signature}) -> str:
    """{description}"""
{code}


if __name__ == "__main__":
    import sys as _sys
    _kwargs = json.loads(_sys.stdin.read() or "{{}}")
    _result = asyncio.run({tool_name}(**_kwargs))
    _sys.stdout.write(json.dumps(_result))
'''


def _validate_tool_name(name: str) -> bool:
    return bool(_NAME_RE.fullmatch(name))


def _validate_parameters(parameters: list[dict]) -> str | None:
    """Return an error string if any parameter is invalid, else None."""
    for p in parameters:
        pname = p.get("name")
        ptype = p.get("type", "str")
        if not isinstance(pname, str) or not _NAME_RE.fullmatch(pname):
            return f"Invalid parameter name: {pname!r}"
        if ptype not in _ALLOWED_PARAM_TYPES:
            return f"Invalid parameter type: {ptype!r}"
    return None


def _sandbox_env() -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }


def _run_sandboxed(file_path: Path, kwargs: dict) -> str:
    """Execute a generated tool file in an isolated interpreter."""
    proc = subprocess.run(
        [sys.executable, "-I", str(file_path)],
        input=json.dumps(kwargs),
        env=_sandbox_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        return json.dumps({"error": proc.stderr.strip() or "sandbox exited non-zero"})
    return proc.stdout


def _make_stub(tool_name: str, description: str, parameters: list[dict], file_path: Path):
    """Build an @tool-decorated stub that shells out to the sandboxed subprocess."""
    param_names = [p["name"] for p in parameters]

    async def _stub(**kwargs) -> str:
        forwarded = {k: kwargs.get(k) for k in param_names}
        return _run_sandboxed(file_path, forwarded)

    _stub.__name__ = tool_name
    _stub.__doc__ = description
    return tool(_stub)


@tool
def create_custom_tool(
    tool_name: str,
    description: str,
    parameters: list[dict],
    python_code: str,
) -> dict:
    """Create a new tool at runtime by writing a Python file.

    The generated file is written to an ephemeral temp directory and executed
    in an isolated Python subprocess (`python -I`) with a minimal environment.
    It has access to: asyncio, json, re, socket, subprocess.

    Args:
        tool_name: Name for the tool (lowercase alphanumeric and underscores,
            max 41 chars, must not start with a digit).
        description: Description of what the tool does.
        parameters: List of parameter dicts with keys: name, type, description.
            ``type`` must be one of str, int, float, bool, dict, list.
        python_code: Python code for the function body (will be indented).

    Returns:
        Dict with keys: success, tool_name, message.
    """
    if not interrupt(
        f"Approve creating custom tool '{tool_name}' that will execute "
        f"arbitrary Python code in a sandboxed subprocess?"
    ):
        return {
            "success": False,
            "tool_name": tool_name,
            "message": "Custom tool creation not approved.",
        }

    if not _validate_tool_name(tool_name):
        return {
            "success": False,
            "tool_name": tool_name,
            "message": (
                "Invalid tool name. Use lowercase letters, digits and "
                "underscores only (max 41 chars, cannot start with a digit)."
            ),
        }

    param_error = _validate_parameters(parameters)
    if param_error:
        return {
            "success": False,
            "tool_name": tool_name,
            "message": param_error,
        }

    # Build parameter signature
    param_parts = []
    for p in parameters:
        ptype = p.get("type", "str")
        param_parts.append(f"{p['name']}: {ptype}")
    param_signature = ", ".join(param_parts)

    # Indent code body
    indented_code = "\n".join(f"    {line}" for line in python_code.strip().splitlines())

    # Escape the description so a crafted docstring cannot break out of the
    # triple-quoted block and inject top-level code.
    safe_description = json.dumps(description)[1:-1]

    file_content = TOOL_TEMPLATE.format(
        tool_name=tool_name,
        description=safe_description,
        param_signature=param_signature,
        code=indented_code,
    )

    CUSTOM_TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    file_path = CUSTOM_TOOLS_DIR / f"{tool_name}.py"
    file_path.write_text(file_content)

    stub = _make_stub(tool_name, safe_description, parameters, file_path)
    _CUSTOM_TOOL_REGISTRY[tool_name] = stub

    return {
        "success": True,
        "tool_name": tool_name,
        "message": (
            f"Tool '{tool_name}' created and registered "
            f"(sandboxed subprocess at {file_path})."
        ),
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
