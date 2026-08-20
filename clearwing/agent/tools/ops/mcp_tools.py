import os
from pathlib import Path
from typing import Any

from clearwing.agent.tooling import interrupt, tool

from ....mcp.client import MCPClient

# Global registry of active MCP clients
_MCP_CLIENTS: dict[str, MCPClient] = {}


def _allowed_commands() -> set[str]:
    raw = os.environ.get(
        "CLEARWING_MCP_ALLOWED_COMMANDS", "python,python3,node,npx,bun"
    )
    return {c.strip() for c in raw.split(",") if c.strip()}


def _servers_dir() -> Path:
    return Path(
        os.environ.get(
            "CLEARWING_MCP_SERVERS_DIR", str(Path.home() / ".clearwing" / "mcp_servers")
        )
    ).resolve()


def _minimal_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", str(Path.home())),
    }


def _validate_launch_spec(command: str, args: list[str]) -> str | None:
    """Return an error string if the launch spec is not permitted, else None."""
    cmd_name = Path(command).name
    allowed = _allowed_commands()
    if cmd_name not in allowed:
        return (
            f"Command '{cmd_name}' is not in the MCP allowlist "
            f"({sorted(allowed)}). Set CLEARWING_MCP_ALLOWED_COMMANDS to extend it."
        )

    if not args:
        return (
            "At least one argument (the server script path) is required so it can "
            "be confined to CLEARWING_MCP_SERVERS_DIR."
        )

    servers_dir = _servers_dir()
    try:
        script = Path(args[0]).resolve()
    except (OSError, ValueError) as exc:  # pragma: no cover - defensive
        return f"Could not resolve server script path: {exc}"
    try:
        script.relative_to(servers_dir)
    except ValueError:
        return (
            f"Server script '{script}' is outside the permitted directory "
            f"'{servers_dir}'. Set CLEARWING_MCP_SERVERS_DIR to change it."
        )
    return None


@tool
def connect_mcp_server(name: str, command: str, args: list[str] | None = None) -> dict[str, Any]:
    """Connect to an external MCP server (Model Context Protocol).

    This allows the agent to access additional tools from external providers,
    such as source code analysis, database access, or cloud APIs.

    The launcher command must be on the ``CLEARWING_MCP_ALLOWED_COMMANDS``
    allowlist (default: ``python,python3,node,npx,bun``) and the first argument
    must resolve to a path under ``CLEARWING_MCP_SERVERS_DIR`` (default:
    ``~/.clearwing/mcp_servers``). The server process is started with a minimal
    ``PATH``/``HOME`` environment.

    Args:
        name: A unique identifier for this MCP server.
        command: The shell command to start the MCP server (stdio transport).
        args: Optional list of arguments for the command.

    Returns:
        Dict with status, server name, and list of available tools.
    """
    args = list(args or [])

    if not interrupt(
        f"Approve launching MCP server '{name}' via `{command} {' '.join(args)}`?"
    ):
        return {"status": "error", "message": "MCP server launch not approved."}

    error = _validate_launch_spec(command, args)
    if error:
        return {"status": "error", "message": error}

    if name in _MCP_CLIENTS:
        return {"status": "already_connected", "name": name}

    try:
        client = MCPClient(command, args, env=_minimal_env())
        client.connect()
        _MCP_CLIENTS[name] = client

        tools = client.list_tools()
        tool_names = [t.get("name") for t in tools]

        return {
            "status": "connected",
            "name": name,
            "tools_available": tool_names,
            "message": f"Successfully connected to MCP server '{name}'.",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@tool
def list_mcp_servers() -> list[dict[str, Any]]:
    """List all currently connected MCP servers and their status.

    Returns:
        List of server info dicts.
    """
    results = []
    for name, client in _MCP_CLIENTS.items():
        try:
            tools = client.list_tools()
            results.append({"name": name, "status": "connected", "tool_count": len(tools)})
        except Exception:
            results.append({"name": name, "status": "disconnected"})
    return results


@tool
def call_mcp_tool(server_name: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call a tool on a connected MCP server.

    Args:
        server_name: The name of the connected MCP server.
        tool_name: The name of the tool to call.
        arguments: Dictionary of arguments to pass to the tool.

    Returns:
        The tool output.
    """
    if server_name not in _MCP_CLIENTS:
        return {"error": f"MCP server '{server_name}' not connected. Use connect_mcp_server first."}

    client = _MCP_CLIENTS[server_name]
    try:
        result = client.call_tool(tool_name, arguments)
        return result
    except Exception as e:
        return {"error": str(e)}


def get_mcp_tools() -> list:
    """Return all MCP-related tools for the agent."""
    return [connect_mcp_server, list_mcp_servers, call_mcp_tool]
