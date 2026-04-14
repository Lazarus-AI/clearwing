from typing import Any

from langchain_core.tools import tool

from ....mcp.client import MCPClient

# Global registry of active MCP clients
_MCP_CLIENTS: dict[str, MCPClient] = {}


@tool
def connect_mcp_server(name: str, command: str, args: list[str] = None) -> dict[str, Any]:
    """Connect to an external MCP server (Model Context Protocol).

    This allows the agent to access additional tools from external providers,
    such as source code analysis, database access, or cloud APIs.

    Args:
        name: A unique identifier for this MCP server.
        command: The shell command to start the MCP server (stdio transport).
        args: Optional list of arguments for the command.

    Returns:
        Dict with status, server name, and list of available tools.
    """
    if name in _MCP_CLIENTS:
        return {"status": "already_connected", "name": name}

    try:
        client = MCPClient(command, args)
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
