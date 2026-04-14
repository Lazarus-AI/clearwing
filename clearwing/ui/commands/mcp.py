"""MCP server subcommand."""


def add_parser(subparsers):
    subparsers.add_parser("mcp", help="Start the MCP stdio server for external agents/IDEs")


def handle(cli, args):
    """Start the MCP stdio server."""
    from ...mcp import MCPServer

    server = MCPServer()
    server.run()
