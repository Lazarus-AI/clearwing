import json
import subprocess
import threading


class MCPClient:
    """MCP client for connecting to external MCP servers via stdio transport."""

    def __init__(self, command: str, args: list[str] = None):
        self.command = command
        self.args = args or []
        self.process: subprocess.Popen | None = None
        self._id_counter = 0
        self._pending_requests: dict[int, threading.Event] = {}
        self._responses: dict[int, dict] = {}
        self._read_thread: threading.Thread | None = None

    def connect(self):
        """Start the MCP server process and the reader thread."""
        self.process = subprocess.Popen(
            [self.command] + self.args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()

        # Initialize
        return self.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "clearwing-client", "version": "1.0.0"},
            },
        )

    def _read_loop(self):
        """Background thread to read responses from the server."""
        for line in self.process.stdout:
            try:
                response = json.loads(line)
                req_id = response.get("id")
                if req_id in self._pending_requests:
                    self._responses[req_id] = response
                    self._pending_requests[req_id].set()
            except json.JSONDecodeError:
                continue

    def call(self, method: str, params: dict = None, timeout: float = 30.0) -> dict:
        """Call a method on the MCP server."""
        self._id_counter += 1
        req_id = self._id_counter

        request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}

        event = threading.Event()
        self._pending_requests[req_id] = event

        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

        if event.wait(timeout):
            response = self._responses.pop(req_id)
            self._pending_requests.pop(req_id)
            if "error" in response:
                raise Exception(f"MCP Error: {response['error']}")
            return response.get("result", {})
        else:
            self._pending_requests.pop(req_id)
            raise TimeoutError(f"MCP request {req_id} ({method}) timed out")

    def list_tools(self) -> list[dict]:
        """List available tools on the server."""
        result = self.call("tools/list")
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        """Call a tool on the server."""
        return self.call("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        """Shut down the server process."""
        if self.process:
            self.process.terminate()
            self.process.wait()
