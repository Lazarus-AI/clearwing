import json
import subprocess
import threading
from collections import deque
from typing import TextIO


class MCPClient:
    """MCP client for connecting to external MCP servers via stdio transport."""

    def __init__(
        self,
        command: str,
        args: list[str] = None,
        env: dict[str, str] | None = None,
        *,
        initialize_timeout: float = 30.0,
        request_timeout: float = 30.0,
    ):
        self.command = command
        self.args = args or []
        self.env = env
        self.initialize_timeout = initialize_timeout
        self.request_timeout = request_timeout
        self.process: subprocess.Popen | None = None
        self._id_counter = 0
        self._pending_requests: dict[int, threading.Event] = {}
        self._responses: dict[int, dict] = {}
        self._read_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._reader_finished = threading.Event()
        self._call_lock = threading.Lock()
        self._stderr_lines: deque[str] = deque(maxlen=100)

    def connect(self):
        """Start the MCP server process and the reader thread."""
        self.process = subprocess.Popen(
            [self.command] + self.args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.env,
        )
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            args=(self.process.stderr,),
            daemon=True,
        )
        self._stderr_thread.start()

        # Initialize
        result = self.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "clearwing-client", "version": "1.0.0"},
            },
            timeout=self.initialize_timeout,
        )
        self.notify("notifications/initialized")
        return result

    def _drain_stderr(self, stream: TextIO | None) -> None:
        """Prevent blocking while retaining a bounded startup diagnostic tail."""
        if stream is not None:
            for line in stream:
                self._stderr_lines.append(line.rstrip())

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self._stderr_lines)

    def _read_loop(self):
        """Background thread to read responses from the server."""
        try:
            for line in self.process.stdout:
                try:
                    response = json.loads(line)
                    req_id = response.get("id")
                    if req_id in self._pending_requests:
                        self._responses[req_id] = response
                        self._pending_requests[req_id].set()
                except json.JSONDecodeError:
                    continue
        finally:
            self._reader_finished.set()
            # A server that exits before replying must wake callers immediately;
            # otherwise they misleadingly wait until the request timeout.
            for event in list(self._pending_requests.values()):
                event.set()

    def call(self, method: str, params: dict = None, timeout: float | None = None) -> dict:
        """Call a method on the MCP server, serializing shared stdio access."""
        timeout = self.request_timeout if timeout is None else timeout
        with self._call_lock:
            self._id_counter += 1
            req_id = self._id_counter

            request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}

            event = threading.Event()
            self._pending_requests[req_id] = event

            if self.process is None or self.process.stdin is None:
                raise RuntimeError("MCP server is not connected")
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
            if self._reader_finished.is_set():
                event.set()

            if event.wait(timeout):
                self._pending_requests.pop(req_id)
                response = self._responses.pop(req_id, None)
                if response is None:
                    if self._stderr_thread is not None:
                        self._stderr_thread.join(timeout=0.2)
                    exit_code = self.process.poll()
                    diagnostic = self.stderr_tail[-4000:]
                    suffix = (
                        f"\nServer stderr tail:\n{diagnostic}" if diagnostic else ""
                    )
                    raise RuntimeError(
                        f"MCP server exited before replying to request {req_id} "
                        f"({method}); exit code {exit_code}{suffix}"
                    )
                if "error" in response:
                    raise Exception(f"MCP Error: {response['error']}")
                return response.get("result", {})
            self._pending_requests.pop(req_id)
            diagnostic = self.stderr_tail[-4000:]
            suffix = f"\nServer stderr tail:\n{diagnostic}" if diagnostic else ""
            raise TimeoutError(
                f"MCP request {req_id} ({method}) timed out after {timeout:.0f}s{suffix}"
            )

    def notify(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (a request without an id)."""
        with self._call_lock:
            if self.process is None or self.process.stdin is None:
                raise RuntimeError("MCP server is not connected")
            request = {"jsonrpc": "2.0", "method": method, "params": params or {}}
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()

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
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
