"""JSON-RPC sandbox backend over Unix sockets or inherited descriptors."""

from __future__ import annotations

import base64
import binascii
import itertools
import json
import logging
import socket
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

from .backend import (
    SandboxEnvironment,
    SandboxEnvironmentSpec,
    SandboxInstance,
    SandboxRunConfig,
)
from .container import ExecResult

logger = logging.getLogger(__name__)

_MAX_RPC_BYTES = 16 * 1024 * 1024
_DEFAULT_CALL_TIMEOUT = 30.0


class SandboxRpcError(RuntimeError):
    """A transport or remote JSON-RPC failure."""

    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


@dataclass
class _PendingCall:
    ready: threading.Event
    response: dict[str, Any] | None = None
    failure: BaseException | None = None


class _FrameError(Exception):
    """A single response frame was malformed but the stream stayed in sync.

    Raised while dispatching one complete, newline-terminated frame. Because
    the frame boundary was intact, the reader can discard just this frame (and
    fail at most the one matching call) and keep serving every other worker on
    the shared connection.
    """


class JsonRpcConnection:
    """Thread-safe JSON-RPC 2.0 client over one full-duplex stream.

    Each message is a UTF-8 JSON object followed by a newline.  Calls are
    multiplexed by JSON-RPC id, so parallel SourceHunt workers do not serialize
    their sandbox commands. ``fd://N`` transfers ownership of an
    already-connected Unix stream socket to this connection; a one-way pipe is
    intentionally rejected.
    """

    def __init__(self, endpoint: str, *, max_message_bytes: int = _MAX_RPC_BYTES):
        self.endpoint = endpoint
        self.max_message_bytes = max_message_bytes
        self._socket = _connect(endpoint)
        # Buffered reader: an unbuffered SocketIO makes readline() issue one
        # recv() per byte (no peek), so a single large response would pin the
        # shared reader thread for seconds and stall every concurrent worker.
        self._reader = self._socket.makefile("rb")
        self._ids = itertools.count(1)
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._pending: dict[int, _PendingCall] = {}
        self._closed: BaseException | None = None
        self._resources_closed = False
        self._reader_thread = threading.Thread(
            target=self._read_responses,
            name="clearwing-sandbox-rpc",
            daemon=True,
        )
        self._reader_thread.start()

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = _DEFAULT_CALL_TIMEOUT,
    ) -> Any:
        if not method or any(character.isspace() for character in method):
            raise ValueError("JSON-RPC method must be a non-empty token")
        request_id = next(self._ids)
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) + 1 > self.max_message_bytes:
            raise SandboxRpcError("sandbox RPC request exceeds the message limit")
        # A non-positive timeout can never wait for a response, so report it
        # before writing the request: otherwise the backend would still run the
        # method's side effects for a call the caller has already given up on.
        if timeout is not None and timeout <= 0:
            raise SandboxRpcError(f"sandbox RPC method {method!r} timed out")
        pending = _PendingCall(threading.Event())
        with self._state_lock:
            if self._closed is not None:
                raise SandboxRpcError("sandbox RPC connection is closed") from self._closed
            self._pending[request_id] = pending
        try:
            with self._write_lock:
                self._socket.sendall(encoded + b"\n")
        except OSError as error:
            with self._state_lock:
                self._pending.pop(request_id, None)
            self._fail_connection(error)
            raise SandboxRpcError("sandbox RPC write failed") from error
        if not pending.ready.wait(timeout):
            with self._state_lock:
                self._pending.pop(request_id, None)
            raise SandboxRpcError(f"sandbox RPC method {method!r} timed out")
        if pending.failure is not None:
            raise SandboxRpcError("sandbox RPC connection failed") from pending.failure
        response = pending.response
        if response is None:
            raise SandboxRpcError("sandbox RPC response is missing")
        remote_error = response.get("error")
        if remote_error is not None:
            if not isinstance(remote_error, dict):
                raise SandboxRpcError("sandbox RPC returned an invalid error")
            message = remote_error.get("message")
            code = remote_error.get("code")
            if not isinstance(message, str) or not isinstance(code, int) or isinstance(code, bool):
                raise SandboxRpcError("sandbox RPC returned an invalid error")
            raise SandboxRpcError(message, code=code, data=remote_error.get("data"))
        if "result" not in response:
            raise SandboxRpcError("sandbox RPC response has no result")
        return response["result"]

    def close(self) -> None:
        self._fail_connection(ConnectionError("sandbox RPC connection was closed"))
        if threading.current_thread() is not self._reader_thread:
            # The shutdown() in _fail_connection unblocks the reader; wait for
            # it to run its teardown so the descriptor is released before we
            # return (belt-and-suspenders _close_resources below is idempotent).
            self._reader_thread.join(timeout=1)
        self._close_resources()

    @property
    def is_closed(self) -> bool:
        with self._state_lock:
            return self._closed is not None

    def _read_responses(self) -> None:
        try:
            while True:
                encoded = self._reader.readline(self.max_message_bytes + 1)
                if not encoded:
                    raise ConnectionError("sandbox RPC peer closed the connection")
                if len(encoded) > self.max_message_bytes or not encoded.endswith(b"\n"):
                    # Oversized/unterminated frame: the newline-delimited stream
                    # is desynced. Discard to the next boundary and keep serving
                    # every other worker instead of tearing down the shared
                    # connection over one giant response. _drain_to_boundary
                    # raises on EOF, which does end the connection.
                    logger.warning(
                        "sandbox RPC response exceeded %d bytes; discarding and resyncing",
                        self.max_message_bytes,
                    )
                    self._drain_to_boundary()
                    continue
                # A complete, newline-terminated frame keeps the stream in sync
                # regardless of its contents, so a malformed one fails at most
                # its matching call — never the connection.
                try:
                    self._dispatch_frame(encoded)
                except _FrameError as error:
                    logger.warning("discarding malformed sandbox RPC response: %s", error)
        except BaseException as error:  # noqa: BLE001 - wake every blocked caller
            self._fail_connection(error)
        finally:
            # The reader thread owns teardown of the reader/socket: doing it
            # here (rather than from another thread that may race a blocked
            # readline) frees the descriptor on every failure path, not just
            # the explicit close() path.
            self._close_resources()

    def _dispatch_frame(self, encoded: bytes) -> None:
        try:
            response = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _FrameError("response is not valid JSON") from error
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
            raise _FrameError("response is not JSON-RPC 2.0")
        request_id = response.get("id")
        if not isinstance(request_id, int) or isinstance(request_id, bool):
            raise _FrameError("response has an invalid id")
        with self._state_lock:
            pending = self._pending.pop(request_id, None)
        if pending is None:
            # A late response after a caller timeout is safe to discard.
            return
        if ("result" in response) == ("error" in response):
            # Well-framed but invalid: fail just this call so the caller gets a
            # definitive error rather than blocking until its timeout.
            pending.failure = SandboxRpcError(
                "sandbox RPC response must contain result or error"
            )
            pending.ready.set()
            return
        pending.response = response
        pending.ready.set()

    def _drain_to_boundary(self) -> None:
        # Discard the remainder of an oversized frame up to (and including) the
        # next newline. Reads are bounded per iteration; the total is bounded by
        # the frame the trusted supervisor actually sent. EOF mid-drain means
        # the peer is gone, which does fail the connection.
        while True:
            chunk = self._reader.readline(self.max_message_bytes + 1)
            if not chunk:
                raise ConnectionError("sandbox RPC peer closed the connection")
            if chunk.endswith(b"\n"):
                return

    def _fail_connection(self, error: BaseException) -> None:
        with self._state_lock:
            if self._closed is None:
                self._closed = error
            pending = list(self._pending.values())
            self._pending.clear()
        for call in pending:
            call.failure = error
            call.ready.set()
        # Wake a reader blocked in readline() so it exits and runs its teardown.
        # Safe from any thread and when the socket is already closed.
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _close_resources(self) -> None:
        with self._close_lock:
            if self._resources_closed:
                return
            self._resources_closed = True
        # Close the makefile and the socket. makefile() reference-counts the
        # descriptor, so both must close for the fd to actually be released.
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._reader.close()
        except OSError:
            pass
        try:
            self._socket.close()
        except OSError:
            pass


def _connect(endpoint: str) -> socket.socket:
    parsed = urlsplit(endpoint)
    if parsed.scheme == "unix":
        if parsed.netloc or parsed.query or parsed.fragment or not parsed.path.startswith("/"):
            raise ValueError("unix sandbox endpoint must contain one absolute socket path")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(parsed.path)
        except BaseException:
            connection.close()
            raise
        return connection
    if parsed.scheme == "fd":
        if parsed.query or parsed.fragment:
            raise ValueError("fd sandbox endpoint must use fd://N")
        if parsed.netloc and parsed.path:
            raise ValueError("fd sandbox endpoint must use fd://N")
        descriptor_text = parsed.netloc or parsed.path.lstrip("/")
        if not descriptor_text.isdigit() or int(descriptor_text) < 3:
            raise ValueError("fd sandbox endpoint must name a descriptor of at least 3")
        try:
            connection = socket.socket(fileno=int(descriptor_text))
        except OSError as error:
            raise ValueError("fd sandbox endpoint must name a socket") from error
        if (
            connection.family != socket.AF_UNIX
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
        ):
            connection.close()
            raise ValueError("fd sandbox endpoint must be a connected Unix stream socket")
        try:
            connection.getpeername()
        except OSError as error:
            connection.close()
            raise ValueError("fd sandbox endpoint must already be connected") from error
        return connection
    raise ValueError("sandbox endpoint must use unix:///path or fd://N")


class SocketSandboxBackend:
    """Sandbox backend that delegates trusted operations over JSON-RPC."""

    name = "jsonrpc"
    _connections: dict[str, JsonRpcConnection] = {}
    _connections_lock = threading.Lock()

    def __init__(
        self,
        endpoint: str,
        *,
        connection: JsonRpcConnection | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("sandbox RPC endpoint is empty")
        self.endpoint = endpoint
        self._connection = connection or self._shared_connection(endpoint)
        self._capabilities_lock = threading.Lock()
        self._capabilities_checked = False

    @classmethod
    def _shared_connection(cls, endpoint: str) -> JsonRpcConnection:
        with cls._connections_lock:
            connection = cls._connections.get(endpoint)
            if connection is None or connection.is_closed:
                connection = JsonRpcConnection(endpoint)
                cls._connections[endpoint] = connection
            return connection

    def _check_capabilities(self) -> None:
        if self._capabilities_checked:
            return
        with self._capabilities_lock:
            if self._capabilities_checked:
                return
            result = self._connection.call("sandbox.capabilities", timeout=5)
            result = _object(result, "sandbox.capabilities")
            if result.get("protocol_version") != 1:
                raise SandboxRpcError("sandbox RPC protocol version is unsupported")
            self._capabilities_checked = True

    def available_cpus(self) -> tuple[float | None, str]:
        self._check_capabilities()
        result = _object(self._connection.call("sandbox.capacity"), "sandbox.capacity")
        cpus = result.get("cpus")
        source = result.get("source", "sandbox backend")
        if cpus is not None and (not isinstance(cpus, (int, float)) or isinstance(cpus, bool)):
            raise SandboxRpcError("sandbox.capacity returned invalid cpus")
        if not isinstance(source, str):
            raise SandboxRpcError("sandbox.capacity returned invalid source")
        return (float(cpus) if cpus is not None else None), source

    def ensure_environment(
        self,
        spec: SandboxEnvironmentSpec,
        on_output: Callable[[str], None] | None = None,
    ) -> SandboxEnvironment:
        self._check_capabilities()
        result = _object(
            self._connection.call(
                "sandbox.environment.ensure",
                {"spec": asdict(spec)},
                timeout=spec.timeout_seconds + 30,
            ),
            "sandbox.environment.ensure",
        )
        environment_ref = result.get("environment_ref")
        if not isinstance(environment_ref, str) or not environment_ref:
            raise SandboxRpcError("sandbox.environment.ensure returned an invalid environment_ref")
        cached = result.get("cached")
        if not isinstance(cached, bool):
            raise SandboxRpcError("sandbox.environment.ensure returned invalid cached state")
        output = result.get("output", [])
        if not isinstance(output, list) or any(not isinstance(line, str) for line in output):
            raise SandboxRpcError("sandbox.environment.ensure returned invalid output")
        if on_output is not None:
            for line in output:
                on_output(line)
        return SandboxEnvironment(environment_ref, cached)

    def create(
        self,
        environment_ref: str,
        config: SandboxRunConfig,
    ) -> SandboxInstance:
        self._check_capabilities()
        return SocketSandboxInstance(self._connection, environment_ref, config)

    def release_environment(self, environment_ref: str) -> None:
        self._check_capabilities()
        self._connection.call(
            "sandbox.environment.release",
            {"environment_ref": environment_ref},
        )


class SocketSandboxInstance:
    """``SandboxInstance`` implemented by the JSON-RPC backend."""

    def __init__(
        self,
        connection: JsonRpcConnection,
        environment_ref: str,
        config: SandboxRunConfig,
    ):
        self.config = config
        self._connection = connection
        self._environment_ref = environment_ref
        self._sandbox_id: str | None = None
        self._short_id: str | None = None
        self.scratch_host_dir: str | None = None
        self.variant: list[str] | None = None
        self.workspace_baseline_commit: str | None = None

    def start(self) -> str:
        if self._sandbox_id is not None:
            return self._sandbox_id
        result = _object(
            self._connection.call(
                "sandbox.start",
                {
                    "environment_ref": self._environment_ref,
                    "config": asdict(self.config),
                },
            ),
            "sandbox.start",
        )
        sandbox_id = result.get("sandbox_id")
        short_id = result.get("short_id", sandbox_id)
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxRpcError("sandbox.start returned an invalid sandbox_id")
        if not isinstance(short_id, str) or not short_id:
            raise SandboxRpcError("sandbox.start returned an invalid short_id")
        self._sandbox_id = sandbox_id
        self._short_id = short_id

        from .registry import ContainerRegistry

        ContainerRegistry.get().register(self)
        return sandbox_id

    def exec(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        sandbox_id = self._require_started("exec")
        # Match SandboxContainer: an explicit zero falls back to the configured
        # timeout, while a negative value disables the in-sandbox timeout.
        effective_timeout = timeout or self.config.timeout_seconds
        call_timeout = effective_timeout + 10 if effective_timeout > 0 else None
        result = _object(
            self._connection.call(
                "sandbox.exec",
                {
                    "sandbox_id": sandbox_id,
                    "command": command,
                    "timeout_seconds": effective_timeout,
                    "env": env or {},
                    "workdir": workdir,
                },
                timeout=call_timeout,
            ),
            "sandbox.exec",
        )
        exit_code = result.get("exit_code")
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        duration = result.get("duration_seconds", 0.0)
        timed_out = result.get("timed_out", False)
        if (
            not isinstance(exit_code, int)
            or isinstance(exit_code, bool)
            or not isinstance(stdout, str)
            or not isinstance(stderr, str)
            or not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or not isinstance(timed_out, bool)
        ):
            raise SandboxRpcError("sandbox.exec returned an invalid result")
        return ExecResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=float(duration),
            timed_out=timed_out,
        )

    def write_file(self, container_path: str, content: bytes) -> None:
        sandbox_id = self._require_started("write_file")
        self._connection.call(
            "sandbox.file.write",
            {
                "sandbox_id": sandbox_id,
                "path": container_path,
                "content_base64": base64.b64encode(content).decode("ascii"),
            },
        )

    def read_file(self, container_path: str) -> bytes:
        sandbox_id = self._require_started("read_file")
        result = _object(
            self._connection.call(
                "sandbox.file.read",
                {"sandbox_id": sandbox_id, "path": container_path},
            ),
            "sandbox.file.read",
        )
        content = result.get("content_base64")
        if not isinstance(content, str):
            raise SandboxRpcError("sandbox.file.read returned invalid content")
        try:
            return base64.b64decode(content, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SandboxRpcError("sandbox.file.read returned invalid base64") from error

    def copy_tree_into(self, host_path: str, container_path: str = "/workspace") -> None:
        sandbox_id = self._require_started("copy_tree_into")
        self._connection.call(
            "sandbox.tree.copy",
            {
                "sandbox_id": sandbox_id,
                "host_path": host_path,
                "container_path": container_path,
            },
            timeout=610,
        )

    def stop(self) -> None:
        if self._sandbox_id is None:
            return
        sandbox_id = self._sandbox_id
        try:
            self._connection.call("sandbox.stop", {"sandbox_id": sandbox_id})
        except Exception:
            logger.debug("Remote sandbox stop failed", exc_info=True)
        finally:
            from .registry import ContainerRegistry

            ContainerRegistry.get().unregister(self)
            self._sandbox_id = None
            self._short_id = None

    def _require_started(self, operation: str) -> str:
        if self._sandbox_id is None:
            raise RuntimeError(f"SocketSandboxInstance.{operation} called before start()")
        return self._sandbox_id

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    @property
    def container_id(self) -> str | None:
        return self._sandbox_id

    @property
    def short_id(self) -> str | None:
        return self._short_id

    @property
    def is_running(self) -> bool:
        return self._sandbox_id is not None

    def __del__(self) -> None:
        if self._sandbox_id is not None:
            logger.warning(
                "Remote sandbox %s was not stopped before garbage collection", self._short_id
            )
            try:
                self.stop()
            except Exception:
                logger.debug("Remote sandbox __del__ cleanup failed", exc_info=True)


def _object(value: Any, method: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SandboxRpcError(f"{method} returned a non-object result")
    return value
