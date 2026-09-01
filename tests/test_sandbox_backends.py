"""Contract tests for pluggable and JSON-RPC sandbox backends."""

from __future__ import annotations

import base64
import json
import os
import socket
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.sandbox.backend import (
    DockerSandboxBackend,
    SandboxBackend,
    SandboxEnvironment,
    SandboxEnvironmentSpec,
    SandboxInstance,
    SandboxRunConfig,
    sandbox_backend_from_env,
)
from clearwing.sandbox.container import ExecResult
from clearwing.sandbox.hunter_sandbox import HunterSandbox
from clearwing.sandbox.rpc_backend import (
    JsonRpcConnection,
    SandboxRpcError,
    SocketSandboxBackend,
)


class _RpcPeer:
    def __init__(self, stream: socket.socket, handler):
        self.stream = stream
        self.handler = handler
        self.requests: list[dict] = []
        self.failure: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        reader = self.stream.makefile("rb")
        try:
            while encoded := reader.readline():
                request = json.loads(encoded)
                self.requests.append(request)
                result = self.handler(request)
                if result is None:
                    continue
                response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
                self.stream.sendall(json.dumps(response).encode() + b"\n")
        except (ConnectionError, OSError):
            pass
        except BaseException as error:  # noqa: BLE001 - reported by the test
            self.failure = error
        finally:
            reader.close()

    def close(self):
        try:
            self.stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.stream.close()
        self.thread.join(timeout=1)
        if self.failure is not None:
            raise self.failure


def _fd_connection(handler):
    client_socket, server_socket = socket.socketpair()
    peer = _RpcPeer(server_socket, handler)
    connection = JsonRpcConnection(f"fd://{client_socket.detach()}")
    return connection, peer


def test_fd_endpoint_uses_connected_duplex_socket():
    connection, peer = _fd_connection(lambda request: request["params"])
    try:
        assert connection.call("test.echo", {"value": 42}) == {"value": 42}
    finally:
        connection.close()
        peer.close()


def test_connection_close_is_idempotent_and_stops_reader():
    connection, peer = _fd_connection(lambda request: request["params"])
    connection.close()
    connection.close()

    assert connection.is_closed
    assert not connection._reader_thread.is_alive()
    peer.close()


def test_fd_endpoint_takes_ownership_of_descriptor():
    client_socket, server_socket = socket.socketpair()
    descriptor = client_socket.detach()
    connection = JsonRpcConnection(f"fd://{descriptor}")

    connection.close()

    with pytest.raises(OSError):
        os.fstat(descriptor)
    server_socket.close()


def test_fd_endpoint_rejects_a_one_way_pipe():
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises((OSError, ValueError)):
            JsonRpcConnection(f"fd://{read_fd}")
    finally:
        for descriptor in (read_fd, write_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_unix_endpoint_connects_to_socket_path():
    # Darwin limits AF_UNIX paths to 104 bytes; pytest's normal temp path can
    # exceed that before the socket filename is appended.
    with tempfile.TemporaryDirectory(prefix="cw-sb-", dir="/tmp") as directory:
        path = Path(directory) / "sandbox.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        accepted: list[_RpcPeer] = []

        def accept():
            stream, _ = listener.accept()
            accepted.append(_RpcPeer(stream, lambda request: request["params"]))

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        connection = JsonRpcConnection(f"unix://{path}")
        try:
            assert connection.call("test.echo", {"transport": "unix"}) == {"transport": "unix"}
        finally:
            connection.close()
            thread.join(timeout=1)
            for peer in accepted:
                peer.close()
            listener.close()


def test_connection_multiplexes_out_of_order_responses():
    client_socket, server_socket = socket.socketpair()
    connection = JsonRpcConnection(f"fd://{client_socket.detach()}")

    def serve_reversed():
        reader = server_socket.makefile("rb")
        requests = [json.loads(reader.readline()), json.loads(reader.readline())]
        for request in reversed(requests):
            response = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": request["params"],
            }
            server_socket.sendall(json.dumps(response).encode() + b"\n")
        reader.close()

    server = threading.Thread(target=serve_reversed, daemon=True)
    server.start()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(connection.call, "test.echo", {"value": "first"})
            second = pool.submit(connection.call, "test.echo", {"value": "second"})
            assert first.result() == {"value": "first"}
            assert second.result() == {"value": "second"}
    finally:
        connection.close()
        server_socket.close()
        server.join(timeout=1)


def test_remote_error_is_exposed_as_typed_exception():
    client_socket, server_socket = socket.socketpair()

    def serve_error():
        request = json.loads(server_socket.makefile("rb").readline())
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": -32010, "message": "capacity exhausted"},
        }
        server_socket.sendall(json.dumps(response).encode() + b"\n")

    server = threading.Thread(target=serve_error, daemon=True)
    server.start()
    connection = JsonRpcConnection(f"fd://{client_socket.detach()}")
    try:
        with pytest.raises(SandboxRpcError, match="capacity exhausted") as caught:
            connection.call("sandbox.start")
        assert caught.value.code == -32010
    finally:
        connection.close()
        server_socket.close()
        server.join(timeout=1)


def test_socket_backend_implements_complete_sandbox_contract():
    def handle(request):
        method = request["method"]
        if method == "sandbox.capabilities":
            return {"protocol_version": 1}
        if method == "sandbox.capacity":
            return {"cpus": 8, "source": "test runtime"}
        if method == "sandbox.environment.ensure":
            return {"environment_ref": "environment:test", "cached": True}
        if method == "sandbox.start":
            return {"sandbox_id": "runtime-id", "short_id": "short"}
        if method == "sandbox.exec":
            return {
                "exit_code": 0,
                "stdout": "ok",
                "stderr": "",
                "duration_seconds": 0.25,
                "timed_out": False,
            }
        if method == "sandbox.file.read":
            return {"content_base64": base64.b64encode(b"result").decode()}
        if method in {
            "sandbox.file.write",
            "sandbox.tree.copy",
            "sandbox.stop",
            "sandbox.environment.release",
        }:
            return {}
        raise AssertionError(f"unexpected method {method}")

    connection, peer = _fd_connection(handle)
    backend = SocketSandboxBackend("fd://99", connection=connection)
    try:
        assert isinstance(backend, SandboxBackend)
        assert backend.available_cpus() == (8.0, "test runtime")
        environment = backend.ensure_environment(
            SandboxEnvironmentSpec(
                cache_key="a" * 64,
                profile="c-cpp",
                features=["build.make", "source.search"],
                sanitizers=["asan"],
            )
        )
        assert environment == SandboxEnvironment("environment:test", cached=True)

        instance = backend.create(environment.reference, SandboxRunConfig())
        assert isinstance(instance, SandboxInstance)
        assert instance.start() == "runtime-id"
        assert instance.short_id == "short"
        assert instance.exec(["true"]) == ExecResult(0, "ok", "", 0.25, False)
        instance.exec(["true"], timeout=0)
        instance.config.timeout_seconds = 0
        instance.exec(["true"])
        instance.write_file("/scratch/input", b"input")
        assert instance.read_file("/scratch/output") == b"result"
        instance.copy_tree_into("/host/source")
        instance.stop()
        backend.release_environment(environment.reference)

        methods = [request["method"] for request in peer.requests]
        assert methods == [
            "sandbox.capabilities",
            "sandbox.capacity",
            "sandbox.environment.ensure",
            "sandbox.start",
            "sandbox.exec",
            "sandbox.exec",
            "sandbox.exec",
            "sandbox.file.write",
            "sandbox.file.read",
            "sandbox.tree.copy",
            "sandbox.stop",
            "sandbox.environment.release",
        ]
        environment_spec = peer.requests[2]["params"]["spec"]
        assert environment_spec["profile"] == "c-cpp"
        assert environment_spec["features"] == ["build.make", "source.search"]
        assert "image" not in environment_spec
        assert "dockerfile" not in environment_spec
        assert "packages" not in environment_spec
        start_config = peer.requests[3]["params"]["config"]
        assert peer.requests[3]["params"]["environment_ref"] == "environment:test"
        assert start_config["policy"] == "sourcehunt"
        assert start_config["isolation"] == "default"
        assert "network_mode" not in start_config
        assert "security_opt" not in start_config
        assert "cap_drop" not in start_config
        assert "runtime" not in start_config
        assert peer.requests[5]["params"]["timeout_seconds"] == 300
        assert peer.requests[6]["params"]["timeout_seconds"] == 0
    finally:
        connection.close()
        peer.close()


def test_backend_selection_defaults_to_docker(monkeypatch):
    monkeypatch.delenv("CLEARWING_SANDBOX_ENDPOINT", raising=False)
    assert isinstance(sandbox_backend_from_env(), DockerSandboxBackend)


def test_docker_backend_rejects_unknown_required_environment_codes():
    process = MagicMock()
    backend = DockerSandboxBackend(process=process)

    with pytest.raises(ValueError, match="profile"):
        backend.ensure_environment(SandboxEnvironmentSpec(cache_key="a" * 64, profile="made-up"))
    with pytest.raises(ValueError, match="feature"):
        backend.ensure_environment(
            SandboxEnvironmentSpec(
                cache_key="b" * 64,
                profile="c-cpp",
                features=["package.libssl-dev"],
            )
        )

    # Validation happens before even consulting the image cache.
    process.run.assert_not_called()


def test_docker_package_resolution_stays_inside_adapter():
    backend = DockerSandboxBackend()
    spec = SandboxEnvironmentSpec(
        cache_key="a" * 64,
        profile="c-cpp",
        features=["source.search", "debug.native", "build.cmake"],
    )

    dockerfile = backend._render_dockerfile(spec)

    assert "ripgrep" in dockerfile
    assert "gdb" in dockerfile
    assert "cmake" in dockerfile
    assert "ripgrep" not in vars(spec).values()


def test_backend_selection_uses_configured_socket(monkeypatch):
    client_socket, server_socket = socket.socketpair()
    endpoint = f"fd://{client_socket.detach()}"
    monkeypatch.setenv("CLEARWING_SANDBOX_ENDPOINT", endpoint)
    backend = None
    try:
        backend = sandbox_backend_from_env()
        assert isinstance(backend, SocketSandboxBackend)
        assert backend.endpoint == endpoint
    finally:
        if backend is not None:
            backend._connection.close()
        server_socket.close()


def test_hunter_sandbox_accepts_an_injected_backend(tmp_path: Path):
    instance = MagicMock()
    instance.scratch_host_dir = None
    instance.workspace_baseline_commit = None
    backend = MagicMock(spec=SandboxBackend)
    backend.name = "test"
    backend.ensure_environment.return_value = SandboxEnvironment("environment:test", cached=False)
    backend.available_cpus.return_value = (4.0, "test")
    backend.create.return_value = instance

    manager = HunterSandbox(repo_path=str(tmp_path), backend=backend)
    manager.build_image()
    spawned = manager.spawn(scratch_mount=False)

    assert spawned is instance
    backend.ensure_environment.assert_called_once()
    backend.create.assert_called_once()
    assert backend.create.call_args.args[0] == "environment:test"
    instance.start.assert_called_once_with()
    assert manager.default_cpu_limit == 3.0
