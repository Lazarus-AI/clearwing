"""Unit tests for SandboxContainer with the docker SDK mocked.

These tests verify the lifecycle (start → exec → write_file → read_file → stop),
mount mode translation, no-network defaults, resource limits, and timeout
wrapping. They do NOT touch a real docker daemon.
"""

from __future__ import annotations

import io
import tarfile
from unittest.mock import MagicMock, patch

import pytest

from clearwing.sandbox.container import (
    ExecResult,
    SandboxConfig,
    SandboxContainer,
)


@pytest.fixture
def mock_docker():
    """Patch docker.from_env so SandboxContainer never hits a real daemon."""
    with patch("docker.from_env") as mock_from_env:
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "containerid12345"
        mock_container.short_id = "container1234"
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client
        yield mock_client, mock_container


class TestSandboxConfig:
    def test_defaults_are_restrictive(self):
        cfg = SandboxConfig(image="alpine:latest")
        assert cfg.network_mode == "none"
        assert cfg.memory_mb == 2048
        assert cfg.timeout_seconds == 300
        assert cfg.working_dir == "/workspace"
        assert cfg.auto_remove is True
        assert cfg.mounts == []
        assert cfg.env == {}


class TestSandboxContainerLifecycle:
    def test_start_calls_containers_run(self, mock_docker):
        client, container = mock_docker
        cfg = SandboxConfig(image="alpine:latest")
        sb = SandboxContainer(cfg)
        cid = sb.start()
        assert cid == "containerid12345"
        client.containers.run.assert_called_once()
        kwargs = client.containers.run.call_args.kwargs
        assert kwargs["image"] == "alpine:latest"
        assert kwargs["network_mode"] == "none"
        assert kwargs["mem_limit"] == "2048m"
        assert kwargs["working_dir"] == "/workspace"

    def test_mounts_translated_to_volumes(self, mock_docker):
        client, _ = mock_docker
        cfg = SandboxConfig(
            image="alpine",
            mounts=[
                ("/host/repo", "/workspace", "ro"),
                ("/host/scratch", "/scratch", "rw"),
            ],
        )
        SandboxContainer(cfg).start()
        kwargs = client.containers.run.call_args.kwargs
        volumes = kwargs["volumes"]
        assert volumes["/host/repo"] == {"bind": "/workspace", "mode": "ro"}
        assert volumes["/host/scratch"] == {"bind": "/scratch", "mode": "rw"}

    def test_env_passed_through(self, mock_docker):
        client, _ = mock_docker
        cfg = SandboxConfig(image="alpine", env={"CFLAGS": "-fsanitize=address"})
        SandboxContainer(cfg).start()
        kwargs = client.containers.run.call_args.kwargs
        assert kwargs["environment"]["CFLAGS"] == "-fsanitize=address"

    def test_stop_calls_stop_and_remove(self, mock_docker):
        _, container = mock_docker
        sb = SandboxContainer(SandboxConfig(image="alpine"))
        sb.start()
        sb.stop()
        container.stop.assert_called_once()
        container.remove.assert_called_once()

    def test_stop_idempotent(self, mock_docker):
        sb = SandboxContainer(SandboxConfig(image="alpine"))
        sb.start()
        sb.stop()
        # Second stop is a no-op (container is None now)
        sb.stop()  # should not raise

    def test_context_manager_starts_and_stops(self, mock_docker):
        _, container = mock_docker
        with SandboxContainer(SandboxConfig(image="alpine")) as sb:
            assert sb.is_running
        container.stop.assert_called_once()
        container.remove.assert_called_once()


class TestSandboxContainerExec:
    def test_exec_returns_exec_result(self, mock_docker):
        _, container = mock_docker
        # Mock exec_run to return an exec result with stdout/stderr tuple
        exec_obj = MagicMock()
        exec_obj.exit_code = 0
        exec_obj.output = (b"hello\n", b"")
        container.exec_run.return_value = exec_obj

        sb = SandboxContainer(SandboxConfig(image="alpine"))
        sb.start()
        result = sb.exec(["echo", "hello"])
        assert isinstance(result, ExecResult)
        assert result.exit_code == 0
        assert result.stdout == "hello\n"
        assert result.stderr == ""
        assert result.timed_out is False

    def test_exec_wraps_in_timeout(self, mock_docker):
        _, container = mock_docker
        exec_obj = MagicMock()
        exec_obj.exit_code = 0
        exec_obj.output = (b"", b"")
        container.exec_run.return_value = exec_obj

        sb = SandboxContainer(SandboxConfig(image="alpine", timeout_seconds=42))
        sb.start()
        sb.exec(["sleep", "100"])
        # The argv passed to exec_run should be wrapped with `timeout`
        called_argv = container.exec_run.call_args[0][0]
        assert called_argv[0] == "timeout"
        assert "42" in called_argv

    def test_exec_string_command_uses_sh_c(self, mock_docker):
        _, container = mock_docker
        exec_obj = MagicMock()
        exec_obj.exit_code = 0
        exec_obj.output = (b"", b"")
        container.exec_run.return_value = exec_obj

        sb = SandboxContainer(SandboxConfig(image="alpine", timeout_seconds=0))
        sb.start()
        sb.exec("echo hello | grep e")
        called_argv = container.exec_run.call_args[0][0]
        # No timeout wrapper since timeout=0
        assert called_argv == ["/bin/sh", "-c", "echo hello | grep e"]

    def test_exec_timeout_exit_code_124(self, mock_docker):
        _, container = mock_docker
        exec_obj = MagicMock()
        exec_obj.exit_code = 124  # `timeout` exit code on timeout
        exec_obj.output = (b"", b"")
        container.exec_run.return_value = exec_obj

        sb = SandboxContainer(SandboxConfig(image="alpine"))
        sb.start()
        result = sb.exec(["sleep", "999"])
        assert result.timed_out is True

    def test_exec_before_start_raises(self, mock_docker):
        sb = SandboxContainer(SandboxConfig(image="alpine"))
        with pytest.raises(RuntimeError, match="before start"):
            sb.exec(["ls"])

    def test_exec_extra_env_merged(self, mock_docker):
        _, container = mock_docker
        exec_obj = MagicMock()
        exec_obj.exit_code = 0
        exec_obj.output = (b"", b"")
        container.exec_run.return_value = exec_obj

        sb = SandboxContainer(SandboxConfig(image="alpine", env={"BASE": "1"}))
        sb.start()
        sb.exec(["env"], env={"EXTRA": "2"})
        env_arg = container.exec_run.call_args.kwargs["environment"]
        assert env_arg["BASE"] == "1"
        assert env_arg["EXTRA"] == "2"


class TestSandboxFileIO:
    def test_write_file_calls_put_archive(self, mock_docker):
        _, container = mock_docker
        sb = SandboxContainer(SandboxConfig(image="alpine"))
        sb.start()
        sb.write_file("/scratch/poc.bin", b"\x00\x01\x02")
        container.put_archive.assert_called_once()
        target_dir = container.put_archive.call_args[0][0]
        assert target_dir == "/scratch"

    def test_write_file_before_start_raises(self, mock_docker):
        sb = SandboxContainer(SandboxConfig(image="alpine"))
        with pytest.raises(RuntimeError, match="before start"):
            sb.write_file("/scratch/x", b"1")

    def test_read_file_returns_bytes(self, mock_docker):
        _, container = mock_docker

        # Build a fake tar stream containing one file
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            data = b"file contents here"
            info = tarfile.TarInfo(name="foo.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        tar_bytes = buf.read()

        # docker SDK get_archive returns (stream_iterable, stat_dict)
        container.get_archive.return_value = (iter([tar_bytes]), {})

        sb = SandboxContainer(SandboxConfig(image="alpine"))
        sb.start()
        content = sb.read_file("/scratch/foo.txt")
        assert content == b"file contents here"
