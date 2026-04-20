"""Tests for writable workspace support in HunterSandbox and SandboxContainer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

from clearwing.sandbox.container import SandboxConfig, SandboxContainer


class TestSandboxConfigCpus:
    def test_default_cpus_is_zero(self):
        cfg = SandboxConfig(image="alpine:latest")
        assert cfg.cpus == 0.0

    def test_cpus_stored(self):
        cfg = SandboxConfig(image="alpine:latest", cpus=8.0)
        assert cfg.cpus == 8.0


class TestSandboxContainerCpus:
    @patch("docker.from_env")
    def test_cpus_wired_to_nano_cpus(self, mock_from_env):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cid123"
        mock_container.short_id = "cid1"
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client

        cfg = SandboxConfig(image="alpine:latest", cpus=4.0)
        sb = SandboxContainer(cfg)
        sb.start()

        kwargs = mock_client.containers.run.call_args.kwargs
        assert kwargs["nano_cpus"] == 4_000_000_000

    @patch("docker.from_env")
    def test_no_nano_cpus_when_zero(self, mock_from_env):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cid123"
        mock_container.short_id = "cid1"
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client

        cfg = SandboxConfig(image="alpine:latest", cpus=0.0)
        sb = SandboxContainer(cfg)
        sb.start()

        kwargs = mock_client.containers.run.call_args.kwargs
        assert "nano_cpus" not in kwargs


class TestCopyTreeInto:
    @patch("docker.from_env")
    @patch("subprocess.Popen")
    def test_copy_tree_into_uses_streaming_tar(self, mock_popen, mock_from_env):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cid123"
        mock_container.short_id = "cid1"
        mock_container.exec_run.return_value = MagicMock(exit_code=0, output=(b"", b""))
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client

        tar_proc = MagicMock()
        tar_proc.stdout = MagicMock()
        tar_proc.wait.return_value = 0

        docker_proc = MagicMock()
        docker_proc.communicate.return_value = (b"", b"")
        docker_proc.returncode = 0

        mock_popen.side_effect = [tar_proc, docker_proc]

        cfg = SandboxConfig(image="alpine:latest")
        sb = SandboxContainer(cfg)
        sb.start()
        sb.copy_tree_into("/tmp/myrepo", "/workspace")

        assert mock_popen.call_count == 2
        tar_call = mock_popen.call_args_list[0]
        assert "tar" in tar_call[0][0]
        assert "/tmp/myrepo" in tar_call[0][0]

        # Regression: the extract side must pass --no-same-owner so tar
        # doesn't try to restore host uid/gid inside a cap-dropped container
        # (CAP_CHOWN is removed by cap_drop=["ALL"]). Without this flag, tar
        # aborts with "Cannot change ownership ... Operation not permitted".
        docker_call = mock_popen.call_args_list[1]
        docker_argv = docker_call[0][0]
        assert "docker" in docker_argv[0]
        assert "--no-same-owner" in docker_argv, (
            f"extract tar must use --no-same-owner: {docker_argv}"
        )

    @patch("docker.from_env")
    def test_exec_retries_on_demux_valueerror(self, mock_from_env):
        """Regression: docker-py's demux_adaptor raises
        `ValueError: N is not a valid stream` when the socket header read
        gets corrupted mid-stream (docker/docker-py#3160). Treat as a
        transient and retry once with the same params — community
        reports confirm the second attempt succeeds.
        """
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cid-demux"
        mock_container.short_id = "cid-demux"

        success = MagicMock(exit_code=0, output=(b"hello world\n", b""))

        call_count = {"n": 0}

        def exec_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ValueError("48 is not a valid stream")
            return success

        mock_container.exec_run.side_effect = exec_side_effect
        mock_client.containers.run.return_value = mock_container
        mock_from_env.return_value = mock_client

        cfg = SandboxConfig(image="alpine:latest")
        sb = SandboxContainer(cfg)
        sb.start()
        result = sb.exec(["echo", "hello world"])

        # Retried once
        assert call_count["n"] == 2
        # Both attempts used the same params (demux=True)
        demux_values = [call.kwargs.get("demux") for call in mock_container.exec_run.call_args_list]
        assert demux_values == [True, True]
        # Demuxed output preserved (stdout/stderr separation intact)
        assert result.exit_code == 0
        assert "hello world" in result.stdout
        assert result.stderr == ""

    def test_copy_tree_into_before_start_raises(self):
        cfg = SandboxConfig(image="alpine:latest")
        sb = SandboxContainer(cfg)
        with pytest.raises(RuntimeError, match="before start"):
            sb.copy_tree_into("/tmp/repo")


class TestHunterSandboxWritableWorkspace:
    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._build_variant_image")
    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._get_client")
    def test_spawn_writable_omits_ro_mount(self, mock_client, mock_build):
        from clearwing.sandbox.hunter_sandbox import HunterSandbox

        mock_build.return_value = "clearwing-sourcehunt:test123"

        manager = HunterSandbox(
            repo_path="/tmp/repo",
            languages=["c"],
            deep_agent_mode=True,
        )

        with patch.object(SandboxContainer, "start", return_value="cid"):
            with patch.object(SandboxContainer, "copy_tree_into"):
                with patch.object(SandboxContainer, "exec", return_value=MagicMock(exit_code=0)):
                    sb = manager.spawn(writable_workspace=True)

        # Check no read-only workspace mount
        for mount in sb.config.mounts:
            host, container, mode = mount
            if container == "/workspace":
                pytest.fail(f"Found /workspace mount with mode={mode}, expected none")

    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._build_variant_image")
    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._get_client")
    def test_spawn_writable_calls_copy_and_git(self, mock_client, mock_build):
        from clearwing.sandbox.hunter_sandbox import HunterSandbox

        mock_build.return_value = "clearwing-sourcehunt:test123"

        manager = HunterSandbox(
            repo_path="/tmp/repo",
            languages=["c"],
            deep_agent_mode=True,
        )

        with patch.object(SandboxContainer, "start", return_value="cid"):
            with patch.object(SandboxContainer, "copy_tree_into") as mock_copy:
                with patch.object(SandboxContainer, "exec") as mock_exec:
                    mock_exec.return_value = MagicMock(exit_code=0)
                    sb = manager.spawn(writable_workspace=True)

        mock_copy.assert_called_once_with("/tmp/repo", "/workspace")
        # git init should have been called
        git_calls = [
            c
            for c in mock_exec.call_args_list
            if isinstance(c[0][0], str) and "git init" in c[0][0]
        ]
        assert len(git_calls) == 1

    def test_deep_agent_mode_adds_packages(self):
        from clearwing.sandbox.hunter_sandbox import HunterSandbox

        with patch("clearwing.sandbox.hunter_sandbox.BuildSystemDetector.detect"):
            manager = HunterSandbox(
                repo_path="/tmp/repo",
                languages=["c"],
                deep_agent_mode=True,
            )

        for pkg in HunterSandbox.DEEP_AGENT_PACKAGES:
            assert pkg in manager.extra_packages

    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._build_variant_image")
    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._get_client")
    def test_spawn_writable_passes_cpus(self, mock_client, mock_build):
        from clearwing.sandbox.hunter_sandbox import HunterSandbox

        mock_build.return_value = "clearwing-sourcehunt:test123"

        manager = HunterSandbox(
            repo_path="/tmp/repo",
            languages=["c"],
            deep_agent_mode=True,
        )

        with patch.object(SandboxContainer, "start", return_value="cid"):
            with patch.object(SandboxContainer, "copy_tree_into"):
                with patch.object(SandboxContainer, "exec", return_value=MagicMock(exit_code=0)):
                    sb = manager.spawn(writable_workspace=True, cpus=8.0)

        assert sb.config.cpus == 8.0
