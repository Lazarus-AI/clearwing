"""Tests for writable workspace support in HunterSandbox and SandboxContainer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from clearwing.sandbox.container import SandboxConfig, SandboxContainer
from clearwing.sandbox.hunter_sandbox import HunterSandbox


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


class TestHunterSandboxCpuPolicy:
    @pytest.mark.parametrize(
        ("available", "expected"),
        [(1, 0.5), (2, 1.0), (3, 2.0), (4, 3.0), (64, 3.0)],
    )
    def test_auto_limit_uses_docker_cpu_count(self, tmp_path, available, expected):
        manager = HunterSandbox(repo_path=str(tmp_path))
        client = MagicMock()
        client.info.return_value = {"NCPU": available}
        manager._client = client

        assert manager.available_cpus == float(available)
        assert manager.default_cpu_limit == expected
        # Both values are cached for every subsequent spawn in the hunt.
        assert manager.default_cpu_limit == expected
        client.info.assert_called_once_with()

    def test_auto_limit_falls_back_to_process_affinity(self, tmp_path):
        manager = HunterSandbox(repo_path=str(tmp_path))
        client = MagicMock()
        client.info.side_effect = RuntimeError("daemon info unavailable")
        manager._client = client

        with patch(
            "clearwing.sandbox.hunter_sandbox.os.sched_getaffinity",
            return_value={0, 1, 2},
            create=True,
        ):
            assert manager.available_cpus == 3.0
            assert manager.default_cpu_limit == 2.0

    def test_auto_limit_falls_back_to_host_cpu_count(self, tmp_path):
        manager = HunterSandbox(repo_path=str(tmp_path))
        client = MagicMock()
        client.info.return_value = {"NCPU": 0}
        manager._client = client

        with (
            patch(
                "clearwing.sandbox.hunter_sandbox.os.sched_getaffinity",
                side_effect=OSError,
                create=True,
            ),
            patch("clearwing.sandbox.hunter_sandbox.os.cpu_count", return_value=2),
        ):
            assert manager.available_cpus == 2.0
            assert manager.default_cpu_limit == 1.0

    def test_explicit_zero_disables_limit_without_cpu_detection(self, tmp_path):
        manager = HunterSandbox(repo_path=str(tmp_path), default_cpus=0.0)
        client = MagicMock()
        manager._client = client

        assert manager.default_cpu_limit == 0.0
        client.info.assert_not_called()

    @pytest.mark.parametrize("value", [-1.0, float("inf"), float("nan")])
    def test_invalid_default_rejected(self, tmp_path, value):
        with pytest.raises(ValueError, match="default_cpus"):
            HunterSandbox(repo_path=str(tmp_path), default_cpus=value)

    def test_spawn_inherits_manager_default(self, tmp_path):
        manager = HunterSandbox(repo_path=str(tmp_path))
        client = MagicMock()
        client.info.return_value = {"NCPU": 2}
        manager._client = client

        with (
            patch.object(HunterSandbox, "_build_variant_image", return_value="sandbox:test"),
            patch.object(SandboxContainer, "start", return_value="cid"),
        ):
            sandbox = manager.spawn(scratch_mount=False)

        assert sandbox.config.cpus == 1.0

    def test_spawn_override_wins_over_manager_default(self, tmp_path):
        manager = HunterSandbox(repo_path=str(tmp_path), default_cpus=1.0)

        with (
            patch.object(HunterSandbox, "_build_variant_image", return_value="sandbox:test"),
            patch.object(SandboxContainer, "start", return_value="cid"),
        ):
            sandbox = manager.spawn(scratch_mount=False, cpus=2.5)

        assert sandbox.config.cpus == 2.5


class TestSourceHuntSandboxCpuWiring:
    def test_runner_passes_override_to_manager_and_removes_hardcoded_limit(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(
            repo_url="test",
            depth="standard",
            max_parallel=1,
            sandbox_cpus=1.5,
        )
        manager = MagicMock()
        manager.build_image.return_value = "sandbox:test"
        manager.default_cpu_limit = 1.5
        manager.available_cpus = 4.0

        with patch("clearwing.sourcehunt.runner.HunterSandbox", return_value=manager) as cls:
            runner._ensure_sandbox_factory("/tmp/repo", [{"language": "c"}])

        cls.assert_called_once_with(
            repo_path="/tmp/repo",
            languages=["c"],
            deep_agent_mode=True,
            extra_packages=["python3-pip"],
            post_install_commands=[
                "pip3 install --break-system-packages pyjwt requests cryptography pycryptodome || true"
            ],
            default_cpus=1.5,
        )
        assert runner.sandbox_factory is not None
        runner.sandbox_factory()
        manager.spawn.assert_called_once_with(
            writable_workspace=True,
            memory_mb=16384,
            timeout_seconds=600,
            runtime=None,
        )

    def test_runner_warns_when_parallel_limits_exceed_daemon_capacity(self, caplog):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(repo_url="test", max_parallel=2)
        manager = MagicMock()
        manager.build_image.return_value = "sandbox:test"
        manager.default_cpu_limit = 3.0
        manager.available_cpus = 4.0

        with patch("clearwing.sourcehunt.runner.HunterSandbox", return_value=manager):
            runner._ensure_sandbox_factory("/tmp/repo", [{"language": "c"}])

        assert "CPU limits are per-container" in caplog.text

    def test_structured_config_sets_sandbox_cpu_override(self):
        from clearwing.sourcehunt import HuntTuning, SourceHuntConfig, TargetConfig
        from clearwing.sourcehunt.runner import SourceHuntRunner

        config = SourceHuntConfig(
            target=TargetConfig(repo_url="test"),
            tuning=HuntTuning(sandbox_cpus=1.25),
        )

        runner = SourceHuntRunner(config=config)

        assert runner._sandbox_cpus == 1.25

    @pytest.mark.parametrize("value", [-1.0, float("inf"), float("nan")])
    def test_runner_rejects_invalid_override(self, value):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        with pytest.raises(ValueError, match="sandbox_cpus"):
            SourceHuntRunner(repo_url="test", sandbox_cpus=value)

    def test_cli_flag_and_default(self):
        import argparse

        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        sourcehunt.add_parser(subparsers)

        explicit = parser.parse_args(["sourcehunt", "test-repo", "--sandbox-cpus", "1.5"])
        automatic = parser.parse_args(["sourcehunt", "test-repo"])

        assert explicit.sandbox_cpus == 1.5
        assert automatic.sandbox_cpus is None


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

        with (
            patch.object(SandboxContainer, "start", return_value="cid"),
            patch.object(SandboxContainer, "copy_tree_into") as mock_copy,
            patch.object(SandboxContainer, "exec") as mock_exec,
        ):
            mock_exec.return_value = MagicMock(exit_code=0)
            manager.spawn(writable_workspace=True)

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
