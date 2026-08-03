"""Tests for sandbox creation correctness.

Validates that HunterSandbox produces correctly-configured containers:
- Dockerfile renders with correct base images and sanitizer flags
- Workspace mounts are correct (ro vs writable copy)
- Image tags are deterministic and content-addressed
- Build failures are surfaced cleanly
- Writable workspace flow: copy_tree_into + git init
- Platform/arch considerations
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from clearwing.sandbox.builders import (
    DEFAULT_BASE_IMAGES,
    BuildRecipe,
    BuildSystemDetector,
    compute_sanitizer_env,
    validate_sanitizer_combo,
)
from clearwing.sandbox.container import SandboxConfig, SandboxContainer
from clearwing.sandbox.hunter_sandbox import HunterSandbox


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def c_repo(tmp_path: Path) -> Path:
    (tmp_path / "Makefile").write_text("all:\n\tgcc -o main main.c\n")
    (tmp_path / "main.c").write_text("int main() { return 0; }\n")
    return tmp_path


@pytest.fixture
def cpp_repo(tmp_path: Path) -> Path:
    (tmp_path / "CMakeLists.txt").write_text("project(test)\n")
    (tmp_path / "main.cpp").write_text("int main() {}\n")
    return tmp_path


@pytest.fixture
def python_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='testpkg'\n")
    (tmp_path / "app.py").write_text("print('hi')\n")
    return tmp_path


@pytest.fixture
def mock_docker():
    with patch("clearwing.sandbox.dind.get_docker_host", return_value=None), \
         patch("docker.from_env") as mock_from_env:
        client = MagicMock()
        mock_from_env.return_value = client
        yield client


# ---------------------------------------------------------------------------
# Dockerfile rendering correctness
# ---------------------------------------------------------------------------


class TestDockerfileRendering:
    def test_c_dockerfile_uses_gcc_base(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo))
        df = sb._render_dockerfile()
        assert df.startswith("FROM gcc:12-bullseye")

    def test_cpp_dockerfile_uses_gcc_base(self, cpp_repo: Path):
        sb = HunterSandbox(repo_path=str(cpp_repo))
        df = sb._render_dockerfile()
        assert "FROM gcc:12-bullseye" in df

    def test_python_dockerfile_no_sanitizer_flags(self, python_repo: Path):
        sb = HunterSandbox(repo_path=str(python_repo))
        df = sb._render_dockerfile()
        assert "FROM python:3.12-slim" in df
        # Python doesn't get CFLAGS sanitizer injection
        assert "fsanitize" not in df

    def test_sanitizer_env_in_dockerfile(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo), sanitizers=["asan", "ubsan"])
        df = sb._render_dockerfile()
        assert "fsanitize=address" in df
        assert "fsanitize=undefined" in df
        assert "ASAN_OPTIONS" in df
        assert "UBSAN_OPTIONS" in df

    def test_msan_variant_dockerfile(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo), sanitizers=["msan"])
        df = sb._render_dockerfile()
        assert "fsanitize=memory" in df
        assert "MSAN_OPTIONS" in df
        # Must NOT contain asan flags
        assert "fsanitize=address" not in df

    def test_apt_packages_include_ripgrep_and_gdb(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo))
        df = sb._render_dockerfile()
        assert "ripgrep" in df
        assert "gdb" in df

    def test_extra_packages_appear_in_dockerfile(self, c_repo: Path):
        sb = HunterSandbox(
            repo_path=str(c_repo), extra_packages=["python3-pip", "curl"]
        )
        df = sb._render_dockerfile()
        assert "python3-pip" in df
        assert "curl" in df

    def test_post_install_commands_render(self, c_repo: Path):
        sb = HunterSandbox(
            repo_path=str(c_repo),
            post_install_commands=["pip3 install pyjwt || true"],
        )
        df = sb._render_dockerfile()
        assert "RUN pip3 install pyjwt || true" in df

    def test_deep_agent_mode_adds_valgrind_and_ltrace(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        df = sb._render_dockerfile()
        assert "valgrind" in df
        assert "ltrace" in df
        assert "python3" in df

    def test_workspace_dir_created(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo))
        df = sb._render_dockerfile()
        assert "WORKDIR /workspace" in df
        assert "mkdir -p /scratch" in df


# ---------------------------------------------------------------------------
# Image tag content-addressing
# ---------------------------------------------------------------------------


class TestImageTagDeterminism:
    def test_same_config_same_tag(self, c_repo: Path):
        sb1 = HunterSandbox(repo_path=str(c_repo), sanitizers=["asan"])
        sb2 = HunterSandbox(repo_path=str(c_repo), sanitizers=["asan"])
        df1 = sb1._render_dockerfile()
        df2 = sb2._render_dockerfile()
        assert sb1._compute_tag(df1) == sb2._compute_tag(df2)

    def test_different_sanitizers_different_tag(self, c_repo: Path):
        sb_asan = HunterSandbox(repo_path=str(c_repo), sanitizers=["asan"])
        sb_msan = HunterSandbox(repo_path=str(c_repo), sanitizers=["msan"])
        tag_asan = sb_asan._compute_tag(sb_asan._render_dockerfile())
        tag_msan = sb_msan._compute_tag(sb_msan._render_dockerfile())
        assert tag_asan != tag_msan

    def test_different_extra_packages_different_tag(self, c_repo: Path):
        sb1 = HunterSandbox(repo_path=str(c_repo))
        sb2 = HunterSandbox(repo_path=str(c_repo), extra_packages=["curl"])
        tag1 = sb1._compute_tag(sb1._render_dockerfile())
        tag2 = sb2._compute_tag(sb2._render_dockerfile())
        assert tag1 != tag2

    def test_tag_prefix(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo))
        tag = sb._compute_tag(sb._render_dockerfile())
        assert tag.startswith("clearwing-sourcehunt:")
        # Hash portion is 12 hex chars
        hash_part = tag.split(":")[1]
        assert len(hash_part) == 12
        assert all(c in "0123456789abcdef" for c in hash_part)


# ---------------------------------------------------------------------------
# Build image flow
# ---------------------------------------------------------------------------


class TestBuildImageFlow:
    @patch("clearwing.sandbox.hunter_sandbox.subprocess.Popen")
    @patch("clearwing.sandbox.hunter_sandbox.subprocess.run")
    def test_build_calls_docker_cli_when_not_cached(self, mock_run, mock_popen, c_repo: Path):
        # subprocess.run: `docker image inspect` → not found
        mock_run.return_value = MagicMock(returncode=1)
        # subprocess.Popen: `docker build` → success
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        sb = HunterSandbox(repo_path=str(c_repo))
        tag = sb.build_image()

        assert tag.startswith("clearwing-sourcehunt:")
        mock_run.assert_called_once()  # inspect only
        mock_popen.assert_called_once()
        build_argv = mock_popen.call_args[0][0]
        assert "docker" in build_argv[0]
        assert "build" in build_argv
        assert tag in build_argv

    @patch("clearwing.sandbox.hunter_sandbox.subprocess.run")
    def test_build_reuses_cached_image(self, mock_run, c_repo: Path):
        # docker image inspect succeeds → cached
        mock_run.return_value = MagicMock(returncode=0)
        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        # Only the inspect call, no build
        mock_run.assert_called_once()
        argv = mock_run.call_args[0][0]
        assert "inspect" in argv

    @patch("clearwing.sandbox.hunter_sandbox.subprocess.Popen")
    @patch("clearwing.sandbox.hunter_sandbox.subprocess.run")
    def test_build_failure_raises_runtime_error(self, mock_run, mock_popen, c_repo: Path):
        # inspect → miss
        mock_run.return_value = MagicMock(returncode=1)
        # build → failure
        mock_proc = MagicMock()
        mock_proc.stdout = iter(["error: apt-get failed"])
        mock_proc.wait.return_value = 1
        mock_proc.returncode = 1
        mock_popen.return_value = mock_proc

        sb = HunterSandbox(repo_path=str(c_repo))
        with pytest.raises(RuntimeError):
            sb.build_image()

    @patch("clearwing.sandbox.hunter_sandbox.subprocess.Popen")
    @patch("clearwing.sandbox.hunter_sandbox.subprocess.run")
    def test_extra_variants_built(self, mock_run, mock_popen, c_repo: Path):
        # inspect always misses
        mock_run.return_value = MagicMock(returncode=1)
        # build always succeeds
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        sb = HunterSandbox(
            repo_path=str(c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        sb.build_image()
        assert mock_run.call_count == 2  # 2 inspects
        assert mock_popen.call_count == 2  # 2 builds
        assert len(sb.available_variants) == 2


# ---------------------------------------------------------------------------
# Spawn container correctness
# ---------------------------------------------------------------------------


class TestSpawnContainer:
    def test_spawn_readonly_workspace(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.short_id = "abc1"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        container = sb.spawn(session_id="test-ro", scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        volumes = kwargs["volumes"]
        repo_abs = os.path.abspath(str(c_repo))
        assert volumes[repo_abs]["bind"] == "/workspace"
        assert volumes[repo_abs]["mode"] == "ro"

    def test_spawn_writable_workspace_mounts_rw(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "writable-cid"
        mock_container.short_id = "writ"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        sb.build_image()
        container = sb.spawn(writable_workspace=True, scratch_mount=False)

        # Writable workspace should bind-mount as rw
        found_rw = False
        for host, container_path, mode in container.config.mounts:
            if container_path == "/workspace":
                assert mode == "rw"
                found_rw = True
        assert found_rw, "Expected /workspace mount with mode=rw"

    def test_spawn_network_disabled(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "net-test"
        mock_container.short_id = "net"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        assert kwargs["network_mode"] == "none"

    def test_spawn_seccomp_is_inline_json(self, c_repo: Path, mock_docker):
        """Security: seccomp profile must be inline JSON, not a file path."""
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "sec-test"
        mock_container.short_id = "sec"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        sec_opts = kwargs["security_opt"]
        seccomp_opts = [o for o in sec_opts if o.startswith("seccomp=")]
        assert len(seccomp_opts) == 1
        value = seccomp_opts[0][len("seccomp="):]
        # Must not be a path
        assert not value.startswith("/")
        parsed = json.loads(value)
        assert parsed.get("defaultAction") == "SCMP_ACT_ALLOW"

    def test_spawn_caps_dropped(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cap-test"
        mock_container.short_id = "cap"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        assert kwargs["cap_drop"] == ["ALL"]
        assert "SYS_PTRACE" in kwargs["cap_add"]

    def test_spawn_scratch_mount_is_rw(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "scratch-test"
        mock_container.short_id = "scr"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(scratch_mount=True)

        kwargs = mock_docker.containers.run.call_args.kwargs
        volumes = kwargs["volumes"]
        rw_mounts = [
            (host, info) for host, info in volumes.items()
            if info.get("mode") == "rw"
        ]
        assert len(rw_mounts) == 1
        assert rw_mounts[0][1]["bind"] == "/scratch"

        sb.cleanup()

    def test_spawn_session_id_in_env(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "env-test"
        mock_container.short_id = "env"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(session_id="hunt-42", scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        assert kwargs["environment"]["CLEARWING_SESSION_ID"] == "hunt-42"

    def test_spawn_sanitizer_variant_in_env(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "var-test"
        mock_container.short_id = "var"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo), sanitizers=["asan", "ubsan"])
        sb.build_image()
        sb.spawn(scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        env = kwargs["environment"]
        # Should contain both, order determined by sorted list in variant_key
        assert "asan" in env["CLEARWING_SANITIZER_VARIANT"]
        assert "ubsan" in env["CLEARWING_SANITIZER_VARIANT"]

    def test_spawn_memory_limit(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "mem-test"
        mock_container.short_id = "mem"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(memory_mb=4096, scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        # mem_limit is passed as "<N>m" string by SandboxContainer
        assert kwargs["mem_limit"] == "4096m"


# ---------------------------------------------------------------------------
# Sanitizer validation
# ---------------------------------------------------------------------------


class TestSanitizerValidation:
    def test_asan_plus_msan_rejected(self):
        with pytest.raises(ValueError, match="cannot coexist"):
            validate_sanitizer_combo(["asan", "msan"])

    def test_asan_plus_tsan_rejected(self):
        with pytest.raises(ValueError, match="cannot coexist"):
            validate_sanitizer_combo(["asan", "tsan"])

    def test_msan_plus_tsan_rejected(self):
        with pytest.raises(ValueError, match="cannot coexist"):
            validate_sanitizer_combo(["msan", "tsan"])

    def test_asan_ubsan_allowed(self):
        validate_sanitizer_combo(["asan", "ubsan"])  # should not raise

    def test_msan_alone_allowed(self):
        validate_sanitizer_combo(["msan"])  # should not raise

    def test_constructor_rejects_bad_combo(self, c_repo: Path):
        with pytest.raises(ValueError):
            HunterSandbox(repo_path=str(c_repo), sanitizers=["asan", "msan"])


# ---------------------------------------------------------------------------
# compute_sanitizer_env correctness
# ---------------------------------------------------------------------------


class TestSanitizerEnv:
    def test_c_asan_ubsan_env(self, c_repo: Path):
        recipe = BuildSystemDetector.detect(str(c_repo))
        env = compute_sanitizer_env(recipe, ["asan", "ubsan"])
        assert "-fsanitize=address" in env["CFLAGS"]
        assert "-fsanitize=undefined" in env["CFLAGS"]
        assert env["CXXFLAGS"] == env["CFLAGS"]
        assert "ASAN_OPTIONS" in env
        assert "UBSAN_OPTIONS" in env

    def test_c_msan_env(self, c_repo: Path):
        recipe = BuildSystemDetector.detect(str(c_repo))
        env = compute_sanitizer_env(recipe, ["msan"])
        assert "-fsanitize=memory" in env["CFLAGS"]
        assert "track-origins" in env["CFLAGS"]
        assert "MSAN_OPTIONS" in env
        # No asan pollution
        assert "ASAN_OPTIONS" not in env

    def test_python_ignores_sanitizers(self, python_repo: Path):
        recipe = BuildSystemDetector.detect(str(python_repo))
        env = compute_sanitizer_env(recipe, ["asan", "ubsan"])
        # Python recipe doesn't inject CFLAGS
        assert "CFLAGS" not in env

    def test_asan_options_non_fatal(self, c_repo: Path):
        """Sandbox must not abort on first ASan error — hunter needs all traces."""
        recipe = BuildSystemDetector.detect(str(c_repo))
        env = compute_sanitizer_env(recipe, ["asan"])
        assert "halt_on_error=0" in env["ASAN_OPTIONS"]
        assert "abort_on_error=0" in env["ASAN_OPTIONS"]


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    def test_cleanup_stops_all_containers(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cleanup-test"
        mock_container.short_id = "cln"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.spawn(scratch_mount=False)
        sb.spawn(scratch_mount=False)
        sb.cleanup()

        assert mock_container.stop.call_count == 2
        assert mock_container.remove.call_count == 2

    def test_cleanup_remove_image(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()

        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        sb.cleanup(remove_image=True)
        mock_docker.images.remove.assert_called_once()

    def test_context_manager_cleans_up(self, c_repo: Path, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "ctx-test"
        mock_container.short_id = "ctx"
        mock_docker.containers.run.return_value = mock_container

        with HunterSandbox(repo_path=str(c_repo)) as sb:
            sb.build_image()
            sb.spawn(scratch_mount=False)

        mock_container.stop.assert_called_once()


# ---------------------------------------------------------------------------
# Writable workspace git init failure is non-fatal
# ---------------------------------------------------------------------------


class TestWritableWorkspaceResilience:
    def test_writable_workspace_mounts_rw_mode(self, c_repo: Path, mock_docker):
        """Writable workspace just sets the bind mount to rw."""
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "rw-test"
        mock_container.short_id = "rw"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        sb.build_image()
        container = sb.spawn(writable_workspace=True, scratch_mount=False)

        kwargs = mock_docker.containers.run.call_args.kwargs
        volumes = kwargs["volumes"]
        repo_abs = os.path.abspath(str(c_repo))
        assert volumes[repo_abs]["mode"] == "rw"


# ---------------------------------------------------------------------------
# Variant selection at spawn time
# ---------------------------------------------------------------------------


class TestVariantSpawn:
    def test_spawn_msan_variant(self, c_repo: Path, mock_docker):
        mock_docker.images.get.side_effect = Exception("not found")

        sb = HunterSandbox(
            repo_path=str(c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        sb.build_image()

        mock_docker.images.get.side_effect = None
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "msan-cid"
        mock_container.short_id = "msa"
        mock_docker.containers.run.return_value = mock_container

        container = sb.spawn(variant=["msan"], scratch_mount=False)
        assert container.variant == ["msan"]

        kwargs = mock_docker.containers.run.call_args.kwargs
        env = kwargs["environment"]
        assert "msan" in env["CLEARWING_SANITIZER_VARIANT"]
        assert "MSAN_OPTIONS" in env

    @patch("clearwing.sandbox.hunter_sandbox.subprocess.Popen")
    @patch("clearwing.sandbox.hunter_sandbox.subprocess.run")
    def test_spawn_unbuilt_variant_auto_builds(self, mock_run, mock_popen, c_repo: Path, mock_docker):
        """Requesting an unbuilt variant auto-builds on demand."""
        # subprocess.run: inspect calls always miss
        mock_run.return_value = MagicMock(returncode=1)
        # subprocess.Popen: builds always succeed
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        sb = HunterSandbox(repo_path=str(c_repo), sanitizers=["asan", "ubsan"])
        sb.build_image()

        mock_container = MagicMock()
        mock_container.id = "tsan-cid"
        mock_container.short_id = "tsa"
        mock_docker.containers.run.return_value = mock_container

        container = sb.spawn(variant=["tsan"], scratch_mount=False)
        assert container.variant == ["tsan"]
        # 2 inspects (primary + tsan) and 2 builds (primary + tsan)
        assert mock_run.call_count == 2
        assert mock_popen.call_count == 2
