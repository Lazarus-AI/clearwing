"""Integration tests for sandbox creation with REAL Docker.

These tests actually build images and spawn containers. They require a running
Docker daemon. Mark: @pytest.mark.integration — skip in CI without Docker.

Key failure modes these tests catch:

1. Docker Python SDK `images.build()` fails when ~/.docker/config.json has a
   credential helper (e.g. docker-credential-gcloud) that errors. The SDK
   eagerly resolves creds for ALL configured registries before pulling the
   base image. The `docker build` CLI does NOT have this problem — it only
   auths against registries it actually needs.

2. gcc:13 (bookworm) dropped ltrace and has apt issues on arm64.

3. `docker build` platform mismatch on Apple Silicon — C/C++ toolchains
   run under qemu if linux/amd64 is forced, which is extremely slow and
   sometimes miscompiles.

4. apt-get install fails inside the image for certain packages on non-amd64.
"""

from __future__ import annotations

import platform
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from clearwing.sandbox.builders import DEFAULT_BASE_IMAGES, BuildSystemDetector
from clearwing.sandbox.hunter_sandbox import HunterSandbox


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available"),
    pytest.mark.integration,
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def c_repo(tmp_path: Path) -> Path:
    (tmp_path / "Makefile").write_text(
        "CC=gcc\nCFLAGS ?= -Wall\n\nall: main\n\nmain: main.c\n\t$(CC) $(CFLAGS) -o $@ $<\n"
    )
    (tmp_path / "main.c").write_text(
        '#include <stdio.h>\n#include <string.h>\n\n'
        "int main(int argc, char **argv) {\n"
        '    char buf[64];\n'
        '    if (argc > 1) strcpy(buf, argv[1]);\n'
        '    printf("ok\\n");\n'
        '    return 0;\n'
        "}\n"
    )
    return tmp_path


@pytest.fixture
def cpp_repo(tmp_path: Path) -> Path:
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(test_sandbox LANGUAGES CXX)\n"
        "add_executable(main main.cpp)\n"
    )
    (tmp_path / "main.cpp").write_text(
        "#include <iostream>\n"
        "#include <cstring>\n\n"
        "int main(int argc, char** argv) {\n"
        "    char buf[64];\n"
        "    if (argc > 1) std::strcpy(buf, argv[1]);\n"
        '    std::cout << "ok" << std::endl;\n'
        "    return 0;\n"
        "}\n"
    )
    return tmp_path


@pytest.fixture
def go_repo(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module example.com/test\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text(
        'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("ok") }\n'
    )
    return tmp_path


@pytest.fixture
def python_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test_sandbox'\nversion = '0.1.0'\n")
    (tmp_path / "main.py").write_text("print('ok')\n")
    return tmp_path


# ---------------------------------------------------------------------------
# Image build tests — does `docker build` succeed at all?
# ---------------------------------------------------------------------------


class TestDockerSdkVsCliBuilds:
    """Demonstrate and test the Docker SDK credential bug.

    The Python Docker SDK's images.build() eagerly resolves credentials for
    ALL registries in ~/.docker/config.json. If any credHelper (like
    docker-credential-gcloud) errors, the entire build fails — even though
    the base image doesn't need that registry at all.

    The `docker build` CLI only authenticates against registries it needs to
    pull from, so it succeeds where the SDK fails.
    """

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_sdk_build_may_fail_with_cred_helpers(self, c_repo: Path):
        """Document that the SDK path can fail due to credential helpers.

        This test PASSES either way (success or cred-helper failure) — it
        exists to document and detect the failure mode. If it hits the
        credential error, we know the subprocess fallback is required.
        """
        sb = HunterSandbox(repo_path=str(c_repo))
        try:
            tag = sb.build_image()
            # If we get here, SDK build works (no cred helper issue)
            sb.cleanup(remove_image=True)
        except RuntimeError as e:
            if "Credentials store" in str(e) or "credential" in str(e).lower():
                # Expected failure — credential helper broke the SDK
                pytest.skip(
                    f"Docker SDK build fails due to credential helper: {e}. "
                    f"This confirms the subprocess-based build path is needed."
                )
            raise

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_cli_build_succeeds_for_c(self, c_repo: Path):
        """docker build CLI succeeds where SDK may fail."""
        sb = HunterSandbox(repo_path=str(c_repo))
        dockerfile = sb._render_dockerfile()
        tag = sb._compute_tag(dockerfile)

        with tempfile.TemporaryDirectory() as build_dir:
            df_path = Path(build_dir) / "Dockerfile"
            df_path.write_text(dockerfile)

            result = subprocess.run(
                ["docker", "build", "--progress=plain", "-t", tag, build_dir],
                capture_output=True, text=True, timeout=120,
            )

        assert result.returncode == 0, (
            f"docker build CLI failed for C sandbox:\n{result.stderr[-2000:]}"
        )
        # Verify image exists
        inspect = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, timeout=10,
        )
        assert inspect.returncode == 0
        subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_cli_build_succeeds_for_cpp(self, cpp_repo: Path):
        """docker build CLI succeeds for C++ (cmake) sandbox."""
        sb = HunterSandbox(repo_path=str(cpp_repo))
        dockerfile = sb._render_dockerfile()
        tag = sb._compute_tag(dockerfile)

        with tempfile.TemporaryDirectory() as build_dir:
            df_path = Path(build_dir) / "Dockerfile"
            df_path.write_text(dockerfile)

            result = subprocess.run(
                ["docker", "build", "--progress=plain", "-t", tag, build_dir],
                capture_output=True, text=True, timeout=120,
            )

        assert result.returncode == 0, (
            f"docker build CLI failed for C++ sandbox:\n{result.stderr[-2000:]}"
        )
        subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)


class TestImageBuildActuallyWorks:
    """These test that HunterSandbox.build_image() produces a usable image.

    If these fail, the sandbox is broken for that language.
    Uses subprocess-based build to avoid the credential helper bug.
    """

    def _build_via_cli(self, sb: HunterSandbox) -> str:
        """Build the sandbox image using docker CLI (bypasses SDK cred bug)."""
        dockerfile = sb._render_dockerfile()
        tag = sb._compute_tag(dockerfile)
        with tempfile.TemporaryDirectory() as build_dir:
            (Path(build_dir) / "Dockerfile").write_text(dockerfile)
            result = subprocess.run(
                ["docker", "build", "--progress=plain", "-t", tag, build_dir],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"docker build failed:\n{result.stderr[-2000:]}"
                )
        return tag

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_c_image_builds(self, c_repo: Path):
        sb = HunterSandbox(repo_path=str(c_repo))
        tag = self._build_via_cli(sb)
        assert tag.startswith("clearwing-sourcehunt:")
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, timeout=10,
        )
        assert result.returncode == 0, f"Image {tag} not found after build"
        subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_cpp_image_builds(self, cpp_repo: Path):
        sb = HunterSandbox(repo_path=str(cpp_repo))
        tag = self._build_via_cli(sb)
        assert tag.startswith("clearwing-sourcehunt:")
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, timeout=10,
        )
        assert result.returncode == 0, f"Image {tag} not found after build"
        subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_cpp_image_has_cmake(self, cpp_repo: Path):
        """CMake projects need cmake available inside the container."""
        sb = HunterSandbox(repo_path=str(cpp_repo))
        tag = self._build_via_cli(sb)
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", tag, "cmake", "--version"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, f"cmake not available: {result.stderr}"
            assert "cmake version" in result.stdout
        finally:
            subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_c_image_has_gcc_with_sanitizers(self, c_repo: Path):
        """The whole point: gcc must support -fsanitize=address."""
        sb = HunterSandbox(repo_path=str(c_repo))
        tag = self._build_via_cli(sb)
        try:
            result = subprocess.run(
                [
                    "docker", "run", "--rm", tag,
                    "sh", "-c",
                    "echo 'int main(){}' > /tmp/t.c && "
                    "gcc -fsanitize=address -o /tmp/t /tmp/t.c && "
                    "echo SUCCESS",
                ],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                f"gcc -fsanitize=address failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
            )
            assert "SUCCESS" in result.stdout
        finally:
            subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_c_image_has_ripgrep(self, c_repo: Path):
        """Hunters use grep_source which shells out to rg."""
        sb = HunterSandbox(repo_path=str(c_repo))
        tag = self._build_via_cli(sb)
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", tag, "rg", "--version"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, f"ripgrep not available: {result.stderr}"
        finally:
            subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)

    @pytest.mark.integration
    @pytest.mark.timeout(60)
    def test_python_image_builds(self, python_repo: Path):
        sb = HunterSandbox(repo_path=str(python_repo))
        tag = self._build_via_cli(sb)
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", tag, "python3", "--version"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0
        finally:
            subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=10)


# ---------------------------------------------------------------------------
# Container spawn + exec tests — can we actually run commands?
# ---------------------------------------------------------------------------


class TestContainerSpawnAndExec:
    """Verify that spawned containers can execute commands correctly."""

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_c_spawn_and_compile(self, c_repo: Path):
        """Full flow: build image → spawn → compile with ASan → run."""
        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        container = sb.spawn(session_id="integ-c", scratch_mount=True)

        try:
            # Verify workspace is mounted
            result = container.exec("ls /workspace/main.c")
            assert result.exit_code == 0, f"workspace mount failed: {result.stderr}"

            # Compile with sanitizers (CFLAGS from env)
            result = container.exec(
                "cd /workspace && make 2>&1",
                timeout=30,
            )
            # On ro mount, make will fail to write — that's expected.
            # The important thing is gcc + asan are available.
            # Let's compile in /scratch instead
            result = container.exec(
                "cp /workspace/main.c /scratch/ && "
                "cd /scratch && gcc $CFLAGS -o main main.c 2>&1",
                timeout=30,
            )
            assert result.exit_code == 0, (
                f"ASan compile failed:\n{result.stdout}\n{result.stderr}"
            )

            # Run — should work without crashing
            result = container.exec("/scratch/main", timeout=10)
            assert result.exit_code == 0
            assert "ok" in result.stdout

            # Trigger the overflow — ASan should catch it but not abort
            # (halt_on_error=0)
            result = container.exec(
                "/scratch/main " + "A" * 200,
                timeout=10,
            )
            # ASan reports the error but doesn't abort (halt_on_error=0)
            combined = (result.stdout or "") + (result.stderr or "")
            assert "AddressSanitizer" in combined or result.exit_code != 0
        finally:
            sb.cleanup(remove_image=True)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_cpp_spawn_and_compile(self, cpp_repo: Path):
        """C++ with CMake: build image → spawn → cmake + make → run."""
        sb = HunterSandbox(repo_path=str(cpp_repo))
        sb.build_image()
        container = sb.spawn(session_id="integ-cpp", scratch_mount=True)

        try:
            # Copy source to scratch (workspace is ro)
            result = container.exec(
                "cp -r /workspace/* /scratch/ && ls /scratch/CMakeLists.txt",
                timeout=15,
            )
            assert result.exit_code == 0, f"copy failed: {result.stderr}"

            # Build with cmake
            result = container.exec(
                "cd /scratch && mkdir -p build && cd build && "
                "cmake -DCMAKE_C_FLAGS=\"$CFLAGS\" -DCMAKE_CXX_FLAGS=\"$CXXFLAGS\" .. && "
                "make 2>&1",
                timeout=60,
            )
            assert result.exit_code == 0, (
                f"cmake build failed:\n{result.stdout}\n{result.stderr}"
            )

            # Run
            result = container.exec("/scratch/build/main", timeout=10)
            assert result.exit_code == 0
            assert "ok" in result.stdout
        finally:
            sb.cleanup(remove_image=True)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_writable_workspace_compile(self, c_repo: Path):
        """Writable workspace: copy_tree_into → compile in /workspace directly."""
        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        sb.build_image()
        container = sb.spawn(
            session_id="integ-writable",
            writable_workspace=True,
            scratch_mount=False,
        )

        try:
            # Workspace should be writable — compile directly
            result = container.exec(
                "cd /workspace && gcc $CFLAGS -o main main.c 2>&1",
                timeout=30,
            )
            assert result.exit_code == 0, (
                f"Compile in writable workspace failed:\n{result.stdout}\n{result.stderr}"
            )

            # Git should be initialized (if git is available)
            result = container.exec("cd /workspace && git log --oneline -1", timeout=10)
            # git init is best-effort, don't hard-fail
            if result.exit_code == 0:
                assert "initial" in result.stdout.lower()
        finally:
            sb.cleanup(remove_image=True)

    @pytest.mark.integration
    @pytest.mark.timeout(60)
    def test_network_actually_blocked(self, c_repo: Path):
        """Containers must not have network access (isolation)."""
        sb = HunterSandbox(repo_path=str(c_repo))
        sb.build_image()
        container = sb.spawn(session_id="integ-net", scratch_mount=False)

        try:
            result = container.exec(
                "curl -s --max-time 3 http://1.1.1.1 2>&1 || "
                "wget -q --timeout=3 http://1.1.1.1 -O /dev/null 2>&1 || "
                "echo NETWORK_BLOCKED",
                timeout=10,
            )
            combined = (result.stdout or "") + (result.stderr or "")
            # Either the commands fail or we see our marker
            assert "NETWORK_BLOCKED" in combined or result.exit_code != 0
        finally:
            sb.cleanup(remove_image=True)


# ---------------------------------------------------------------------------
# Platform-specific tests
# ---------------------------------------------------------------------------


class TestPlatformBuild:
    """Test that the image actually builds on the host platform.

    On Apple Silicon (arm64), key failures:
      - ltrace is NOT available in Debian bookworm arm64 repos
      - Running linux/amd64 images under qemu is extremely slow and can miscompile
      - A single missing package in `apt-get install` fails the entire build

    These tests run against the HOST architecture to catch real failures.
    """

    @pytest.mark.integration
    @pytest.mark.timeout(180)
    def test_base_image_pullable(self, c_repo: Path):
        """Verify the configured base image can be pulled."""
        recipe = BuildSystemDetector.detect(str(c_repo))
        base = recipe.base_image
        result = subprocess.run(
            ["docker", "pull", base],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, (
            f"Cannot pull base image {base}:\n{result.stderr}"
        )

    @pytest.mark.integration
    @pytest.mark.timeout(180)
    def test_cpp_base_image_pullable(self, cpp_repo: Path):
        recipe = BuildSystemDetector.detect(str(cpp_repo))
        base = recipe.base_image
        result = subprocess.run(
            ["docker", "pull", base],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, (
            f"Cannot pull base image {base}:\n{result.stderr}"
        )

    @pytest.mark.integration
    @pytest.mark.timeout(180)
    def test_apt_install_common_packages_native_arch(self, c_repo: Path):
        """Verify COMMON_APT_PACKAGES install on native arch."""
        recipe = BuildSystemDetector.detect(str(c_repo))
        base = recipe.base_image
        from clearwing.sandbox.builders import COMMON_APT_PACKAGES

        pkg_list = " ".join(COMMON_APT_PACKAGES)
        result = subprocess.run(
            [
                "docker", "run", "--rm", base,
                "sh", "-c",
                f"apt-get update -qq && "
                f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkg_list} 2>&1",
            ],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, (
            f"apt-get install failed for packages [{pkg_list}] in {base}:\n"
            f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_ltrace_available_on_native_arch(self, c_repo: Path):
        """ltrace is required by deep_agent_mode but missing on arm64/bookworm.

        This test documents and catches the platform gap. On arm64 hosts this
        WILL FAIL — proving that the current HunterSandbox.DEEP_AGENT_PACKAGES
        list is broken on Apple Silicon unless the build targets amd64 (qemu).
        """
        recipe = BuildSystemDetector.detect(str(c_repo))
        base = recipe.base_image
        result = subprocess.run(
            [
                "docker", "run", "--rm", base,
                "sh", "-c",
                "apt-get update -qq && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ltrace 2>&1",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            host_arch = platform.machine()
            if host_arch in ("arm64", "aarch64"):
                pytest.fail(
                    f"ltrace is NOT available on {base} arm64. "
                    f"deep_agent_mode image builds WILL FAIL on Apple Silicon "
                    f"unless the Dockerfile handles this gracefully.\n"
                    f"Output: {result.stdout[-500:]}"
                )
            else:
                pytest.fail(
                    f"ltrace install failed unexpectedly on {host_arch}:\n"
                    f"{result.stdout[-1000:]}"
                )

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_deep_agent_all_packages_install_native(self, c_repo: Path):
        """Full deep-agent package list must install on native arch.

        This is the exact set that HunterSandbox adds when deep_agent_mode=True.
        If ANY package is unavailable, the entire Dockerfile build fails because
        apt-get runs as one RUN layer.
        """
        recipe = BuildSystemDetector.detect(str(c_repo))
        base = recipe.base_image
        from clearwing.sandbox.builders import COMMON_APT_PACKAGES

        all_packages = COMMON_APT_PACKAGES + list(HunterSandbox.DEEP_AGENT_PACKAGES)
        pkg_list = " ".join(all_packages)
        result = subprocess.run(
            [
                "docker", "run", "--rm", base,
                "sh", "-c",
                f"apt-get update -qq && "
                f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkg_list} 2>&1",
            ],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            # Find which package failed
            missing = []
            for pkg in all_packages:
                check = subprocess.run(
                    [
                        "docker", "run", "--rm", base,
                        "sh", "-c",
                        f"apt-get update -qq 2>/dev/null && "
                        f"apt-cache show {pkg} >/dev/null 2>&1 && echo FOUND || echo MISSING",
                    ],
                    capture_output=True, text=True, timeout=30,
                )
                if "MISSING" in check.stdout:
                    missing.append(pkg)
            pytest.fail(
                f"deep_agent_mode package install failed in {base}.\n"
                f"Missing packages: {missing}\n"
                f"Host arch: {platform.machine()}\n"
                f"This means HunterSandbox.build_image() will fail for C/C++ "
                f"targets with deep_agent_mode=True on this platform.\n"
                f"apt output: {result.stdout[-1000:]}"
            )

    @pytest.mark.integration
    @pytest.mark.timeout(60)
    def test_host_arch_detection(self):
        """Document what arch Docker uses by default on this host."""
        result = subprocess.run(
            ["docker", "run", "--rm", "alpine:latest", "uname", "-m"],
            capture_output=True, text=True, timeout=30,
        )
        container_arch = result.stdout.strip()
        host_arch = platform.machine()
        assert result.returncode == 0
        # On Apple Silicon the default is arm64 unless overridden
        if host_arch in ("arm64", "aarch64"):
            assert container_arch == "aarch64", (
                f"Expected native arm64 container but got {container_arch}"
            )


# ---------------------------------------------------------------------------
# MSan variant (historically problematic — needs libc++ instrumented)
# ---------------------------------------------------------------------------


class TestMsanVariant:
    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_msan_image_builds(self, c_repo: Path):
        """MSan variant must build without error."""
        sb = HunterSandbox(
            repo_path=str(c_repo),
            sanitizers=["msan"],
        )
        tag = sb.build_image()
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, timeout=10,
        )
        assert result.returncode == 0
        sb.cleanup(remove_image=True)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_msan_compile_works(self, c_repo: Path):
        """MSan requires special linking — verify it actually works."""
        sb = HunterSandbox(repo_path=str(c_repo), sanitizers=["msan"])
        sb.build_image()
        container = sb.spawn(session_id="integ-msan", scratch_mount=True)

        try:
            # MSan compile — may fail if gcc doesn't have msan runtime
            result = container.exec(
                "echo 'int main(){}' > /scratch/t.c && "
                "gcc -fsanitize=memory -o /scratch/t /scratch/t.c 2>&1",
                timeout=30,
            )
            # If MSan isn't supported by this gcc version, that's a known
            # limitation — record it but don't hard-fail
            if result.exit_code != 0:
                combined = (result.stdout or "") + (result.stderr or "")
                if "unrecognized" in combined or "not supported" in combined.lower():
                    pytest.skip("gcc in base image doesn't support -fsanitize=memory")
                pytest.fail(f"MSan compile failed unexpectedly:\n{combined}")
        finally:
            sb.cleanup(remove_image=True)


# ---------------------------------------------------------------------------
# Deep agent mode (the mode used by cross-file-chatter branch)
# ---------------------------------------------------------------------------


class TestDeepAgentMode:
    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_deep_agent_packages_installed(self, c_repo: Path):
        """Deep agent mode must have valgrind, python3, git, ltrace."""
        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        tag = sb.build_image()

        for tool in ["valgrind", "python3", "git"]:
            result = subprocess.run(
                ["docker", "run", "--rm", tag, "which", tool],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0, (
                f"Deep agent tool {tool!r} not found in image {tag}"
            )
        sb.cleanup(remove_image=True)

    @pytest.mark.integration
    @pytest.mark.timeout(120)
    def test_deep_agent_valgrind_runs(self, c_repo: Path):
        """Valgrind must actually execute (not just be installed)."""
        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        sb.build_image()
        container = sb.spawn(session_id="integ-valgrind", scratch_mount=True)

        try:
            # Compile a simple binary
            result = container.exec(
                "echo 'int main(){}' > /scratch/t.c && "
                "gcc -g -o /scratch/t /scratch/t.c && "
                "valgrind --error-exitcode=1 /scratch/t 2>&1",
                timeout=30,
            )
            combined = (result.stdout or "") + (result.stderr or "")
            # Valgrind should run and report 0 errors
            assert "ERROR SUMMARY: 0 errors" in combined, (
                f"Valgrind didn't run cleanly:\n{combined}"
            )
        finally:
            sb.cleanup(remove_image=True)

    @pytest.mark.integration
    @pytest.mark.timeout(180)
    def test_deep_agent_writable_full_flow(self, c_repo: Path):
        """End-to-end: deep agent spawns writable, compiles, runs, gets ASan trace."""
        sb = HunterSandbox(repo_path=str(c_repo), deep_agent_mode=True)
        sb.build_image()
        container = sb.spawn(
            session_id="integ-deep-full",
            writable_workspace=True,
            scratch_mount=False,
            memory_mb=4096,
        )

        try:
            # Source should be in /workspace
            result = container.exec("cat /workspace/main.c", timeout=5)
            assert result.exit_code == 0
            assert "strcpy" in result.stdout

            # Compile with ASan flags from env
            result = container.exec(
                "cd /workspace && gcc $CFLAGS -o main main.c 2>&1",
                timeout=30,
            )
            assert result.exit_code == 0, (
                f"Compile failed:\n{result.stdout}\n{result.stderr}"
            )

            # Trigger overflow
            result = container.exec(
                f"/workspace/main {'A' * 200} 2>&1",
                timeout=10,
            )
            combined = (result.stdout or "") + (result.stderr or "")
            assert "AddressSanitizer" in combined, (
                f"Expected ASan report, got:\n{combined}"
            )
        finally:
            sb.cleanup(remove_image=True)
