"""Unit tests for HunterSandbox and BuildSystemDetector with docker mocked."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from clearwing.sandbox.builders import (
    BuildRecipe,
    BuildSystemDetector,
    DEFAULT_BASE_IMAGES,
)
from clearwing.sandbox.hunter_sandbox import HunterSandbox


@pytest.fixture
def temp_repo(tmp_path: Path):
    """Create a tiny temp directory tree to act as a cloned repo."""
    return tmp_path


# --- BuildSystemDetector ---------------------------------------------------


class TestBuildSystemDetector:
    def test_detects_make(self, temp_repo: Path):
        (temp_repo / "Makefile").write_text("all:\n\techo hi\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "make"
        assert recipe.primary_language == "c"
        assert "asan" in recipe.sanitizer_flags

    def test_detects_cmake(self, temp_repo: Path):
        (temp_repo / "CMakeLists.txt").write_text("project(foo)\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "cmake"
        assert recipe.primary_language == "cpp"
        assert "cmake" in " ".join(recipe.apt_packages)

    def test_detects_cargo(self, temp_repo: Path):
        (temp_repo / "Cargo.toml").write_text('[package]\nname = "x"\n')
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "cargo"
        assert recipe.primary_language == "rust"
        assert recipe.base_image == DEFAULT_BASE_IMAGES["rust"]

    def test_detects_go(self, temp_repo: Path):
        (temp_repo / "go.mod").write_text("module foo\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "go"
        assert recipe.primary_language == "go"
        assert "race" in recipe.sanitizer_flags

    def test_detects_python_pyproject(self, temp_repo: Path):
        (temp_repo / "pyproject.toml").write_text("[project]\nname='x'\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "python"
        assert recipe.primary_language == "python"

    def test_detects_python_setup_py(self, temp_repo: Path):
        (temp_repo / "setup.py").write_text("from setuptools import setup\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "python"

    def test_detects_npm(self, temp_repo: Path):
        (temp_repo / "package.json").write_text('{"name":"x"}\n')
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "npm"
        assert recipe.primary_language == "node"

    def test_cmake_takes_priority_over_makefile(self, temp_repo: Path):
        (temp_repo / "CMakeLists.txt").write_text("project(foo)\n")
        (temp_repo / "Makefile").write_text("all:\n\techo hi\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "cmake"

    def test_cargo_takes_priority_over_makefile(self, temp_repo: Path):
        (temp_repo / "Cargo.toml").write_text('[package]\nname = "x"\n')
        (temp_repo / "Makefile").write_text("all:\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "cargo"

    def test_unknown_returns_unknown(self, temp_repo: Path):
        # Empty repo
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.system == "unknown"
        assert recipe.primary_language == "unknown"

    def test_language_guess_from_python_files(self, temp_repo: Path):
        # No build system files, just .py files
        (temp_repo / "main.py").write_text("print('hi')\n")
        (temp_repo / "lib.py").write_text("x = 1\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.primary_language == "python"

    def test_language_guess_from_c_files(self, temp_repo: Path):
        (temp_repo / "main.c").write_text("int main(){}\n")
        (temp_repo / "util.h").write_text("#define X 1\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert recipe.primary_language == "c"

    def test_recipe_includes_ripgrep_in_apt(self, temp_repo: Path):
        (temp_repo / "Makefile").write_text("all:\n")
        recipe = BuildSystemDetector.detect(str(temp_repo))
        assert "ripgrep" in recipe.apt_packages


# --- HunterSandbox.build_image ---------------------------------------------


@pytest.fixture
def mock_docker():
    with patch("docker.from_env") as mock_from_env:
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        yield mock_client


class TestHunterSandboxBuildImage:
    def test_build_image_calls_images_build(self, temp_repo: Path, mock_docker):
        (temp_repo / "Makefile").write_text("all:\n")
        # Make images.get raise so we go down the build path
        mock_docker.images.get.side_effect = Exception("not found")

        sb = HunterSandbox(repo_path=str(temp_repo))
        tag = sb.build_image()
        assert tag.startswith("clearwing-sourcehunt:")
        mock_docker.images.build.assert_called_once()
        kwargs = mock_docker.images.build.call_args.kwargs
        assert kwargs["tag"] == tag

    def test_build_image_reuses_cached(self, temp_repo: Path, mock_docker):
        (temp_repo / "Makefile").write_text("all:\n")
        # images.get succeeds → reuse
        mock_docker.images.get.return_value = MagicMock()

        sb = HunterSandbox(repo_path=str(temp_repo))
        sb.build_image()
        mock_docker.images.build.assert_not_called()

    def test_dockerfile_includes_recipe_apt_packages(self, temp_repo: Path):
        (temp_repo / "Makefile").write_text("all:\n")
        sb = HunterSandbox(repo_path=str(temp_repo))
        df = sb._render_dockerfile()
        assert "FROM gcc:13" in df
        assert "ripgrep" in df
        assert "gdb" in df

    def test_dockerfile_sets_sanitizer_env(self, temp_repo: Path):
        (temp_repo / "Makefile").write_text("all:\n")
        sb = HunterSandbox(repo_path=str(temp_repo))
        df = sb._render_dockerfile()
        # CFLAGS should be set with the sanitizer flags from the recipe
        assert "CFLAGS=" in df
        assert "fsanitize=address" in df

    def test_dockerfile_for_python_no_gcc_needed(self, temp_repo: Path):
        (temp_repo / "pyproject.toml").write_text("[project]\nname='x'\n")
        sb = HunterSandbox(repo_path=str(temp_repo))
        df = sb._render_dockerfile()
        assert "FROM python:3.12-slim" in df

    def test_image_tag_is_content_addressed(self, temp_repo: Path):
        (temp_repo / "Makefile").write_text("all:\n")

        sb1 = HunterSandbox(repo_path=str(temp_repo), sanitizers=["asan"])
        sb2 = HunterSandbox(repo_path=str(temp_repo), sanitizers=["asan"])
        sb3 = HunterSandbox(repo_path=str(temp_repo), sanitizers=["asan", "ubsan"])
        # Same config → same tag
        assert sb1._compute_tag(sb1._render_dockerfile()) == sb2._compute_tag(sb2._render_dockerfile())
        # Different sanitizers → different tag
        tag_a = sb1._compute_tag(sb1._render_dockerfile())
        tag_c = sb3._compute_tag(sb3._render_dockerfile())
        # Note: dockerfile is identical because env is from recipe; sanitizer
        # list is hashed in too, so tags differ
        assert tag_a != tag_c


class TestHunterSandboxSpawn:
    def test_spawn_starts_no_network_container(self, temp_repo: Path, mock_docker):
        (temp_repo / "Makefile").write_text("all:\n")
        mock_docker.images.get.return_value = MagicMock()  # cached
        mock_container = MagicMock()
        mock_container.id = "cid"
        mock_container.short_id = "cid"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(temp_repo))
        sb.build_image()
        spawned = sb.spawn(session_id="test-session", scratch_mount=False)

        assert spawned.is_running
        kwargs = mock_docker.containers.run.call_args.kwargs
        assert kwargs["network_mode"] == "none"
        # Workspace mount is read-only
        volumes = kwargs["volumes"]
        repo_abs = os.path.abspath(str(temp_repo))
        assert volumes[repo_abs]["bind"] == "/workspace"
        assert volumes[repo_abs]["mode"] == "ro"
        # Session id was injected into env
        assert kwargs["environment"]["CLEARWING_SESSION_ID"] == "test-session"

    def test_spawn_with_scratch_mount(self, temp_repo: Path, mock_docker):
        (temp_repo / "Makefile").write_text("all:\n")
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cid"
        mock_container.short_id = "cid"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(temp_repo))
        sb.build_image()
        spawned = sb.spawn(scratch_mount=True)

        kwargs = mock_docker.containers.run.call_args.kwargs
        volumes = kwargs["volumes"]
        # Find the rw mount (the scratch dir)
        rw_mounts = [
            (host, info) for host, info in volumes.items()
            if info["mode"] == "rw"
        ]
        assert len(rw_mounts) == 1
        assert rw_mounts[0][1]["bind"] == "/scratch"

        # Cleanup the host scratch dir
        sb.cleanup()

    def test_cleanup_stops_all_spawned(self, temp_repo: Path, mock_docker):
        (temp_repo / "Makefile").write_text("all:\n")
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "cid"
        mock_container.short_id = "cid"
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(temp_repo))
        sb.build_image()
        sb.spawn(scratch_mount=False)
        sb.spawn(scratch_mount=False)
        sb.cleanup()
        # Both containers stopped (call_count == 2 since same mock used twice)
        assert mock_container.stop.call_count == 2
        assert mock_container.remove.call_count == 2

    def test_cleanup_remove_image(self, temp_repo: Path, mock_docker):
        (temp_repo / "Makefile").write_text("all:\n")
        mock_docker.images.get.return_value = MagicMock()

        sb = HunterSandbox(repo_path=str(temp_repo))
        sb.build_image()
        sb.cleanup(remove_image=True)
        mock_docker.images.remove.assert_called_once()
