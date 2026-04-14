"""Production tests for the v0.4 MSan build variant pipeline.

Covers:
    - BuildRecipe.env_for_sanitizers computes distinct flag sets
    - validate_sanitizer_combo rejects asan+msan
    - HunterSandbox builds one image per variant, with distinct tags
    - spawn(variant=...) dispatches to the right image
    - HunterContext.get_sandbox_for_variant caches variant containers
    - compile_file / run_with_sanitizer accept sanitizer_variant
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnexploit.agent.tools.hunter_tools import (
    HunterContext,
    _parse_variant_arg,
    build_hunter_tools,
)
from vulnexploit.sandbox.builders import (
    BuildRecipe,
    BuildSystemDetector,
    INCOMPATIBLE_SANITIZER_PAIRS,
    compute_sanitizer_env,
    validate_sanitizer_combo,
)
from vulnexploit.sandbox.container import ExecResult
from vulnexploit.sandbox.hunter_sandbox import HunterSandbox


# --- validate_sanitizer_combo ----------------------------------------------


class TestValidateSanitizerCombo:
    def test_asan_msan_rejected(self):
        with pytest.raises(ValueError, match="cannot coexist"):
            validate_sanitizer_combo(["asan", "msan"])

    def test_asan_tsan_rejected(self):
        with pytest.raises(ValueError, match="cannot coexist"):
            validate_sanitizer_combo(["asan", "tsan"])

    def test_msan_tsan_rejected(self):
        with pytest.raises(ValueError, match="cannot coexist"):
            validate_sanitizer_combo(["msan", "tsan"])

    def test_asan_ubsan_allowed(self):
        validate_sanitizer_combo(["asan", "ubsan"])

    def test_msan_ubsan_allowed(self):
        validate_sanitizer_combo(["msan", "ubsan"])

    def test_msan_alone_allowed(self):
        validate_sanitizer_combo(["msan"])

    def test_all_incompatible_pairs_are_listed(self):
        """Every pair in INCOMPATIBLE_SANITIZER_PAIRS should actually raise."""
        for a, b in INCOMPATIBLE_SANITIZER_PAIRS:
            with pytest.raises(ValueError):
                validate_sanitizer_combo([a, b])


# --- compute_sanitizer_env --------------------------------------------------


class TestComputeSanitizerEnv:
    def _c_recipe(self) -> BuildRecipe:
        return BuildSystemDetector._make_recipe()

    def test_asan_ubsan_combo(self):
        recipe = self._c_recipe()
        env = compute_sanitizer_env(recipe, ["asan", "ubsan"])
        assert "-fsanitize=address" in env["CFLAGS"]
        assert "-fsanitize=undefined" in env["CFLAGS"]
        # Runtime env vars are merged for each sanitizer
        assert "ASAN_OPTIONS" in env
        assert "UBSAN_OPTIONS" in env

    def test_msan_standalone(self):
        recipe = self._c_recipe()
        env = compute_sanitizer_env(recipe, ["msan"])
        assert "-fsanitize=memory" in env["CFLAGS"]
        assert "-fsanitize-memory-track-origins=2" in env["CFLAGS"]
        # No ASan flags
        assert "-fsanitize=address" not in env["CFLAGS"]
        # MSan runtime options injected
        assert "MSAN_OPTIONS" in env
        # ASan options NOT injected
        assert "ASAN_OPTIONS" not in env

    def test_msan_ubsan_combo(self):
        recipe = self._c_recipe()
        env = compute_sanitizer_env(recipe, ["msan", "ubsan"])
        assert "-fsanitize=memory" in env["CFLAGS"]
        assert "-fsanitize=undefined" in env["CFLAGS"]
        # ASan not present
        assert "-fsanitize=address" not in env["CFLAGS"]

    def test_asan_msan_rejected(self):
        recipe = self._c_recipe()
        with pytest.raises(ValueError):
            compute_sanitizer_env(recipe, ["asan", "msan"])

    def test_python_recipe_ignores_sanitizers(self):
        """Non-C languages shouldn't get C sanitizer flags injected."""
        recipe = BuildSystemDetector._python_recipe()
        env = compute_sanitizer_env(recipe, ["asan"])
        assert "CFLAGS" not in env or "-fsanitize" not in env.get("CFLAGS", "")

    def test_flag_order_deterministic(self):
        """Same inputs → same flag string (matters for image tag hashing)."""
        recipe = self._c_recipe()
        env1 = compute_sanitizer_env(recipe, ["asan", "ubsan"])
        env2 = compute_sanitizer_env(recipe, ["asan", "ubsan"])
        assert env1["CFLAGS"] == env2["CFLAGS"]

    def test_distinct_combos_produce_distinct_flags(self):
        recipe = self._c_recipe()
        asan_env = compute_sanitizer_env(recipe, ["asan", "ubsan"])
        msan_env = compute_sanitizer_env(recipe, ["msan", "ubsan"])
        assert asan_env["CFLAGS"] != msan_env["CFLAGS"]


# --- HunterSandbox variant management --------------------------------------


@pytest.fixture
def temp_c_repo(tmp_path: Path) -> Path:
    """A tiny repo detected as C by the build system detector."""
    (tmp_path / "Makefile").write_text("all:\n\techo hi\n")
    return tmp_path


@pytest.fixture
def mock_docker():
    with patch("docker.from_env") as mock_from_env:
        client = MagicMock()
        mock_from_env.return_value = client
        yield client


class TestHunterSandboxVariantValidation:
    def test_primary_asan_msan_rejected(self, temp_c_repo):
        with pytest.raises(ValueError, match="cannot coexist"):
            HunterSandbox(repo_path=str(temp_c_repo), sanitizers=["asan", "msan"])

    def test_extra_variant_asan_msan_rejected(self, temp_c_repo):
        with pytest.raises(ValueError, match="cannot coexist"):
            HunterSandbox(
                repo_path=str(temp_c_repo),
                sanitizers=["asan"],
                extra_variants=[["asan", "msan"]],
            )

    def test_asan_primary_with_msan_extra_is_allowed(self, temp_c_repo):
        """The WHOLE POINT: primary ASan combo + extra MSan combo as separate images."""
        sb = HunterSandbox(
            repo_path=str(temp_c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        assert sb.sanitizers == ["asan", "ubsan"]
        assert sb.extra_variants == [["msan"]]


class TestHunterSandboxVariantImages:
    def test_build_image_builds_primary_only_by_default(self, temp_c_repo, mock_docker):
        mock_docker.images.get.side_effect = Exception("not found")
        sb = HunterSandbox(repo_path=str(temp_c_repo))
        sb.build_image()
        # One image built, one variant registered
        assert mock_docker.images.build.call_count == 1
        assert len(sb._variant_images) == 1
        assert "asan+ubsan" in sb._variant_images

    def test_build_image_builds_extra_variants(self, temp_c_repo, mock_docker):
        mock_docker.images.get.side_effect = Exception("not found")
        sb = HunterSandbox(
            repo_path=str(temp_c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        sb.build_image()
        # Two images built (primary + msan)
        assert mock_docker.images.build.call_count == 2
        assert "asan+ubsan" in sb._variant_images
        assert "msan" in sb._variant_images
        # They have different tags
        assert sb._variant_images["asan+ubsan"] != sb._variant_images["msan"]

    def test_variant_images_have_distinct_tags(self, temp_c_repo):
        """Distinct sanitizer combos must hash to distinct image tags."""
        sb = HunterSandbox(repo_path=str(temp_c_repo))
        asan_tag = sb._compute_tag(
            sb._render_dockerfile(sanitizers=["asan", "ubsan"]),
            sanitizers=["asan", "ubsan"],
        )
        msan_tag = sb._compute_tag(
            sb._render_dockerfile(sanitizers=["msan"]),
            sanitizers=["msan"],
        )
        assert asan_tag != msan_tag

    def test_dockerfile_includes_variant_comment(self, temp_c_repo):
        sb = HunterSandbox(repo_path=str(temp_c_repo))
        df = sb._render_dockerfile(sanitizers=["msan", "ubsan"])
        assert "Sanitizer variant: msan,ubsan" in df

    def test_msan_dockerfile_has_track_origins(self, temp_c_repo):
        sb = HunterSandbox(repo_path=str(temp_c_repo))
        df = sb._render_dockerfile(sanitizers=["msan"])
        assert "-fsanitize=memory" in df
        assert "-fsanitize-memory-track-origins" in df
        # MSan dockerfile should NOT mention ASan
        assert "-fsanitize=address" not in df

    def test_asan_dockerfile_has_no_msan_flags(self, temp_c_repo):
        sb = HunterSandbox(repo_path=str(temp_c_repo))
        df = sb._render_dockerfile(sanitizers=["asan", "ubsan"])
        assert "-fsanitize=address" in df
        assert "-fsanitize=undefined" in df
        assert "-fsanitize=memory" not in df

    def test_build_variant_images_returns_map(self, temp_c_repo, mock_docker):
        mock_docker.images.get.side_effect = Exception("not found")
        sb = HunterSandbox(
            repo_path=str(temp_c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        images = sb.build_variant_images()
        assert set(images.keys()) == {"asan+ubsan", "msan"}


class TestHunterSandboxSpawnVariant:
    def test_spawn_primary_uses_primary_image(self, temp_c_repo, mock_docker):
        mock_docker.images.get.return_value = MagicMock()  # cached
        mock_container = MagicMock(id="cid", short_id="cid")
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(
            repo_path=str(temp_c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        sb.build_image()
        primary_tag = sb._variant_images["asan+ubsan"]

        sb.spawn(scratch_mount=False)   # default variant
        kwargs = mock_docker.containers.run.call_args.kwargs
        assert kwargs["image"] == primary_tag
        # Env reflects ASan+UBSan
        assert "ASAN_OPTIONS" in kwargs["environment"]

    def test_spawn_msan_variant_uses_msan_image(self, temp_c_repo, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock(id="cid", short_id="cid")
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(
            repo_path=str(temp_c_repo),
            sanitizers=["asan", "ubsan"],
            extra_variants=[["msan"]],
        )
        sb.build_image()
        msan_tag = sb._variant_images["msan"]

        sb.spawn(scratch_mount=False, variant=["msan"])
        kwargs = mock_docker.containers.run.call_args.kwargs
        assert kwargs["image"] == msan_tag
        # Env reflects MSan (not ASan)
        assert "MSAN_OPTIONS" in kwargs["environment"]
        assert "ASAN_OPTIONS" not in kwargs["environment"]

    def test_spawn_variant_auto_builds_on_demand(self, temp_c_repo, mock_docker):
        """If a caller asks for a variant that wasn't declared, HunterSandbox
        builds it on the fly rather than raising."""
        mock_docker.images.get.side_effect = Exception("not found")
        mock_container = MagicMock(id="cid", short_id="cid")
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(temp_c_repo))   # no extra_variants
        sb.build_image()

        # Ask for MSan — should trigger an on-demand build
        sb.spawn(scratch_mount=False, variant=["msan"])
        # Two builds total: primary + the on-demand msan
        assert mock_docker.images.build.call_count == 2

    def test_spawn_variant_tags_container_with_variant_env(self, temp_c_repo, mock_docker):
        mock_docker.images.get.return_value = MagicMock()
        mock_container = MagicMock(id="cid", short_id="cid")
        mock_docker.containers.run.return_value = mock_container

        sb = HunterSandbox(repo_path=str(temp_c_repo), extra_variants=[["msan"]])
        sb.build_image()
        sb.spawn(scratch_mount=False, variant=["msan"])
        env = mock_docker.containers.run.call_args.kwargs["environment"]
        assert env["VULNEXPLOIT_SANITIZER_VARIANT"] == "msan"


# --- Hunter tools: sanitizer_variant parameter ----------------------------


class TestParseVariantArg:
    def test_empty(self):
        assert _parse_variant_arg("") is None
        assert _parse_variant_arg(None) is None

    def test_single(self):
        assert _parse_variant_arg("msan") == ["msan"]

    def test_comma_separated(self):
        assert _parse_variant_arg("asan,ubsan") == ["asan", "ubsan"]

    def test_plus_separated(self):
        assert _parse_variant_arg("msan+ubsan") == ["msan", "ubsan"]

    def test_uppercase_normalized(self):
        assert _parse_variant_arg("MSAN") == ["msan"]

    def test_whitespace_stripped(self):
        assert _parse_variant_arg(" asan , ubsan ") == ["asan", "ubsan"]


class TestHunterContextVariantCaching:
    def test_variant_none_returns_primary(self):
        primary = MagicMock(name="primary_sandbox")
        ctx = HunterContext(repo_path="/tmp", sandbox=primary)
        assert ctx.get_sandbox_for_variant(None) is primary

    def test_default_variant_returns_primary(self):
        """Passing the default sanitizer combo returns the primary sandbox
        without spawning a new container."""
        primary = MagicMock(name="primary")
        ctx = HunterContext(
            repo_path="/tmp",
            sandbox=primary,
            default_sanitizers=("asan", "ubsan"),
        )
        result = ctx.get_sandbox_for_variant(["asan", "ubsan"])
        assert result is primary

    def test_msan_variant_spawns_from_manager(self):
        primary = MagicMock(name="primary")
        manager = MagicMock(name="manager")
        variant_sb = MagicMock(name="variant")
        manager.spawn.return_value = variant_sb

        ctx = HunterContext(
            repo_path="/tmp",
            sandbox=primary,
            sandbox_manager=manager,
        )
        result = ctx.get_sandbox_for_variant(["msan"])
        assert result is variant_sb
        manager.spawn.assert_called_once_with(session_id=None, variant=["msan"])

    def test_variant_cached_across_calls(self):
        primary = MagicMock(name="primary")
        manager = MagicMock(name="manager")
        variant_sb = MagicMock(name="variant")
        manager.spawn.return_value = variant_sb

        ctx = HunterContext(
            repo_path="/tmp",
            sandbox=primary,
            sandbox_manager=manager,
        )
        r1 = ctx.get_sandbox_for_variant(["msan"])
        r2 = ctx.get_sandbox_for_variant(["msan"])
        assert r1 is r2
        # Manager.spawn was called exactly once (second call hit the cache)
        assert manager.spawn.call_count == 1

    def test_variant_without_manager_degrades_to_primary(self):
        primary = MagicMock(name="primary")
        ctx = HunterContext(repo_path="/tmp", sandbox=primary)
        # Variant requested, no manager → degrades
        result = ctx.get_sandbox_for_variant(["msan"])
        assert result is primary

    def test_manager_spawn_failure_degrades_to_primary(self):
        primary = MagicMock(name="primary")
        manager = MagicMock(name="manager")
        manager.spawn.side_effect = RuntimeError("docker daemon down")

        ctx = HunterContext(
            repo_path="/tmp",
            sandbox=primary,
            sandbox_manager=manager,
        )
        result = ctx.get_sandbox_for_variant(["msan"])
        assert result is primary   # failed spawn → fall back to primary

    def test_cleanup_variants_stops_cached(self):
        primary = MagicMock(name="primary")
        manager = MagicMock(name="manager")
        variant_sb = MagicMock(name="variant")
        manager.spawn.return_value = variant_sb

        ctx = HunterContext(
            repo_path="/tmp",
            sandbox=primary,
            sandbox_manager=manager,
        )
        ctx.get_sandbox_for_variant(["msan"])
        ctx.cleanup_variants()
        variant_sb.stop.assert_called_once()
        assert ctx.variant_sandboxes == {}


class TestCompileFileVariantDispatch:
    def test_compile_file_with_msan_variant(self):
        primary = MagicMock()
        primary.exec = MagicMock(return_value=ExecResult(0, "", "", 0.1))
        manager = MagicMock()
        msan_sandbox = MagicMock()
        msan_sandbox.exec = MagicMock(return_value=ExecResult(0, "", "", 0.1))
        manager.spawn.return_value = msan_sandbox

        ctx = HunterContext(
            repo_path="/tmp/repo",
            sandbox=primary,
            sandbox_manager=manager,
        )
        tools = build_hunter_tools(ctx)
        compile_tool = next(t for t in tools if t.name == "compile_file")
        result = compile_tool.invoke({
            "file_path": "src/foo.c",
            "sanitizer_variant": "msan",
        })
        # The MSan sandbox was used for compile, not the primary
        msan_sandbox.exec.assert_called_once()
        primary.exec.assert_not_called()
        # Returned variant reflects what was compiled with
        assert "msan" in result.get("variant", "")

    def test_compile_file_default_uses_primary(self):
        primary = MagicMock()
        primary.exec = MagicMock(return_value=ExecResult(0, "", "", 0.1))
        ctx = HunterContext(
            repo_path="/tmp/repo",
            sandbox=primary,
        )
        tools = build_hunter_tools(ctx)
        compile_tool = next(t for t in tools if t.name == "compile_file")
        compile_tool.invoke({"file_path": "src/foo.c"})
        primary.exec.assert_called_once()


class TestRunWithSanitizerVariantDispatch:
    def test_run_with_msan_variant(self):
        primary = MagicMock()
        primary.exec = MagicMock(return_value=ExecResult(0, "__EXITCODE__0", "", 0.1))
        manager = MagicMock()
        msan_sandbox = MagicMock()
        msan_sandbox.exec = MagicMock(return_value=ExecResult(0, "ok", "", 0.1))
        manager.spawn.return_value = msan_sandbox

        ctx = HunterContext(
            repo_path="/tmp/repo",
            sandbox=primary,
            sandbox_manager=manager,
        )
        tools = build_hunter_tools(ctx)
        run_tool = next(t for t in tools if t.name == "run_with_sanitizer")
        result = run_tool.invoke({
            "binary": "/scratch/x.bin",
            "sanitizer_variant": "msan",
        })
        msan_sandbox.exec.assert_called_once()
        primary.exec.assert_not_called()
        assert result["variant"] == "msan"

    def test_run_with_asan_plus_ubsan_uses_primary(self):
        """The default combo routes to the primary sandbox (no fresh spawn)."""
        primary = MagicMock()
        primary.exec = MagicMock(return_value=ExecResult(0, "ok", "", 0.1))
        manager = MagicMock()

        ctx = HunterContext(
            repo_path="/tmp/repo",
            sandbox=primary,
            sandbox_manager=manager,
            default_sanitizers=("asan", "ubsan"),
        )
        tools = build_hunter_tools(ctx)
        run_tool = next(t for t in tools if t.name == "run_with_sanitizer")
        run_tool.invoke({
            "binary": "/scratch/x.bin",
            "sanitizer_variant": "asan,ubsan",
        })
        primary.exec.assert_called_once()
        manager.spawn.assert_not_called()
