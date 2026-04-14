"""HunterSandbox: builds and manages a sanitizer-instrumented container per hunt.

Lifecycle:
    1. SourceHuntRunner instantiates HunterSandbox(repo_path, languages).
    2. .build_image() runs once after preprocessing — produces a tagged image
       with the toolchain, apt deps, and sanitizer flags pre-baked.
    3. Each hunter agent calls .spawn(session_id) → SandboxContainer with
       /workspace mounted read-only and /scratch as a tmpfs scratch dir.
    4. .cleanup() removes spawned containers and (optionally) the image.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile

from .builders import (
    BuildRecipe,
    BuildSystemDetector,
    compute_sanitizer_env,
    validate_sanitizer_combo,
)
from .container import SandboxConfig, SandboxContainer

logger = logging.getLogger(__name__)


class HunterSandbox:
    """Per-hunt sanitizer-instrumented Docker image and container manager.

    Builds an image with the project's build dependencies and ASan/UBSan
    flags, then spawns no-network containers for hunter agents that mount
    the source tree read-only.
    """

    IMAGE_NAME_PREFIX = "clearwing-sourcehunt"

    # Default "extra" variants to build alongside the primary. These let
    # a single HunterSandbox own both an ASan+UBSan image and an MSan
    # image, and spawn containers from either one by name.
    DEFAULT_EXTRA_VARIANTS: tuple[tuple[str, ...], ...] = ()

    def __init__(
        self,
        repo_path: str,
        languages: list[str] | None = None,
        sanitizers: list[str] | None = None,  # primary combo
        extra_variants: list[list[str]] | None = None,  # e.g. [["msan"]]
        extra_packages: list[str] | None = None,
        build_recipe: BuildRecipe | None = None,
    ):
        self.repo_path = os.path.abspath(repo_path)
        self.languages = languages or []
        self.sanitizers = sanitizers or ["asan", "ubsan"]
        validate_sanitizer_combo(self.sanitizers)
        # Additional variants to build (each is itself a sanitizer combo).
        # These are often incompatible with the primary — the whole point.
        self.extra_variants: list[list[str]] = [
            list(v) for v in (extra_variants or self.DEFAULT_EXTRA_VARIANTS)
        ]
        for v in self.extra_variants:
            validate_sanitizer_combo(v)
        self.extra_packages = extra_packages or []
        self.build_recipe = build_recipe or BuildSystemDetector.detect(self.repo_path)
        self._client = None
        self._image_tag: str | None = None  # primary variant tag
        # Variant image map — {variant_key: image_tag}
        self._variant_images: dict[str, str] = {}
        self._spawned: list[SandboxContainer] = []

    # --- Lifecycle ----------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            import docker

            self._client = docker.from_env()
        return self._client

    def build_image(self) -> str:
        """Build the primary sandbox image. Returns its tag.

        Also builds any declared `extra_variants` so subsequent `spawn(variant=)`
        calls can pick between them without another build pass. MSan is the
        motivating case: it can't coexist with ASan in a single binary, so
        the caller declares it as an extra variant.
        """
        primary_key = self._variant_key(self.sanitizers)
        primary_tag = self._build_variant_image(self.sanitizers)
        self._variant_images[primary_key] = primary_tag
        self._image_tag = primary_tag

        for variant in self.extra_variants:
            key = self._variant_key(variant)
            if key == primary_key:
                continue  # already built
            tag = self._build_variant_image(variant)
            self._variant_images[key] = tag

        return primary_tag

    def build_variant_images(self) -> dict[str, str]:
        """Build every declared variant. Returns {variant_key: image_tag}.

        Idempotent — variants that are already built (cached by content hash
        in the docker daemon) just get re-tagged without rebuilding.
        """
        self.build_image()
        return dict(self._variant_images)

    def _build_variant_image(self, sanitizers: list[str]) -> str:
        """Build one sandbox image for the given sanitizer combo."""
        client = self._get_client()
        dockerfile = self._render_dockerfile(sanitizers=sanitizers)
        tag = self._compute_tag(dockerfile, sanitizers=sanitizers)

        try:
            client.images.get(tag)
            logger.debug("Reusing sourcehunt sandbox image %s", tag)
            return tag
        except Exception:
            pass

        with tempfile.TemporaryDirectory(prefix="clearwing-sandbox-build-") as build_dir:
            dockerfile_path = os.path.join(build_dir, "Dockerfile")
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(dockerfile)

            logger.info(
                "Building sourcehunt sandbox image %s (sanitizers=%s)",
                tag,
                ",".join(sanitizers),
            )
            try:
                client.images.build(path=build_dir, tag=tag, rm=True, forcerm=True)
            except Exception as e:
                logger.warning("Sandbox image build failed", exc_info=True)
                raise RuntimeError(f"Failed to build sandbox image: {e}") from e

        return tag

    def spawn(
        self,
        session_id: str | None = None,
        memory_mb: int = 2048,
        timeout_seconds: int = 300,
        scratch_mount: bool = True,
        variant: list[str] | None = None,
    ) -> SandboxContainer:
        """Start a fresh container from one of the built variant images.

        The container has:
            - /workspace mounted read-only from self.repo_path
            - /scratch as a writable tmpfs (if scratch_mount=True)
            - network_mode="none"
            - memory and CPU caps
            - Sanitizer env vars computed for the selected variant

        Args:
            variant: Sanitizer combo for the spawned container. Defaults to
                self.sanitizers (the primary combo). Must have been built
                via `build_image()` or listed in `extra_variants`. Pass e.g.
                `variant=["msan"]` to spawn from the MSan image.

        Returns a SandboxContainer ready for exec/write/read.
        """
        if self._image_tag is None:
            self.build_image()

        chosen = list(variant) if variant is not None else list(self.sanitizers)
        key = self._variant_key(chosen)
        image_tag = self._variant_images.get(key)
        if image_tag is None:
            # Auto-build on demand if the caller asks for a variant that
            # wasn't declared up front.
            try:
                validate_sanitizer_combo(chosen)
            except ValueError:
                raise
            image_tag = self._build_variant_image(chosen)
            self._variant_images[key] = image_tag

        # Build mounts list — workspace ro, scratch rw via host tmpdir
        mounts: list[tuple[str, str, str]] = [
            (self.repo_path, "/workspace", "ro"),
        ]
        scratch_host_dir = None
        if scratch_mount:
            scratch_host_dir = tempfile.mkdtemp(prefix="clearwing-scratch-")
            mounts.append((scratch_host_dir, "/scratch", "rw"))

        # Compute the env for the CHOSEN variant, not the default recipe env
        env = compute_sanitizer_env(self.build_recipe, chosen)
        if session_id:
            env["CLEARWING_SESSION_ID"] = session_id
        # Mark the variant so hunter tools can introspect which image is running
        env["CLEARWING_SANITIZER_VARIANT"] = ",".join(chosen)

        cfg = SandboxConfig(
            image=image_tag,
            network_mode="none",
            mounts=mounts,
            memory_mb=memory_mb,
            cpu_shares=1024,
            timeout_seconds=timeout_seconds,
            env=env,
            working_dir="/workspace",
            name=None,
        )

        sb = SandboxContainer(cfg)
        sb.start()
        # Stash scratch host dir + variant on the container for cleanup / introspection
        sb._scratch_host_dir = scratch_host_dir  # type: ignore[attr-defined]
        sb._variant = chosen  # type: ignore[attr-defined]
        self._spawned.append(sb)
        return sb

    @property
    def available_variants(self) -> list[list[str]]:
        """Return every sanitizer combo that has a built image."""
        out: list[list[str]] = []
        for key in self._variant_images.keys():
            out.append(key.split("+") if key else [])
        return out

    def cleanup(self, remove_image: bool = False) -> None:
        """Stop all spawned containers and optionally remove the image."""
        for sb in self._spawned:
            try:
                sb.stop()
            except Exception:
                logger.debug("HunterSandbox cleanup container failed", exc_info=True)
            scratch = getattr(sb, "_scratch_host_dir", None)
            if scratch:
                try:
                    import shutil

                    shutil.rmtree(scratch, ignore_errors=True)
                except Exception:
                    pass
        self._spawned.clear()

        if remove_image and self._image_tag:
            try:
                client = self._get_client()
                client.images.remove(self._image_tag, force=True)
            except Exception:
                logger.debug("HunterSandbox image remove failed", exc_info=True)

    # --- Context manager ----------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    # --- Dockerfile rendering -----------------------------------------------

    def _render_dockerfile(self, sanitizers: list[str] | None = None) -> str:
        """Render the Dockerfile for a specific sanitizer variant.

        When `sanitizers` is None the primary combo is used — which is what
        the old single-variant build_image() called.
        """
        recipe = self.build_recipe
        variant = sanitizers if sanitizers is not None else self.sanitizers
        # Compute the env block for THIS variant (not the recipe's default)
        env_dict = compute_sanitizer_env(recipe, variant)

        apt_packages = " ".join(recipe.apt_packages + self.extra_packages)
        env_lines = []
        for k, v in env_dict.items():
            if " " in v or '"' in v:
                v_escaped = v.replace('"', '\\"')
                env_lines.append(f'ENV {k}="{v_escaped}"')
            else:
                env_lines.append(f"ENV {k}={v}")
        env_block = "\n".join(env_lines)

        if apt_packages.strip():
            apt_block = (
                "RUN apt-get update -qq && "
                f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {apt_packages} && "
                "rm -rf /var/lib/apt/lists/*"
            )
        else:
            apt_block = "# (no apt packages)"

        # Variant header makes the Dockerfile self-documenting so a human
        # inspecting the built image via `docker history` knows what's in it
        variant_header = f"# Sanitizer variant: {','.join(variant)}"
        dockerfile = f"""FROM {recipe.base_image}

{variant_header}

{apt_block}

{env_block}

WORKDIR /workspace

# /scratch is mounted at runtime as a writable tmpfs
RUN mkdir -p /scratch
"""
        return dockerfile

    def _compute_tag(
        self,
        dockerfile: str,
        sanitizers: list[str] | None = None,
    ) -> str:
        """Content-addressed image tag.

        The sanitizer list is baked into the hash so every variant gets a
        distinct tag — otherwise the daemon would cache-collide when the
        same repo is built with ASan+UBSan AND MSan variants.
        """
        variant = sanitizers if sanitizers is not None else self.sanitizers
        h = hashlib.sha256()
        h.update(dockerfile.encode("utf-8"))
        h.update(",".join(sorted(variant)).encode("utf-8"))
        h.update(",".join(sorted(self.extra_packages)).encode("utf-8"))
        digest = h.hexdigest()[:12]
        return f"{self.IMAGE_NAME_PREFIX}:{digest}"

    @staticmethod
    def _variant_key(sanitizers: list[str]) -> str:
        """Stable string key for the variant map."""
        return "+".join(sorted(sanitizers))

    @property
    def image_tag(self) -> str | None:
        return self._image_tag

    @property
    def primary_language(self) -> str:
        return self.build_recipe.primary_language
