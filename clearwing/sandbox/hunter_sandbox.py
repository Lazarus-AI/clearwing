"""HunterSandbox: prepares and manages isolated SourceHunt environments.

Lifecycle:
    1. SourceHuntRunner instantiates HunterSandbox(repo_path, languages).
    2. .prepare_environment() asks the configured backend for the required
       toolchain, tools, and sanitizer support.
    3. Each hunter agent calls .spawn(session_id) → SandboxInstance with
       /workspace mounted read-only and /scratch as a tmpfs scratch dir.
    4. .cleanup() removes spawned instances and optionally releases prepared
       environments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import shutil
import subprocess
import tempfile
import time

from clearwing.core.events import EventBus

from .backend import (
    DockerSandboxBackend,
    SandboxBackend,
    SandboxEnvironmentSpec,
    SandboxInstance,
    SandboxRunConfig,
    sandbox_backend_from_env,
)
from .builders import (
    BuildRecipe,
    BuildSystemDetector,
    compute_sanitizer_env,
    validate_sanitizer_combo,
)

logger = logging.getLogger(__name__)


class HunterSandbox:
    """Per-hunt environment and sandbox-instance manager.

    Requests a logical toolchain environment with the project's build tools
    and sanitizer support, then spawns no-network instances that mount the
    source tree read-only. Providers decide how environments are materialized.
    """

    IMAGE_NAME_PREFIX = "clearwing-sourcehunt"
    AUTO_CPU_CAP = 3.0
    MIN_CPU_LIMIT = 0.5

    # Default extra variants to prepare alongside the primary. These let one
    # HunterSandbox own both ASan+UBSan and MSan environments.
    DEFAULT_EXTRA_VARIANTS: tuple[tuple[str, ...], ...] = ()

    DEEP_AGENT_FEATURES = [
        "runtime.python",
        "debug.valgrind",
        "build.ccache",
        "vcs.git",
    ]
    # Library-call tracing is useful but unavailable on some architectures.
    DEEP_AGENT_OPTIONAL_FEATURES = ["trace.library-calls"]

    def __init__(
        self,
        repo_path: str,
        languages: list[str] | None = None,
        sanitizers: list[str] | None = None,  # primary combo
        extra_variants: list[list[str]] | None = None,  # e.g. [["msan"]]
        extra_features: list[str] | None = None,
        build_recipe: BuildRecipe | None = None,
        deep_agent_mode: bool = False,
        default_cpus: float | None = None,
        backend: SandboxBackend | None = None,
        gvisor_runtime: str | None = None,
    ):
        self._validate_cpu_limit(default_cpus, name="default_cpus")
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
        self.extra_features = list(extra_features or [])
        self._optional_features: list[str] = []
        self.deep_agent_mode = deep_agent_mode
        if deep_agent_mode:
            for feature in self.DEEP_AGENT_FEATURES:
                if feature not in self.extra_features:
                    self.extra_features.append(feature)
            self._optional_features.extend(self.DEEP_AGENT_OPTIONAL_FEATURES)
        self.build_recipe = build_recipe or BuildSystemDetector.detect(self.repo_path)
        self._client = None
        # The operator-selected gVisor-compatible runtime that implements
        # "enhanced" isolation. Preserved as the exact name so spawn() honors
        # e.g. "kata-runtime" instead of silently falling back to plain runc.
        self.gvisor_runtime = gvisor_runtime
        self.backend = (
            backend
            if backend is not None
            else sandbox_backend_from_env(
                self._get_client,
                process=subprocess,
                temporary_directory=tempfile.TemporaryDirectory,
                enhanced_runtime=gvisor_runtime or "runsc",
            )
        )
        self._environment_ref: str | None = None
        self._variant_environments: dict[str, str] = {}
        # Compatibility aliases for callers that predate pluggable backends.
        self._image_tag: str | None = None
        self._variant_images = self._variant_environments
        self._spawned: list[SandboxInstance] = []
        self._default_cpus = None if default_cpus is None else float(default_cpus)
        self._resolved_default_cpus: float | None = None
        self._available_cpus: float | None = None
        self._cpu_count_source = ""

    @staticmethod
    def _validate_cpu_limit(cpus: float | None, *, name: str = "cpus") -> None:
        if cpus is None:
            return
        if not math.isfinite(cpus) or cpus < 0:
            raise ValueError(f"{name} must be a finite number greater than or equal to 0")

    @property
    def available_cpus(self) -> float:
        """Logical CPUs available to the Docker daemon, with portable fallbacks."""
        if self._available_cpus is None:
            self._available_cpus, self._cpu_count_source = self._detect_available_cpus()
        return self._available_cpus

    @property
    def default_cpu_limit(self) -> float:
        """Resolve the configured or automatic per-container CPU limit."""
        if self._default_cpus is not None:
            return self._default_cpus
        if self._resolved_default_cpus is None:
            available = self.available_cpus
            if available <= 1.0:
                limit = self.MIN_CPU_LIMIT
            else:
                limit = min(self.AUTO_CPU_CAP, available - 1.0)
            self._resolved_default_cpus = limit
            logger.info(
                "HunterSandbox CPU limit auto-selected: %.2f (%s reports %.2f logical CPUs)",
                limit,
                self._cpu_count_source,
                available,
            )
        return self._resolved_default_cpus

    def _detect_available_cpus(self) -> tuple[float, str]:
        try:
            daemon_cpus, source = self.backend.available_cpus()
            if (
                isinstance(daemon_cpus, (int, float))
                and not isinstance(daemon_cpus, bool)
                and math.isfinite(daemon_cpus)
                and daemon_cpus > 0
            ):
                return float(daemon_cpus), source
        except Exception:
            logger.debug("Could not query sandbox backend CPU count", exc_info=True)

        try:
            get_affinity = getattr(os, "sched_getaffinity", None)
            affinity = get_affinity(0) if get_affinity is not None else None
            if affinity:
                return float(len(affinity)), "process affinity"
        except OSError:
            pass

        system_cpus = os.cpu_count()
        if system_cpus is not None and system_cpus > 0:
            return float(system_cpus), "host"
        return 1.0, "fallback"

    def _resolve_cpu_limit(self, cpus: float | None) -> float:
        if cpus is None:
            return self.default_cpu_limit
        self._validate_cpu_limit(cpus)
        return float(cpus)

    # --- Lifecycle ----------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            from .dind import get_docker_client

            self._client = get_docker_client()
        return self._client

    def prepare_environment(self) -> str:
        """Prepare the primary environment and return its opaque reference.

        Also prepares declared ``extra_variants`` so later ``spawn`` calls can
        select them without another preparation pass. MSan is the motivating
        case: it cannot coexist with ASan in a single instrumented binary.
        """
        primary_key = self._variant_key(self.sanitizers)
        primary_ref = self._prepare_variant_environment(self.sanitizers)
        self._variant_environments[primary_key] = primary_ref
        self._environment_ref = primary_ref
        self._image_tag = primary_ref

        for variant in self.extra_variants:
            key = self._variant_key(variant)
            if key == primary_key:
                continue
            environment_ref = self._prepare_variant_environment(variant)
            self._variant_environments[key] = environment_ref

        return primary_ref

    def build_image(self) -> str:
        """Compatibility alias for :meth:`prepare_environment`."""

        return self.prepare_environment()

    def prepare_variant_environments(self) -> dict[str, str]:
        """Prepare every declared variant and return opaque references.

        Providers may satisfy an equivalent request from their own cache.
        """
        self.prepare_environment()
        return dict(self._variant_environments)

    def build_variant_images(self) -> dict[str, str]:
        """Compatibility alias for :meth:`prepare_variant_environments`."""

        return self.prepare_variant_environments()

    def _environment_spec(self, sanitizers: list[str]) -> SandboxEnvironmentSpec:
        environment = compute_sanitizer_env(self.build_recipe, sanitizers)
        features = list(dict.fromkeys([*self.build_recipe.features, *self.extra_features]))
        optional_features = list(dict.fromkeys(self._optional_features))
        identity = {
            "profile": self.build_recipe.profile,
            "features": sorted(features),
            "optional_features": sorted(optional_features),
            "sanitizers": sorted(sanitizers),
            "environment": environment,
        }
        cache_key = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return SandboxEnvironmentSpec(
            cache_key=cache_key,
            profile=self.build_recipe.profile,
            features=features,
            optional_features=optional_features,
            sanitizers=list(sanitizers),
            environment=environment,
        )

    def _prepare_variant_environment(self, sanitizers: list[str]) -> str:
        """Prepare one logical environment for a sanitizer combination."""

        spec = self._environment_spec(sanitizers)
        san_str = ",".join(sanitizers) if sanitizers else "none"
        logger.info(
            "Preparing SourceHunt environment %s (backend=%s, profile=%s, sanitizers=%s)",
            spec.cache_key[:16],
            self.backend.name,
            spec.profile,
            san_str,
        )
        EventBus().emit_message(
            f"sandbox preparing  backend={self.backend.name}  "
            f"profile={spec.profile}  lang={self.build_recipe.primary_language}"
            f"  sanitizers={san_str}  key={spec.cache_key[:16]}",
            "info",
        )
        _t = time.monotonic()
        try:
            environment = self.backend.ensure_environment(
                spec,
                on_output=lambda line: EventBus().emit_message(f"sandbox | {line}", "debug"),
            )
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning("Sandbox environment preparation failed: %s", e)
            logger.debug("Sandbox environment preparation failed", exc_info=True)
            raise RuntimeError(f"Failed to prepare sandbox environment: {e}") from e
        if environment.cached:
            logger.debug("Reusing SourceHunt environment %s", environment.reference)
            EventBus().emit_message(f"sandbox cached  key={spec.cache_key[:16]}", "info")
            return environment.reference
        logger.debug(
            "Prepared SourceHunt environment %s in %.2fs",
            environment.reference,
            time.monotonic() - _t,
        )
        EventBus().emit_message(f"sandbox ready  key={spec.cache_key[:16]}", "info")
        return environment.reference

    def _build_variant_image(self, sanitizers: list[str]) -> str:
        """Compatibility alias for the pre-provider image implementation."""

        return self._prepare_variant_environment(sanitizers)

    def spawn(
        self,
        session_id: str | None = None,
        memory_mb: int = 2048,
        timeout_seconds: int = 300,
        scratch_mount: bool = True,
        variant: list[str] | None = None,
        writable_workspace: bool = False,
        cpus: float | None = None,
        runtime: str | None = None,
    ) -> SandboxInstance:
        """Start a fresh sandbox from one of the prepared environments.

        The container has:
            - /workspace mounted read-only from self.repo_path (default),
              or a writable copy of the source tree (writable_workspace=True)
            - /scratch as a writable tmpfs (if scratch_mount=True)
            - network_mode="none"
            - memory and CPU caps
            - Sanitizer env vars computed for the selected variant

        Args:
            variant: Sanitizer combo for the spawned container. Defaults to
                self.sanitizers (the primary combo). Must have been built
                via ``prepare_environment()`` or listed in ``extra_variants``.
                Pass e.g. ``variant=["msan"]`` to select the MSan environment.
            writable_workspace: If True, copy the source tree into the
                container instead of bind-mounting it read-only. The agent
                can then modify source, recompile, and use git diff.
            cpus: CPU limit. ``None`` uses the manager default, while 0
                explicitly disables the limit. Passed to SandboxConfig.

        Returns a SandboxInstance ready for exec/write/read.
        """
        if self._environment_ref is None:
            self.prepare_environment()

        chosen = list(variant) if variant is not None else list(self.sanitizers)
        key = self._variant_key(chosen)
        environment_ref = self._variant_environments.get(key)
        if environment_ref is None:
            # Prepare on demand if the caller asks for a variant that
            # wasn't declared up front.
            try:
                validate_sanitizer_combo(chosen)
            except ValueError:
                raise
            environment_ref = self._prepare_variant_environment(chosen)
            self._variant_environments[key] = environment_ref

        # Build mounts list
        mounts: list[tuple[str, str, str]] = []
        if not writable_workspace:
            mounts.append((self.repo_path, "/workspace", "ro"))
        scratch_host_dir = None
        if scratch_mount:
            scratch_host_dir = tempfile.mkdtemp(prefix="clearwing-scratch-")
            mounts.append((scratch_host_dir, "/scratch", "rw"))

        # Compute the env for the CHOSEN variant, not the default recipe env
        env = compute_sanitizer_env(self.build_recipe, chosen)
        if session_id:
            env["CLEARWING_SESSION_ID"] = session_id
        # Mark the variant so hunter tools can introspect the active instrumentation.
        env["CLEARWING_SANITIZER_VARIANT"] = ",".join(chosen)

        resolved_cpus = self._resolve_cpu_limit(cpus)
        cfg = SandboxRunConfig(
            policy="sourcehunt",
            isolation="enhanced" if runtime else "default",
            mounts=mounts,
            memory_mb=memory_mb,
            cpus=resolved_cpus,
            timeout_seconds=timeout_seconds,
            env=env,
            working_dir="/workspace",
            pids_limit=512,
        )

        sb = self.backend.create(environment_ref, cfg)
        _t = time.monotonic()
        sb.start()
        logger.debug(
            "Sandbox instance started environment=%s in %.2fs",
            environment_ref,
            time.monotonic() - _t,
        )

        if writable_workspace:
            sb.copy_tree_into(self.repo_path, "/workspace")
            try:
                baseline = sb.exec(
                    "cd /workspace && "
                    "rm -rf /workspace/.git && "
                    "find . -name .git -type f -delete && "
                    "git init -q && git add -A && "
                    "git -c user.name=clearwing -c user.email=clearwing@localhost "
                    "commit -m initial -q && git rev-parse HEAD",
                    timeout=120,
                )
                if baseline.exit_code != 0:
                    raise RuntimeError(baseline.stderr or "git baseline creation failed")
                sb.workspace_baseline_commit = baseline.stdout.strip()
            except Exception:
                logger.warning("git init in writable workspace failed", exc_info=True)

        # Stash scratch host dir + variant on the container for cleanup / introspection
        sb.scratch_host_dir = scratch_host_dir
        sb.variant = chosen
        self._spawned.append(sb)
        return sb

    @property
    def available_variants(self) -> list[list[str]]:
        """Return every sanitizer combo that has a prepared environment."""
        out: list[list[str]] = []
        for key in self._variant_environments.keys():
            out.append(key.split("+") if key else [])
        return out

    def cleanup(self, remove_image: bool = False) -> None:
        """Stop instances and optionally release their environments.

        ``remove_image`` is retained as a compatibility name. A non-Docker
        provider may release an overlay, pod template, or another cached
        substrate instead of an OCI image.
        """
        for sb in self._spawned:
            try:
                sb.stop()
            except Exception:
                logger.debug("HunterSandbox cleanup container failed", exc_info=True)
            scratch = sb.scratch_host_dir
            if scratch:
                try:
                    shutil.rmtree(scratch, ignore_errors=True)
                except Exception:
                    pass
        self._spawned.clear()

        if remove_image:
            for environment_ref in set(self._variant_environments.values()):
                try:
                    self.backend.release_environment(environment_ref)
                except Exception:
                    logger.debug("HunterSandbox environment release failed", exc_info=True)

    # --- Context manager ----------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    # --- Compatibility helpers for the original Docker-only API -------------

    def _render_dockerfile(self, sanitizers: list[str] | None = None) -> str:
        """Render the default Docker adapter's private materialization."""

        variant = sanitizers if sanitizers is not None else self.sanitizers
        docker_backend = (
            self.backend
            if isinstance(self.backend, DockerSandboxBackend)
            else DockerSandboxBackend()
        )
        return docker_backend._render_dockerfile(self._environment_spec(variant))

    def _compute_tag(
        self,
        dockerfile: str,
        sanitizers: list[str] | None = None,
    ) -> str:
        """Return the default Docker adapter's content-addressed tag."""

        del dockerfile  # Dockerfile content is no longer the logical identity.
        variant = sanitizers if sanitizers is not None else self.sanitizers
        docker_backend = (
            self.backend
            if isinstance(self.backend, DockerSandboxBackend)
            else DockerSandboxBackend()
        )
        return docker_backend._environment_image(self._environment_spec(variant))

    @staticmethod
    def _variant_key(sanitizers: list[str]) -> str:
        """Stable string key for the variant map."""
        return "+".join(sorted(sanitizers))

    @property
    def image_tag(self) -> str | None:
        return self._image_tag

    @property
    def environment_ref(self) -> str | None:
        return self._environment_ref

    @property
    def primary_language(self) -> str:
        return self.build_recipe.primary_language
