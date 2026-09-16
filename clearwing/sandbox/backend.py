"""Pluggable execution boundary for SourceHunt sandboxes.

Backends are trusted infrastructure adapters. Clearwing describes the
toolchain and tools it needs; a backend owns runtime-specific images,
processes, filesystems, credentials, and cleanup.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, field
from types import ModuleType
from typing import Protocol, runtime_checkable

from .container import ExecResult, SandboxConfig, SandboxContainer
from .image_prestage import DEFAULT_BASE_IMAGE_TAGS


@dataclass(frozen=True)
class SandboxEnvironmentSpec:
    """Provider-neutral requirements for one prepared environment.

    ``profile`` and ``features`` are logical capability names. They are not
    image references or package-manager identifiers. ``cache_key`` identifies
    the complete request and lets a provider reuse an equivalent environment.
    """

    cache_key: str
    profile: str
    features: list[str] = field(default_factory=list)
    optional_features: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300


@dataclass(frozen=True)
class SandboxEnvironment:
    """An opaque provider-owned environment reference."""

    reference: str
    cached: bool


@dataclass
class SandboxRunConfig:
    """Isolation and resource policy for one sandbox instance."""

    policy: str = "sourcehunt"
    isolation: str = "default"
    mounts: list[tuple[str, str, str]] = field(default_factory=list)
    memory_mb: int = 2048
    cpus: float | None = None
    timeout_seconds: int = 300
    env: dict[str, str] = field(default_factory=dict)
    working_dir: str = "/workspace"
    pids_limit: int = 512


@runtime_checkable
class SandboxInstance(Protocol):
    """Runtime-neutral sandbox instance consumed by SourceHunt."""

    scratch_host_dir: str | None
    variant: list[str] | None
    workspace_baseline_commit: str | None

    def start(self) -> str: ...

    def exec(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult: ...

    def write_file(self, container_path: str, content: bytes) -> None: ...

    def read_file(self, container_path: str) -> bytes: ...

    def copy_tree_into(
        self,
        host_path: str,
        container_path: str = "/workspace",
    ) -> None: ...

    def stop(self) -> None: ...

    @property
    def config(self) -> SandboxRunConfig | SandboxConfig: ...

    @property
    def container_id(self) -> str | None: ...

    @property
    def short_id(self) -> str | None: ...

    @property
    def is_running(self) -> bool: ...


@runtime_checkable
class SandboxBackend(Protocol):
    """Provider contract used by ``HunterSandbox``.

    Providers may implement an environment with a cached OCI image, a
    writable rootfs overlay, a preconfigured pod, or another isolation
    primitive. Those details are deliberately absent from this interface.
    """

    name: str

    def available_cpus(self) -> tuple[float | None, str]: ...

    def ensure_environment(
        self,
        spec: SandboxEnvironmentSpec,
        on_output: Callable[[str], None] | None = None,
    ) -> SandboxEnvironment: ...

    def create(
        self,
        environment_ref: str,
        config: SandboxRunConfig,
    ) -> SandboxInstance: ...

    def release_environment(self, environment_ref: str) -> None: ...


# These implementation details belong to the zero-configuration Docker
# adapter. They never appear in SandboxEnvironmentSpec or on the RPC wire.
# The logical-profile → base-tag mapping is owned by image_prestage (the single
# source of truth), so offline pre-staging always covers exactly the profiles
# this backend can build. Operators pass digest-pinned refs via profile_images
# (see image_prestage.PinManifest.build_image_map) for offline-safe builds.
_DOCKER_PROFILE_IMAGES: dict[str, str] = dict(DEFAULT_BASE_IMAGE_TAGS)

_DOCKER_FEATURE_PACKAGES: dict[str, tuple[str, ...]] = {
    "source.search": ("ripgrep",),
    "debug.native": ("gdb",),
    "trace.syscalls": ("strace",),
    "trace.library-calls": ("ltrace",),
    "process.timeout": ("coreutils",),
    "trust.roots": ("ca-certificates",),
    "build.native": ("build-essential",),
    "build.make": (),
    "build.cmake": ("cmake",),
    "build.cargo": (),
    "build.go": (),
    "build.maven": ("maven",),
    "build.npm": (),
    "toolchain.native": ("gcc", "g++"),
    "toolchain.clang": ("clang",),
    "runtime.python": ("python3",),
    "debug.valgrind": ("valgrind",),
    "build.ccache": ("ccache",),
    "vcs.git": ("git",),
}


class DockerSandboxBackend:
    """Docker default that privately materializes logical environments."""

    name = "docker"

    def __init__(
        self,
        client_factory: Callable[[], object] | None = None,
        *,
        process: ModuleType = subprocess,
        temporary_directory: Callable[
            ..., AbstractContextManager[str]
        ] = tempfile.TemporaryDirectory,
        profile_images: Mapping[str, str] | None = None,
        feature_packages: Mapping[str, tuple[str, ...]] | None = None,
        enhanced_runtime: str = "runsc",
        offline_build: bool = False,
        extra_labels: Mapping[str, str] | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._process = process
        self._temporary_directory = temporary_directory
        self._profile_images = {**_DOCKER_PROFILE_IMAGES, **(profile_images or {})}
        # Extra container labels merged onto every sandbox this backend creates.
        # Used to tag a run's sandboxes (e.g. clearwing.recursive_run=<id>) so a
        # label-scoped watchdog kill (sandbox_kill) reaps only that run's
        # containers. Additive + default-None → existing behaviour unchanged.
        self._extra_labels = dict(extra_labels or {})
        # Closed-network hunting: never let `docker build` reach the registry to
        # revalidate a base manifest. Combined with digest-pinned profile_images
        # (from image_prestage) and a locally pre-staged base, builds run fully
        # offline and dodge Docker Hub's per-IP manifest rate limit.
        self._offline_build = offline_build
        self._feature_packages = {
            **_DOCKER_FEATURE_PACKAGES,
            **(feature_packages or {}),
        }
        # The concrete container runtime that implements "enhanced" isolation.
        # This is a Docker-adapter detail that never crosses the neutral
        # SandboxRunConfig (or the RPC boundary); operators select an installed
        # gVisor-compatible runtime (e.g. "runsc", "runsc-kvm", "kata-runtime")
        # and the adapter honors that exact name instead of assuming "runsc".
        self._enhanced_runtime = enhanced_runtime or "runsc"

    def _client(self):
        if self._client_factory is not None:
            return self._client_factory()
        from .dind import get_docker_client

        return get_docker_client()

    def available_cpus(self) -> tuple[float | None, str]:
        try:
            value = self._client().info().get("NCPU")
        except Exception:
            return None, "Docker daemon"
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value), "Docker daemon"
        return None, "Docker daemon"

    def ensure_environment(
        self,
        spec: SandboxEnvironmentSpec,
        on_output: Callable[[str], None] | None = None,
    ) -> SandboxEnvironment:
        from .dind import get_subprocess_env

        docker_env = get_subprocess_env()

        # Offline fast-path: on an air-gapped host the fat per-profile image
        # (base + every feature package, loaded from the bundle) is used
        # directly. It contains a superset of any spec's features, so no build
        # and no apt/registry contact is needed. We still validate the request
        # against the closed feature/profile mapping first (a stale or malicious
        # spec must not slip through), then confirm the fat image is present.
        if self._offline_build:
            from .image_prestage import offline_image_tag

            self._render_dockerfile(spec)  # validates profile + every feature
            fat = offline_image_tag(spec.profile)
            check_fat = self._process.run(
                ["docker", "image", "inspect", fat],
                capture_output=True,
                timeout=10,
                env=docker_env,
            )
            if check_fat.returncode == 0:
                return SandboxEnvironment(fat, cached=True)
            # Fall through: no fat image loaded; the digest-pinned base build
            # below runs with --pull=false (works if the base was pre-staged).

        image = self._environment_image(spec)
        # Resolve and validate every required capability even on a cache hit.
        # A stale or malicious cache key must not bypass the closed mapping.
        dockerfile = self._render_dockerfile(spec)
        check = self._process.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
            env=docker_env,
        )
        if check.returncode == 0:
            return SandboxEnvironment(image, cached=True)

        with self._temporary_directory(prefix="clearwing-sandbox-build-") as build_dir:
            dockerfile_path = f"{build_dir}/Dockerfile"
            with open(dockerfile_path, "w", encoding="utf-8") as file:
                file.write(dockerfile)
            build_cmd = [
                "docker",
                "build",
                "--platform",
                self._target_platform(spec.profile),
            ]
            if self._offline_build:
                # Use the local base image as-is; do not contact the registry to
                # pull or revalidate the FROM manifest.
                build_cmd.append("--pull=false")
            build_cmd += ["-t", image, build_dir]
            process = self._process.Popen(
                build_cmd,
                stdout=self._process.PIPE,
                stderr=self._process.STDOUT,
                text=True,
                env=docker_env,
            )
            output_lines: list[str] = []
            assert process.stdout is not None
            # A wall-clock watchdog bounds the *whole* build. Reading stdout to
            # EOF and only then calling wait(timeout=...) never bounds a build
            # that hangs with stdout still open (e.g. a stalled base-image
            # pull): the read blocks until the process exits, so wait() sees an
            # already-finished process. The timer kills the build after
            # timeout_seconds regardless of whether it is producing output.
            timed_out = threading.Event()

            def _kill_on_timeout() -> None:
                timed_out.set()
                try:
                    process.kill()
                except Exception:  # noqa: BLE001 - process may have already exited
                    pass

            watchdog = threading.Timer(spec.timeout_seconds, _kill_on_timeout)
            watchdog.start()
            try:
                for line in process.stdout:
                    line = line.rstrip()
                    if line:
                        output_lines.append(line)
                        if on_output is not None:
                            on_output(line)
                process.wait()
            finally:
                watchdog.cancel()
            if timed_out.is_set():
                raise RuntimeError(
                    f"Sandbox environment preparation timed out after {spec.timeout_seconds}s"
                )
            if process.returncode != 0:
                raise RuntimeError("\n".join(output_lines[-40:]))
        return SandboxEnvironment(image, cached=False)

    def _environment_image(self, spec: SandboxEnvironmentSpec) -> str:
        if not spec.cache_key:
            raise ValueError("sandbox environment cache_key must not be empty")
        # Include the entire request in the Docker cache identity. This avoids
        # trusting a caller-supplied cache key while preserving that key for
        # providers with their own content-addressing scheme.
        encoded = json.dumps(asdict(spec), sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(encoded).hexdigest()[:20]
        return f"clearwing-sourcehunt:{digest}"

    def _render_dockerfile(self, spec: SandboxEnvironmentSpec) -> str:
        base_image = self._profile_images.get(spec.profile)
        if base_image is None:
            raise ValueError(f"Docker sandbox does not support profile {spec.profile!r}")

        required_packages: list[str] = []
        for feature in spec.features:
            packages = self._feature_packages.get(feature)
            if packages is None:
                raise ValueError(f"Docker sandbox does not support feature {feature!r}")
            required_packages.extend(packages)

        optional_packages: list[str] = []
        for feature in spec.optional_features:
            optional_packages.extend(self._feature_packages.get(feature, ()))

        required_packages = list(dict.fromkeys(required_packages))
        optional_packages = list(dict.fromkeys(optional_packages))
        required_block = self._apt_install_block(required_packages, optional=False)
        optional_block = self._apt_install_block(optional_packages, optional=True)
        sanitizer_comment = ",".join(spec.sanitizers) or "none"
        return f"""FROM {base_image}

# Logical profile: {spec.profile}
# Sanitizer requirements: {sanitizer_comment}

{required_block}

{optional_block}

WORKDIR /workspace
RUN mkdir -p /scratch
"""

    # Feature classes whose packages may be absent on a given base distro
    # (e.g. ltrace is not in Debian 11 bullseye) or are pure conveniences.
    # For the fat offline image these are best-effort: a missing one is skipped
    # rather than failing the whole build. Core build/toolchain/runtime/vcs
    # packages remain required.
    _OFFLINE_OPTIONAL_FEATURES = frozenset(
        {"debug.native", "debug.valgrind", "trace.syscalls", "trace.library-calls"}
    )

    def _all_feature_packages(self) -> list[str]:
        """Union of every feature's apt packages — the fat-image package set."""
        seen: list[str] = []
        for packages in self._feature_packages.values():
            for pkg in packages:
                if pkg not in seen:
                    seen.append(pkg)
        return seen

    def _offline_package_split(self) -> tuple[list[str], list[str]]:
        """(required, optional) apt packages for the fat offline image."""
        optional: list[str] = []
        for feature in self._OFFLINE_OPTIONAL_FEATURES:
            optional.extend(self._feature_packages.get(feature, ()))
        optional = list(dict.fromkeys(optional))
        required = [p for p in self._all_feature_packages() if p not in optional]
        return required, optional

    def render_offline_dockerfile(self, profile: str, base_ref: str) -> str:
        """Fat per-profile Dockerfile: base + every feature package.

        Built on a connected host and shipped in the offline bundle; on the
        air-gapped host the resulting image satisfies any spec's feature subset
        without apt or a registry. Trace/debug extras are installed best-effort
        so a package absent on a particular base distro (e.g. ltrace on Debian
        11) is skipped instead of failing the whole image.
        """
        if profile not in self._profile_images:
            raise ValueError(f"Docker sandbox does not support profile {profile!r}")
        required, optional = self._offline_package_split()
        required_block = self._apt_install_block(required, optional=False)
        optional_block = self._offline_besteffort_block(optional)
        return f"""FROM {base_ref}

# Fat offline sandbox image for logical profile: {profile}
# Core toolchain is required; trace/debug extras are best-effort.

{required_block}

{optional_block}

WORKDIR /workspace
RUN mkdir -p /scratch
"""

    @staticmethod
    def _offline_besteffort_block(packages: list[str]) -> str:
        """Install each package independently; never fail the build on a miss.

        A per-package loop (not one apt call) so one unavailable package on a
        given base distro does not abort the rest.
        """
        if not packages:
            return "# (no optional features)"
        pkg_list = " ".join(packages)
        prep = (
            "{ [ -f /etc/apt/sources.list ] && sed -ri '/-security/d' "
            "/etc/apt/sources.list; } || true"
        )
        install = (
            "apt-get update -o Acquire::Retries=3 -qq || true; "
            f"for p in {pkg_list}; do "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            '-o Acquire::Retries=3 "$p" || echo "skip unavailable package: $p" >&2; '
            "done; rm -rf /var/lib/apt/lists/*"
        )
        return f"RUN {prep}; {install}"

    def build_offline_image(
        self,
        profile: str,
        base_ref: str,
        *,
        on_output: Callable[[str], None] | None = None,
        timeout_seconds: int = 3600,
    ) -> str:
        """Build and tag the fat per-profile image; return its tag.

        Intended for the connected build host (`clearwing prestage export`).
        Uses the digest-pinned ``base_ref`` so the fat image is reproducible.
        """
        from .dind import get_subprocess_env
        from .image_prestage import offline_image_tag

        tag = offline_image_tag(profile)
        dockerfile = self.render_offline_dockerfile(profile, base_ref)
        docker_env = get_subprocess_env()
        with self._temporary_directory(prefix="clearwing-offline-build-") as build_dir:
            with open(f"{build_dir}/Dockerfile", "w", encoding="utf-8") as fh:
                fh.write(dockerfile)
            proc = self._process.Popen(
                [
                    "docker",
                    "build",
                    "--platform",
                    self._target_platform(profile),
                    "-t",
                    tag,
                    build_dir,
                ],
                stdout=self._process.PIPE,
                stderr=self._process.STDOUT,
                text=True,
                env=docker_env,
            )
            assert proc.stdout is not None
            timed_out = threading.Event()

            def _kill() -> None:
                timed_out.set()
                try:
                    proc.kill()
                except Exception:
                    pass

            watchdog = threading.Timer(timeout_seconds, _kill)
            watchdog.start()
            lines: list[str] = []
            try:
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        lines.append(line)
                        if on_output is not None:
                            on_output(line)
                proc.wait()
            finally:
                watchdog.cancel()
            if timed_out.is_set():
                raise RuntimeError(f"Offline image build for {profile} timed out")
            if proc.returncode != 0:
                raise RuntimeError("\n".join(lines[-40:]))
        return tag

    @staticmethod
    def _target_platform(profile: str) -> str:
        if profile == "c-cpp" and platform.machine() in ("arm64", "aarch64"):
            return "linux/arm64"
        return "linux/amd64"

    @staticmethod
    def _apt_install_block(packages: list[str], *, optional: bool) -> str:
        if not packages:
            return "# (no optional features)" if optional else "# (no additional features)"
        package_list = " ".join(packages)
        # Debian security pockets rotate point releases and delete the superseded
        # .debs, so fetching e.g. `libc-dev-bin_2.31-13+deb11uN` 404s until the
        # mirror index catches up — persistently enough that retrying `apt-get
        # update` alone does not clear it within a CI window. Drop the -security
        # source so apt installs the base-archive version instead (a throwaway
        # build sandbox does not need the security-patched build tools), then
        # still retry to ride out transient per-file fetch errors. Kept as one
        # RUN layer; the base image (asserted elsewhere) is unchanged.
        prep = "{ [ -f /etc/apt/sources.list ] && sed -ri '/-security/d' /etc/apt/sources.list; } || true"
        install = (
            "ok=0; for attempt in 1 2 3; do "
            "apt-get update -o Acquire::Retries=3 -qq && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            f"-o Acquire::Retries=3 {package_list} "
            '&& { ok=1; break; } || { echo "apt attempt $attempt failed; retrying" >&2; sleep 5; }; '
            "done; rm -rf /var/lib/apt/lists/*"
        )
        if optional:
            # Optional features must never fail the build.
            return f"RUN {prep}; {install}"
        # Required packages: fail the build only if every retry is exhausted.
        return f'RUN {prep}; {install}; [ "$ok" = 1 ]'

    def create(
        self,
        environment_ref: str,
        config: SandboxRunConfig,
    ) -> SandboxContainer:
        if config.policy != "sourcehunt":
            raise ValueError(f"Docker sandbox does not support policy {config.policy!r}")
        if config.isolation not in {"default", "enhanced"}:
            raise ValueError(
                f"Docker sandbox does not support isolation level {config.isolation!r}"
            )

        from .seccomp_profiles import get_seccomp_profile

        seccomp_json = json.dumps(get_seccomp_profile("hunter"))
        labels = {"managed-by": "clearwing", **self._extra_labels}
        return SandboxContainer(
            SandboxConfig(
                image=environment_ref,
                labels=labels,
                network_mode="none",
                mounts=config.mounts,
                memory_mb=config.memory_mb,
                cpu_shares=1024,
                # The provider-neutral contract uses None for an unspecified
                # limit. Docker's existing adapter represents that as 0.0.
                cpus=0.0 if config.cpus is None else config.cpus,
                timeout_seconds=config.timeout_seconds,
                env=config.env,
                working_dir=config.working_dir,
                pids_limit=config.pids_limit,
                security_opt=[f"seccomp={seccomp_json}"],
                cap_drop=["ALL"],
                cap_add=["SYS_PTRACE"],
                runtime=self._enhanced_runtime if config.isolation == "enhanced" else None,
            )
        )

    def release_environment(self, environment_ref: str) -> None:
        self._client().images.remove(environment_ref, force=True)


def sandbox_backend_from_env(
    docker_client_factory: Callable[[], object] | None = None,
    *,
    process: ModuleType = subprocess,
    temporary_directory: Callable[..., AbstractContextManager[str]] = tempfile.TemporaryDirectory,
    enhanced_runtime: str = "runsc",
) -> SandboxBackend:
    """Select the configured backend, defaulting to the original Docker path.

    ``enhanced_runtime`` is the operator-selected container runtime that
    implements "enhanced" isolation for the Docker adapter. It is deliberately
    a Docker-only concern: a remote RPC supervisor decides for itself how to
    realize "enhanced", so the runtime name never crosses the RPC boundary.
    """

    endpoint = os.environ.get("CLEARWING_SANDBOX_ENDPOINT", "").strip()
    if endpoint:
        from .rpc_backend import SocketSandboxBackend

        return SocketSandboxBackend(endpoint)
    provider = os.environ.get("CLEARWING_SANDBOX_BACKEND", "docker").strip().lower()
    if provider == "kubernetes":
        from .kubernetes import KubernetesSandboxBackend

        return KubernetesSandboxBackend()
    if provider != "docker":
        raise ValueError(f"unknown sandbox backend {provider!r}")
    # Closed-network mode: when CLEARWING_SANDBOX_OFFLINE is set, build from the
    # digest-pinned base images produced by `clearwing prestage` and never let
    # `docker build` reach the registry. If no pins have been staged the map is
    # empty and the backend falls back to the default tags (which will fail
    # offline — that is the operator's signal to run prestage first).
    offline = os.environ.get("CLEARWING_SANDBOX_OFFLINE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    profile_images: Mapping[str, str] | None = None
    if offline:
        from .image_prestage import ImagePinStore

        profile_images = {
            p: ref
            for p, ref in ImagePinStore().load().build_image_map().items()
            if "@sha256:" in ref  # only trust digest-pinned refs offline
        }
    # Optional per-run container labels ("k=v,k2=v2"), e.g. the recursive flow's
    # clearwing.recursive_run=<id> so a label-scoped watchdog kill reaps only
    # that run's sandboxes. Absent → no extra labels (unchanged behaviour).
    extra_labels = _parse_label_env(os.environ.get("CLEARWING_SANDBOX_EXTRA_LABELS", ""))
    return DockerSandboxBackend(
        docker_client_factory,
        process=process,
        temporary_directory=temporary_directory,
        enhanced_runtime=enhanced_runtime,
        profile_images=profile_images,
        offline_build=offline,
        extra_labels=extra_labels or None,
    )


def _parse_label_env(raw: str) -> dict[str, str]:
    """Parse a ``k=v,k2=v2`` label string; ignore malformed pairs."""
    labels: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            k = k.strip()
            if k:
                labels[k] = v.strip()
    return labels
