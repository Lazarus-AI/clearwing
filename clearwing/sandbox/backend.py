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
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, field
from types import ModuleType
from typing import Protocol, runtime_checkable

from .container import ExecResult, SandboxConfig, SandboxContainer


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
    cpus: float = 0.0
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
_DOCKER_PROFILE_IMAGES: dict[str, str] = {
    "c-cpp": "gcc:12-bullseye",
    "rust": "rust:1-slim",
    "go": "golang:1.22",
    "python": "python:3.12-slim",
    "java": "eclipse-temurin:21",
    "node": "node:20-slim",
    "generic": "debian:11-slim",
}

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
    ) -> None:
        self._client_factory = client_factory
        self._process = process
        self._temporary_directory = temporary_directory
        self._profile_images = {**_DOCKER_PROFILE_IMAGES, **(profile_images or {})}
        self._feature_packages = {
            **_DOCKER_FEATURE_PACKAGES,
            **(feature_packages or {}),
        }

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

        image = self._environment_image(spec)
        # Resolve and validate every required capability even on a cache hit.
        # A stale or malicious cache key must not bypass the closed mapping.
        dockerfile = self._render_dockerfile(spec)
        docker_env = get_subprocess_env()
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
            process = self._process.Popen(
                [
                    "docker",
                    "build",
                    "--platform",
                    self._target_platform(spec.profile),
                    "-t",
                    image,
                    build_dir,
                ],
                stdout=self._process.PIPE,
                stderr=self._process.STDOUT,
                text=True,
                env=docker_env,
            )
            output_lines: list[str] = []
            assert process.stdout is not None
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    output_lines.append(line)
                    if on_output is not None:
                        on_output(line)
            try:
                process.wait(timeout=spec.timeout_seconds)
            except self._process.TimeoutExpired as error:
                process.kill()
                raise RuntimeError(
                    f"Sandbox environment preparation timed out after {spec.timeout_seconds}s"
                ) from error
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
        failure = " 2>/dev/null || true ;" if optional else " &&"
        return (
            "RUN apt-get update -qq && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            f"{package_list}{failure} rm -rf /var/lib/apt/lists/*"
        )

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
        return SandboxContainer(
            SandboxConfig(
                image=environment_ref,
                network_mode="none",
                mounts=config.mounts,
                memory_mb=config.memory_mb,
                cpu_shares=1024,
                cpus=config.cpus,
                timeout_seconds=config.timeout_seconds,
                env=config.env,
                working_dir=config.working_dir,
                pids_limit=config.pids_limit,
                security_opt=[f"seccomp={seccomp_json}"],
                cap_drop=["ALL"],
                cap_add=["SYS_PTRACE"],
                runtime="runsc" if config.isolation == "enhanced" else None,
            )
        )

    def release_environment(self, environment_ref: str) -> None:
        self._client().images.remove(environment_ref, force=True)


def sandbox_backend_from_env(
    docker_client_factory: Callable[[], object] | None = None,
    *,
    process: ModuleType = subprocess,
    temporary_directory: Callable[..., AbstractContextManager[str]] = tempfile.TemporaryDirectory,
) -> SandboxBackend:
    """Select the configured backend, defaulting to the original Docker path."""

    endpoint = os.environ.get("CLEARWING_SANDBOX_ENDPOINT", "").strip()
    if endpoint:
        from .rpc_backend import SocketSandboxBackend

        return SocketSandboxBackend(endpoint)
    return DockerSandboxBackend(
        docker_client_factory,
        process=process,
        temporary_directory=temporary_directory,
    )
