"""Pluggable execution boundary for SourceHunt sandboxes.

Backends are trusted infrastructure adapters.  Clearwing owns the SourceHunt
policy and build recipe; a backend owns the runtime-specific image, process,
filesystem, and cleanup operations used to enforce that policy.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from types import ModuleType
from typing import Protocol, runtime_checkable

from .container import ExecResult, SandboxConfig, SandboxContainer


@dataclass(frozen=True)
class SandboxImageBuild:
    """One content-addressed OCI image requested by ``HunterSandbox``."""

    image: str
    dockerfile: str
    platform: str
    timeout_seconds: int = 300


@runtime_checkable
class SandboxInstance(Protocol):
    """Runtime-neutral sandbox instance consumed by SourceHunt."""

    config: SandboxConfig
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
    def container_id(self) -> str | None: ...

    @property
    def short_id(self) -> str | None: ...

    @property
    def is_running(self) -> bool: ...


@runtime_checkable
class SandboxBackend(Protocol):
    """Provider contract used by ``HunterSandbox``.

    Implementations may use a local container daemon, a remote service, or a
    cluster API.  ``ensure_image`` returns ``True`` when the requested image
    was already cached and ``False`` when it was prepared during the call.
    """

    name: str

    def available_cpus(self) -> tuple[float | None, str]: ...

    def ensure_image(
        self,
        build: SandboxImageBuild,
        on_output: Callable[[str], None] | None = None,
    ) -> bool: ...

    def create(self, config: SandboxConfig) -> SandboxInstance: ...

    def remove_image(self, image: str) -> None: ...


class DockerSandboxBackend:
    """The original Docker implementation, now behind ``SandboxBackend``."""

    name = "docker"

    def __init__(
        self,
        client_factory: Callable[[], object] | None = None,
        *,
        process: ModuleType = subprocess,
        temporary_directory: Callable[
            ..., AbstractContextManager[str]
        ] = tempfile.TemporaryDirectory,
    ) -> None:
        self._client_factory = client_factory
        self._process = process
        self._temporary_directory = temporary_directory

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

    def ensure_image(
        self,
        build: SandboxImageBuild,
        on_output: Callable[[str], None] | None = None,
    ) -> bool:
        from .dind import get_subprocess_env

        docker_env = get_subprocess_env()
        check = self._process.run(
            ["docker", "image", "inspect", build.image],
            capture_output=True,
            timeout=10,
            env=docker_env,
        )
        if check.returncode == 0:
            return True

        with self._temporary_directory(prefix="clearwing-sandbox-build-") as build_dir:
            dockerfile_path = f"{build_dir}/Dockerfile"
            with open(dockerfile_path, "w", encoding="utf-8") as file:
                file.write(build.dockerfile)
            process = self._process.Popen(
                [
                    "docker",
                    "build",
                    "--platform",
                    build.platform,
                    "-t",
                    build.image,
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
                process.wait(timeout=build.timeout_seconds)
            except self._process.TimeoutExpired as error:
                process.kill()
                raise RuntimeError(
                    f"Sandbox image build timed out after {build.timeout_seconds}s"
                ) from error
            if process.returncode != 0:
                raise RuntimeError("\n".join(output_lines[-40:]))
        return False

    def create(self, config: SandboxConfig) -> SandboxContainer:
        return SandboxContainer(config)

    def remove_image(self, image: str) -> None:
        self._client().images.remove(image, force=True)


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
