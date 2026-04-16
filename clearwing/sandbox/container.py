"""Generic Docker sandbox container with no-network and read-only-mount defaults.

This is the isolation primitive used by HunterSandbox to run hunter agents
against a cloned source tree. Distinct from kali_docker_tool — there are no
approval gates, no apt-get install, no network access, and no host-volume
write access to the source tree.
"""

from __future__ import annotations

import io
import logging
import os
import tarfile
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Result from a single command executed inside a sandbox container."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    timed_out: bool = False


@dataclass
class SandboxConfig:
    """Isolation config for a SandboxContainer.

    Defaults are restrictive: no network, 2 GB RAM, 5 minute exec timeout.
    Override per use case (the hunter sandbox, e.g., wants writable /scratch
    and an explicit working_dir of /workspace).
    """

    image: str
    network_mode: str = "none"  # "none" | "bridge" | "host"
    mounts: list[tuple[str, str, str]] = field(default_factory=list)
    # (host_path, container_path, "ro"|"rw")
    memory_mb: int = 2048
    cpu_shares: int = 1024
    timeout_seconds: int = 300  # default per-exec timeout
    env: dict[str, str] = field(default_factory=dict)
    working_dir: str = "/workspace"
    name: str | None = None
    auto_remove: bool = True


class SandboxContainer:
    """Lifecycle-managed Docker container for sourcehunt agents.

    Usage:
        with SandboxContainer(config) as sb:
            sb.start()
            result = sb.exec(["ls", "-la"])
            sb.write_file("/scratch/poc.bin", b"\\x00\\x01\\x02")
            assert result.exit_code == 0

    The container is created on `start()` and removed on `stop()` /  __exit__.
    On any unexpected exception, cleanup() is called to prevent leaks.
    """

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._client = None
        self._container = None

    # --- Lifecycle ----------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            import docker  # local import — keeps the module importable without docker

            self._client = docker.from_env()
        return self._client

    def start(self) -> str:
        """Create and start the container. Returns the container id."""
        client = self._get_client()

        # Translate mounts into the docker SDK format
        volumes = {}
        for host_path, container_path, mode in self.config.mounts:
            volumes[host_path] = {"bind": container_path, "mode": mode}

        # Build kwargs
        kwargs = {
            "image": self.config.image,
            "command": "sleep infinity",
            "detach": True,
            "tty": True,
            "network_mode": self.config.network_mode,
            "mem_limit": f"{self.config.memory_mb}m",
            "cpu_shares": self.config.cpu_shares,
            "volumes": volumes,
            "environment": self.config.env,
            "working_dir": self.config.working_dir,
        }
        if self.config.name:
            kwargs["name"] = self.config.name
        # auto_remove conflicts with detached non-restart containers in some
        # docker versions; we'll handle removal manually in stop()

        self._container = client.containers.run(**kwargs)
        logger.debug("Sandbox container started: %s", self._container.short_id)
        return self._container.id

    def exec(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Run a command inside the container.

        Args:
            command: A list of argv strings (preferred) or a shell string.
                Lists are passed directly; strings are run via /bin/sh -c.
            timeout: Per-exec timeout in seconds. Falls back to config.
            env: Extra environment variables for this exec.
            workdir: Override the container working_dir for this exec only.

        Returns:
            ExecResult(exit_code, stdout, stderr, duration_seconds, timed_out).
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.exec called before start()")

        start_time = time.monotonic()
        effective_timeout = timeout or self.config.timeout_seconds

        # docker SDK exec_run does not enforce timeouts natively — we shell-wrap
        # the command in `timeout` if provided
        if isinstance(command, list):
            argv = command
        else:
            argv = ["/bin/sh", "-c", command]

        if effective_timeout > 0:
            # Prepend coreutils `timeout` if available; ignore errors otherwise
            argv = ["timeout", "--kill-after=2", str(effective_timeout)] + argv

        merged_env = dict(self.config.env)
        if env:
            merged_env.update(env)

        try:
            exec_result = self._container.exec_run(
                argv,
                tty=False,
                demux=True,
                environment=merged_env,
                workdir=workdir or self.config.working_dir,
            )
        except Exception as e:
            logger.warning("Sandbox exec failed", exc_info=True)
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_seconds=time.monotonic() - start_time,
                timed_out=False,
            )

        exit_code = exec_result.exit_code if exec_result.exit_code is not None else -1
        # `demux=True` returns (stdout_bytes, stderr_bytes); either may be None
        out_bytes, err_bytes = exec_result.output or (b"", b"")
        stdout = (out_bytes or b"").decode("utf-8", errors="replace")
        stderr = (err_bytes or b"").decode("utf-8", errors="replace")
        duration = time.monotonic() - start_time
        # `timeout` exits with 124 on timeout, 137 on SIGKILL
        timed_out = exit_code in (124, 137)
        return ExecResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
        )

    def write_file(self, container_path: str, content: bytes) -> None:
        """Write a file into the container at `container_path` (use /scratch).

        Implementation: tar the file in-memory and put_archive() it.
        Useful for dropping fuzz inputs / test cases that the hunter generated.
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.write_file called before start()")

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=os.path.basename(container_path))
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)
        target_dir = os.path.dirname(container_path) or "/"
        self._container.put_archive(target_dir, buf.read())

    def read_file(self, container_path: str) -> bytes:
        """Read a file from the container as bytes.

        Implementation: get_archive() returns a tar stream; we extract the
        single file from it.
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.read_file called before start()")

        stream, _stat = self._container.get_archive(container_path)
        buf = io.BytesIO(b"".join(stream))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f is not None:
                        return f.read()
        return b""

    def stop(self) -> None:
        """Stop and remove the container. Idempotent."""
        if self._container is None:
            return
        try:
            self._container.stop(timeout=5)
        except Exception:
            logger.debug("Sandbox container stop failed", exc_info=True)
        try:
            self._container.remove(force=True)
        except Exception:
            logger.debug("Sandbox container remove failed", exc_info=True)
        self._container = None

    # --- Context manager ----------------------------------------------------

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    # --- Properties ---------------------------------------------------------

    @property
    def container_id(self) -> str | None:
        return self._container.id if self._container else None

    @property
    def short_id(self) -> str | None:
        return self._container.short_id if self._container else None

    @property
    def is_running(self) -> bool:
        return self._container is not None
