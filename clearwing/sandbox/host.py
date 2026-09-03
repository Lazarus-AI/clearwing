"""Host-exec sandbox: implement the advertised /workspace layout without Docker.

HunterSandbox's Docker image build can fail (missing buildx, nested Docker,
no daemon). The runner used to log "falling back to host mode" and then leave
``sandbox_factory`` unset, so deep-agent ``execute`` / ``read_file`` /
``write_file`` all returned ``no sandbox available`` while the prompt still
claimed a shell at ``/workspace``.

This container duck-types ``SandboxContainer`` for the hunt tools:

- ``cwd`` is the cloned repo on the host
- ``/workspace`` and ``/workspace/...`` map onto that repo
- ``/scratch`` maps onto a private temp dir

No network isolation and no sanitizers — this is a degraded but *honest*
execution world. Callers that cannot even install this must fail closed
(``invalid_harness``) instead of hunting blind.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .container import ExecResult

logger = logging.getLogger(__name__)

_WORKSPACE = "/workspace"
_SCRATCH = "/scratch"


class HostSandboxContainer:
    """Hunt-tool sandbox that execs on the host with Docker path aliases."""

    def __init__(self, repo_path: str, timeout_seconds: int = 600) -> None:
        self.repo_path = str(Path(repo_path).resolve())
        self.timeout_seconds = max(1, int(timeout_seconds))
        self._scratch: Path | None = None
        self._started = False
        self.scratch_host_dir: str | None = None
        self.variant: list[str] | None = None

    @property
    def workspace_root(self) -> str:
        """Path the model is told to use (matches Docker HunterSandbox)."""
        return _WORKSPACE

    @property
    def host_workspace(self) -> str:
        return self.repo_path

    @property
    def is_running(self) -> bool:
        return self._started

    @property
    def container_id(self) -> str | None:
        return "host" if self._started else None

    @property
    def short_id(self) -> str | None:
        return "host" if self._started else None

    def start(self) -> str:
        if not Path(self.repo_path).is_dir():
            raise RuntimeError(f"HostSandboxContainer: repo_path is not a directory: {self.repo_path}")
        self._scratch = Path(tempfile.mkdtemp(prefix="clearwing-host-scratch-"))
        self.scratch_host_dir = str(self._scratch)
        self._started = True
        logger.info(
            "HostSandboxContainer started repo=%s scratch=%s (maps %s → host tree)",
            self.repo_path,
            self._scratch,
            _WORKSPACE,
        )
        return "host"

    def stop(self) -> None:
        self._started = False
        if self._scratch is not None:
            shutil.rmtree(self._scratch, ignore_errors=True)
            self._scratch = None
            self.scratch_host_dir = None

    def __enter__(self) -> HostSandboxContainer:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.stop()
        return False

    def map_path(self, container_path: str) -> str:
        """Translate a Docker-layout path to a host path."""
        path = container_path.strip() or "."
        if path == _WORKSPACE or path.startswith(_WORKSPACE + "/"):
            rest = path[len(_WORKSPACE) :].lstrip("/")
            return str(Path(self.repo_path, rest)) if rest else self.repo_path
        if path == _SCRATCH or path.startswith(_SCRATCH + "/"):
            scratch = self._scratch or Path(self.repo_path)
            rest = path[len(_SCRATCH) :].lstrip("/")
            return str(scratch / rest) if rest else str(scratch)
        return path

    def _rewrite_text(self, text: str) -> str:
        scratch = str(self._scratch) if self._scratch is not None else self.repo_path
        # Longer prefix first so /workspace/foo is not double-touched.
        return text.replace(_WORKSPACE, self.repo_path).replace(_SCRATCH, scratch)

    def exec(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        if not self._started:
            raise RuntimeError("HostSandboxContainer.exec called before start()")

        start_time = time.monotonic()
        effective_timeout = timeout or self.timeout_seconds
        if isinstance(command, list):
            argv = [self._rewrite_text(part) for part in command]
        else:
            argv = ["/bin/sh", "-c", self._rewrite_text(command)]

        cwd = self.map_path(workdir) if workdir else self.repo_path
        merged = os.environ.copy()
        if env:
            merged.update(env)

        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=merged,
                capture_output=True,
                text=True,
                timeout=effective_timeout if effective_timeout > 0 else None,
            )
            return ExecResult(
                exit_code=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                duration_seconds=time.monotonic() - start_time,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            return ExecResult(
                exit_code=124,
                stdout=stdout,
                stderr=stderr or f"timed out after {effective_timeout}s",
                duration_seconds=time.monotonic() - start_time,
                timed_out=True,
            )
        except Exception as exc:
            logger.warning("HostSandboxContainer exec failed", exc_info=True)
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=time.monotonic() - start_time,
                timed_out=False,
            )

    def write_file(self, container_path: str, content: bytes) -> None:
        if not self._started:
            raise RuntimeError("HostSandboxContainer.write_file called before start()")
        if not container_path.startswith("/"):
            container_path = _WORKSPACE + "/" + container_path.lstrip("./")
        host_path = Path(self.map_path(container_path))
        host_path.parent.mkdir(parents=True, exist_ok=True)
        host_path.write_bytes(content)

    def copy_tree_into(
        self,
        host_path: str,
        container_path: str = _WORKSPACE,
    ) -> None:
        dest = Path(self.map_path(container_path))
        src = Path(host_path)
        if dest.resolve() == src.resolve():
            return
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest, dirs_exist_ok=True)


def host_sandbox_factory(repo_path: str, timeout_seconds: int = 600):
    """Return a ``sandbox_factory()`` that spawns a started host sandbox."""

    resolved = str(Path(repo_path).resolve())

    def _spawn(**kw) -> HostSandboxContainer:
        timeout = int(kw.get("timeout_seconds") or timeout_seconds)
        sandbox = HostSandboxContainer(resolved, timeout_seconds=timeout)
        sandbox.start()
        return sandbox

    return _spawn
