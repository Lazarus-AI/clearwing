"""Kubernetes-backed SandboxContainer implementation.

Runs sandbox workloads as Kubernetes Pods instead of local Docker
containers. Implements the same interface as SandboxContainer so hunter
agents are backend-agnostic.

Requires: CLEARWING_SANDBOX_BACKEND=kubernetes
"""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import time
import uuid

from .container import ExecResult, SandboxConfig, SandboxContainer
from .kube_client import core_v1_api, namespace, parent_pod_owner_reference

logger = logging.getLogger(__name__)

_POD_STARTUP_TIMEOUT_SECONDS = 120
# Hard ceiling multiplier — activeDeadlineSeconds is set to this factor
# times the configured exec timeout so a zombie pod self-terminates even
# if our process crashes.
_DEADLINE_MULTIPLIER = 3
_MIN_DEADLINE_SECONDS = 900  # 15 minutes floor


class KubeSandboxContainer(SandboxContainer):
    """SandboxContainer backed by a Kubernetes Pod.

    Creates a long-running Pod (not a Job) so we can exec into it multiple
    times, matching the Docker container lifecycle model.
    """

    def __init__(self, config: SandboxConfig):
        # Don't call super().__init__ — we override the full lifecycle
        self._config = config
        self._pod_name: str | None = None
        self._namespace = namespace()
        self._started = False
        # Public attributes expected by HunterSandbox
        self.scratch_host_dir: str | None = None
        self.variant: list[str] = []

    @property
    def container_id(self) -> str:
        return self._pod_name or ""

    @property
    def short_id(self) -> str:
        return (self._pod_name or "")[:12]

    @property
    def is_running(self) -> bool:
        if not self._pod_name:
            return False
        try:
            pod = core_v1_api().read_namespaced_pod_status(self._pod_name, self._namespace)
            return pod.status.phase == "Running"
        except Exception:
            return False

    def start(self) -> str:
        """Create and start a Pod matching the SandboxConfig."""
        from kubernetes import client

        api = core_v1_api()
        cfg = self._config
        pod_id = uuid.uuid4().hex[:8]
        self._pod_name = f"clearwing-sandbox-{pod_id}"

        # Build env vars
        env_vars = [
            client.V1EnvVar(name=k, value=v) for k, v in cfg.env.items()
        ]

        # Resource limits
        resources = client.V1ResourceRequirements(
            limits={"memory": f"{cfg.memory_mb}Mi"},
            requests={"memory": f"{min(cfg.memory_mb, 512)}Mi"},
        )
        if cfg.cpus > 0:
            resources.limits["cpu"] = str(cfg.cpus)
            resources.requests["cpu"] = str(min(cfg.cpus, 0.5))

        # Security context matching Docker config
        security_context = client.V1SecurityContext(
            run_as_non_root=False,
            read_only_root_filesystem=cfg.read_only_rootfs,
            capabilities=client.V1Capabilities(
                drop=cfg.cap_drop,
                add=cfg.cap_add,
            ),
        )

        container = client.V1Container(
            name="sandbox",
            image=cfg.image,
            command=["sleep", "infinity"],
            working_dir=cfg.working_dir,
            env=env_vars,
            resources=resources,
            security_context=security_context,
        )

        # Compute activeDeadlineSeconds so k8s kills zombie pods
        deadline = max(
            _MIN_DEADLINE_SECONDS,
            cfg.timeout_seconds * _DEADLINE_MULTIPLIER,
        )

        pod_spec = client.V1PodSpec(
            containers=[container],
            restart_policy="Never",
            host_network=False,
            automount_service_account_token=False,
            active_deadline_seconds=deadline,
        )

        # Set ownerReference to parent pod for cascading GC
        owner_ref = parent_pod_owner_reference()
        owner_references = [owner_ref] if owner_ref else None

        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(
                name=self._pod_name,
                namespace=self._namespace,
                labels={
                    "managed-by": "clearwing",
                    "purpose": "sandbox",
                    "clearwing-session": cfg.env.get("CLEARWING_SESSION_ID", "unknown"),
                },
                owner_references=owner_references,
            ),
            spec=pod_spec,
        )

        api.create_namespaced_pod(self._namespace, pod)
        self._wait_for_running()
        self._started = True
        logger.debug("K8s sandbox pod %s running (deadline=%ds)", self._pod_name, deadline)
        return self._pod_name

    def _wait_for_running(self) -> None:
        """Block until the Pod reaches Running phase."""
        from kubernetes import watch

        api = core_v1_api()
        deadline = time.monotonic() + _POD_STARTUP_TIMEOUT_SECONDS
        w = watch.Watch()
        try:
            for event in w.stream(
                api.list_namespaced_pod,
                self._namespace,
                field_selector=f"metadata.name={self._pod_name}",
                timeout_seconds=_POD_STARTUP_TIMEOUT_SECONDS,
            ):
                pod = event["object"]
                if pod.status.phase == "Running":
                    return
                if pod.status.phase in ("Failed", "Succeeded"):
                    raise RuntimeError(
                        f"Sandbox pod {self._pod_name} entered {pod.status.phase}"
                    )
                if time.monotonic() > deadline:
                    break
        finally:
            w.stop()
        raise RuntimeError(
            f"Sandbox pod {self._pod_name} did not reach Running within "
            f"{_POD_STARTUP_TIMEOUT_SECONDS}s"
        )

    def exec(
        self,
        command: str | list[str],
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Execute a command inside the sandbox Pod.

        Uses the Kubernetes exec websocket with separate stdout/stderr
        channels and parses the real exit code from the status channel.
        """
        from kubernetes.stream import stream

        if timeout is None:
            timeout = self._config.timeout_seconds

        # Build the shell command with optional env/workdir prefix
        shell_cmd = self._build_shell_command(command, env, workdir)
        exec_command = ["/bin/sh", "-c", shell_cmd]

        started = time.monotonic()
        timed_out = False
        try:
            resp = stream(
                core_v1_api().connect_get_namespaced_pod_exec,
                self._pod_name,
                self._namespace,
                container="sandbox",
                command=exec_command,
                stderr=True,
                stdout=True,
                stdin=False,
                tty=False,
                _preload_content=False,
            )
            # Read until completion or timeout
            resp.run_forever(timeout=timeout)

            stdout = resp.read_stdout() or ""
            stderr = resp.read_stderr() or ""
            exit_code = self._parse_exit_code(resp)

        except Exception as exc:
            elapsed = time.monotonic() - started
            if elapsed >= (timeout - 1):  # within 1s of timeout
                timed_out = True
                stdout = ""
                stderr = f"Command timed out after {timeout}s"
                exit_code = 124
            else:
                stdout = ""
                stderr = str(exc)
                exit_code = 1

        duration = time.monotonic() - started
        return ExecResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
        )

    @staticmethod
    def _build_shell_command(
        command: str | list[str],
        env: dict[str, str] | None,
        workdir: str | None,
    ) -> str:
        """Compose the shell command string with env/workdir prefix."""
        prefix = ""
        if workdir:
            prefix += f"cd {workdir} && "
        if env:
            exports = " ".join(f"{k}={v}" for k, v in env.items())
            prefix += f"export {exports} && "

        if isinstance(command, str):
            return f"{prefix}{command}"
        return f"{prefix}{' '.join(command)}"

    @staticmethod
    def _parse_exit_code(resp) -> int:
        """Extract the process exit code from the websocket status channel.

        Channel 3 carries a JSON status message:
          {"status": "Success"} → exit 0
          {"status": "Failure", "message": "...", "reason": "NonZeroExitCode",
           "details": {"causes": [{"reason": "ExitCode", "message": "N"}]}}
        """
        try:
            err_channel = resp.read_channel(3)
            if not err_channel:
                return 0
            status = json.loads(err_channel)
            if status.get("status") == "Success":
                return 0
            # Extract exit code from details.causes
            details = status.get("details", {})
            for cause in details.get("causes", []):
                if cause.get("reason") == "ExitCode":
                    return int(cause.get("message", "1"))
            # Generic failure without explicit code
            return 1
        except (json.JSONDecodeError, ValueError, TypeError):
            return 1

    def write_file(self, container_path: str, content: bytes) -> None:
        """Write a file into the sandbox Pod via stdin tar pipe."""
        from kubernetes.stream import stream

        dest_dir = os.path.dirname(container_path)
        filename = os.path.basename(container_path)

        # Build tar archive in memory
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=filename)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        tar_bytes = buf.getvalue()

        # Exec tar extraction with stdin pipe
        resp = stream(
            core_v1_api().connect_get_namespaced_pod_exec,
            self._pod_name,
            self._namespace,
            container="sandbox",
            command=["/bin/sh", "-c", f"mkdir -p {dest_dir} && tar -xf - -C {dest_dir}"],
            stderr=True,
            stdout=True,
            stdin=True,
            tty=False,
            _preload_content=False,
        )
        resp.write_stdin(tar_bytes)
        resp.close()

    def read_file(self, container_path: str) -> bytes:
        """Read a file from the sandbox Pod via stdout tar pipe."""
        from kubernetes.stream import stream

        resp = stream(
            core_v1_api().connect_get_namespaced_pod_exec,
            self._pod_name,
            self._namespace,
            container="sandbox",
            command=["/bin/sh", "-c", f"tar -cf - -C / {container_path.lstrip('/')}"],
            stderr=True,
            stdout=True,
            stdin=False,
            tty=False,
            _preload_content=False,
        )
        resp.run_forever(timeout=30)
        stdout_data = resp.read_stdout(timeout=0)

        if not stdout_data:
            raise FileNotFoundError(f"Cannot read {container_path}")

        # Extract file content from tar
        tar_buf = io.BytesIO(stdout_data.encode("latin-1") if isinstance(stdout_data, str) else stdout_data)
        with tarfile.open(fileobj=tar_buf, mode="r") as tar:
            members = tar.getmembers()
            if not members:
                raise FileNotFoundError(f"Cannot read {container_path}")
            f = tar.extractfile(members[0])
            if f is None:
                raise FileNotFoundError(f"Cannot read {container_path}: not a regular file")
            return f.read()

    def copy_tree_into(self, host_path: str, container_path: str) -> None:
        """Copy a directory tree into the Pod via stdin tar pipe.

        Pipes a tar archive directly into the container's stdin —
        no base64 encoding, no shell arg limits, single round-trip.
        """
        import subprocess

        from kubernetes.stream import stream

        # Create tar locally
        result = subprocess.run(
            ["tar", "-cf", "-", "-C", host_path, "."],
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to tar {host_path}: {result.stderr.decode()}")

        tar_bytes = result.stdout

        # Pipe into container via exec stdin
        resp = stream(
            core_v1_api().connect_get_namespaced_pod_exec,
            self._pod_name,
            self._namespace,
            container="sandbox",
            command=["/bin/sh", "-c", f"mkdir -p {container_path} && tar -xf - --no-same-owner -C {container_path}"],
            stderr=True,
            stdout=True,
            stdin=True,
            tty=False,
            _preload_content=False,
        )
        # Write in chunks to avoid websocket frame size limits
        chunk_size = 1024 * 1024  # 1MB chunks
        for i in range(0, len(tar_bytes), chunk_size):
            resp.write_stdin(tar_bytes[i:i + chunk_size])
        resp.close()

    def stop(self) -> None:
        """Delete the sandbox Pod."""
        if not self._pod_name:
            return
        try:
            core_v1_api().delete_namespaced_pod(
                self._pod_name,
                self._namespace,
                grace_period_seconds=5,
            )
            logger.debug("K8s sandbox pod %s deleted", self._pod_name)
        except Exception:
            logger.debug("Failed to delete sandbox pod %s", self._pod_name, exc_info=True)
        self._started = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def __del__(self):
        if self._started:
            try:
                self.stop()
            except Exception:
                pass
