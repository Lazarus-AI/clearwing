"""Kubernetes-backed SandboxContainer implementation.

Runs sandbox workloads as Kubernetes Jobs/Pods instead of local Docker
containers. Implements the same interface as SandboxContainer so hunter
agents are backend-agnostic.

Requires: CLEARWING_SANDBOX_BACKEND=kubernetes
"""

from __future__ import annotations

import io
import logging
import os
import tarfile
import time
import uuid

from .container import ExecResult, SandboxConfig, SandboxContainer

logger = logging.getLogger(__name__)

_NAMESPACE_ENV = "CLEARWING_SANDBOX_NAMESPACE"
_EXEC_TIMEOUT_SECONDS = 600
_POD_STARTUP_TIMEOUT_SECONDS = 120


def _namespace() -> str:
    ns = os.environ.get(_NAMESPACE_ENV)
    if ns:
        return ns
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
            return f.read().strip()
    except OSError:
        return "default"


class KubeSandboxContainer(SandboxContainer):
    """SandboxContainer backed by a Kubernetes Pod.

    Creates a long-running Pod (not a Job) so we can exec into it multiple
    times, matching the Docker container lifecycle model.
    """

    def __init__(self, config: SandboxConfig):
        # Don't call super().__init__ — we override the full lifecycle
        self._config = config
        self._pod_name: str | None = None
        self._namespace = _namespace()
        self._core_v1 = None
        self._started = False
        # Public attributes expected by HunterSandbox
        self.scratch_host_dir: str | None = None
        self.variant: list[str] = []

    def _api(self):
        if self._core_v1 is None:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
            self._core_v1 = client.CoreV1Api()
        return self._core_v1

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
            pod = self._api().read_namespaced_pod_status(self._pod_name, self._namespace)
            return pod.status.phase == "Running"
        except Exception:
            return False

    def start(self) -> str:
        """Create and start a Pod matching the SandboxConfig."""
        from kubernetes import client

        api = self._api()
        cfg = self._config
        pod_id = uuid.uuid4().hex[:8]
        self._pod_name = f"clearwing-sandbox-{pod_id}"

        # Build env vars
        env_vars = [
            client.V1EnvVar(name=k, value=v) for k, v in cfg.env.items()
        ]

        # Resource limits
        resources = client.V1ResourceRequirements(
            limits={
                "memory": f"{cfg.memory_mb}Mi",
            },
            requests={
                "memory": f"{min(cfg.memory_mb, 512)}Mi",
            },
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

        # Pod-level security and network policy
        pod_spec = client.V1PodSpec(
            containers=[container],
            restart_policy="Never",
            # Network isolation: use a NetworkPolicy on the namespace rather
            # than Docker's network_mode=none. The pod itself is created
            # without hostNetwork so default namespace policies apply.
            host_network=False,
            automount_service_account_token=False,
        )

        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(
                name=self._pod_name,
                namespace=self._namespace,
                labels={
                    "managed-by": "clearwing",
                    "purpose": "sandbox",
                    "clearwing-session": cfg.env.get("CLEARWING_SESSION_ID", "unknown"),
                },
            ),
            spec=pod_spec,
        )

        api.create_namespaced_pod(self._namespace, pod)
        self._wait_for_running()
        self._started = True
        logger.debug("K8s sandbox pod %s running", self._pod_name)
        return self._pod_name

    def _wait_for_running(self) -> None:
        """Block until the Pod reaches Running phase."""
        from kubernetes import watch

        api = self._api()
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
        """Execute a command inside the sandbox Pod via kubectl exec."""
        from kubernetes.stream import stream

        if timeout is None:
            timeout = self._config.timeout_seconds

        if isinstance(command, str):
            exec_command = ["/bin/sh", "-c", command]
        else:
            exec_command = list(command)

        # Prepend env vars and workdir if specified
        if env or workdir:
            shell_prefix = ""
            if workdir:
                shell_prefix += f"cd {workdir} && "
            if env:
                exports = " ".join(f"{k}={v}" for k, v in env.items())
                shell_prefix += f"export {exports} && "
            if isinstance(command, str):
                exec_command = ["/bin/sh", "-c", f"{shell_prefix}{command}"]
            else:
                joined = " ".join(command)
                exec_command = ["/bin/sh", "-c", f"{shell_prefix}{joined}"]

        started = time.monotonic()
        timed_out = False
        try:
            # Use the kubernetes python client's exec
            resp = stream(
                self._api().connect_get_namespaced_pod_exec,
                self._pod_name,
                self._namespace,
                container="sandbox",
                command=exec_command,
                stderr=True,
                stdout=True,
                stdin=False,
                tty=False,
                _preload_content=True,
                _request_timeout=timeout,
            )
            # stream() returns the combined output as a string for _preload_content=True
            stdout = resp if isinstance(resp, str) else ""
            stderr = ""
            exit_code = 0
        except Exception as exc:
            elapsed = time.monotonic() - started
            if elapsed >= timeout:
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

    def write_file(self, container_path: str, content: bytes) -> None:
        """Write a file into the sandbox Pod."""
        # Create a tar archive in memory and pipe it via exec
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=os.path.basename(container_path))
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)

        dest_dir = os.path.dirname(container_path)
        self.exec(f"mkdir -p {dest_dir}")

        # Write via base64 encoding to avoid binary transfer issues
        import base64

        encoded = base64.b64encode(buf.getvalue()).decode("ascii")
        self.exec(
            f"echo '{encoded}' | base64 -d | tar -xf - -C {dest_dir}"
        )

    def read_file(self, container_path: str) -> bytes:
        """Read a file from the sandbox Pod."""
        import base64

        result = self.exec(f"base64 < {container_path}")
        if result.exit_code != 0:
            raise FileNotFoundError(
                f"Cannot read {container_path}: {result.stderr}"
            )
        return base64.b64decode(result.stdout.strip())

    def copy_tree_into(self, host_path: str, container_path: str) -> None:
        """Copy a directory tree into the Pod.

        Creates a tar of the host path and streams it into the container.
        """
        import subprocess

        self.exec(f"mkdir -p {container_path}")

        # Create tar locally, base64 encode, exec into pod
        result = subprocess.run(
            ["tar", "-cf", "-", "-C", host_path, "."],
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to tar {host_path}: {result.stderr.decode()}")

        import base64

        # For large trees, chunk the transfer
        encoded = base64.b64encode(result.stdout).decode("ascii")
        chunk_size = 500_000  # ~375KB decoded per chunk
        if len(encoded) <= chunk_size:
            self.exec(
                f"echo '{encoded}' | base64 -d | tar -xf - --no-same-owner -C {container_path}"
            )
        else:
            # Write chunks to a temp file in the container
            self.exec("rm -f /tmp/_transfer.tar.b64")
            for i in range(0, len(encoded), chunk_size):
                chunk = encoded[i : i + chunk_size]
                self.exec(f"echo -n '{chunk}' >> /tmp/_transfer.tar.b64")
            self.exec(
                f"base64 -d /tmp/_transfer.tar.b64 | tar -xf - --no-same-owner -C {container_path} && "
                f"rm -f /tmp/_transfer.tar.b64"
            )

    def stop(self) -> None:
        """Delete the sandbox Pod."""
        if not self._pod_name:
            return
        try:
            self._api().delete_namespaced_pod(
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
