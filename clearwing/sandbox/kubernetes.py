"""Kubernetes implementation of the pluggable sandbox contracts.

The Kubernetes dependency is deliberately imported lazily. Importing
``clearwing.sandbox`` therefore does not require the optional extra unless
this backend is selected.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import subprocess
import tarfile
import time
import uuid
from collections.abc import Callable
from typing import Any

from .backend import (
    SandboxEnvironment,
    SandboxEnvironmentSpec,
    SandboxRunConfig,
)
from .container import ExecResult

_STARTUP_TIMEOUT_SECONDS = 120
_DEADLINE_FLOOR_SECONDS = 900


def kubernetes_namespace() -> str:
    """Return the configured or in-cluster namespace."""
    configured = os.environ.get("CLEARWING_SANDBOX_NAMESPACE", "").strip()
    if configured:
        return configured
    try:
        with open(
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            encoding="utf-8",
        ) as namespace_file:
            return namespace_file.read().strip() or "default"
    except OSError:
        return "default"


def _core_v1_api():
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


class KubernetesSandboxBackend:
    """Create isolated sandbox pods from a pre-built toolchain image.

    ``CLEARWING_SANDBOX_IMAGE`` is intentionally provider configuration, not
    part of the provider-neutral environment request. Deployments should
    publish an image containing every logical feature they grant.
    """

    name = "kubernetes"

    def __init__(
        self,
        *,
        image: str | None = None,
        namespace: str | None = None,
        api_factory: Callable[[], Any] = _core_v1_api,
    ) -> None:
        self.image = image or os.environ.get("CLEARWING_SANDBOX_IMAGE", "").strip()
        if not self.image:
            raise ValueError(
                "Kubernetes sandbox requires CLEARWING_SANDBOX_IMAGE or image="
            )
        self.namespace = namespace or kubernetes_namespace()
        self._api_factory = api_factory

    def available_cpus(self) -> tuple[float | None, str]:
        return None, "Kubernetes scheduler"

    def ensure_environment(
        self,
        spec: SandboxEnvironmentSpec,
        on_output: Callable[[str], None] | None = None,
    ) -> SandboxEnvironment:
        if not spec.cache_key:
            raise ValueError("sandbox environment cache_key must not be empty")
        if on_output is not None:
            on_output(f"Using pre-built Kubernetes sandbox image {self.image}")
        return SandboxEnvironment(self.image, cached=True)

    def create(
        self,
        environment_ref: str,
        config: SandboxRunConfig,
    ) -> KubernetesSandbox:
        if config.policy != "sourcehunt":
            raise ValueError(f"Kubernetes sandbox does not support policy {config.policy!r}")
        if config.isolation not in {"default", "enhanced"}:
            raise ValueError(
                f"Kubernetes sandbox does not support isolation level {config.isolation!r}"
            )
        if config.mounts:
            raise ValueError("Kubernetes sandbox does not accept host-path mounts")
        return KubernetesSandbox(
            environment_ref,
            config,
            namespace=self.namespace,
            api_factory=self._api_factory,
        )

    def release_environment(self, environment_ref: str) -> None:
        # Images are deployment-managed and shared; a run never deletes them.
        return None


class KubernetesSandbox:
    """A ``SandboxInstance`` implemented by one short-lived Kubernetes Pod."""

    scratch_host_dir: str | None = None
    variant: list[str] | None = None
    workspace_baseline_commit: str | None = None

    def __init__(
        self,
        image: str,
        config: SandboxRunConfig,
        *,
        namespace: str,
        api_factory: Callable[[], Any] = _core_v1_api,
    ) -> None:
        self.image = image
        self._config = config
        self.namespace = namespace
        self._api_factory = api_factory
        self._pod_name: str | None = None

    @property
    def config(self) -> SandboxRunConfig:
        return self._config

    @property
    def container_id(self) -> str | None:
        return self._pod_name

    @property
    def short_id(self) -> str | None:
        return self._pod_name[-8:] if self._pod_name else None

    @property
    def is_running(self) -> bool:
        if self._pod_name is None:
            return False
        try:
            pod = self._api_factory().read_namespaced_pod_status(
                self._pod_name, self.namespace
            )
            return bool(pod.status.phase == "Running")
        except Exception:
            return False

    def start(self) -> str:
        if self._pod_name is not None:
            return self._pod_name
        from kubernetes import client

        pod_name = f"clearwing-sandbox-{uuid.uuid4().hex[:12]}"
        resources: dict[str, str] = {"memory": f"{self._config.memory_mb}Mi"}
        requests: dict[str, str] = {
            "memory": f"{min(self._config.memory_mb, 512)}Mi"
        }
        if self._config.cpus > 0:
            resources["cpu"] = str(self._config.cpus)
            requests["cpu"] = str(min(self._config.cpus, 0.5))
        security_context = client.V1SecurityContext(
            allow_privilege_escalation=False,
            capabilities=client.V1Capabilities(drop=["ALL"], add=["SYS_PTRACE"]),
        )
        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(
                name=pod_name,
                namespace=self.namespace,
                labels={"app.kubernetes.io/managed-by": "clearwing", "purpose": "sandbox"},
            ),
            spec=client.V1PodSpec(
                automount_service_account_token=False,
                enable_service_links=False,
                host_network=False,
                restart_policy="Never",
                active_deadline_seconds=max(
                    _DEADLINE_FLOOR_SECONDS, self._config.timeout_seconds * 3
                ),
                containers=[
                    client.V1Container(
                        name="sandbox",
                        image=self.image,
                        command=["/bin/sh", "-c", "trap : TERM INT; sleep infinity & wait"],
                        working_dir=self._config.working_dir,
                        env=[
                            client.V1EnvVar(name=name, value=value)
                            for name, value in self._config.env.items()
                        ],
                        resources=client.V1ResourceRequirements(
                            limits=resources, requests=requests
                        ),
                        security_context=security_context,
                    )
                ],
            ),
        )
        api = self._api_factory()
        api.create_namespaced_pod(self.namespace, pod)
        self._pod_name = pod_name
        try:
            self._wait_until_running(api)
        except BaseException:
            self.stop()
            raise
        return pod_name

    def _wait_until_running(self, api: Any) -> None:
        deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            pod = api.read_namespaced_pod_status(self._pod_name, self.namespace)
            phase = pod.status.phase
            if phase == "Running":
                return
            if phase in {"Failed", "Succeeded"}:
                raise RuntimeError(f"sandbox pod entered terminal phase {phase}")
            time.sleep(0.5)
        raise TimeoutError("sandbox pod did not become ready within 120 seconds")

    def _stream(self, command: list[str], *, stdin: bytes | None = None):
        if self._pod_name is None:
            raise RuntimeError("sandbox pod has not been started")
        from kubernetes.stream import stream

        response = stream(
            self._api_factory().connect_get_namespaced_pod_exec,
            self._pod_name,
            self.namespace,
            container="sandbox",
            command=command,
            stderr=True,
            stdout=True,
            stdin=stdin is not None,
            tty=False,
            _preload_content=False,
        )
        if stdin is not None:
            for offset in range(0, len(stdin), 1024 * 1024):
                response.write_stdin(stdin[offset : offset + 1024 * 1024])
            response.close_stdin()
        return response

    def exec(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        effective_timeout = self._config.timeout_seconds if timeout is None else timeout
        shell_command = command if isinstance(command, str) else shlex.join(command)
        if env:
            exports = " ".join(
                f"{name}={shlex.quote(value)}" for name, value in env.items()
            )
            shell_command = f"export {exports} && {shell_command}"
        if workdir:
            shell_command = f"cd {shlex.quote(workdir)} && {shell_command}"
        started = time.monotonic()
        response = self._stream(["/bin/sh", "-c", shell_command])
        try:
            response.run_forever(timeout=effective_timeout)
            stdout = response.read_stdout() or ""
            stderr = response.read_stderr() or ""
            exit_code = self._parse_exit_code(response)
            timed_out = False
        except TimeoutError:
            response.close()
            stdout, stderr, exit_code, timed_out = "", "command timed out", 124, True
        return ExecResult(
            exit_code, stdout, stderr, time.monotonic() - started, timed_out
        )

    @staticmethod
    def _parse_exit_code(response: Any) -> int:
        try:
            status = response.read_channel(3)
            if not status:
                return 0
            decoded = json.loads(status)
            if decoded.get("status") == "Success":
                return 0
            for cause in decoded.get("details", {}).get("causes", []):
                if cause.get("reason") == "ExitCode":
                    return int(cause["message"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            pass
        return 1

    def write_file(self, container_path: str, content: bytes) -> None:
        parent, name = os.path.split(container_path)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        response = self._stream(
            ["tar", "-xf", "-", "--no-same-owner", "-C", parent],
            stdin=archive.getvalue(),
        )
        response.run_forever(timeout=30)

    def read_file(self, container_path: str) -> bytes:
        response = self._stream(
            ["tar", "-cf", "-", "-C", "/", container_path.lstrip("/")]
        )
        response.run_forever(timeout=30)
        payload = response.read_stdout()
        if isinstance(payload, str):
            payload = payload.encode("latin-1")
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
            member = tar.next()
            if member is None:
                raise FileNotFoundError(container_path)
            extracted = tar.extractfile(member)
            if extracted is None:
                raise FileNotFoundError(container_path)
            return extracted.read()

    def copy_tree_into(self, host_path: str, container_path: str = "/workspace") -> None:
        result = subprocess.run(
            ["tar", "-cf", "-", "-C", host_path, "."],
            capture_output=True,
            timeout=120,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        response = self._stream(
            ["tar", "-xf", "-", "--no-same-owner", "-C", container_path],
            stdin=result.stdout,
        )
        response.run_forever(timeout=120)

    def stop(self) -> None:
        if self._pod_name is None:
            return
        pod_name, self._pod_name = self._pod_name, None
        try:
            self._api_factory().delete_namespaced_pod(
                pod_name, self.namespace, grace_period_seconds=5
            )
        except Exception:
            pass

    def __enter__(self) -> KubernetesSandbox:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()
