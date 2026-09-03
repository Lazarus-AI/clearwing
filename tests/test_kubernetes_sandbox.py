"""Contract tests for the Kubernetes sandbox provider."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from clearwing.sandbox.backend import (
    SandboxBackend,
    SandboxEnvironmentSpec,
    SandboxInstance,
    SandboxRunConfig,
)
from clearwing.sandbox.kubernetes import KubernetesSandbox, KubernetesSandboxBackend


def test_kubernetes_backend_implements_contract():
    backend = KubernetesSandboxBackend(image="registry.test/sandbox:1", namespace="jobs")
    assert isinstance(backend, SandboxBackend)
    environment = backend.ensure_environment(
        SandboxEnvironmentSpec(cache_key="a" * 64, profile="c-cpp")
    )
    sandbox = backend.create(environment.reference, SandboxRunConfig())
    assert isinstance(sandbox, SandboxInstance)
    assert environment.reference == "registry.test/sandbox:1"
    assert sandbox.namespace == "jobs"


def test_backend_selection(monkeypatch):
    from clearwing.sandbox.backend import sandbox_backend_from_env

    monkeypatch.delenv("CLEARWING_SANDBOX_ENDPOINT", raising=False)
    monkeypatch.setenv("CLEARWING_SANDBOX_BACKEND", "kubernetes")
    monkeypatch.setenv("CLEARWING_SANDBOX_IMAGE", "registry.test/sandbox:1")
    assert isinstance(sandbox_backend_from_env(), KubernetesSandboxBackend)


def test_host_mounts_are_rejected():
    backend = KubernetesSandboxBackend(image="sandbox:1")
    config = SandboxRunConfig(mounts=[("/host", "/workspace", "ro")])
    with pytest.raises(ValueError, match="host-path"):
        backend.create("sandbox:1", config)


def test_pod_lifecycle(monkeypatch):
    client = pytest.importorskip("kubernetes.client")
    api = MagicMock()
    api.read_namespaced_pod_status.return_value = SimpleNamespace(
        status=SimpleNamespace(phase="Running")
    )
    sandbox = KubernetesSandbox(
        "sandbox:1", SandboxRunConfig(), namespace="jobs", api_factory=lambda: api
    )
    monkeypatch.setattr(client, "V1Pod", MagicMock(side_effect=lambda **kw: kw))

    identity = sandbox.start()
    assert identity.startswith("clearwing-sandbox-")
    assert sandbox.is_running
    api.create_namespaced_pod.assert_called_once()

    sandbox.stop()
    api.delete_namespaced_pod.assert_called_once()
    assert sandbox.container_id is None


def test_exit_code_parsing():
    response = MagicMock()
    response.read_channel.return_value = (
        '{"status":"Failure","details":{"causes":'
        '[{"reason":"ExitCode","message":"137"}]}}'
    )
    assert KubernetesSandbox._parse_exit_code(response) == 137
