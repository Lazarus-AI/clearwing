"""Sandbox backend factory — dispatches between Docker and Kubernetes.

The backend is selected by the ``CLEARWING_SANDBOX_BACKEND`` env var:
  - ``docker`` (default): uses the local Docker daemon via docker-py.
  - ``kubernetes``: creates Kubernetes Jobs that run the same sandbox image
    as a Pod (for cwpro-managed deployments where DinD isn't available).

Both backends implement the same SandboxContainer interface so hunter agents
are backend-agnostic.
"""

from __future__ import annotations

import logging
import os

from .container import SandboxConfig, SandboxContainer

logger = logging.getLogger(__name__)

_BACKEND_ENV = "CLEARWING_SANDBOX_BACKEND"
_BACKEND_DOCKER = "docker"
_BACKEND_KUBERNETES = "kubernetes"


def is_kubernetes_backend() -> bool:
    """True when the configured sandbox backend is Kubernetes."""
    return os.environ.get(_BACKEND_ENV, _BACKEND_DOCKER).lower() == _BACKEND_KUBERNETES


def create_sandbox(config: SandboxConfig) -> SandboxContainer:
    """Create a sandbox container using the configured backend.

    For Docker (default): returns a standard SandboxContainer backed by docker-py.
    For Kubernetes: returns a KubeSandboxContainer that runs as a K8s Job/Pod.
    """
    if is_kubernetes_backend():
        from .kube_sandbox import KubeSandboxContainer

        return KubeSandboxContainer(config)
    return SandboxContainer(config)
