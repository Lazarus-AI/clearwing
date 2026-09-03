"""Sandbox primitives for sourcehunt and other source-code-aware agent flows.

Distinct from clearwing/agent/tools/kali_docker_tool.py — that tool is
attack-focused (approval gates, apt-get install, network access). The sandbox
primitives here are isolation-focused: no network, read-only mounts, resource
limits, and sanitizer-capable toolchain environments.
"""

from .backend import (
    DockerSandboxBackend,
    SandboxBackend,
    SandboxEnvironment,
    SandboxEnvironmentSpec,
    SandboxInstance,
    SandboxRunConfig,
    sandbox_backend_from_env,
)
from .builders import BuildRecipe, BuildSystemDetector
from .container import ExecResult, SandboxConfig, SandboxContainer
from .dind import get_docker_client, get_docker_host, get_subprocess_env
from .hunter_sandbox import HunterSandbox
from .kubernetes import KubernetesSandbox, KubernetesSandboxBackend
from .registry import ContainerRegistry
from .rpc_backend import JsonRpcConnection, SandboxRpcError, SocketSandboxBackend

__all__ = [
    "ContainerRegistry",
    "DockerSandboxBackend",
    "ExecResult",
    "JsonRpcConnection",
    "SandboxBackend",
    "SandboxConfig",
    "SandboxContainer",
    "SandboxEnvironment",
    "SandboxEnvironmentSpec",
    "SandboxInstance",
    "SandboxRpcError",
    "SandboxRunConfig",
    "SocketSandboxBackend",
    "BuildRecipe",
    "BuildSystemDetector",
    "HunterSandbox",
    "KubernetesSandbox",
    "KubernetesSandboxBackend",
    "get_docker_client",
    "get_docker_host",
    "get_subprocess_env",
    "sandbox_backend_from_env",
]
