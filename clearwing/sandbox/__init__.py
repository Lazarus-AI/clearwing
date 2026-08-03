"""Sandbox primitives for sourcehunt and other source-code-aware agent flows.

Distinct from clearwing/agent/tools/kali_docker_tool.py — that tool is
attack-focused (approval gates, apt-get install, network access). The sandbox
primitives here are isolation-focused: no network, read-only mounts, resource
limits, and sanitizer-instrumented build images.
"""

from .builders import BuildRecipe, BuildSystemDetector
from .container import ExecResult, SandboxConfig, SandboxContainer
from .dind import get_docker_client, get_docker_host, get_subprocess_env
from .factory import create_sandbox, is_kubernetes_backend
from .hunter_sandbox import HunterSandbox
from .registry import ContainerRegistry

__all__ = [
    "ContainerRegistry",
    "ExecResult",
    "SandboxConfig",
    "SandboxContainer",
    "BuildRecipe",
    "BuildSystemDetector",
    "HunterSandbox",
    "create_sandbox",
    "is_kubernetes_backend",
    "get_docker_client",
    "get_docker_host",
    "get_subprocess_env",
]
