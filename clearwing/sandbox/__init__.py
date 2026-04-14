"""Sandbox primitives for sourcehunt and other source-code-aware agent flows.

Distinct from clearwing/agent/tools/kali_docker_tool.py — that tool is
attack-focused (approval gates, apt-get install, network access). The sandbox
primitives here are isolation-focused: no network, read-only mounts, resource
limits, and sanitizer-instrumented build images.
"""

from .builders import BuildRecipe, BuildSystemDetector
from .container import ExecResult, SandboxConfig, SandboxContainer
from .hunter_sandbox import HunterSandbox

__all__ = [
    "ExecResult",
    "SandboxConfig",
    "SandboxContainer",
    "BuildRecipe",
    "BuildSystemDetector",
    "HunterSandbox",
]
