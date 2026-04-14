"""Runtime capability detection for optional clearwing subsystems.

The network-agent graph gates a handful of features on subsystem
availability: memory summarization, event-bus publishing, telemetry
cost tracking, audit logging, knowledge-graph population, and input/
output guardrails. Each of these subsystems is currently part of the
base install, but we want a single point of truth for "is this
subsystem actually importable in the current process" so that:

1. Stripped / partial installs degrade gracefully rather than crashing
   on first use.
2. Future moves of any subsystem to `[project.optional-dependencies]`
   just work — no graph.py changes needed beyond flipping the extras
   metadata.
3. The graph's import section stays unconditional, so static analysis
   tools (ruff/mypy) see real symbols instead of `Optional[None]`
   fallbacks.

Usage:
    from clearwing.capabilities import capabilities
    if capabilities.has("memory"):
        episodic_memory = EpisodicMemory(session_id)

The `capabilities` object is a frozen singleton computed once at
import time. Every probe runs inside its own try/except ImportError
so a missing one doesn't take the rest down.
"""

from __future__ import annotations

from dataclasses import dataclass


def _detect_installed() -> frozenset[str]:
    installed: set[str] = set()

    try:
        import clearwing.safety.guardrails  # noqa: F401

        installed.add("guardrails")
    except ImportError:
        pass

    try:
        import clearwing.data.memory  # noqa: F401

        installed.add("memory")
    except ImportError:
        pass

    try:
        import clearwing.observability.telemetry  # noqa: F401

        installed.add("telemetry")
    except ImportError:
        pass

    try:
        import clearwing.core.events  # noqa: F401

        installed.add("events")
    except ImportError:
        pass

    try:
        import clearwing.safety.audit  # noqa: F401

        installed.add("audit")
    except ImportError:
        pass

    try:
        import clearwing.data.knowledge  # noqa: F401

        installed.add("knowledge")
    except ImportError:
        pass

    return frozenset(installed)


@dataclass(frozen=True)
class Capabilities:
    """Frozen snapshot of subsystems importable in this process."""

    installed: frozenset[str]

    def has(self, name: str) -> bool:
        """True if the named subsystem is available in this process."""
        return name in self.installed


capabilities = Capabilities(installed=_detect_installed())


__all__ = ["Capabilities", "capabilities"]
