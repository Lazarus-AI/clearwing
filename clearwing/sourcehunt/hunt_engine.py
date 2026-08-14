"""Domain contract for running one Sourcehunt discovery assignment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .state import FileTarget, Finding


@dataclass(frozen=True, slots=True)
class HuntAssignment:
    """Everything a hunt engine needs to investigate one ranked target."""

    file_target: FileTarget
    session_id: str
    work_item_id: str
    budget_usd: float = 0.0
    seed_transcript: str | None = None
    entry_point: Any = None
    seed_context: str | None = None


@dataclass(frozen=True, slots=True)
class HuntOutcome:
    """Engine-neutral result consumed by the existing Sourcehunt pipeline."""

    findings: tuple[Finding, ...]
    cost_usd: float
    tokens_used: int
    stop_reason: str


class HuntEngine(Protocol):
    """The single extension seam for Sourcehunt discovery execution."""

    async def hunt(self, assignment: HuntAssignment, sandbox: Any) -> HuntOutcome: ...


__all__ = ["HuntAssignment", "HuntEngine", "HuntOutcome"]
