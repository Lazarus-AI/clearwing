"""Adapter from the hunt-engine contract to Clearwing's native agent loop."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .hunt_engine import HuntAssignment, HuntOutcome

logger = logging.getLogger(__name__)


class NativeHuntEngine:
    """Run an assignment with the existing ``NativeHunter`` implementation."""

    def __init__(self, build_hunter: Callable[[HuntAssignment, Any], Any]) -> None:
        self._build_hunter = build_hunter

    async def hunt(self, assignment: HuntAssignment, sandbox: Any) -> HuntOutcome:
        hunter, context = self._build_hunter(assignment, sandbox)
        try:
            result = await hunter.arun()
            return HuntOutcome(
                findings=tuple(result.findings),
                cost_usd=result.cost_usd,
                tokens_used=result.tokens_used,
                stop_reason=result.stop_reason,
            )
        finally:
            try:
                context.cleanup_variants()
            except Exception:
                logger.debug("Variant sandbox cleanup failed", exc_info=True)


__all__ = ["NativeHuntEngine"]
