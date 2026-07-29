"""EventBus — singleton pub/sub system that decouples the agent from the UI."""

from __future__ import annotations

import enum
import logging
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from clearwing.core.event_payloads import (
        BenchmarkProgressPayload,
        CampaignProgressPayload,
        DisclosureUpdatePayload,
        EvalProgressPayload,
        HuntProgressPayload,
        SourcehuntStagePayload,
        ValidationResultPayload,
    )

logger = logging.getLogger(__name__)


class EventType(enum.Enum):
    """All event categories recognised by the bus."""

    STATE_CHANGED = "state_changed"
    MESSAGE = "message"
    TOOL_START = "tool_start"
    TOOL_RESULT = "tool_result"
    FLAG_FOUND = "flag_found"
    APPROVAL_NEEDED = "approval_needed"
    COST_UPDATE = "cost_update"
    ERROR = "error"
    USER_INPUT = "user_input"
    USER_COMMAND = "user_command"
    CAMPAIGN_PROGRESS = "campaign_progress"
    SOURCEHUNT_STAGE = "sourcehunt_stage"
    HUNT_PROGRESS = "hunt_progress"
    VALIDATION_RESULT = "validation_result"
    DISCLOSURE_UPDATE = "disclosure_update"
    BENCHMARK_PROGRESS = "benchmark_progress"
    EVAL_PROGRESS = "eval_progress"
    FINDING_RECORDED = "finding_recorded"
    HUNTER_STATUS = "hunter_status"
    TRACE_STEP = "trace_step"


class EventBus:
    """Thread-safe singleton pub/sub event bus.

    Only one instance exists per process.  Handlers are isolated — if one
    raises an exception the remaining handlers still execute and the error is
    logged rather than propagated.
    """

    _instance: EventBus | None = None
    _init_lock = threading.Lock()

    # Instance attributes — set in __new__ (singleton construction path,
    # not __init__). Declared here so mypy sees them on every EventBus
    # instance after the first call.
    _handlers: dict[EventType, list[Callable]]
    _lock: threading.Lock

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    def __new__(cls) -> EventBus:
        if cls._instance is None:
            with cls._init_lock:
                # Double-checked locking
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._handlers = {et: [] for et in EventType}
                    instance._lock = threading.Lock()
                    cls._instance = instance
        return cls._instance

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def subscribe(self, event_type: EventType, handler: Callable) -> None:
        """Register *handler* to be called whenever *event_type* is emitted."""
        with self._lock:
            if handler not in self._handlers[event_type]:
                self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType, handler: Callable) -> None:
        """Remove a previously registered *handler*."""
        with self._lock:
            try:
                self._handlers[event_type].remove(handler)
            except ValueError:
                pass  # handler was not registered — nothing to do

    def emit(self, event_type: EventType, data: Any = None) -> None:
        """Invoke every handler registered for *event_type*.

        Each handler is called with *data* as its sole argument.  If a handler
        raises an exception, the error is logged and the remaining handlers
        continue to execute.
        """
        with self._lock:
            handlers = list(self._handlers[event_type])

        for handler in handlers:
            try:
                handler(data)
            except Exception:
                logger.exception("Handler %r failed for event %s", handler, event_type.value)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def emit_message(self, content: str, msg_type: str = "info") -> None:
        """Emit a :pyattr:`EventType.MESSAGE` event."""
        self.emit(EventType.MESSAGE, {"content": content, "type": msg_type})

    def emit_tool(self, tool_name: str, phase: str, data: Any = None) -> None:
        """Emit a :pyattr:`EventType.TOOL_START` or :pyattr:`EventType.TOOL_RESULT` event."""
        event_type = EventType.TOOL_START if phase == "start" else EventType.TOOL_RESULT
        self.emit(event_type, {"tool": tool_name, "phase": phase, "data": data})

    def emit_flag(self, flag: str, context: Any = None) -> None:
        """Emit a :pyattr:`EventType.FLAG_FOUND` event."""
        self.emit(EventType.FLAG_FOUND, {"flag": flag, "context": context})

    def emit_cost(self, tokens: int, cost_usd: float) -> None:
        """Emit a :pyattr:`EventType.COST_UPDATE` event."""
        self.emit(EventType.COST_UPDATE, {"tokens": tokens, "cost_usd": cost_usd})

    def emit_campaign_progress(self, payload: CampaignProgressPayload) -> None:
        self.emit(EventType.CAMPAIGN_PROGRESS, payload)

    def emit_sourcehunt_stage(self, payload: SourcehuntStagePayload) -> None:
        self.emit(EventType.SOURCEHUNT_STAGE, payload)

    def emit_hunt_progress(self, payload: HuntProgressPayload) -> None:
        self.emit(EventType.HUNT_PROGRESS, payload)

    def emit_validation_result(self, payload: ValidationResultPayload) -> None:
        self.emit(EventType.VALIDATION_RESULT, payload)

    def emit_disclosure_update(self, payload: DisclosureUpdatePayload) -> None:
        self.emit(EventType.DISCLOSURE_UPDATE, payload)

    def emit_benchmark_progress(self, payload: BenchmarkProgressPayload) -> None:
        self.emit(EventType.BENCHMARK_PROGRESS, payload)

    def emit_eval_progress(self, payload: EvalProgressPayload) -> None:
        self.emit(EventType.EVAL_PROGRESS, payload)
