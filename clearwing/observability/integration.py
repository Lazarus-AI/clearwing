"""Integration between observability and the Clearwing agent."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any, ClassVar

from clearwing.core.events import EventBus, EventType

from .metrics import MetricsCollector
from .otel import configure_telemetry, force_flush, get_tracer, telemetry_configured

logger = logging.getLogger(__name__)


class ObservabilityIntegration:
    """Connects the Tracer and MetricsCollector to the EventBus.

    When enabled, automatically records:
    - Spans for each tool call and LLM invocation
    - Counters for tool calls, LLM calls, findings
    - Gauges for cost, token counts
    - Histograms for tool and LLM latencies

    Usage::

        from clearwing.observability.integration import ObservabilityIntegration

        obs = ObservabilityIntegration(debug=True)
        obs.connect()  # subscribes to EventBus
        # ... run agent ...
        obs.disconnect()
        print(obs.metrics.format_prometheus())

    For env-driven auto-wiring at process startup, prefer
    :meth:`bootstrap_from_env` — it is a no-op unless OTLP export is configured.
    """

    # Process-wide singleton established by :meth:`bootstrap_from_env` so
    # startup hooks in the CLI and webui don't double-subscribe. Tests may
    # clear this by calling ``disconnect()``, which unsets the reference.
    _singleton: ClassVar[ObservabilityIntegration | None] = None
    _singleton_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, *, exporters: list | None = None):
        self.provider = configure_telemetry(exporters=exporters)
        self.tracer = get_tracer("clearwing")
        self.metrics = MetricsCollector()
        self._connected = False
        self._handlers: dict[EventType, Callable[[Any], None]] = {}

    @classmethod
    def bootstrap_from_env(cls) -> ObservabilityIntegration | None:
        """Idempotently instantiate and connect when OTLP export is configured.

        Returns the shared singleton, or ``None`` if
        Standard ``OTEL_*`` variables are preferred; Phoenix variables remain
        compatibility aliases. Safe to call from every process entry point;
        subsequent calls return the same EventBus integration.
        """
        if not telemetry_configured():
            return None
        with cls._singleton_lock:
            if cls._singleton is None:
                instance = cls()
                instance.connect()
                cls._singleton = instance
                logger.info("ObservabilityIntegration bootstrapped from env")
            return cls._singleton

    def connect(self) -> None:
        """Subscribe to EventBus events."""
        if self._connected:
            return

        bus = EventBus()
        self._handlers = {
            EventType.TOOL_START: self._on_tool_start,
            EventType.TOOL_RESULT: self._on_tool_result,
            EventType.COST_UPDATE: self._on_cost_update,
            EventType.FLAG_FOUND: self._on_flag_found,
            EventType.MESSAGE: self._on_message,
            EventType.ERROR: self._on_error,
        }
        for event_type, handler in self._handlers.items():
            bus.subscribe(event_type, handler)

        self._connected = True

    def disconnect(self) -> None:
        """Unsubscribe from EventBus events and flush."""
        if not self._connected:
            return

        bus = EventBus()
        for event_type, handler in self._handlers.items():
            bus.unsubscribe(event_type, handler)

        force_flush()
        self._connected = False
        # Release the bootstrap singleton so a follow-up bootstrap can create
        # a fresh instance (primarily useful for tests).
        if type(self)._singleton is self:
            type(self)._singleton = None

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_tool_start(self, data: Any) -> None:
        tool_name = data.get("tool", "unknown") if isinstance(data, dict) else "unknown"
        self.metrics.increment("tool_calls_total", labels={"tool": tool_name})

    def _on_tool_result(self, data: Any) -> None:
        if not isinstance(data, dict):
            return
        tool_name = data.get("tool", "unknown")
        content_length = data.get("content_length", 0)
        flags = data.get("flags_found", 0)

        self.metrics.set_gauge(
            "tool_result_size_bytes",
            float(content_length),
            labels={"tool": tool_name},
        )
        if flags > 0:
            self.metrics.increment("flags_found_total", value=float(flags))

    def _on_cost_update(self, data: Any) -> None:
        if not isinstance(data, dict):
            return
        model = data.get("model", "unknown")
        input_tokens = int(data.get("input_tokens", 0) or 0)
        output_tokens = int(data.get("output_tokens", 0) or 0)
        self.metrics.increment("llm_calls_total", labels={"model": model})
        self.metrics.increment("input_tokens_total", value=float(input_tokens))
        self.metrics.increment("output_tokens_total", value=float(output_tokens))
        self.metrics.set_gauge("total_cost_usd", data.get("total_cost_usd", 0.0))


    def _on_flag_found(self, data: Any) -> None:
        self.metrics.increment("flags_found_total")

    def _on_message(self, data: Any) -> None:
        msg_type = data.get("type", "info") if isinstance(data, dict) else "info"
        self.metrics.increment("messages_total", labels={"type": msg_type})

    def _on_error(self, data: Any) -> None:
        self.metrics.increment("errors_total")
