"""Integration between observability and the Clearwing agent."""

from __future__ import annotations

import logging
from typing import Any

from clearwing.core.events import EventBus, EventType

from .metrics import MetricsCollector
from .tracer import ConsoleExporter, InMemoryExporter, Tracer

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
    """

    def __init__(self, debug: bool = False, exporters: list = None):
        if exporters is None:
            exporters = []
            if debug:
                exporters.append(ConsoleExporter())
        self._in_memory = InMemoryExporter()
        exporters.append(self._in_memory)

        self.tracer = Tracer(service_name="clearwing", exporters=exporters)
        self.metrics = MetricsCollector()
        self._connected = False
        self._handlers = {}

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
        self.tracer.new_trace()

    def disconnect(self) -> None:
        """Unsubscribe from EventBus events and flush."""
        if not self._connected:
            return

        bus = EventBus()
        for event_type, handler in self._handlers.items():
            bus.unsubscribe(event_type, handler)

        self.tracer.shutdown()
        self._connected = False

    @property
    def spans(self) -> list:
        """Get all recorded spans."""
        return self._in_memory.get_spans()

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
        self.metrics.increment("llm_calls_total", labels={"model": data.get("model", "unknown")})
        self.metrics.increment("input_tokens_total", value=float(data.get("input_tokens", 0)))
        self.metrics.increment("output_tokens_total", value=float(data.get("output_tokens", 0)))
        self.metrics.set_gauge("total_cost_usd", data.get("total_cost_usd", 0.0))

    def _on_flag_found(self, data: Any) -> None:
        self.metrics.increment("flags_found_total")

    def _on_message(self, data: Any) -> None:
        msg_type = data.get("type", "info") if isinstance(data, dict) else "info"
        self.metrics.increment("messages_total", labels={"type": msg_type})

    def _on_error(self, data: Any) -> None:
        self.metrics.increment("errors_total")
