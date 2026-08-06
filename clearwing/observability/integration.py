"""Integration between observability and the Clearwing agent."""

from __future__ import annotations

import logging
import os
from typing import Any, ClassVar

from clearwing.core.events import EventBus, EventType

from .phoenix import phoenix_exporter_from_env
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

    For env-driven auto-wiring at process startup, prefer
    :meth:`bootstrap_from_env` — it is a no-op unless Phoenix env vars are set.
    """

    # Process-wide singleton established by :meth:`bootstrap_from_env` so
    # startup hooks in the CLI and webui don't double-subscribe. Tests may
    # clear this by calling ``disconnect()``, which unsets the reference.
    _singleton: ClassVar["ObservabilityIntegration | None"] = None

    def __init__(self, debug: bool = False, exporters: list = None):
        if exporters is None:
            exporters = []
            if debug:
                exporters.append(ConsoleExporter())
            if phoenix_exp := phoenix_exporter_from_env():
                exporters.append(phoenix_exp)
        self._in_memory = InMemoryExporter()
        exporters.append(self._in_memory)

        self.tracer = Tracer(service_name="clearwing", exporters=exporters)
        self.metrics = MetricsCollector()
        self._connected = False
        self._handlers = {}

    @classmethod
    def bootstrap_from_env(cls) -> "ObservabilityIntegration | None":
        """Idempotently instantiate + connect when Phoenix env vars are set.

        Returns the shared singleton, or ``None`` if
        ``PHOENIX_ENDPOINT`` / ``PHOENIX_PROJECT`` are unset. Safe to call
        from every process entry point (CLI ``main()``, FastAPI
        ``create_app()``, machine-fd subcommand); subsequent calls return the
        already-connected instance without re-subscribing to the EventBus.
        """
        if cls._singleton is not None:
            return cls._singleton
        if not os.environ.get("PHOENIX_ENDPOINT") or not os.environ.get("PHOENIX_PROJECT"):
            return None
        instance = cls()
        instance.connect()
        cls._singleton = instance
        logger.info("ObservabilityIntegration bootstrapped from env")
        return instance

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
        # Release the bootstrap singleton so a follow-up bootstrap can create
        # a fresh instance (primarily useful for tests).
        if type(self)._singleton is self:
            type(self)._singleton = None

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
        model = data.get("model", "unknown")
        input_tokens = int(data.get("input_tokens", 0) or 0)
        output_tokens = int(data.get("output_tokens", 0) or 0)
        cached_tokens = int(data.get("cached_tokens", 0) or 0)

        self.metrics.increment("llm_calls_total", labels={"model": model})
        self.metrics.increment("input_tokens_total", value=float(input_tokens))
        self.metrics.increment("output_tokens_total", value=float(output_tokens))
        self.metrics.set_gauge("total_cost_usd", data.get("total_cost_usd", 0.0))

        # Emit a synthetic span so Arize Phoenix sees per-call LLM telemetry.
        # Attribute names follow the OpenInference semantic conventions —
        # https://github.com/Arize-ai/openinference/blob/main/spec/semantic_conventions.md
        # — so Phoenix renders the span in its LLM view rather than as a
        # generic "internal" span.
        import time

        now = time.time()
        elapsed_ms = data.get("elapsed_ms", 0) or 0
        elapsed_s = elapsed_ms / 1000.0
        attributes = {
            "openinference.span.kind": "LLM",
            "llm.model_name": model,
            "llm.provider": data.get("provider", "unknown"),
            "llm.token_count.prompt": input_tokens,
            "llm.token_count.completion": output_tokens,
            "llm.token_count.total": input_tokens + output_tokens,
            "llm.token_count.cached": cached_tokens,
            "llm.cost_usd": data.get("total_cost_usd", 0.0),
        }
        with self.tracer.span("llm_call", attributes=attributes) as s:
            # Backdate start so the span duration reflects actual call latency.
            if elapsed_s > 0:
                s.start_time = now - elapsed_s

    def _on_flag_found(self, data: Any) -> None:
        self.metrics.increment("flags_found_total")

    def _on_message(self, data: Any) -> None:
        msg_type = data.get("type", "info") if isinstance(data, dict) else "info"
        self.metrics.increment("messages_total", labels={"type": msg_type})

    def _on_error(self, data: Any) -> None:
        self.metrics.increment("errors_total")
