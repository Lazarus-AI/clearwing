"""Lightweight tracing for Clearwing agent operations."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Span:
    """A single trace span representing an operation."""

    trace_id: str
    span_id: str
    name: str
    parent_span_id: str | None = None
    start_time: float = 0.0
    end_time: float = 0.0
    status: str = "ok"  # ok, error
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def add_event(self, name: str, attributes: dict = None) -> None:
        self.events.append(
            {
                "name": name,
                "timestamp": time.time(),
                "attributes": attributes or {},
            }
        )

    def set_error(self, error: str) -> None:
        self.status = "error"
        self.attributes["error.message"] = error

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "attributes": self.attributes,
            "events": self.events,
        }


class SpanExporter:
    """Base class for span exporters."""

    def export(self, spans: list[Span]) -> None:
        raise NotImplementedError

    def shutdown(self) -> None:
        pass


class ConsoleExporter(SpanExporter):
    """Exports spans to the console/logger for debugging."""

    def export(self, spans: list[Span]) -> None:
        for span in spans:
            logger.info(
                "SPAN [%s] %s (%.1fms) status=%s attrs=%s",
                span.span_id[:8],
                span.name,
                span.duration_ms,
                span.status,
                span.attributes,
            )


class InMemoryExporter(SpanExporter):
    """Stores spans in memory for testing and inspection."""

    def __init__(self):
        self.spans: list[Span] = []
        self._lock = threading.Lock()

    def export(self, spans: list[Span]) -> None:
        with self._lock:
            self.spans.extend(spans)

    def get_spans(self, name: str = None) -> list[Span]:
        with self._lock:
            if name:
                return [s for s in self.spans if s.name == name]
            return list(self.spans)

    def clear(self) -> None:
        with self._lock:
            self.spans.clear()


class Tracer:
    """Lightweight tracer for instrumenting Clearwing operations.

    Supports:
    - Nested spans with parent-child relationships
    - Span attributes and events
    - Multiple exporters (console, in-memory, OTLP)
    - Thread-safe operation
    - Context manager API

    Usage::

        tracer = Tracer(service_name="clearwing")
        with tracer.span("scan_target", attributes={"target": "10.0.0.1"}) as s:
            # do work
            s.add_event("port_found", {"port": 22})
            with tracer.span("detect_services") as child:
                # nested work
                pass
    """

    def __init__(self, service_name: str = "clearwing", exporters: list[SpanExporter] = None):
        self.service_name = service_name
        self._exporters = exporters or []
        self._lock = threading.Lock()
        self._active_spans: dict[int, Span] = {}  # thread_id -> current span
        self._completed_spans: list[Span] = []
        self._batch_size = 10  # export after this many spans
        self._trace_id: str = uuid.uuid4().hex

    def new_trace(self) -> str:
        """Start a new trace and return the trace ID."""
        self._trace_id = uuid.uuid4().hex
        return self._trace_id

    @contextmanager
    def span(self, name: str, attributes: dict = None):
        """Create a span as a context manager.

        Automatically sets start/end times and parent relationships.
        """
        thread_id = threading.get_ident()
        parent = self._active_spans.get(thread_id)

        s = Span(
            trace_id=self._trace_id,
            span_id=uuid.uuid4().hex[:16],
            name=name,
            parent_span_id=parent.span_id if parent else None,
            start_time=time.time(),
            attributes=attributes or {},
        )
        s.set_attribute("service.name", self.service_name)

        self._active_spans[thread_id] = s

        try:
            yield s
        except Exception as e:
            s.set_error(str(e))
            raise
        finally:
            s.end_time = time.time()
            # Restore parent as active span
            if parent:
                self._active_spans[thread_id] = parent
            else:
                self._active_spans.pop(thread_id, None)

            with self._lock:
                self._completed_spans.append(s)
                if len(self._completed_spans) >= self._batch_size:
                    self._flush()

    def _flush(self) -> None:
        """Export completed spans to all exporters."""
        spans = self._completed_spans[:]
        self._completed_spans.clear()
        for exporter in self._exporters:
            try:
                exporter.export(spans)
            except Exception:
                logger.exception("Exporter %r failed", exporter)

    def flush(self) -> None:
        """Manually flush all pending spans."""
        with self._lock:
            self._flush()

    def shutdown(self) -> None:
        """Flush remaining spans and shut down exporters."""
        self.flush()
        for exporter in self._exporters:
            try:
                exporter.shutdown()
            except Exception:
                pass

    @property
    def active_span(self) -> Span | None:
        """Get the currently active span for this thread."""
        return self._active_spans.get(threading.get_ident())

    def get_completed_spans(self) -> list[Span]:
        """Get all completed spans (before flush)."""
        with self._lock:
            return list(self._completed_spans)
