"""Phoenix span exporter via the OpenTelemetry OTLP pipeline.

Configuration via environment variables (both required for env-based init):
    PHOENIX_ENDPOINT    — Phoenix collector endpoint
    PHOENIX_PROJECT     — Project name
"""

from __future__ import annotations

import logging
import os

from .tracer import Span, SpanExporter

logger = logging.getLogger(__name__)


def _span_kind_from_openinference(span: Span):
    """Derive OTel SpanKind from an ``openinference.span.kind`` attribute.

    Phoenix's UI keys off both the attribute string and the OTel ``SpanKind``
    enum. We keep the attribute on the outgoing span (so Phoenix classifies it
    correctly) and additionally translate to the most fitting OTel kind:

    - ``"LLM"`` / ``"TOOL"``  → ``SpanKind.CLIENT`` (outbound call)
    - ``"CHAIN"`` / ``"AGENT"`` → ``SpanKind.INTERNAL`` (internal orchestration)
    - unset / anything else   → ``SpanKind.INTERNAL``
    """
    from opentelemetry.trace import SpanKind

    kind = span.attributes.get("openinference.span.kind")
    if kind in ("LLM", "TOOL"):
        return SpanKind.CLIENT
    return SpanKind.INTERNAL


def _to_readable_span(span: Span, resource):
    """Bridge a Clearwing Span to an OTel ReadableSpan."""
    from opentelemetry.sdk.trace import ReadableSpan as _ReadableSpan
    from opentelemetry.trace import SpanContext, TraceFlags
    from opentelemetry.trace.status import Status, StatusCode

    trace_id = int(span.trace_id, 16) & ((1 << 128) - 1)
    span_id = int(span.span_id, 16) & ((1 << 64) - 1)
    parent_id = int(span.parent_span_id, 16) & ((1 << 64) - 1) if span.parent_span_id else 0

    ctx = SpanContext(trace_id=trace_id, span_id=span_id, is_remote=False, trace_flags=TraceFlags(0x01))
    parent_ctx = SpanContext(trace_id=trace_id, span_id=parent_id, is_remote=False, trace_flags=TraceFlags(0x01)) if parent_id else None

    status = Status(StatusCode.ERROR, span.attributes.get("error.message", "")) if span.status == "error" else Status(StatusCode.OK)

    return _ReadableSpan(
        name=span.name,
        context=ctx,
        parent=parent_ctx,
        resource=resource,
        attributes=span.attributes,
        events=tuple(),
        kind=_span_kind_from_openinference(span),
        status=status,
        start_time=int(span.start_time * 1e9),
        end_time=int(span.end_time * 1e9),
    )


class PhoenixExporter(SpanExporter):
    """Exports Clearwing spans to a self-hosted Phoenix instance via OTel OTLP/HTTP."""

    def __init__(self, endpoint: str, project_name: str):
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        self.endpoint = endpoint.rstrip("/")
        self.project_name = project_name

        self._resource = Resource.create({"service.name": "clearwing", "project.name": self.project_name})
        otlp = OTLPSpanExporter(endpoint=f"{self.endpoint}/v1/traces")
        self._processor = BatchSpanProcessor(otlp)
        logger.info("PhoenixExporter → %s (project=%s)", self.endpoint, self.project_name)

    def export(self, spans: list[Span]) -> None:
        for span in spans:
            self._processor.on_end(_to_readable_span(span, self._resource))

    def shutdown(self) -> None:
        self._processor.shutdown()


def phoenix_exporter_from_env() -> PhoenixExporter | None:
    """Create a PhoenixExporter if PHOENIX_ENDPOINT and PHOENIX_PROJECT are set, else return None."""
    endpoint = os.environ.get("PHOENIX_ENDPOINT")
    project = os.environ.get("PHOENIX_PROJECT")
    if not endpoint or not project:
        return None
    return PhoenixExporter(endpoint=endpoint, project_name=project)
