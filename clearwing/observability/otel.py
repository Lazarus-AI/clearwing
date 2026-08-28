"""Standard OpenTelemetry setup and Clearwing tracing helpers."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

from openinference.instrumentation import OITracer, TraceConfig
from openinference.semconv.trace import OpenInferenceSpanKindValues
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanProcessor

from clearwing.provenance import clearwing_build_provenance

logger = logging.getLogger(__name__)

_provider_lock = threading.Lock()
_provider: TracerProvider | None = None


class _ClearwingProvenanceSpanProcessor(SpanProcessor):
    """Attach build identity directly to every span exported by Clearwing."""

    def __init__(self) -> None:
        provenance = clearwing_build_provenance()
        self._attributes = {
            "clearwing.version": provenance["version"],
            "clearwing.commit_sha": provenance["commit_sha"],
        }

    def on_start(self, span, parent_context=None) -> None:  # type: ignore[no-untyped-def]
        for key, value in self._attributes.items():
            span.set_attribute(key, value)

    def on_end(self, span) -> None:  # type: ignore[no-untyped-def]
        return None

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return True

def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


_trace_config = TraceConfig(
    hide_inputs=not _env_enabled("CLEARWING_TRACE_INPUTS"),
    hide_outputs=not _env_enabled("CLEARWING_TRACE_OUTPUTS"),
)


def telemetry_configured() -> bool:
    """Return whether environment configuration requests OTLP tracing."""
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        return False
    return bool(
        os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("PHOENIX_ENDPOINT")
    )


def configure_telemetry(
    *,
    exporters: Sequence[SpanExporter] | None = None,
    service_name: str | None = None,
) -> TracerProvider | None:
    """Configure the process-wide OTel SDK once.

    Standard ``OTEL_*`` variables are preferred. ``PHOENIX_ENDPOINT`` and
    ``PHOENIX_PROJECT`` remain supported as compatibility aliases.
    """
    global _provider

    if exporters is None and not telemetry_configured():
        return None
    with _provider_lock:
        if _provider is not None:
            return _provider

        current = trace.get_tracer_provider()
        if isinstance(current, TracerProvider):
            current.add_span_processor(_ClearwingProvenanceSpanProcessor())
            _provider = current
            logger.info("Using the process's existing OpenTelemetry SDK provider")
            return current

        resource_attributes: dict[str, str] = {
            "service.name": service_name or os.environ.get("OTEL_SERVICE_NAME", "clearwing")
        }
        if project := os.environ.get("PHOENIX_PROJECT"):
            resource_attributes["openinference.project.name"] = project

        provider = TracerProvider(resource=Resource.create(resource_attributes))
        provider.add_span_processor(_ClearwingProvenanceSpanProcessor())
        selected_exporters = list(exporters) if exporters is not None else [_otlp_exporter()]
        for exporter in selected_exporters:
            provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        _provider = provider
        logger.info("OpenTelemetry configured for service %s", resource_attributes["service.name"])
        return provider


def _otlp_exporter() -> SpanExporter:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    # Let the exporter resolve the standard endpoint and header variables,
    # including their signal-specific variants. They take precedence over the
    # Phoenix compatibility aliases below.
    if os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT"
    ):
        return OTLPSpanExporter()

    if endpoint := os.environ.get("PHOENIX_ENDPOINT"):
        kwargs: dict[str, object] = {"endpoint": f"{endpoint.rstrip('/')}/v1/traces"}
        standard_headers_configured = bool(
            os.environ.get("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
            or os.environ.get("OTEL_EXPORTER_OTLP_HEADERS")
        )
        if api_key := os.environ.get("PHOENIX_API_KEY"):
            if not standard_headers_configured:
                kwargs["headers"] = {"api_key": api_key}
        return OTLPSpanExporter(**kwargs)
    return OTLPSpanExporter()


def get_tracer(name: str = "clearwing") -> trace.Tracer:
    """Return a tracer from the active process-wide provider."""
    return trace.get_tracer(name)


def get_oi_tracer(name: str = "clearwing") -> OITracer:
    """Return a privacy-safe OpenInference tracer over the active OTel tracer."""
    return OITracer(get_tracer(name), config=_trace_config)


@contextmanager
def llm_span(*, model: str, provider: str | None = None) -> Iterator[trace.Span]:
    """Create a current LLM span using OTel GenAI and OpenInference attributes."""
    model_name = model if isinstance(model, str) else "unknown"
    provider_name = provider if isinstance(provider, str) and provider else "unknown"
    attributes = {
        "openinference.span.kind": "LLM",
        "llm.model_name": model_name,
        "llm.provider": provider_name,
        "gen_ai.operation.name": "chat",
        "gen_ai.provider.name": provider_name,
        "gen_ai.request.model": model_name,
    }
    with get_oi_tracer("clearwing.llm").start_as_current_span(
        "llm.chat",
        attributes=attributes,
        kind=trace.SpanKind.CLIENT,
        openinference_span_kind=OpenInferenceSpanKindValues.LLM,
    ) as span:
        yield span


def record_llm_result(
    span: trace.Span,
    *,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
    cost_usd: float | None = None,
    response_model: str | None = None,
) -> None:
    """Attach response usage to an LLM span without recording prompt content."""
    span.set_attribute("gen_ai.usage.input_tokens", input_tokens)
    span.set_attribute("gen_ai.usage.output_tokens", output_tokens)
    span.set_attribute("llm.token_count.prompt", input_tokens)
    span.set_attribute("llm.token_count.completion", output_tokens)
    span.set_attribute("llm.token_count.total", input_tokens + output_tokens)
    span.set_attribute("llm.token_count.cached", cached_tokens)
    if cost_usd is not None:
        span.set_attribute("llm.cost_usd", cost_usd)
    if isinstance(response_model, str) and response_model:
        span.set_attribute("gen_ai.response.model", response_model)


def force_flush(timeout_millis: int = 30_000) -> bool:
    """Flush the configured SDK provider, if Clearwing owns it."""
    return _provider.force_flush(timeout_millis) if _provider is not None else True


def shutdown_telemetry() -> None:
    """Flush and shut down the configured SDK provider."""
    if _provider is not None:
        _provider.shutdown()
