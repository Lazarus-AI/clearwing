from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from clearwing.observability import otel


@pytest.fixture
def spans(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(otel, "get_tracer", provider.get_tracer)
    return exporter


def test_openinference_decorators_preserve_async_parentage(spans):
    tracer = otel.get_oi_tracer("test")

    @tracer.chain(name="child")
    async def child():
        await asyncio.sleep(0)

    @tracer.agent(name="parent")
    async def parent():
        await child()

    asyncio.run(parent())
    by_name = {span.name: span for span in spans.get_finished_spans()}
    assert by_name["child"].parent.span_id == by_name["parent"].context.span_id
    assert by_name["parent"].attributes["openinference.span.kind"] == "AGENT"


def test_llm_span_records_standard_and_openinference_attributes(spans):
    with otel.llm_span(model="gpt-5.4", provider="openai") as span:
        otel.record_llm_result(
            span,
            input_tokens=100,
            output_tokens=25,
            cached_tokens=40,
            cost_usd=0.003,
            response_model="gpt-5.4-2026-08-01",
        )

    finished = spans.get_finished_spans()[0]
    assert finished.name == "llm.chat"
    assert finished.kind.name == "CLIENT"
    assert finished.attributes["gen_ai.provider.name"] == "openai"
    assert finished.attributes["gen_ai.usage.input_tokens"] == 100
    assert finished.attributes["openinference.span.kind"] == "LLM"
    assert finished.attributes["llm.cost_usd"] == 0.003


def test_llm_spans_use_per_call_cost(spans):
    for cost in (3.0, 3.0):
        with otel.llm_span(model="claude-sonnet-4-6", provider="anthropic") as span:
            otel.record_llm_result(span, input_tokens=1_000_000, output_tokens=0, cost_usd=cost)

    assert [span.attributes["llm.cost_usd"] for span in spans.get_finished_spans()] == [3.0, 3.0]


def test_provenance_processor_attaches_build_metadata_to_every_span(spans, monkeypatch):
    commit_sha = "a" * 40
    monkeypatch.setenv("CLEARWING_COMMIT_SHA", commit_sha)
    provider = TracerProvider()
    provider.add_span_processor(otel._ClearwingProvenanceSpanProcessor())
    provider.add_span_processor(SimpleSpanProcessor(spans))
    tracer = provider.get_tracer("test")

    with tracer.start_as_current_span("parent"):
        with tracer.start_as_current_span("child"):
            pass

    for span in spans.get_finished_spans():
        assert span.attributes["clearwing.version"]
        assert span.attributes["clearwing.commit_sha"] == commit_sha


def test_openinference_decorator_records_exceptions(spans):
    tracer = otel.get_oi_tracer("test")

    @tracer.chain(name="broken")
    def broken():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        broken()
    finished = spans.get_finished_spans()[0]
    assert finished.status.is_ok is False
    assert [event.name for event in finished.events] == ["exception"]


def test_openinference_decorators_hide_inputs_and_outputs(spans):
    tracer = otel.get_oi_tracer("test")

    @tracer.tool(name="inspect_file")
    def inspect_file(secret_source: str) -> str:
        return secret_source.upper()

    assert inspect_file("private source") == "PRIVATE SOURCE"
    attributes = spans.get_finished_spans()[0].attributes
    assert attributes["input.value"] == "__REDACTED__"
    assert attributes["output.value"] == "__REDACTED__"


def test_standard_and_phoenix_environment_detection(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("PHOENIX_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert otel.telemetry_configured() is False

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    assert otel.telemetry_configured() is True
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://collector:4318/v1/traces")
    assert otel.telemetry_configured() is True
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert otel.telemetry_configured() is False


def test_phoenix_api_key_becomes_otlp_header(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_HEADERS", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", raising=False)
    monkeypatch.setenv("PHOENIX_ENDPOINT", "https://phoenix.example")
    monkeypatch.setenv("PHOENIX_API_KEY", "secret-key")

    with patch(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"
    ) as exporter:
        otel._otlp_exporter()

    exporter.assert_called_once_with(
        endpoint="https://phoenix.example/v1/traces",
        headers={"api_key": "secret-key"},
    )


def test_standard_otlp_configuration_takes_precedence_over_phoenix(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://otel.example/v1/traces")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=standard")
    monkeypatch.setenv("PHOENIX_ENDPOINT", "https://phoenix.example")
    monkeypatch.setenv("PHOENIX_API_KEY", "phoenix-key")

    with patch(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"
    ) as exporter:
        otel._otlp_exporter()

    exporter.assert_called_once_with()
