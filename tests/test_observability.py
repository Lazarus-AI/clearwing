"""Tests for the observability module."""

import threading
import time

import pytest

from clearwing.observability.integration import ObservabilityIntegration
from clearwing.observability.metrics import MetricPoint, MetricsCollector
from clearwing.observability.tracer import (
    ConsoleExporter,
    InMemoryExporter,
    Span,
    Tracer,
)

# ---------------------------------------------------------------------------
# Span tests
# ---------------------------------------------------------------------------


class TestSpan:
    def test_duration(self):
        s = Span(trace_id="t1", span_id="s1", name="test", start_time=1.0, end_time=2.5)
        assert s.duration_ms == 1500.0

    def test_duration_not_ended(self):
        s = Span(trace_id="t1", span_id="s1", name="test", start_time=1.0)
        assert s.duration_ms == 0.0

    def test_set_attribute(self):
        s = Span(trace_id="t1", span_id="s1", name="test")
        s.set_attribute("key", "value")
        assert s.attributes["key"] == "value"

    def test_add_event(self):
        s = Span(trace_id="t1", span_id="s1", name="test")
        s.add_event("found_port", {"port": 22})
        assert len(s.events) == 1
        assert s.events[0]["name"] == "found_port"
        assert s.events[0]["attributes"]["port"] == 22

    def test_set_error(self):
        s = Span(trace_id="t1", span_id="s1", name="test")
        s.set_error("connection refused")
        assert s.status == "error"
        assert s.attributes["error.message"] == "connection refused"

    def test_to_dict(self):
        s = Span(trace_id="t1", span_id="s1", name="test", start_time=1.0, end_time=2.0)
        d = s.to_dict()
        assert d["trace_id"] == "t1"
        assert d["span_id"] == "s1"
        assert d["duration_ms"] == 1000.0


# ---------------------------------------------------------------------------
# Exporter tests
# ---------------------------------------------------------------------------


class TestInMemoryExporter:
    def test_export(self):
        exp = InMemoryExporter()
        spans = [Span(trace_id="t1", span_id="s1", name="test")]
        exp.export(spans)
        assert len(exp.get_spans()) == 1

    def test_filter_by_name(self):
        exp = InMemoryExporter()
        exp.export(
            [
                Span(trace_id="t1", span_id="s1", name="scan"),
                Span(trace_id="t1", span_id="s2", name="exploit"),
            ]
        )
        assert len(exp.get_spans("scan")) == 1
        assert len(exp.get_spans("exploit")) == 1

    def test_clear(self):
        exp = InMemoryExporter()
        exp.export([Span(trace_id="t1", span_id="s1", name="test")])
        exp.clear()
        assert len(exp.get_spans()) == 0


class TestConsoleExporter:
    def test_export_no_error(self):
        exp = ConsoleExporter()
        spans = [Span(trace_id="t1", span_id="s1", name="test", start_time=1.0, end_time=2.0)]
        exp.export(spans)  # should not raise


# ---------------------------------------------------------------------------
# Tracer tests
# ---------------------------------------------------------------------------


class TestTracer:
    def test_span_context_manager(self):
        exporter = InMemoryExporter()
        tracer = Tracer(exporters=[exporter])
        tracer._batch_size = 1  # flush immediately

        with tracer.span("test_op") as s:
            s.set_attribute("key", "val")

        spans = exporter.get_spans()
        assert len(spans) == 1
        assert spans[0].name == "test_op"
        assert spans[0].attributes["key"] == "val"
        assert spans[0].duration_ms > 0

    def test_nested_spans(self):
        exporter = InMemoryExporter()
        tracer = Tracer(exporters=[exporter])
        tracer._batch_size = 100

        with tracer.span("parent"):
            with tracer.span("child"):
                pass

        tracer.flush()
        spans = exporter.get_spans()
        assert len(spans) == 2

        child_span = [s for s in spans if s.name == "child"][0]
        parent_span = [s for s in spans if s.name == "parent"][0]
        assert child_span.parent_span_id == parent_span.span_id

    def test_span_error(self):
        exporter = InMemoryExporter()
        tracer = Tracer(exporters=[exporter])
        tracer._batch_size = 1

        with pytest.raises(ValueError):
            with tracer.span("failing"):
                raise ValueError("boom")

        spans = exporter.get_spans()
        assert len(spans) == 1
        assert spans[0].status == "error"
        assert "boom" in spans[0].attributes["error.message"]

    def test_new_trace(self):
        tracer = Tracer()
        id1 = tracer._trace_id
        id2 = tracer.new_trace()
        assert id1 != id2

    def test_flush(self):
        exporter = InMemoryExporter()
        tracer = Tracer(exporters=[exporter])
        tracer._batch_size = 100  # won't auto-flush

        with tracer.span("op"):
            pass

        assert len(exporter.get_spans()) == 0
        tracer.flush()
        assert len(exporter.get_spans()) == 1

    def test_shutdown(self):
        exporter = InMemoryExporter()
        tracer = Tracer(exporters=[exporter])
        tracer._batch_size = 100

        with tracer.span("op"):
            pass

        tracer.shutdown()
        assert len(exporter.get_spans()) == 1

    def test_active_span(self):
        tracer = Tracer()
        assert tracer.active_span is None

        with tracer.span("test"):
            assert tracer.active_span is not None
            assert tracer.active_span.name == "test"

        assert tracer.active_span is None

    def test_service_name(self):
        exporter = InMemoryExporter()
        tracer = Tracer(service_name="my-service", exporters=[exporter])
        tracer._batch_size = 1

        with tracer.span("op"):
            pass

        spans = exporter.get_spans()
        assert spans[0].attributes["service.name"] == "my-service"

    def test_thread_safety(self):
        exporter = InMemoryExporter()
        tracer = Tracer(exporters=[exporter])
        tracer._batch_size = 100

        def worker(name):
            with tracer.span(name):
                time.sleep(0.01)

        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        tracer.flush()
        assert len(exporter.get_spans()) == 5


# ---------------------------------------------------------------------------
# MetricsCollector tests
# ---------------------------------------------------------------------------


class TestMetricsCollector:
    def test_increment(self):
        m = MetricsCollector()
        m.increment("calls")
        m.increment("calls")
        assert m.get_counter("calls") == 2.0

    def test_increment_with_value(self):
        m = MetricsCollector()
        m.increment("tokens", value=100)
        m.increment("tokens", value=50)
        assert m.get_counter("tokens") == 150.0

    def test_increment_with_labels(self):
        m = MetricsCollector()
        m.increment("calls", labels={"model": "sonnet"})
        m.increment("calls", labels={"model": "haiku"})
        assert m.get_counter("calls", labels={"model": "sonnet"}) == 1.0
        assert m.get_counter("calls", labels={"model": "haiku"}) == 1.0

    def test_set_gauge(self):
        m = MetricsCollector()
        m.set_gauge("cost", 0.05)
        assert m.get_gauge("cost") == 0.05
        m.set_gauge("cost", 0.10)
        assert m.get_gauge("cost") == 0.10

    def test_observe_histogram(self):
        m = MetricsCollector()
        m.observe("latency", 1.0)
        m.observe("latency", 2.0)
        m.observe("latency", 3.0)
        stats = m.get_histogram("latency")
        assert stats["count"] == 3
        assert stats["sum"] == 6.0
        assert stats["min"] == 1.0
        assert stats["max"] == 3.0
        assert stats["avg"] == 2.0

    def test_empty_histogram(self):
        m = MetricsCollector()
        stats = m.get_histogram("nonexistent")
        assert stats["count"] == 0

    def test_get_all_metrics(self):
        m = MetricsCollector()
        m.increment("calls")
        m.set_gauge("cost", 0.05)
        m.observe("latency", 1.5)
        result = m.get_all_metrics()
        assert "calls" in str(result["counters"])
        assert "cost" in str(result["gauges"])
        assert "latency" in str(result["histograms"])

    def test_reset(self):
        m = MetricsCollector()
        m.increment("calls")
        m.set_gauge("cost", 1.0)
        m.reset()
        assert m.get_counter("calls") == 0.0
        assert m.get_gauge("cost") == 0.0

    def test_format_prometheus(self):
        m = MetricsCollector()
        m.increment("http_requests_total", labels={"method": "GET"})
        m.set_gauge("memory_bytes", 1024.0)
        output = m.format_prometheus()
        assert "http_requests_total" in output
        assert "memory_bytes" in output
        assert "counter" in output
        assert "gauge" in output

    def test_history(self):
        m = MetricsCollector()
        m.increment("calls")
        m.increment("calls")
        history = m.get_history("calls")
        assert len(history) == 2
        assert all(h.name == "calls" for h in history)

    def test_history_limit(self):
        m = MetricsCollector()
        for _ in range(20):
            m.increment("calls")
        assert len(m.get_history("calls", limit=5)) == 5

    def test_thread_safety(self):
        m = MetricsCollector()

        def worker():
            for _ in range(100):
                m.increment("calls")

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert m.get_counter("calls") == 500.0


# ---------------------------------------------------------------------------
# MetricPoint tests
# ---------------------------------------------------------------------------


class TestMetricPoint:
    def test_fields(self):
        p = MetricPoint(name="calls", value=1.0, timestamp=time.time())
        assert p.name == "calls"
        assert p.metric_type == "gauge"

    def test_with_labels(self):
        p = MetricPoint(
            name="calls",
            value=1.0,
            timestamp=time.time(),
            labels={"model": "sonnet"},
            metric_type="counter",
        )
        assert p.labels["model"] == "sonnet"
        assert p.metric_type == "counter"


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestObservabilityIntegration:
    def test_init(self):
        obs = ObservabilityIntegration()
        assert obs.tracer is not None
        assert obs.metrics is not None
        assert obs._connected is False

    def test_init_debug(self):
        obs = ObservabilityIntegration(debug=True)
        # Should have ConsoleExporter + InMemoryExporter
        assert len(obs.tracer._exporters) == 2

    def test_connect_disconnect(self):
        obs = ObservabilityIntegration()
        obs.connect()
        assert obs._connected is True
        obs.disconnect()
        assert obs._connected is False

    def test_double_connect(self):
        obs = ObservabilityIntegration()
        obs.connect()
        obs.connect()  # should not raise or duplicate
        assert obs._connected is True
        obs.disconnect()

    def test_on_tool_start(self):
        obs = ObservabilityIntegration()
        obs._on_tool_start({"tool": "scan_ports"})
        assert obs.metrics.get_counter("tool_calls_total", labels={"tool": "scan_ports"}) == 1.0

    def test_on_tool_result(self):
        obs = ObservabilityIntegration()
        obs._on_tool_result(
            {
                "tool": "scan_ports",
                "content_length": 500,
                "flags_found": 0,
            }
        )
        assert (
            obs.metrics.get_gauge("tool_result_size_bytes", labels={"tool": "scan_ports"}) == 500.0
        )

    def test_on_tool_result_with_flags(self):
        obs = ObservabilityIntegration()
        obs._on_tool_result(
            {
                "tool": "kali_execute",
                "content_length": 100,
                "flags_found": 2,
            }
        )
        assert obs.metrics.get_counter("flags_found_total") == 2.0

    def test_on_cost_update(self):
        obs = ObservabilityIntegration()
        obs._on_cost_update(
            {
                "model": "claude-sonnet-4-6",
                "input_tokens": 1000,
                "output_tokens": 500,
                "total_cost_usd": 0.05,
            }
        )
        assert (
            obs.metrics.get_counter("llm_calls_total", labels={"model": "claude-sonnet-4-6"}) == 1.0
        )
        assert obs.metrics.get_counter("input_tokens_total") == 1000.0
        assert obs.metrics.get_gauge("total_cost_usd") == 0.05

    def test_on_flag_found(self):
        obs = ObservabilityIntegration()
        obs._on_flag_found({"flag": "flag{test}", "context": "output"})
        assert obs.metrics.get_counter("flags_found_total") == 1.0

    def test_on_message(self):
        obs = ObservabilityIntegration()
        obs._on_message({"content": "hello", "type": "info"})
        assert obs.metrics.get_counter("messages_total", labels={"type": "info"}) == 1.0

    def test_on_error(self):
        obs = ObservabilityIntegration()
        obs._on_error({"error": "something broke"})
        assert obs.metrics.get_counter("errors_total") == 1.0

    def test_spans_property(self):
        obs = ObservabilityIntegration()
        assert obs.spans == []
