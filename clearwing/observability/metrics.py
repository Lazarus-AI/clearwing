"""Metrics collection for Clearwing operations."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MetricPoint:
    """A single metric data point."""
    name: str
    value: float
    timestamp: float
    labels: dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # gauge, counter, histogram


class MetricsCollector:
    """Collects and exposes operational metrics.

    Tracks:
    - LLM call counts, latencies, token usage
    - Tool call counts, latencies, success rates
    - Scan progress (ports scanned, services found, vulns found)
    - Cost accumulation over time
    - Agent turn counts

    Thread-safe for concurrent access.

    Usage::

        metrics = MetricsCollector()
        metrics.increment("llm_calls_total", labels={"model": "claude-sonnet-4-6"})
        metrics.observe("llm_latency_seconds", 1.5, labels={"model": "claude-sonnet-4-6"})
        metrics.set_gauge("total_cost_usd", 0.05)
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}
        self._labels: dict[str, dict[str, str]] = {}
        self._history: list[MetricPoint] = []
        self._max_history = 10000

    def increment(self, name: str, value: float = 1.0, labels: dict = None) -> None:
        """Increment a counter metric."""
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value
            if labels:
                self._labels[key] = labels
            self._record(name, self._counters[key], labels, "counter")

    def set_gauge(self, name: str, value: float, labels: dict = None) -> None:
        """Set a gauge metric to an absolute value."""
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value
            if labels:
                self._labels[key] = labels
            self._record(name, value, labels, "gauge")

    def observe(self, name: str, value: float, labels: dict = None) -> None:
        """Record an observation for a histogram metric."""
        key = self._key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)
            if labels:
                self._labels[key] = labels
            self._record(name, value, labels, "histogram")

    def get_counter(self, name: str, labels: dict = None) -> float:
        """Get the current value of a counter."""
        key = self._key(name, labels)
        with self._lock:
            return self._counters.get(key, 0.0)

    def get_gauge(self, name: str, labels: dict = None) -> float:
        """Get the current value of a gauge."""
        key = self._key(name, labels)
        with self._lock:
            return self._gauges.get(key, 0.0)

    def get_histogram(self, name: str, labels: dict = None) -> dict:
        """Get histogram statistics."""
        key = self._key(name, labels)
        with self._lock:
            values = self._histograms.get(key, [])
            if not values:
                return {"count": 0, "sum": 0.0, "min": 0.0, "max": 0.0, "avg": 0.0}
            return {
                "count": len(values),
                "sum": sum(values),
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
            }

    def get_all_metrics(self) -> dict:
        """Get all current metric values."""
        with self._lock:
            result = {"counters": {}, "gauges": {}, "histograms": {}}
            for key, value in self._counters.items():
                result["counters"][key] = {
                    "value": value,
                    "labels": self._labels.get(key, {}),
                }
            for key, value in self._gauges.items():
                result["gauges"][key] = {
                    "value": value,
                    "labels": self._labels.get(key, {}),
                }
            for key, values in self._histograms.items():
                result["histograms"][key] = {
                    "count": len(values),
                    "sum": sum(values),
                    "min": min(values) if values else 0,
                    "max": max(values) if values else 0,
                    "avg": sum(values) / len(values) if values else 0,
                    "labels": self._labels.get(key, {}),
                }
            return result

    def get_history(self, name: str = None, limit: int = 100) -> list[MetricPoint]:
        """Get historical metric points."""
        with self._lock:
            if name:
                points = [p for p in self._history if p.name == name]
            else:
                points = list(self._history)
            return points[-limit:]

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._labels.clear()
            self._history.clear()

    def format_prometheus(self) -> str:
        """Format all metrics in Prometheus exposition format."""
        lines = []
        with self._lock:
            for key, value in sorted(self._counters.items()):
                labels = self._labels.get(key, {})
                label_str = self._format_labels(labels)
                name = key.split("{")[0] if "{" in key else key
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name}{label_str} {value}")

            for key, value in sorted(self._gauges.items()):
                labels = self._labels.get(key, {})
                label_str = self._format_labels(labels)
                name = key.split("{")[0] if "{" in key else key
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name}{label_str} {value}")

            for key, values in sorted(self._histograms.items()):
                labels = self._labels.get(key, {})
                label_str = self._format_labels(labels)
                name = key.split("{")[0] if "{" in key else key
                lines.append(f"# TYPE {name} summary")
                lines.append(f"{name}_count{label_str} {len(values)}")
                lines.append(f"{name}_sum{label_str} {sum(values)}")

        return "\n".join(lines)

    @staticmethod
    def _key(name: str, labels: dict = None) -> str:
        if not labels:
            return name
        label_parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_parts}}}"

    @staticmethod
    def _format_labels(labels: dict) -> str:
        if not labels:
            return ""
        parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{{{parts}}}"

    def _record(self, name: str, value: float, labels: dict, metric_type: str) -> None:
        """Record a metric point in history (caller must hold lock)."""
        point = MetricPoint(
            name=name,
            value=value,
            timestamp=time.time(),
            labels=labels or {},
            metric_type=metric_type,
        )
        self._history.append(point)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
