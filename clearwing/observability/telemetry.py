"""Cost tracking and telemetry for Clearwing LLM usage."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from clearwing.core.events import EventBus, EventType


@dataclass
class ToolUsage:
    """Tracks usage statistics for a single tool."""

    name: str
    calls: int = 0
    total_duration_ms: int = 0


@dataclass
class CostSummary:
    """Snapshot of current cost and usage metrics."""

    input_tokens: int
    output_tokens: int
    total_cost_usd: float
    tool_calls: int
    by_tool: dict[str, ToolUsage]


class CostTracker:
    """Singleton that tracks LLM token usage, costs, and tool call metrics.

    Thread-safe via an internal lock.
    """

    _instance: CostTracker | None = None
    _lock_cls = threading.Lock  # used only for singleton creation

    # USD per 1M tokens. Adjust non-Claude rows to match your provider's
    # billing (glm-5.2 below is a self-hosted/gateway estimate).
    PRICING: dict[str, dict[str, float]] = {
        "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
        "claude-opus-4-7": {"input": 15.0, "output": 75.0},
        "claude-opus-4-6": {"input": 15.0, "output": 75.0},
        "claude-haiku-4-5": {"input": 0.80, "output": 4.0},
        # Self-hosted / air-gapped inference has no real per-token API cost,
        # but it must stay nonzero: HunterPool's tier dispatch gate
        # (pool.py _submit_next: `spent >= budget`) uses accumulated cost as
        # a proxy for work done to decide when to stop feeding it new files.
        # A price of exactly 0.0 makes `spent` permanently 0, which disables
        # that gate regardless of --budget and lets a hunt run against every
        # file in the repo. This is nominal — ~1/1000th of Haiku pricing —
        # so it still tracks token volume without applying real API rates to
        # free local generations.
        "local-model": {"input": 0.001, "output": 0.003},
        # Fireworks "Standard" serving path. cached_input applies to the subset
        # of input tokens served from the provider's prompt cache.
        "glm-5.2": {"input": 1.40, "cached_input": 0.14, "output": 4.40},
    }

    _DEFAULT_MODEL = "claude-sonnet-4-6"

    @classmethod
    def estimate_cost(
        cls,
        input_tokens: int,
        output_tokens: int,
        model: str,
        cached_tokens: int = 0,
    ) -> float:
        """USD cost for one call. Prices are per 1M tokens.

        ``cached_tokens`` (a subset of ``input_tokens``) bills at the model's
        ``cached_input`` rate when defined, else at the full input rate. Unknown
        models fall back to the default (Sonnet) pricing.
        """
        pricing = cls.PRICING.get(model, cls.PRICING[cls._DEFAULT_MODEL])
        cached_rate = pricing.get("cached_input", pricing["input"])
        uncached = max(input_tokens - cached_tokens, 0)
        return (
            uncached * pricing["input"]
            + cached_tokens * cached_rate
            + output_tokens * pricing["output"]
        ) / 1_000_000

    def __new__(cls) -> CostTracker:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._lock = threading.Lock()
        self.input_tokens: int = 0
        self.output_tokens: int = 0
        self.total_cost_usd: float = 0.0
        self.tool_calls: int = 0
        self.by_tool: dict[str, ToolUsage] = {}
        self.cost_limit: float | None = None
        self._initialized = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_llm_call(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str,
        cached_tokens: int = 0,
    ) -> None:
        """Record token usage for a single LLM call and update the running cost.

        If *model* is not present in the pricing table the default Sonnet
        pricing is used.  ``cached_tokens`` bills at the model's cached rate.
        When an ``EventBus`` is available a ``COST_UPDATE`` event is emitted
        after updating counters.
        """
        cost = self.estimate_cost(input_tokens, output_tokens, model, cached_tokens)

        with self._lock:
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.total_cost_usd += cost

        try:
            EventBus.emit(
                EventType.COST_UPDATE,
                {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost": cost,
                    "total_cost_usd": self.total_cost_usd,
                    "model": model,
                },
            )
        except Exception:
            pass  # telemetry should never break the caller

    def record_tool_call(self, tool_name: str, duration_ms: int) -> None:
        """Record a tool invocation and its wall-clock duration."""
        with self._lock:
            self.tool_calls += 1
            if tool_name not in self.by_tool:
                self.by_tool[tool_name] = ToolUsage(name=tool_name)
            usage = self.by_tool[tool_name]
            usage.calls += 1
            usage.total_duration_ms += duration_ms

    def get_summary(self) -> CostSummary:
        """Return a point-in-time snapshot of all tracked metrics."""
        with self._lock:
            return CostSummary(
                input_tokens=self.input_tokens,
                output_tokens=self.output_tokens,
                total_cost_usd=self.total_cost_usd,
                tool_calls=self.tool_calls,
                by_tool=dict(self.by_tool),
            )

    def is_over_limit(self) -> bool:
        """Return ``True`` if a cost limit is set and the current spend exceeds it."""
        with self._lock:
            if self.cost_limit is None:
                return False
            return self.total_cost_usd > self.cost_limit

    def reset(self) -> None:
        """Reset all counters to their initial state."""
        with self._lock:
            self.input_tokens = 0
            self.output_tokens = 0
            self.total_cost_usd = 0.0
            self.tool_calls = 0
            self.by_tool = {}
