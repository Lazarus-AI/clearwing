"""Tests for the CostTracker telemetry module."""

from vulnexploit.observability.telemetry import CostTracker, CostSummary, ToolUsage


def _reset_tracker():
    """Reset the CostTracker singleton for test isolation."""
    CostTracker._instance = None


class TestToolUsage:
    def test_defaults(self):
        tu = ToolUsage(name="nmap")
        assert tu.name == "nmap"
        assert tu.calls == 0
        assert tu.total_duration_ms == 0


class TestCostSummary:
    def test_fields(self):
        cs = CostSummary(
            input_tokens=100,
            output_tokens=50,
            total_cost_usd=0.01,
            tool_calls=3,
            by_tool={},
        )
        assert cs.input_tokens == 100
        assert cs.total_cost_usd == 0.01


class TestCostTracker:
    def setup_method(self):
        _reset_tracker()

    def teardown_method(self):
        _reset_tracker()

    def test_singleton(self):
        t1 = CostTracker()
        t2 = CostTracker()
        assert t1 is t2

    def test_initial_state(self):
        t = CostTracker()
        assert t.input_tokens == 0
        assert t.output_tokens == 0
        assert t.total_cost_usd == 0.0
        assert t.tool_calls == 0
        assert t.by_tool == {}
        assert t.cost_limit is None

    def test_record_llm_call_sonnet(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        # Cost = (1000 * 3.0 + 500 * 15.0) / 1_000_000 = (3000 + 7500) / 1M = 0.0105
        assert t.input_tokens == 1000
        assert t.output_tokens == 500
        assert abs(t.total_cost_usd - 0.0105) < 1e-6

    def test_record_llm_call_opus(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-opus-4-6")
        # Cost = (1000 * 15.0 + 500 * 75.0) / 1_000_000 = (15000 + 37500) / 1M = 0.0525
        assert abs(t.total_cost_usd - 0.0525) < 1e-6

    def test_record_llm_call_haiku(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-haiku-4-5")
        # Cost = (1000 * 0.80 + 500 * 4.0) / 1_000_000 = (800 + 2000) / 1M = 0.0028
        assert abs(t.total_cost_usd - 0.0028) < 1e-6

    def test_unknown_model_uses_sonnet_pricing(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "unknown-model")
        assert abs(t.total_cost_usd - 0.0105) < 1e-6

    def test_cumulative_calls(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        t.record_llm_call(2000, 1000, "claude-sonnet-4-6")
        assert t.input_tokens == 3000
        assert t.output_tokens == 1500

    def test_record_tool_call(self):
        t = CostTracker()
        t.record_tool_call("scan_ports", 150)
        t.record_tool_call("scan_ports", 200)
        t.record_tool_call("detect_os", 50)
        assert t.tool_calls == 3
        assert t.by_tool["scan_ports"].calls == 2
        assert t.by_tool["scan_ports"].total_duration_ms == 350
        assert t.by_tool["detect_os"].calls == 1

    def test_get_summary(self):
        t = CostTracker()
        t.record_llm_call(100, 50, "claude-sonnet-4-6")
        t.record_tool_call("nmap", 100)
        summary = t.get_summary()
        assert isinstance(summary, CostSummary)
        assert summary.input_tokens == 100
        assert summary.output_tokens == 50
        assert summary.tool_calls == 1
        assert "nmap" in summary.by_tool

    def test_is_over_limit_no_limit(self):
        t = CostTracker()
        t.record_llm_call(1000000, 500000, "claude-opus-4-6")
        assert not t.is_over_limit()

    def test_is_over_limit_under(self):
        t = CostTracker()
        t.cost_limit = 1.0
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        assert not t.is_over_limit()

    def test_is_over_limit_exceeded(self):
        t = CostTracker()
        t.cost_limit = 0.001
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        assert t.is_over_limit()

    def test_reset(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        t.record_tool_call("nmap", 100)
        t.reset()
        assert t.input_tokens == 0
        assert t.output_tokens == 0
        assert t.total_cost_usd == 0.0
        assert t.tool_calls == 0
        assert t.by_tool == {}

    def test_pricing_table(self):
        assert "claude-sonnet-4-6" in CostTracker.PRICING
        assert "claude-opus-4-6" in CostTracker.PRICING
        assert "claude-haiku-4-5" in CostTracker.PRICING
        for model, prices in CostTracker.PRICING.items():
            assert "input" in prices
            assert "output" in prices
            assert prices["input"] > 0
            assert prices["output"] > 0
