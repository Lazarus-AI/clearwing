"""Tests for record_finding / record_trace_step (clearwing/agent/tools/hunt/reporting.py)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from clearwing.agent.tools.hunt.reporting import build_reporting_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext


@pytest.fixture
def ctx():
    return HunterContext(repo_path="/tmp/repo", sandbox=MagicMock(), agent_mode="deep")


@pytest.fixture
def tools(ctx):
    return {t.name: t.handler for t in build_reporting_tools(ctx)}


def _record_finding(tools, **overrides):
    args = dict(
        file="app.py",
        line_number=42,
        finding_type="sql_injection",
        severity="high",
        cwe="CWE-89",
        description="SQL built via string concatenation.",
        code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
    )
    args.update(overrides)
    return tools["record_finding"](**args)


def test_record_finding_requires_trace_step(tools):
    result = _record_finding(tools)
    assert result["error"]["code"] == "MISSING_TRACE"


def test_record_finding_records_after_trace_step(tools, ctx):
    tools["record_trace_step"](
        file="app.py", line=42, note="ENTRY/SINK: SQL reaches database execution"
    )
    result = _record_finding(tools)
    assert "Finding recorded" in result
    assert len(ctx.findings) == 1


def test_record_finding_rejects_exact_line_duplicate(tools, ctx):
    tools["record_trace_step"](file="app.py", line=42, note="ENTRY/SINK: first path")
    first = _record_finding(tools)
    assert "Finding recorded" in first

    tools["record_trace_step"](file="app.py", line=42, note="ENTRY/SINK: entry again")
    second = _record_finding(tools, description="Differently worded but same bug.")

    assert second["error"]["code"] == "DUPLICATE_FINDING"
    assert len(ctx.findings) == 1  # the duplicate must NOT be appended
    assert len(ctx.trace_steps) == 1  # rejected duplicate preserves accumulated evidence


def test_record_finding_allows_different_lines(tools, ctx):
    tools["record_trace_step"](file="app.py", line=42, note="ENTRY/SINK: first path")
    _record_finding(tools, line_number=42)

    tools["record_trace_step"](file="app.py", line=99, note="ENTRY/SINK: second path")
    result = _record_finding(tools, line_number=99, description="A different bug entirely.")

    assert "Finding recorded" in result
    assert len(ctx.findings) == 2


def test_record_finding_rejects_trace_without_entry_and_sink(tools, ctx):
    tools["record_trace_step"](file="app.py", line=42, note="Relevant code")

    result = _record_finding(tools)

    assert result["error"]["code"] == "INCOMPLETE_TRACE"
    assert len(ctx.findings) == 0
    assert len(ctx.trace_steps) == 1
