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


def test_record_finding_requires_complete_invariant_map_for_flagged_lead(tools, ctx):
    ctx.potentials.append(
        {
            "id": "lead-1",
            "file": "app.py",
            "line": 42,
            "security_invariant": "Queries must keep user input out of SQL syntax.",
        }
    )
    tools["record_trace_step"](
        file="app.py", line=42, note="ENTRY/SINK: user input reaches SQL execution"
    )

    result = _record_finding(tools)

    assert result["error"]["code"] == "INCOMPLETE_INVARIANT_MAP"
    assert len(ctx.findings) == 0
    assert len(ctx.trace_steps) == 1


def test_record_finding_requires_mapped_potential_for_subsystem_hunt(tools, ctx):
    ctx.require_invariant_map = True
    tools["record_trace_step"](
        file="app.py", line=42, note="ENTRY/SINK: user input reaches SQL execution"
    )

    result = _record_finding(tools)

    assert result["error"]["code"] == "INCOMPLETE_INVARIANT_MAP"
    assert len(ctx.findings) == 0


def test_record_finding_accepts_complete_invariant_map(tools, ctx):
    ctx.potentials.append(
        {
            "id": "lead-1",
            "file": "app.py",
            "line": 42,
            "security_boundary": "database query execution",
            "security_invariant": "Queries must keep user input out of SQL syntax.",
            "attacker_inputs": ["user_id"],
            "required_relationships": ["user_id must be passed as a bound parameter"],
            "observed_checks": ["no parameter binding occurs"],
            "missing_checks": ["no rejection or escaping before interpolation"],
        }
    )
    tools["record_trace_step"](
        file="app.py", line=42, note="ENTRY/SINK: user input reaches SQL execution"
    )

    result = _record_finding(tools)

    assert "Finding recorded" in result
    assert len(ctx.findings) == 1
    assert ctx.potentials == []
    assert ctx.potential_history[0]["status"] == "confirmed"
    assert ctx.potential_history[0]["finding_id"] == ctx.findings[0].id


def test_record_trace_step_below_cap_preserves_strings(tools, ctx):
    snippet = "x" * 100
    note = "y" * 200
    tools["record_trace_step"](file="app.py", line=1, code_snippet=snippet, note=note)
    step = ctx.trace_steps[0]
    assert step.code_snippet == snippet
    assert step.note == note
    assert step.truncated is False
    assert step.original_chars == 0


def test_record_trace_step_truncates_above_cap(ctx):
    ctx.trace_step_max_chars = 32
    tools = {t.name: t.handler for t in build_reporting_tools(ctx)}
    snippet = "a" * 100
    note = "b" * 50
    tools["record_trace_step"](file="app.py", line=1, code_snippet=snippet, note=note)
    step = ctx.trace_steps[0]
    assert step.code_snippet == "a" * 32
    assert step.note == "b" * 32
    assert step.truncated is True
    assert step.original_chars == 150


def test_record_trace_step_cap_disabled_leaves_strings_untouched(ctx):
    ctx.trace_step_max_chars = 0
    tools = {t.name: t.handler for t in build_reporting_tools(ctx)}
    snippet = "a" * 10_000
    note = "b" * 8_000
    tools["record_trace_step"](file="app.py", line=1, code_snippet=snippet, note=note)
    step = ctx.trace_steps[0]
    assert step.code_snippet == snippet
    assert step.note == note
    assert step.truncated is False
    assert step.original_chars == 0
