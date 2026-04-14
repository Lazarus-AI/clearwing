"""Unit tests for the interactive @tool wrapper around sourcehunt."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


FIXTURE_PY_SQLI = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"


def test_hunt_source_code_is_discoverable_via_get_all_tools():
    from vulnexploit.agent.tools import get_all_tools
    tools = get_all_tools()
    names = {t.name for t in tools}
    assert "hunt_source_code" in names
    assert "list_sourcehunt_findings" in names


def test_get_sourcehunt_tools_returns_two_tools():
    from vulnexploit.agent.tools.sourcehunt_tools import get_sourcehunt_tools
    tools = get_sourcehunt_tools()
    assert len(tools) == 2
    names = {t.name for t in tools}
    assert names == {"hunt_source_code", "list_sourcehunt_findings"}


def test_hunt_source_code_runs_quick_against_local_fixture(tmp_path):
    """The @tool wrapper should run the runner end-to-end on a local path."""
    from vulnexploit.agent.tools.sourcehunt_tools import hunt_source_code

    summary = hunt_source_code.invoke({
        "repo_url_or_path": str(FIXTURE_PY_SQLI),
        "depth": "quick",
        "output_dir": str(tmp_path),
    })
    assert isinstance(summary, str)
    assert "Source hunt complete" in summary
    assert "Files ranked: 1" in summary
    # The py_sqli fixture has an f-string SQL injection that SourceAnalyzer
    # catches, so the summary should include at least one finding line
    assert "CRITICAL" in summary or "Top findings" in summary


def test_hunt_source_code_returns_summary_for_empty_repo(tmp_path):
    """An empty directory still produces a valid summary, not an error."""
    from vulnexploit.agent.tools.sourcehunt_tools import hunt_source_code

    empty = tmp_path / "empty_repo"
    empty.mkdir()
    summary = hunt_source_code.invoke({
        "repo_url_or_path": str(empty),
        "depth": "quick",
        "output_dir": str(tmp_path / "out"),
    })
    assert "Source hunt complete" in summary
    # Files ranked = 0 because there are no source files
    assert "Files ranked: 0" in summary


def test_list_sourcehunt_findings_recalls_recent_run(tmp_path):
    """After hunt_source_code runs, list_sourcehunt_findings returns the cache."""
    from vulnexploit.agent.tools.sourcehunt_tools import (
        hunt_source_code,
        list_sourcehunt_findings,
        _RECENT_SESSIONS,
    )

    # Clear the cache to start fresh
    _RECENT_SESSIONS.clear()

    hunt_source_code.invoke({
        "repo_url_or_path": str(FIXTURE_PY_SQLI),
        "depth": "quick",
        "output_dir": str(tmp_path),
    })

    findings = list_sourcehunt_findings.invoke({})
    assert isinstance(findings, list)
    assert len(findings) >= 1
    # Each finding has a file and line_number
    for f in findings:
        assert "file" in f
        assert "line_number" in f


def test_list_sourcehunt_findings_with_unknown_session_id():
    from vulnexploit.agent.tools.sourcehunt_tools import (
        list_sourcehunt_findings,
        _RECENT_SESSIONS,
    )
    _RECENT_SESSIONS.clear()
    out = list_sourcehunt_findings.invoke({"session_id": "missing"})
    assert isinstance(out, list)
    assert "no source hunts" in out[0]["error"]


def test_prompt_template_mentions_hunt_source_code():
    """The interactive agent's system prompt should advertise the new tool."""
    from vulnexploit.agent.prompts import SYSTEM_PROMPT_TEMPLATE
    assert "hunt_source_code" in SYSTEM_PROMPT_TEMPLATE
    assert "Overwing" in SYSTEM_PROMPT_TEMPLATE
