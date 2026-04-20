"""Unit tests for deep agent mode tools (execute, read_file, write_file)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from clearwing.agent.tools.hunt.deep_agent import _OUTPUT_CAP, build_deep_agent_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.sandbox.container import ExecResult


@pytest.fixture
def mock_sandbox():
    sb = MagicMock()
    sb.exec.return_value = ExecResult(
        exit_code=0, stdout="hello\n", stderr="", duration_seconds=0.1
    )
    return sb


@pytest.fixture
def ctx(mock_sandbox):
    return HunterContext(repo_path="/tmp/repo", sandbox=mock_sandbox)


@pytest.fixture
def tools(ctx):
    return {t.name: t for t in build_deep_agent_tools(ctx)}


def test_build_deep_agent_tools_set(ctx):
    """The deep-agent tool palette deliberately does NOT include a
    `think` tool. Model reasoning is captured via
    `capture_reasoning_content=True` on every chat request and written
    into the hunter transcript's `reasoning_content` field — a scratchpad
    tool would be a redundant no-op that wastes a tool-call round-trip."""
    tools = build_deep_agent_tools(ctx)
    names = {t.name for t in tools}
    assert "think" not in names
    assert {"execute", "read_file", "write_file", "record_finding"} <= names


def test_execute_runs_command(tools, mock_sandbox):
    result = tools["execute"].handler(command="ls -la")
    mock_sandbox.exec.assert_called_once_with("ls -la", timeout=300)
    assert result["exit_code"] == 0
    assert result["stdout"] == "hello\n"
    assert result["timed_out"] is False
    assert "duration_seconds" in result


def test_execute_custom_timeout(tools, mock_sandbox):
    tools["execute"].handler(command="make", timeout=600)
    mock_sandbox.exec.assert_called_once_with("make", timeout=600)


def test_execute_caps_large_output(tools, mock_sandbox):
    big_stdout = "x" * (_OUTPUT_CAP + 1000)
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=0, stdout=big_stdout, stderr="", duration_seconds=0.1
    )
    result = tools["execute"].handler(command="cat bigfile")
    assert len(result["stdout"]) < len(big_stdout)
    assert "truncated" in result["stdout"]


def test_execute_no_sandbox():
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=None)
    tools = {t.name: t for t in build_deep_agent_tools(ctx)}
    result = tools["execute"].handler(command="ls")
    assert "error" in result


def test_read_file_with_defaults(tools, mock_sandbox):
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=0,
        stdout="     1\tline1\n     2\tline2\n",
        stderr="",
        duration_seconds=0.05,
    )
    result = tools["read_file"].handler(path="/workspace/foo.c")
    mock_sandbox.exec.assert_called_once()
    cmd = mock_sandbox.exec.call_args[0][0]
    assert "awk" in cmd
    assert "/workspace/foo.c" in cmd
    # Default offset=0, limit=2000 → start=1, end=2000
    assert "s=1" in cmd
    assert "e=2000" in cmd
    assert "line1" in result


def test_read_file_with_offset_limit(tools, mock_sandbox):
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=0, stdout="content", stderr="", duration_seconds=0.05
    )
    tools["read_file"].handler(path="/workspace/bar.c", offset=10, limit=50)
    cmd = mock_sandbox.exec.call_args[0][0]
    # offset=10, limit=50 → start=11, end=60
    assert "s=11" in cmd
    assert "e=60" in cmd


def test_read_file_uses_absolute_line_numbers(tools, mock_sandbox):
    """Regression: previously `sed ... | cat -n` numbered output from 1
    regardless of offset, so a hunter asking for lines 101-150 got
    back "line 1..line 50" and then reported findings against the
    wrong line numbers. The awk command must emit NR (the file's real
    line number) not a 1-based counter of output lines.
    """
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=0, stdout="", stderr="", duration_seconds=0.01
    )
    tools["read_file"].handler(path="/workspace/x.c", offset=100, limit=50)
    cmd = mock_sandbox.exec.call_args[0][0]
    # The awk program must print NR (the file's real line number), not
    # a locally-rebased counter. The regex must reference NR directly
    # in the print expression.
    assert 'printf "%6d' in cmd and "NR, $0" in cmd, cmd


def test_read_file_error(tools, mock_sandbox):
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=1, stdout="", stderr="No such file", duration_seconds=0.01
    )
    result = tools["read_file"].handler(path="/workspace/missing.c")
    assert "error" in result.lower()


def test_write_file_creates_dirs(tools, mock_sandbox):
    result = tools["write_file"].handler(path="/workspace/new/dir/file.c", contents="int main() {}")
    assert mock_sandbox.exec.call_count == 1
    mkdir_cmd = mock_sandbox.exec.call_args[0][0]
    assert "mkdir -p" in mkdir_cmd
    mock_sandbox.write_file.assert_called_once_with("/workspace/new/dir/file.c", b"int main() {}")
    assert "Wrote" in result
    assert "13 bytes" in result


def test_record_finding_present(tools):
    assert "record_finding" in tools
