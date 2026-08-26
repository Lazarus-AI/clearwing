"""Unit tests for deep agent mode tools (execute, read_file, write_file)."""

from __future__ import annotations

from unittest.mock import MagicMock

import jsonschema
import pytest

from clearwing.agent.tools.hunt.deep_agent import _OUTPUT_CAP, build_deep_agent_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.sandbox.container import ExecResult
from clearwing.sourcehunt.callgraph import CallGraphBuilder


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


def test_read_function_lazily_indexes_go_definition(tmp_path, mock_sandbox):
    builder = CallGraphBuilder()
    if not builder.available:
        pytest.skip("tree-sitter grammars not installed")

    target = tmp_path / "target.go"
    target.write_text("package sample\n\nfunc Entry() {}\n", encoding="utf-8")
    helper = tmp_path / "models" / "helper.go"
    helper.parent.mkdir()
    helper.write_text(
        "package models\n\nfunc CanMaintainerWriteToBranch() bool { return true }\n",
        encoding="utf-8",
    )
    graph = builder.build(str(tmp_path), files=[str(target)])
    assert "CanMaintainerWriteToBranch" not in graph.defined_in

    ctx = HunterContext(repo_path=str(tmp_path), sandbox=mock_sandbox, callgraph=graph)
    tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}
    result = tools["read_function"].invoke({"name": "CanMaintainerWriteToBranch"})

    assert result["status"] == "found_after_expansion"
    assert result["file"] == "models/helper.go"
    assert graph.defined_in["CanMaintainerWriteToBranch"] == {"models/helper.go"}


def test_read_function_reports_ambiguous_lazy_go_definitions(tmp_path, mock_sandbox):
    builder = CallGraphBuilder()
    if not builder.available:
        pytest.skip("tree-sitter grammars not installed")

    target = tmp_path / "target.go"
    target.write_text("package sample\n\nfunc Entry() {}\n", encoding="utf-8")
    for directory, receiver in (("one", "First"), ("two", "Second")):
        candidate = tmp_path / directory / "helper.go"
        candidate.parent.mkdir()
        candidate.write_text(
            f"package {directory}\n\ntype {receiver} struct{{}}\n"
            f"func ({receiver}) Check() bool {{ return true }}\n",
            encoding="utf-8",
        )
    graph = builder.build(str(tmp_path), files=[str(target)])
    ctx = HunterContext(repo_path=str(tmp_path), sandbox=mock_sandbox, callgraph=graph)
    tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}

    result = tools["read_function"].invoke({"name": "Check"})

    assert result["status"] == "ambiguous"
    assert {candidate["file"] for candidate in result["candidates"]} == {
        "one/helper.go",
        "two/helper.go",
    }


def test_read_function_lazily_indexes_rust_definition(tmp_path, mock_sandbox):
    builder = CallGraphBuilder()
    if not builder.available:
        pytest.skip("tree-sitter grammars not installed")

    target = tmp_path / "target.rs"
    target.write_text("fn entry() {}\n", encoding="utf-8")
    helper = tmp_path / "src" / "vectors.rs"
    helper.parent.mkdir()
    helper.write_text(
        "impl Device {\n    pub(crate) fn allocate_vectors<T>(&self) -> usize { 4 }\n}\n",
        encoding="utf-8",
    )
    graph = builder.build(str(tmp_path), files=[str(target)])
    ctx = HunterContext(
        repo_path=str(tmp_path),
        file_path="target.rs",
        sandbox=mock_sandbox,
        callgraph=graph,
    )
    tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}

    result = tools["read_function"].invoke({"name": "allocate_vectors"})

    assert result["status"] == "found_after_expansion"
    assert result["file"] == "src/vectors.rs"
    assert graph.defined_in["allocate_vectors"] == {"src/vectors.rs"}


def test_lookup_callers_discloses_partial_coverage(tmp_path, mock_sandbox):
    builder = CallGraphBuilder()
    if not builder.available:
        pytest.skip("tree-sitter grammars not installed")

    target = tmp_path / "target.go"
    target.write_text("package sample\n\nfunc Entry() {}\n", encoding="utf-8")
    graph = builder.build(str(tmp_path), files=[str(target)])
    ctx = HunterContext(repo_path=str(tmp_path), sandbox=mock_sandbox, callgraph=graph)
    tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}

    result = tools["lookup_callers"].invoke({"func_name": "Missing"})

    assert result["coverage"] == {
        "scope": "indexed_files_only",
        "indexed_file_count": 1,
        "complete": False,
    }
    assert "unindexed files may contain callers" in result["note"]


def test_lookup_callees_lazily_indexes_c_definitions(tmp_path, mock_sandbox):
    builder = CallGraphBuilder()
    if not builder.available:
        pytest.skip("tree-sitter grammars not installed")

    target = tmp_path / "target.c"
    target.write_text(
        'int helper(int value);\nint entry(int value) { return helper(value) + printf("x"); }\n',
        encoding="utf-8",
    )
    helper = tmp_path / "lib" / "helper.c"
    helper.parent.mkdir()
    helper.write_text(
        "static int unrelated(void) { return 0; }\nint helper(int value) { return value + 1; }\n",
        encoding="utf-8",
    )
    graph = builder.build(str(tmp_path), files=[str(target)])
    assert "helper" not in graph.defined_in
    ctx = HunterContext(repo_path=str(tmp_path), sandbox=mock_sandbox, callgraph=graph)
    tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}

    result = tools["lookup_callees"].invoke({"func_name": "entry"})

    assert result["callees"] == {
        "lib/helper.c": [{"func": "helper", "start_line": 2, "end_line": 2}]
    }
    assert "printf" in result["unresolved"]
    assert graph.defined_in["helper"] == {"lib/helper.c"}
    assert result["coverage"]["indexed_file_count"] == 2


def test_lookup_callees_lazily_indexes_rust_definitions(tmp_path, mock_sandbox):
    builder = CallGraphBuilder()
    if not builder.available:
        pytest.skip("tree-sitter grammars not installed")

    target = tmp_path / "target.rs"
    target.write_text(
        "fn entry(value: u32) -> u32 { helper(value) + external(value) }\n",
        encoding="utf-8",
    )
    helper = tmp_path / "src" / "helper.rs"
    helper.parent.mkdir()
    helper.write_text(
        "pub(crate) async fn helper<T>(value: u32) -> u32 { value + 1 }\n",
        encoding="utf-8",
    )
    graph = builder.build(str(tmp_path), files=[str(target)])
    assert "helper" not in graph.defined_in
    ctx = HunterContext(repo_path=str(tmp_path), sandbox=mock_sandbox, callgraph=graph)
    tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}

    result = tools["lookup_callees"].invoke({"func_name": "entry"})

    assert result["callees"] == {
        "src/helper.rs": [{"func": "helper", "start_line": 1, "end_line": 1}]
    }
    assert "external" in result["unresolved"]
    assert graph.defined_in["helper"] == {"src/helper.rs"}
    assert result["coverage"]["indexed_file_count"] == 2


def test_execute_runs_command(tools, mock_sandbox):
    result = tools["execute"].handler(command="ls -la")
    mock_sandbox.exec.assert_called_once_with("ls -la", timeout=30)
    assert result["exit_code"] == 0
    assert result["stdout"] == "hello\n"
    assert result["timed_out"] is False
    assert "duration_seconds" in result


def test_execute_custom_shorter_timeout(tools, mock_sandbox):
    tools["execute"].handler(command="make", timeout=10)
    mock_sandbox.exec.assert_called_once_with("make", timeout=10)


def test_execute_caps_timeout_at_thirty_seconds(tools, mock_sandbox):
    tools["execute"].handler(command="make", timeout=600)
    mock_sandbox.exec.assert_called_once_with("make", timeout=30)


def test_execute_schema_rejects_timeout_above_thirty_seconds(tools, mock_sandbox):
    with pytest.raises(jsonschema.ValidationError):
        tools["execute"].invoke({"command": "make", "timeout": 31})
    mock_sandbox.exec.assert_not_called()


def test_execute_rejects_unexpected_arguments(tools, mock_sandbox):
    with pytest.raises(jsonschema.ValidationError):
        tools["execute"].invoke({"command": "ls -la", "_comment": "list files"})
    mock_sandbox.exec.assert_not_called()


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


def test_read_file_rejects_unexpected_arguments(tools, mock_sandbox):
    with pytest.raises(jsonschema.ValidationError):
        tools["read_file"].invoke({"path": "/workspace/foo.c", "description": "inspect source"})
    mock_sandbox.exec.assert_not_called()


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


def test_write_file_rejects_unexpected_arguments(tools, mock_sandbox):
    with pytest.raises(jsonschema.ValidationError):
        tools["write_file"].invoke(
            {
                "path": "/workspace/new/file.c",
                "contents": "source",
                "_comment": "create fixture",
            }
        )
    mock_sandbox.exec.assert_not_called()
    mock_sandbox.write_file.assert_not_called()


@pytest.mark.parametrize("tool_name", ["execute", "read_file", "write_file"])
def test_deep_agent_tool_schemas_disallow_extra_properties(tools, tool_name):
    assert tools[tool_name].schema["additionalProperties"] is False


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("execute", {}),
        ("read_file", {}),
        ("write_file", {"path": "/workspace/file.c"}),
    ],
)
def test_deep_agent_tools_still_require_declared_arguments(tools, tool_name, arguments):
    with pytest.raises(jsonschema.ValidationError):
        tools[tool_name].invoke(arguments)


def test_record_finding_present(tools):
    assert "record_finding" in tools
