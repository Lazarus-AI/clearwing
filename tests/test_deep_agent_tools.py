"""Unit tests for deep agent mode search and sandbox tools."""

from __future__ import annotations

import subprocess
from pathlib import Path
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
    assert "semgrep_scan" not in names
    assert {
        "grep_source",
        "find_source",
        "execute",
        "read_file",
        "write_file",
        "record_finding",
    } <= names


def _repo_tools(repo: Path):
    return {t.name: t for t in build_deep_agent_tools(HunterContext(repo_path=str(repo)))}


def test_deep_grep_source_bounded_and_explicit_empty(tmp_path):
    source = tmp_path / "src" / "codec.c"
    source.parent.mkdir()
    source.write_text("".join(f"needle {line}\n" for line in range(45)))
    tools = _repo_tools(tmp_path)

    found = tools["grep_source"].invoke({"pattern": "needle", "path": "src"})
    assert found["status"] == "truncated"
    assert found["truncated"] is True
    assert found["count"] == 40
    assert found["matches"][0] == {
        "file": "src/codec.c",
        "line_number": 1,
        "matched_text": "needle 0",
    }
    assert "read_file" in found["next_action"]

    empty = tools["grep_source"].invoke({"pattern": "absent", "path": "src"})
    assert empty["status"] == "no_matches"
    assert empty["matches"] == []
    assert empty["truncated"] is False


def test_deep_find_source_matches_files_directories_and_stays_in_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "src" / "parser"
    target.mkdir(parents=True)
    for index in range(45):
        (target / f"parser_{index:02}.c").write_text("int x;\n")
    outside = tmp_path / "outside_secret.c"
    outside.write_text("secret\n")
    (repo / "outside_secret.c").symlink_to(outside)
    tools = _repo_tools(repo)

    files = tools["find_source"].invoke({"query": "parser_", "kind": "file"})
    assert files["status"] == "truncated"
    assert files["count"] == 40
    assert all(hit["type"] == "file" for hit in files["matches"])
    directories = tools["find_source"].invoke({"query": "pars*", "kind": "directory"})
    assert directories["matches"] == [{"path": "src/parser", "type": "directory"}]
    assert tools["find_source"].invoke({"query": "missing"})["status"] == "no_matches"
    assert tools["find_source"].invoke({"query": "secret"})["status"] == "no_matches"
    assert tools["find_source"].invoke({"query": "x", "path": "../"})["status"] == "error"


def test_deep_grep_sandbox_command_has_global_result_cap(tmp_path):
    source = tmp_path / "src.c"
    source.write_text("needle\n")
    sandbox = MagicMock()
    sandbox.exec.return_value = ExecResult(
        exit_code=0,
        stdout="".join(f"/workspace/src.c:{line}:needle\n" for line in range(1, 42)),
        stderr="",
        duration_seconds=0.01,
    )
    tools = {t.name: t for t in build_deep_agent_tools(HunterContext(str(tmp_path), sandbox))}

    result = tools["grep_source"].invoke({"pattern": "needle"})

    assert result["status"] == "truncated"
    assert len(result["matches"]) == 40
    command = sandbox.exec.call_args.args[0]
    assert "head -n 41" in command
    assert "/workspace" in command


def test_deep_find_uses_bounded_sandbox_repository_search(tmp_path):
    (tmp_path / "src").mkdir()
    sandbox = MagicMock()
    sandbox.exec.return_value = ExecResult(
        exit_code=0,
        stdout="directory\t/workspace/src/parser\nfile\t/workspace/src/parser.c\n",
        stderr="",
        duration_seconds=0.01,
    )
    tools = {t.name: t for t in build_deep_agent_tools(HunterContext(str(tmp_path), sandbox))}

    result = tools["find_source"].invoke({"query": "parser", "path": "src"})

    assert result["status"] == "matches"
    assert result["matches"] == [
        {"path": "src/parser", "type": "directory"},
        {"path": "src/parser.c", "type": "file"},
    ]
    command = sandbox.exec.call_args.args[0]
    assert "find /workspace/src" in command
    assert "head -n 41" in command
    assert sandbox.exec.call_args.kwargs["timeout"] == 30


def test_deep_find_sandbox_command_returns_real_paths(tmp_path):
    (tmp_path / "src" / "parser").mkdir(parents=True)
    (tmp_path / "src" / "parser.c").write_text("int parse(void);\n")
    sandbox = MagicMock()

    def run_in_test_repo(command, timeout):
        completed = subprocess.run(
            command.replace("/workspace", str(tmp_path)),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ExecResult(
            exit_code=completed.returncode,
            stdout=completed.stdout.replace(str(tmp_path), "/workspace"),
            stderr=completed.stderr,
            duration_seconds=0.01,
        )

    sandbox.exec.side_effect = run_in_test_repo
    tools = {t.name: t for t in build_deep_agent_tools(HunterContext(str(tmp_path), sandbox))}

    result = tools["find_source"].invoke({"query": "pars*", "path": "src"})

    assert result["status"] == "matches"
    assert result["matches"] == [
        {"path": "src/parser", "type": "directory"},
        {"path": "src/parser.c", "type": "file"},
    ]


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


@pytest.mark.parametrize(
    "command",
    [
        "find / -name evp.h",
        "cd /workspace && find /workspace -name internal.h",
        "grep -rn cipher_final / 2>/dev/null | head",
        "grep -rn RDPGFX_SURFACE_COMMAND --include=*.h .",
        "find . -name pkcs15.h",
    ],
)
def test_execute_redirects_broad_search_to_repository_tools(tools, mock_sandbox, command):
    result = tools["execute"].handler(command=command)
    assert "grep_source" in result["error"]
    assert "find_source" in result["error"]
    mock_sandbox.exec.assert_not_called()


def test_execute_ignores_unexpected_arguments(tools, mock_sandbox):
    result = tools["execute"].invoke({"command": "ls -la", "_comment": "list files"})
    mock_sandbox.exec.assert_called_once_with("ls -la", timeout=300)
    assert result["exit_code"] == 0


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


def test_read_file_appends_total_line_metadata(tools, mock_sandbox):
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=0,
        stdout="     1\tline1\n",
        stderr="__CLEARWING_TOTAL_LINES__=1\n",
        duration_seconds=0.05,
    )

    result = tools["read_file"].handler(path="/workspace/foo.c")

    assert result.endswith("[CLEARWING_READ_METADATA total_lines=1]")


def test_read_file_with_offset_limit(tools, mock_sandbox):
    mock_sandbox.exec.return_value = ExecResult(
        exit_code=0, stdout="content", stderr="", duration_seconds=0.05
    )
    tools["read_file"].handler(path="/workspace/bar.c", offset=10, limit=50)
    cmd = mock_sandbox.exec.call_args[0][0]
    # offset=10, limit=50 → start=11, end=60
    assert "s=11" in cmd
    assert "e=60" in cmd


def test_read_file_ignores_unexpected_arguments(tools, mock_sandbox):
    result = tools["read_file"].invoke(
        {"path": "/workspace/foo.c", "description": "inspect source"}
    )
    mock_sandbox.exec.assert_called_once()
    assert result == "hello\n"


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


def test_write_file_ignores_unexpected_arguments(tools, mock_sandbox):
    result = tools["write_file"].invoke(
        {
            "path": "/workspace/new/file.c",
            "contents": "source",
            "_comment": "create fixture",
        }
    )
    mock_sandbox.write_file.assert_called_once_with("/workspace/new/file.c", b"source")
    assert result == "Wrote 6 bytes to /workspace/new/file.c"


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
    with pytest.raises(TypeError):
        tools[tool_name].invoke(arguments)


def test_record_finding_present(tools):
    assert "record_finding" in tools
