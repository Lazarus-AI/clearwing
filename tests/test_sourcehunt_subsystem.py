"""Tests for spec 006 — cross-subsystem hunt mode."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.sourcehunt.state import FileTarget, SubsystemTarget
from clearwing.sourcehunt.subsystem import (
    SubsystemHuntConfig,
    SubsystemHuntRunner,
    _dir_prefix,
    identify_subsystems_auto,
    subsystem_from_path,
)


def _ft(path: str, priority: float = 2.0, tags: list | None = None) -> FileTarget:
    return FileTarget(
        path=path,
        language="c",
        loc=500,
        tags=tags or [],
        priority=priority,
        surface=int(priority),
        influence=2,
        reachability=3,
    )


# ---------------------------------------------------------------------------
# _dir_prefix
# ---------------------------------------------------------------------------


def test_dir_prefix_two_components():
    assert _dir_prefix("net/ipv4/tcp_input.c") == "net/ipv4"


def test_dir_prefix_one_component():
    assert _dir_prefix("src/main.c") == "src"


def test_dir_prefix_flat():
    assert _dir_prefix("main.c") == "main.c"


def test_dir_prefix_deep():
    assert _dir_prefix("a/b/c/d/e.c") == "a/b"


# ---------------------------------------------------------------------------
# identify_subsystems_auto
# ---------------------------------------------------------------------------


def test_identify_subsystems_auto_basic():
    files = [
        _ft("net/ipv4/tcp_input.c", 4.0),
        _ft("net/ipv4/tcp_output.c", 3.5),
        _ft("net/ipv4/tcp_sack.c", 4.5),
        _ft("net/ipv4/utils.c", 1.5),
        _ft("fs/ext4/inode.c", 2.0),
        _ft("fs/ext4/super.c", 2.5),
    ]
    result = identify_subsystems_auto(files)
    assert len(result) == 1
    assert result[0].root_path == "net/ipv4"
    assert result[0].name == "net_ipv4"
    assert len(result[0].files) == 4  # includes the low-priority utils.c
    assert result[0].priority == 4.5


def test_identify_subsystems_auto_multiple_dirs():
    files = [
        _ft("net/ipv4/tcp_input.c", 4.0),
        _ft("net/ipv4/tcp_output.c", 4.0),
        _ft("net/ipv4/tcp_sack.c", 4.0),
        _ft("fs/nfsd/nfs4proc.c", 4.0),
        _ft("fs/nfsd/nfs4state.c", 4.0),
        _ft("fs/nfsd/nfs4xdr.c", 4.0),
    ]
    result = identify_subsystems_auto(files)
    assert len(result) == 2
    names = {s.name for s in result}
    assert "net_ipv4" in names
    assert "fs_nfsd" in names


def test_identify_subsystems_auto_below_threshold():
    files = [
        _ft("net/ipv4/tcp_input.c", 4.0),
        _ft("net/ipv4/tcp_output.c", 4.0),
        # Only 2 high-rank files — below threshold of 3
        _ft("net/ipv4/utils.c", 1.0),
    ]
    result = identify_subsystems_auto(files)
    assert len(result) == 0


def test_identify_subsystems_auto_max_files_cap():
    files = [_ft(f"net/ipv4/file_{i}.c", 4.0) for i in range(80)]
    result = identify_subsystems_auto(files, max_files_per_subsystem=50)
    assert len(result) == 1
    assert len(result[0].files) == 50


def test_identify_subsystems_auto_max_subsystems_cap():
    files = []
    for i in range(15):
        for j in range(3):
            files.append(_ft(f"dir{i}/sub/file_{j}.c", 4.0))
    result = identify_subsystems_auto(files, max_subsystems=10)
    assert len(result) == 10


def test_subsystem_priority_is_max():
    files = [
        _ft("net/ipv4/a.c", 3.0),
        _ft("net/ipv4/b.c", 4.5),
        _ft("net/ipv4/c.c", 4.0),
    ]
    result = identify_subsystems_auto(files)
    assert len(result) == 1
    assert result[0].priority == 4.5


def test_identify_subsystems_auto_sorted_by_priority():
    files = [
        _ft("alpha/sub/a.c", 4.0),
        _ft("alpha/sub/b.c", 4.0),
        _ft("alpha/sub/c.c", 4.0),
        _ft("beta/sub/a.c", 5.0),
        _ft("beta/sub/b.c", 5.0),
        _ft("beta/sub/c.c", 5.0),
    ]
    result = identify_subsystems_auto(files)
    assert len(result) == 2
    assert result[0].priority >= result[1].priority


def test_identify_subsystems_with_entry_points():
    files = [
        _ft("net/ipv4/a.c", 4.0),
        _ft("net/ipv4/b.c", 4.0),
        _ft("net/ipv4/c.c", 4.0),
    ]
    mock_ep = MagicMock()
    mock_ep.function_name = "tcp_rcv"
    ep_map = {"net/ipv4/a.c": [mock_ep]}

    result = identify_subsystems_auto(files, entry_points_by_file=ep_map)
    assert len(result) == 1
    assert len(result[0].entry_points) == 1


# ---------------------------------------------------------------------------
# subsystem_from_path
# ---------------------------------------------------------------------------


def test_subsystem_from_path_basic():
    files = [
        _ft("net/ipv4/tcp_input.c", 4.0),
        _ft("net/ipv4/tcp_output.c", 3.5),
        _ft("fs/ext4/inode.c", 2.0),
    ]
    result = subsystem_from_path("net/ipv4", files)
    assert result.source == "manual"
    assert len(result.files) == 2
    assert result.priority == 4.0
    assert result.root_path == "net/ipv4"


def test_subsystem_from_path_trailing_slash():
    files = [_ft("net/ipv4/tcp.c", 4.0)]
    result = subsystem_from_path("net/ipv4/", files)
    assert len(result.files) == 1


def test_subsystem_from_path_glob():
    files = [
        _ft("libavcodec/h264_parser.c", 4.0),
        _ft("libavcodec/h264_slice.c", 3.5),
        _ft("libavcodec/vp9_decode.c", 2.0),
    ]
    result = subsystem_from_path("libavcodec/h264*", files)
    assert len(result.files) == 2


def test_subsystem_from_path_no_match():
    files = [_ft("src/main.c", 2.0)]
    with pytest.raises(ValueError, match="No files match"):
        subsystem_from_path("nonexistent/dir", files)


def test_subsystem_from_path_max_files():
    files = [_ft(f"net/ipv4/f_{i}.c", float(i % 5)) for i in range(80)]
    result = subsystem_from_path("net/ipv4", files, max_files=50)
    assert len(result.files) == 50


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------


def test_subsystem_prompt_includes_file_listing():
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    subsystem = SubsystemTarget(
        name="net_ipv4",
        root_path="net/ipv4",
        files=[_ft("net/ipv4/tcp.c", 4.0), _ft("net/ipv4/udp.c", 3.0)],
    )
    prompt = _build_subsystem_prompt(subsystem, "linux")
    assert "net/ipv4/tcp.c" in prompt
    assert "net/ipv4/udp.c" in prompt
    assert "net_ipv4" in prompt
    assert "linux" in prompt


def test_subsystem_prompt_cross_file_calls():
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    callgraph = MagicMock()
    callgraph.calls_out = {"net/ipv4/tcp.c": {"send_data"}}
    callgraph.defined_in = {"send_data": {"net/ipv4/udp.c"}}

    subsystem = SubsystemTarget(
        name="net_ipv4",
        root_path="net/ipv4",
        files=[_ft("net/ipv4/tcp.c", 4.0), _ft("net/ipv4/udp.c", 3.0)],
    )
    prompt = _build_subsystem_prompt(subsystem, "linux", callgraph=callgraph)
    assert "tcp.c" in prompt
    assert "udp.c" in prompt
    # Cross-file calls are no longer explicitly listed in the prompt;
    # the callgraph is used at runtime via lookup_callers instead.
    assert "cross-file" in prompt.lower()


def test_subsystem_prompt_existing_findings():
    from clearwing.sourcehunt.findings_pool import FindingsPool
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    pool = FindingsPool()
    from clearwing.findings.types import Finding

    f = Finding(
        id="f1", file="net/ipv4/tcp.c", line_number=42,
        cwe="CWE-787", severity="high", description="heap overflow in tcp",
        primitive_type="bounded_write", cluster_id="c1",
    )
    pool._findings["f1"] = f

    subsystem = SubsystemTarget(
        name="net_ipv4",
        root_path="net/ipv4",
        files=[_ft("net/ipv4/tcp.c", 4.0)],
    )
    prompt = _build_subsystem_prompt(subsystem, "linux", findings_pool=pool)
    assert "heap overflow in tcp" in prompt
    assert "already found" in prompt


def test_subsystem_prompt_entry_points():
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    ep = MagicMock()
    ep.function_name = "tcp_rcv_established"
    ep.file_path = "net/ipv4/tcp_input.c"
    ep.entry_type = "protocol_parser"

    subsystem = SubsystemTarget(
        name="net_ipv4",
        root_path="net/ipv4",
        files=[_ft("net/ipv4/tcp_input.c", 4.0)],
        entry_points=[ep],
    )
    prompt = _build_subsystem_prompt(subsystem, "linux")
    assert "tcp_rcv_established" in prompt
    assert "protocol_parser" in prompt


# ---------------------------------------------------------------------------
# build_subsystem_hunter_agent
# ---------------------------------------------------------------------------


def test_build_subsystem_hunter_agent_tools():
    from clearwing.sourcehunt.hunter import build_subsystem_hunter_agent

    subsystem = SubsystemTarget(
        name="test_sub",
        root_path="src/parser",
        files=[_ft("src/parser/main.c", 4.0)],
    )
    mock_llm = MagicMock()
    hunter, ctx = build_subsystem_hunter_agent(
        subsystem=subsystem,
        repo_path="/tmp/repo",
        sandbox=None,
        llm=mock_llm,
        session_id="test-session",
    )
    tool_names = [t.name for t in hunter.tools]
    assert "execute" in tool_names
    assert "read_file" in tool_names
    assert "record_finding" in tool_names


def test_build_subsystem_hunter_agent_max_steps():
    from clearwing.sourcehunt.hunter import build_subsystem_hunter_agent

    subsystem = SubsystemTarget(
        name="test_sub",
        root_path="src/parser",
        files=[_ft("src/parser/main.c", 4.0)],
    )
    mock_llm = MagicMock()
    hunter, ctx = build_subsystem_hunter_agent(
        subsystem=subsystem,
        repo_path="/tmp/repo",
        sandbox=None,
        llm=mock_llm,
        session_id="test-session",
    )
    assert hunter.max_steps == 3000
    assert hunter.agent_mode == "deep"


def test_build_subsystem_hunter_agent_specialist():
    from clearwing.sourcehunt.hunter import build_subsystem_hunter_agent

    subsystem = SubsystemTarget(
        name="test_sub",
        root_path="src/parser",
        files=[_ft("src/parser/main.c", 4.0)],
    )
    mock_llm = MagicMock()
    hunter, ctx = build_subsystem_hunter_agent(
        subsystem=subsystem,
        repo_path="/tmp/repo",
        sandbox=None,
        llm=mock_llm,
        session_id="test-session",
    )
    assert ctx.specialist == "subsystem"
    assert ctx.file_path == "src/parser"


def test_build_subsystem_hunter_initial_message():
    from clearwing.sourcehunt.hunter import build_subsystem_hunter_agent

    subsystem = SubsystemTarget(
        name="net_ipv4",
        root_path="net/ipv4",
        files=[_ft("net/ipv4/tcp.c", 4.0), _ft("net/ipv4/udp.c", 3.0)],
    )
    mock_llm = MagicMock()
    hunter, ctx = build_subsystem_hunter_agent(
        subsystem=subsystem,
        repo_path="/tmp/repo",
        sandbox=None,
        llm=mock_llm,
        session_id="test-session",
    )
    assert "cross-file" in hunter.initial_user_message
    assert "net_ipv4" in hunter.initial_user_message
    assert "2 files" in hunter.initial_user_message


# ---------------------------------------------------------------------------
# NativeHunter.initial_user_message
# ---------------------------------------------------------------------------


def test_native_hunter_initial_user_message():
    from clearwing.agent.tools.hunt.sandbox import HunterContext
    from clearwing.sourcehunt.hunter import NativeHunter

    ctx = HunterContext(repo_path="/tmp", file_path="src/main.c")
    hunter = NativeHunter(
        llm=MagicMock(),
        prompt="test",
        tools=[],
        ctx=ctx,
        initial_user_message="Custom start message.",
    )
    assert hunter.initial_user_message == "Custom start message."


def test_native_hunter_default_message():
    from clearwing.agent.tools.hunt.sandbox import HunterContext
    from clearwing.sourcehunt.hunter import NativeHunter

    ctx = HunterContext(repo_path="/tmp", file_path="src/main.c")
    hunter = NativeHunter(
        llm=MagicMock(),
        prompt="test",
        tools=[],
        ctx=ctx,
    )
    assert hunter.initial_user_message == ""


# ---------------------------------------------------------------------------
# SubsystemHuntRunner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subsystem_hunt_runner_no_llm():
    runner = SubsystemHuntRunner(SubsystemHuntConfig(
        subsystems=[SubsystemTarget(name="test", root_path="src", files=[])],
        repo_path="/tmp",
        llm=None,
    ))
    result = await runner.arun()
    assert result == []


@pytest.mark.asyncio
async def test_subsystem_hunt_runner_no_subsystems():
    runner = SubsystemHuntRunner(SubsystemHuntConfig(
        subsystems=[],
        repo_path="/tmp",
        llm=MagicMock(),
    ))
    result = await runner.arun()
    assert result == []
