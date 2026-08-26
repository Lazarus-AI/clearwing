"""Tests for spec 006 — cross-subsystem hunt mode."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from clearwing.llm import NativeToolSpec
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.state import FileTarget, StageOutcome, SubsystemTarget
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
    assert "Survey before committing" in prompt
    assert "For each major security boundary, build an invariant map" in prompt
    assert "Lifecycle/state" in prompt


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
    assert "vulnerabilities" in prompt.lower()


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


def test_subsystem_prompt_has_generic_cross_platform_path_threat_advice():
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    subsystem = SubsystemTarget(
        name="archive_extraction",
        root_path="src/extract",
        files=[_ft("src/extract/archive.c", 4.0)],
    )

    prompt = _build_subsystem_prompt(subsystem, "extractor")

    assert "Path confinement" in prompt
    assert "drive/UNC roots" in prompt
    assert "compact interpretation matrix" in prompt
    assert "every supported target platform" in prompt
    assert "backslash traversal" not in prompt.lower()


def test_subsystem_prompt_has_allocation_access_extent_threat_advice():
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    subsystem = SubsystemTarget(
        name="buffer_processing",
        root_path="src/buffer",
        files=[_ft("src/buffer/copy.c", 4.0)],
    )

    prompt = _build_subsystem_prompt(subsystem, "processor")
    normalized = " ".join(prompt.split())

    assert "Allocation/access extent" in normalized
    assert "expressions used for validation, allocation, and access" in normalized
    assert "live bounds of every object" in normalized
    assert "required inequalities" in normalized
    assert "values actually consumed at the sink" in normalized
    assert "gdi_CacheToSurface" not in normalized


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


def test_build_subsystem_hunter_agent_uses_serena_instead_of_callgraph_navigation(
    monkeypatch,
):
    from clearwing.sourcehunt import hunter as hunter_module

    def tool(name: str) -> NativeToolSpec:
        return NativeToolSpec(name=name, description=name, schema={}, handler=lambda: None)

    monkeypatch.setattr(
        hunter_module,
        "build_deep_agent_tools",
        lambda ctx: [
            tool("execute"),
            tool("lookup_callers"),
            tool("lookup_callees"),
            tool("list_functions"),
            tool("read_function"),
        ],
    )
    subsystem = SubsystemTarget(
        name="test_sub",
        root_path="src/parser",
        files=[_ft("src/parser/main.c", 4.0)],
    )

    built, _ = hunter_module.build_subsystem_hunter_agent(
        subsystem=subsystem,
        repo_path="/tmp/repo",
        sandbox=None,
        llm=MagicMock(),
        session_id="test-session",
        callgraph=MagicMock(functions={}, calls_out={}, defined_in={}),
        semantic_tools=[tool("serena_find_symbol"), tool("serena_find_referencing_symbols")],
    )

    tool_names = [item.name for item in built.tools]
    assert "execute" in tool_names
    assert "serena_find_symbol" in tool_names
    assert "serena_find_referencing_symbols" in tool_names
    assert not ({"lookup_callers", "lookup_callees", "list_functions", "read_function"} & set(tool_names))


def test_build_subsystem_hunter_agent_keeps_callgraph_navigation_without_serena(
    monkeypatch,
):
    from clearwing.sourcehunt import hunter as hunter_module

    def tool(name: str) -> NativeToolSpec:
        return NativeToolSpec(name=name, description=name, schema={}, handler=lambda: None)

    callgraph_tools = [
        tool("lookup_callers"),
        tool("lookup_callees"),
        tool("list_functions"),
        tool("read_function"),
    ]
    monkeypatch.setattr(
        hunter_module,
        "build_deep_agent_tools",
        lambda ctx: [tool("execute"), *callgraph_tools],
    )
    subsystem = SubsystemTarget(
        name="test_sub",
        root_path="src/parser",
        files=[_ft("src/parser/main.c", 4.0)],
    )

    built, _ = hunter_module.build_subsystem_hunter_agent(
        subsystem=subsystem,
        repo_path="/tmp/repo",
        sandbox=None,
        llm=MagicMock(),
        session_id="test-session",
        callgraph=MagicMock(functions={}, calls_out={}, defined_in={}),
    )

    assert {item.name for item in callgraph_tools} <= {item.name for item in built.tools}


@pytest.mark.asyncio
async def test_subsystem_runner_accumulates_unresolved_potentials(monkeypatch, tmp_path):
    subsystem = SubsystemTarget(
        name="test_sub",
        root_path="src/parser",
        files=[_ft("src/parser/main.c", 4.0)],
    )
    runner = SubsystemHuntRunner(
        SubsystemHuntConfig(subsystems=[subsystem], repo_path=str(tmp_path), llm=MagicMock())
    )
    potentials = [
        {
            "id": "lead-1",
            "file": "src/parser/main.c",
            "line": 12,
            "note": "unclear length",
            "hypothesis": "CWE-787",
            "priority": "high",
        }
    ]

    async def fake_run(*args, **kwargs):
        return [], 0.0, 0, "completed", potentials

    monkeypatch.setattr(runner, "_run_one_subsystem", fake_run)

    assert await runner.arun() == []
    assert runner.all_potentials == potentials


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
    assert hunter.max_steps == 2000
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


@pytest.mark.asyncio
async def test_subsystem_hunt_runner_preserves_budget_exhaustion(monkeypatch):
    runner = SubsystemHuntRunner(
        SubsystemHuntConfig(
            subsystems=[SubsystemTarget(name="test", root_path="src", files=[])],
            repo_path="/tmp",
            llm=MagicMock(),
        )
    )

    async def budget_exhausted(*args, **kwargs):
        return [], 1.0, 10, "budget_exhausted", []

    monkeypatch.setattr(runner, "_run_one_subsystem", budget_exhausted)

    assert await runner.arun() == []
    assert runner.budget_exhausted is True


def test_subsystem_budget_stop_marks_sourcehunt_run_incomplete(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "clearwing.sourcehunt.checkpoints.repository_commit_sha",
        lambda repo_path: "a" * 40,
    )

    class BudgetExhaustedSubsystemRunner:
        def __init__(self, config):
            self.total_spent = 1.0
            self.budget_exhausted = True
            self.all_potentials = []

        async def arun(self):
            return []

    monkeypatch.setattr(
        "clearwing.sourcehunt.subsystem.SubsystemHuntRunner",
        BudgetExhaustedSubsystemRunner,
    )
    repo = tmp_path / "repo"
    source_dir = repo / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "app.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    progress = []
    runner_options = {
        "repo_url": str(repo),
        "local_path": str(repo),
        "depth": "standard",
        "output_formats": ["json"],
        "no_rank": True,
        "no_verify": True,
        "no_exploit": True,
        "enable_mechanism_memory": False,
        "enable_knowledge_graph": False,
        "enable_behavior_monitor": False,
        "enable_findings_pool": False,
        "enable_subsystem_hunt": True,
        "subsystem_paths": ["src"],
        "no_per_file_hunt": True,
        "preprocessing": False,
        "shard_entry_points": False,
        "hunter_llm": MagicMock(),
        "sandbox_factory": lambda: None,
        "on_progress": progress.append,
    }
    output = tmp_path / "out"
    runner = SourceHuntRunner(
        output_dir=str(output),
        **runner_options,
    )

    result = runner.run()
    manifest = json.loads(
        (output / result.session_id / "manifest.json").read_text(encoding="utf-8")
    )

    assert runner._spend_ledger is not None
    assert runner._spend_ledger.exhausted is False
    assert result.status == "budget_exhausted"
    assert result.exit_code == 3
    assert result.checkpoint is not None
    assert result.checkpoint["hunt"]["result"]["subsystem_status"] == "budget_exhausted"
    assert result.pipeline_status.stages["subsystem_hunt"].outcome is StageOutcome.SKIPPED
    fresh_budget_event = next(
        event
        for event in progress
        if event.stage == "subsystem_hunt" and event.status == "budget_exhausted"
    )
    assert fresh_budget_event.findings_so_far == 0
    assert fresh_budget_event.cost_usd == 1.0
    assert manifest["status"] == "budget_exhausted"
    assert manifest["complete"] is False

    class UnexpectedSubsystemRunner:
        def __init__(self, config):
            raise AssertionError("subsystem hunt ran instead of restoring its checkpoint")

    monkeypatch.setattr(
        "clearwing.sourcehunt.subsystem.SubsystemHuntRunner",
        UnexpectedSubsystemRunner,
    )
    resumed_output = tmp_path / "resumed-out"
    first_run_event_count = len(progress)
    resumed = SourceHuntRunner(
        output_dir=str(resumed_output),
        checkpoint=result.checkpoint,
        **runner_options,
    )

    resumed_result = resumed.run()
    resumed_manifest = json.loads(
        (resumed_output / resumed_result.session_id / "manifest.json").read_text(encoding="utf-8")
    )

    assert resumed_result.status == "budget_exhausted"
    assert resumed_result.exit_code == 3
    assert resumed_result.pipeline_status.stages["subsystem_hunt"].outcome is StageOutcome.SKIPPED
    resumed_budget_event = next(
        event
        for event in progress[first_run_event_count:]
        if event.stage == "subsystem_hunt" and event.status == "budget_exhausted"
    )
    assert resumed_budget_event.findings_so_far == 0
    assert resumed_budget_event.cost_usd == 1.0
    assert resumed_manifest["status"] == "budget_exhausted"
    assert resumed_manifest["complete"] is False


# ---------------------------------------------------------------------------
# File-cap: configurable + never silent (regression for CVE-2026-5747)
# ---------------------------------------------------------------------------


def test_subsystem_from_path_uncapped_by_default():
    """An explicit --subsystem PATH is a deliberate scope: hunt every match."""
    files = [_ft(f"net/f{i}.c", priority=1.0) for i in range(120)]
    st = subsystem_from_path("net", files)
    assert len(st.files) == 120


def test_explicit_scope_retains_ground_truth_file_uncapped():
    """CVE-2026-5747 shape: >50 equal-priority siblings, ground-truth file last.

    Under the old silent [:50] cap it was dropped out of scope; uncapped-by-
    default now keeps it.
    """
    files = [_ft(f"transport/pci/f{i}.c", priority=1.0) for i in range(85)]
    files.append(_ft("transport/pci/common_config.c", priority=1.0))
    st = subsystem_from_path("transport/pci", files)
    assert "transport/pci/common_config.c" in [f["path"] for f in st.files]


def test_subsystem_from_path_explicit_cap_warns_and_drops(caplog):
    files = [_ft(f"net/f{i}.c", priority=float(i)) for i in range(60)]
    with caplog.at_level("WARNING"):
        st = subsystem_from_path("net", files, max_files=50)
    assert len(st.files) == 50
    assert "DROPPING" in caplog.text


def test_identify_subsystems_auto_default_cap_warns_on_drop(caplog):
    files = [_ft(f"net/ipv4/f{i}.c", priority=3.5) for i in range(60)]
    with caplog.at_level("WARNING"):
        subs = identify_subsystems_auto(files)
    assert len(subs) == 1
    assert len(subs[0].files) == 50  # DEFAULT_MAX_FILES_PER_SUBSYSTEM
    assert "DROPPED" in caplog.text


def test_identify_subsystems_auto_uncapped_keeps_all():
    files = [_ft(f"net/ipv4/f{i}.c", priority=3.5) for i in range(60)]
    subs = identify_subsystems_auto(files, max_files_per_subsystem=None)
    assert len(subs) == 1
    assert len(subs[0].files) == 60


def test_identify_subsystems_auto_custom_cap_is_honored():
    files = [_ft(f"net/ipv4/f{i}.c", priority=3.5) for i in range(60)]
    subs = identify_subsystems_auto(files, max_files_per_subsystem=10)
    assert len(subs[0].files) == 10


# ---------------------------------------------------------------------------
# _build_subsystem_prompt file-listing cap (second, independent 50-file cap)
# ---------------------------------------------------------------------------


def test_subsystem_prompt_uncapped_by_default_lists_all_files():
    """The prompt builder must not re-truncate an (already-scoped) subsystem.

    CVE-2026-5747 shape: 85 equal-priority siblings plus the ground-truth file
    last. The old hard-coded ``subsystem.files[:50]`` in the prompt builder hid
    it from the model's file listing even after the partitioner kept it.
    """
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    files = [_ft(f"transport/pci/f{i:03d}.c", priority=1.0) for i in range(85)]
    files.append(_ft("transport/pci/common_config.c", priority=1.0))
    subsystem = SubsystemTarget(
        name="transport_pci", root_path="transport/pci", files=files
    )
    prompt = _build_subsystem_prompt(subsystem, "target")
    assert "transport/pci/common_config.c" in prompt
    assert "transport/pci/f000.c" in prompt


def test_subsystem_prompt_cap_warns_and_keeps_highest_priority(caplog):
    from clearwing.sourcehunt.hunter import _build_subsystem_prompt

    files = [_ft(f"net/f{i:03d}.c", priority=float(i)) for i in range(60)]
    subsystem = SubsystemTarget(name="net", root_path="net", files=files)
    with caplog.at_level("WARNING"):
        prompt = _build_subsystem_prompt(subsystem, "target", max_files_in_prompt=10)
    # Highest-priority files survive the cap; lowest-priority are dropped.
    assert "net/f059.c" in prompt
    assert "net/f000.c" not in prompt
    # And the drop is never silent.
    assert "dropping" in caplog.text.lower()
