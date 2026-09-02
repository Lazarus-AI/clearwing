"""Tests for NativeHunter agent loop with deep agent mode."""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from genai_pyo3 import ToolCall

from clearwing.agent.tools.hunt import build_reporting_tools
from clearwing.agent.tools.hunt.potentials import build_potential_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.llm.native import NativeToolSpec
from clearwing.sourcehunt.hunter import NativeHunter


@dataclass
class FakeUsage:
    prompt_tokens: int = 100
    completion_tokens: int = 50
    total_tokens: int = 150


class FakeResponse:
    def __init__(self, text="", tool_calls_list=None, usage=None, reasoning_content=None):
        self._text = text
        self._tool_calls = tool_calls_list or []
        self.usage = usage or FakeUsage()
        self.provider_model_name = "test-model"
        self.reasoning_content = reasoning_content

    @property
    def first_text(self):
        return self._text

    @property
    def tool_calls(self):
        return self._tool_calls


def _make_tool_call(fn_name, fn_arguments=None):
    return ToolCall(f"call_{fn_name}", fn_name, json.dumps(fn_arguments or {}))


def _make_hunter(agent_mode="constrained", max_steps=20, budget_usd=0.0):
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())

    def noop_handler(**kwargs):
        return "ok"

    tools = [
        NativeToolSpec(
            name="think",
            description="think",
            schema={"type": "object", "properties": {"notes": {"type": "string"}}},
            handler=noop_handler,
        ),
    ]

    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=max_steps,
        agent_mode=agent_mode,
        budget_usd=budget_usd,
    )
    return hunter, llm


@pytest.mark.asyncio
async def test_hunter_reminds_model_to_preserve_articulated_potential():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=5)
    llm.achat.side_effect = [
        FakeResponse(
            reasoning_content="Let me verify the read-only deploy key bypass hypothesis.",
            tool_calls_list=[_make_tool_call("execute", {"notes": "verify"})],
        ),
        FakeResponse(text="done"),
    ]

    hunter.tools[0].name = "execute"

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        await hunter.arun()

    second_messages = llm.achat.call_args_list[1].kwargs["messages"]
    serialized = [message.to_dict() for message in second_messages]
    assert any(
        "Call flag_potential now" in str(message.get("content", "")) for message in serialized
    )


@pytest.mark.asyncio
async def test_hunter_checkpoints_after_four_investigative_calls_without_potential():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=7)
    hunter.tools[0].name = "execute"
    llm.achat.side_effect = [
        *[
            FakeResponse(
                reasoning_content="Continue mapping the subsystem.",
                tool_calls_list=[_make_tool_call("execute", {"notes": f"step {index}"})],
            )
            for index in ("alpha", "bravo", "charlie", "delta")
        ],
        FakeResponse(text="done"),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        await hunter.arun()

    fifth_messages = llm.achat.call_args_list[4].kwargs["messages"]
    serialized = [message.to_dict() for message in fifth_messages]
    checkpoint = next(
        str(message.get("content", ""))
        for message in serialized
        if "LEAD CHECKPOINT" in str(message.get("content", ""))
    )
    assert "NO_POTENTIAL" in checkpoint
    assert "semantic-navigation query" in checkpoint


@pytest.mark.asyncio
async def test_active_potential_does_not_force_resolution_or_hide_navigation_tools():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())

    tools = [
        *build_potential_tools(ctx),
        NativeToolSpec(
            name="execute",
            description="execute",
            schema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
                "additionalProperties": False,
            },
            handler=lambda command, **kwargs: "ok",
        ),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=5,
        agent_mode="deep",
    )
    llm.achat.side_effect = [
        FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "flag_potential",
                    {
                        "file": "src/auth.go",
                        "line": 42,
                        "hypothesis": "Cached authorization crosses resources.",
                    },
                )
            ]
        ),
        FakeResponse(
            tool_calls_list=[_make_tool_call("execute", {"command": "grep auth src/auth.go"})]
        ),
        FakeResponse(text="done"),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        await hunter.arun()

    third_turn_tools = llm.achat.call_args_list[2].kwargs["tools"]
    third_turn_names = {tool.name for tool in third_turn_tools}
    assert "execute" in third_turn_names
    assert {"update_potential", "dismiss_potential", "defer_potential"} <= third_turn_names
    third_turn_messages = llm.achat.call_args_list[2].kwargs["messages"]
    assert not any(
        "Verification budget reached" in str(message.to_dict().get("content", ""))
        for message in third_turn_messages
    )


@pytest.mark.asyncio
async def test_flagging_potential_preserves_broad_investigation_context():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())
    tools = [
        *build_potential_tools(ctx),
        NativeToolSpec(
            name="execute",
            description="execute",
            schema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
                "additionalProperties": False,
            },
            handler=lambda command, **kwargs: f"evidence:{command}",
        ),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=9,
        agent_mode="deep",
    )
    llm.achat.side_effect = [
        *[
            FakeResponse(
                reasoning_content="Survey another security boundary.",
                tool_calls_list=[_make_tool_call("execute", {"command": command})],
            )
            for command in ("alpha", "bravo", "charlie", "delta", "echo")
        ],
        FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "flag_potential",
                    {
                        "file": "src/auth.go",
                        "line": 42,
                        "hypothesis": "Cached authorization crosses resources.",
                    },
                )
            ]
        ),
        FakeResponse(text="done"),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        await hunter.arun()

    post_flag_messages = llm.achat.call_args_list[6].kwargs["messages"]
    assert any("evidence:alpha" in str(message.to_dict()) for message in post_flag_messages)


@pytest.mark.asyncio
async def test_constrained_mode_stops_at_max_steps():
    hunter, llm = _make_hunter(agent_mode="constrained", max_steps=3)

    # Always return a tool call so it never stops naturally
    llm.achat.return_value = FakeResponse(
        tool_calls_list=[_make_tool_call("think", {"notes": "thinking"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert llm.achat.call_count == 3
    assert result.stop_reason == "max_steps"


@pytest.mark.asyncio
async def test_deep_mode_terminates_on_budget():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=500, budget_usd=0.01)

    # Each call costs ~$0.003 with FakeUsage defaults and test-model pricing fallback
    llm.achat.return_value = FakeResponse(
        tool_calls_list=[_make_tool_call("think", {"notes": "thinking"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        with patch("clearwing.sourcehunt.hunter._estimate_cost_usd", return_value=0.005):
            result = await hunter.arun()

    # Should stop after 2 steps: 0.005 + 0.005 = 0.01 >= 0.01 * 0.9
    assert llm.achat.call_count == 2
    assert result.stop_reason == "budget_exhausted"


@pytest.mark.asyncio
async def test_deep_mode_safety_cap():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=5, budget_usd=0.0)

    llm.achat.return_value = FakeResponse(
        tool_calls_list=[_make_tool_call("think", {"notes": "thinking"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    # With budget_usd=0 (unlimited), should stop at max_steps=5
    assert llm.achat.call_count == 5
    assert result.stop_reason == "max_steps"


@pytest.mark.asyncio
async def test_deep_mode_stops_on_degenerate_loop():
    # Real failure mode observed against crAPI with a local devstral model
    # (both 4-bit and 6-bit quantizations): it keeps reissuing the exact
    # same already-throttled tool call forever and never recovers. This
    # must not be allowed to grind through the full max_steps budget.
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=500, budget_usd=0.0)

    llm.achat.return_value = FakeResponse(
        tool_calls_list=[_make_tool_call("think", {"notes": "same notes"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "degenerate_loop"
    # Should bail out well short of the 500-step budget.
    assert llm.achat.call_count < 25


@pytest.mark.asyncio
async def test_deep_mode_throttles_repeated_calls():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=10, budget_usd=0.0)

    call_count = [0]

    async def achat_side_effect(**kwargs):
        call_count[0] += 1
        if call_count[0] >= 8:
            return FakeResponse(text="done")
        return FakeResponse(
            tool_calls_list=[_make_tool_call("think", {"notes": "same notes"})],
        )

    llm.achat.side_effect = achat_side_effect

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    # Full-shell agents can get stuck in the same degenerate repetition loops
    # as constrained ones (e.g. a local model reissuing the same shell
    # command with no progress), so deep mode must throttle too.
    logged = mock_logger.log.call_args_list
    skipped = [
        c
        for c in logged
        if len(c[0]) > 1 and isinstance(c[0][1], dict) and c[0][1].get("repeated_skip")
    ]
    assert len(skipped) > 0


@pytest.mark.asyncio
async def test_constrained_mode_throttles_repeated_calls():
    hunter, llm = _make_hunter(agent_mode="constrained", max_steps=10)

    call_count = [0]

    async def achat_side_effect(**kwargs):
        call_count[0] += 1
        if call_count[0] >= 8:
            return FakeResponse(text="done")
        return FakeResponse(
            tool_calls_list=[_make_tool_call("think", {"notes": "same notes"})],
        )

    llm.achat.side_effect = achat_side_effect

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    # In constrained mode, after 3 identical calls the 4th+ should be skipped
    logged = mock_logger.log.call_args_list
    skipped = [
        c
        for c in logged
        if len(c[0]) > 1 and isinstance(c[0][1], dict) and c[0][1].get("repeated_skip") is True
    ]
    assert len(skipped) > 0


@pytest.mark.asyncio
async def test_throttles_calls_with_mutating_tail():
    # Mirrors a real degenerate loop: the model reissues the same shell
    # command each turn but appends another redundant clause, so the
    # arguments string keeps growing and never matches exactly.
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=10, budget_usd=0.0)

    call_count = [0]

    # A long shared prefix (like a real shell one-liner) followed by a
    # growing tail — the dedup key truncates at 300 chars, so the prefix
    # must be long enough to exceed that before the tail starts diverging.
    shared_prefix = 'python3 -c "..."' + " or 'rest_framework' in d.lower()" * 15

    async def achat_side_effect(**kwargs):
        call_count[0] += 1
        if call_count[0] >= 8:
            return FakeResponse(text="done")
        command = shared_prefix + " or 'x' in d" * call_count[0]
        return FakeResponse(
            tool_calls_list=[_make_tool_call("think", {"notes": command})],
        )

    llm.achat.side_effect = achat_side_effect

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    logged = mock_logger.log.call_args_list
    skipped = [
        c
        for c in logged
        if len(c[0]) > 1 and isinstance(c[0][1], dict) and c[0][1].get("repeated_skip")
    ]
    assert len(skipped) > 0


@pytest.mark.asyncio
async def test_throttles_calls_with_growing_numeric_prefix():
    # Mirrors a real degenerate loop observed against crAPI: the model
    # reissues the same short shell command but widens a numeric flag near
    # the *front* of the string each turn (`grep -B10 ...` -> `-B1750 ...`).
    # Because the whole argument string is short, a raw 300-char prefix is
    # unique on every call (the diverging digits are included in the
    # prefix), so a plain-prefix dedup key never matches and the loop runs
    # unthrottled. Digits must be normalized before truncating for this to
    # throttle.
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=10, budget_usd=0.0)

    call_count = [0]

    async def achat_side_effect(**kwargs):
        call_count[0] += 1
        if call_count[0] >= 8:
            return FakeResponse(text="done")
        n = 10 + call_count[0] * 10
        command = f'grep -B{n} -A5 "verify=False" views.py | head -{n + 20}'
        return FakeResponse(
            tool_calls_list=[_make_tool_call("think", {"notes": command})],
        )

    llm.achat.side_effect = achat_side_effect

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    logged = mock_logger.log.call_args_list
    skipped = [
        c
        for c in logged
        if len(c[0]) > 1 and isinstance(c[0][1], dict) and c[0][1].get("repeated_skip")
    ]
    assert len(skipped) > 0


@pytest.mark.asyncio
async def test_read_file_pagination_is_not_falsely_throttled():
    # Real failure mode observed against crAPI: read_file's offset/limit
    # digits used to get stripped before the dedup check, so any four
    # legitimately-different paginated reads of the same file collapsed
    # to one key and the 4th+ was falsely rejected as "already made this
    # call" even though it targeted genuinely unread lines.
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=20, budget_usd=0.0)

    offsets = [0, 100, 200, 300, 400, 500, 600]
    call_count = [0]

    async def achat_side_effect(**kwargs):
        i = call_count[0]
        call_count[0] += 1
        if i >= len(offsets):
            return FakeResponse(text="done")
        return FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "read_file",
                    {"path": "views.py", "offset": offsets[i], "limit": 100},
                )
            ],
        )

    llm.achat.side_effect = achat_side_effect

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    logged = mock_logger.log.call_args_list
    skipped = [
        c
        for c in logged
        if len(c[0]) > 1 and isinstance(c[0][1], dict) and c[0][1].get("repeated_skip")
    ]
    assert len(skipped) == 0


@pytest.mark.asyncio
async def test_read_file_exact_repeat_still_throttled():
    # The fix must not disable throttling entirely for read_file — a truly
    # identical (path, offset, limit) repeated verbatim is still a
    # degenerate loop and must still be caught.
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=10, budget_usd=0.0)

    call_count = [0]

    async def achat_side_effect(**kwargs):
        call_count[0] += 1
        if call_count[0] >= 8:
            return FakeResponse(text="done")
        return FakeResponse(
            tool_calls_list=[
                _make_tool_call("read_file", {"path": "views.py", "offset": 0, "limit": 2000})
            ],
        )

    llm.achat.side_effect = achat_side_effect

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    logged = mock_logger.log.call_args_list
    skipped = [
        c
        for c in logged
        if len(c[0]) > 1 and isinstance(c[0][1], dict) and c[0][1].get("repeated_skip")
    ]
    assert len(skipped) > 0


@pytest.mark.asyncio
async def test_record_trace_step_tolerates_explicit_null_optional_args():
    # Real failure mode observed against crAPI: devstral-small sends explicit
    # `"function": null` for the unused optional `function` param instead of
    # omitting it. Tool-call arguments are passed straight through to the
    # handler as **kwargs without going through the declared Pydantic input
    # schema, so `function=None` reached TraceStep's plain `str` field (not
    # Optional) and raised a pydantic ValidationError. _run_tool's generic
    # except caught it and returned an error string, but the trace step was
    # silently dropped instead of recorded — 38 times in one batch run.
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())
    ctx.files_read.add("views.py")
    tools = build_reporting_tools(ctx)

    llm = AsyncMock()
    llm.achat.side_effect = [
        FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "record_trace_step",
                    {
                        "file": "views.py",
                        "line": 10,
                        "function": None,
                        "code_snippet": "verify=False,",
                        "note": "SINK: disables TLS verification",
                    },
                )
            ],
        ),
        FakeResponse(text="done"),
    ]

    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=2,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        await hunter.arun()

    assert len(ctx.trace_steps) == 1
    assert ctx.trace_steps[0].function == ""
    assert ctx.trace_steps[0].line == 10
    assert ctx.trace_steps[0].note == "SINK: disables TLS verification"


@pytest.mark.asyncio
async def test_hunter_completes_when_no_tool_calls():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=500, budget_usd=100.0)

    llm.achat.return_value = FakeResponse(text="No vulnerabilities found.")

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert llm.achat.call_count == 1
    assert len(result.findings) == 0
    assert result.stop_reason == "completed"


def _stub_sandbox_for_deep_read():
    sandbox = MagicMock()
    exec_result = MagicMock()
    exec_result.exit_code = 0
    exec_result.stdout = "     1\tline one\n     2\tline two\n"
    exec_result.stderr = ""
    exec_result.timed_out = False
    exec_result.duration_seconds = 0.01
    sandbox.exec.return_value = exec_result
    return sandbox


def _build_deep_hunter(sandbox, max_steps=20):
    from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools

    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=sandbox)
    tools = build_deep_agent_tools(ctx)
    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=max_steps,
        agent_mode="deep",
    )
    return hunter, llm, ctx


@pytest.mark.asyncio
async def test_deep_read_file_counts_as_progress():
    # Deep-mode read_file doesn't populate ctx.files_read (that set is fed by
    # the constrained read_source_file tool). Each first read of a NEW file
    # must count as progress via ctx.deep_files_read, otherwise the stall
    # guard collapses to (0, 0, 0, 0) during early exploration.
    hunter, llm, ctx = _build_deep_hunter(_stub_sandbox_for_deep_read())
    hunter.max_steps_without_progress = 3

    paths = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call(
                "read_file",
                {"path": f"/workspace/foo_{next(paths)}.c"},
            )
        ],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    # Distinct file paths keep the deep_files_read set growing → progress on
    # every step → should run to max_steps.
    assert result.stop_reason == "max_steps"
    assert llm.achat.call_count == 20
    assert len(ctx.deep_files_read) == 20


@pytest.mark.asyncio
async def test_deep_read_same_file_repeated_does_not_reset_stall():
    # Re-reading the SAME path 10 times must not reset the stall counter —
    # spec: only the *first* read of an unread file counts as progress.
    hunter, llm, ctx = _build_deep_hunter(_stub_sandbox_for_deep_read())
    hunter.max_steps_without_progress = 3

    # Vary offset each call so the degenerate_loop guard (which fires on
    # identical repeated calls) doesn't preempt the stall guard — but the
    # path is always the same, so no new file enters deep_files_read.
    offsets = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call(
                "read_file",
                {"path": "/workspace/only_file.c", "offset": next(offsets) * 100, "limit": 50},
            )
        ],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert llm.achat.call_count < 20
    assert ctx.deep_files_read == {"/workspace/only_file.c"}


@pytest.mark.asyncio
async def test_deep_execute_failing_does_not_reset_stall():
    # A stream of varied FAILING execute commands (distinct arguments, so not
    # a degenerate_loop) must not reset the stall counter — execute never
    # counts as progress.
    from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools

    llm = AsyncMock()
    sandbox = MagicMock()
    fail_result = MagicMock()
    fail_result.exit_code = 2
    fail_result.stdout = ""
    fail_result.stderr = "ls: no such file"
    fail_result.timed_out = False
    fail_result.duration_seconds = 0.01
    sandbox.exec.return_value = fail_result
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=sandbox)
    tools = build_deep_agent_tools(ctx)
    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=20,
        agent_mode="deep",
    )
    hunter.max_steps_without_progress = 3

    counter = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call(
                "execute",
                {"command": f"ls /nonexistent{next(counter)}"},
            )
        ],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert llm.achat.call_count < 20
    assert ctx.deep_files_read == set()


@pytest.mark.asyncio
async def test_deep_write_file_does_not_reset_stall():
    # write_file never counts as progress.
    from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools

    llm = AsyncMock()
    sandbox = MagicMock()
    ok_result = MagicMock()
    ok_result.exit_code = 0
    ok_result.stdout = ""
    ok_result.stderr = ""
    ok_result.timed_out = False
    ok_result.duration_seconds = 0.01
    sandbox.exec.return_value = ok_result
    sandbox.write_file.return_value = None
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=sandbox)
    tools = build_deep_agent_tools(ctx)
    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=tools,
        ctx=ctx,
        max_steps=20,
        agent_mode="deep",
    )
    hunter.max_steps_without_progress = 3

    counter = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call(
                "write_file",
                {"path": f"/tmp/scratch_{next(counter)}.txt", "contents": "x"},
            )
        ],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert llm.achat.call_count < 20
    assert ctx.deep_files_read == set()


def test_hunt_tuning_max_steps_without_progress_default():
    from clearwing.sourcehunt.config import HuntTuning

    assert HuntTuning().max_steps_without_progress == 8


@pytest.mark.asyncio
async def test_max_steps_without_progress_zero_disables_stall_guard():
    # A hunter configured with max_steps_without_progress=0 must never stall,
    # only stop on max_steps / budget / degenerate_loop / empty_response.
    hunter, llm, ctx = _build_deep_hunter(_stub_sandbox_for_deep_read(), max_steps=6)
    hunter.max_steps_without_progress = 0

    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call("read_file", {"path": "/workspace/only_file.c"}),
        ],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    # Same path reread every step: stall guard would fire at step 3, but it's
    # disabled — the degenerate_loop guard picks it up instead.
    assert result.stop_reason != "stalled"


@pytest.mark.asyncio
async def test_hunter_stalls_when_no_progress():
    # Distinct, schema-valid calls that never add a finding, a potential, or a
    # first file read. Not identical (so not degenerate_loop) and not empty
    # (so not empty_response): only the stalled guard stops it before max_steps.
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=500, budget_usd=0.0)
    hunter.max_steps_without_progress = 3

    counter = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        text="still thinking",
        tool_calls_list=[_make_tool_call("think", {"notes": f"step {next(counter)}"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert llm.achat.call_count < 20  # stops well short of max_steps
