"""Tests for NativeHunter agent loop with deep agent mode."""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from genai_pyo3 import ToolCall

from clearwing.agent.tools.hunt import build_reporting_tools
from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools
from clearwing.agent.tools.hunt.potentials import build_potential_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.llm.native import NativeToolSpec
from clearwing.sourcehunt.hunter import NativeHunter, _read_file_tool_response, _tool_output_text


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


def test_read_metadata_does_not_treat_source_word_as_truncation():
    summary, returned = _read_file_tool_response(
        {"path": "parser.py", "offset": 0, "limit": 1},
        "     1\ttruncated = False\n[CLEARWING_READ_METADATA total_lines=2]",
        [],
    )

    assert returned == (1, 1)
    assert "Truncated: False" in summary


def test_read_metadata_uses_delivered_lines_for_eof_and_continuation():
    source = "".join(f"{line:6d}\t{'x' * 220}\n" for line in range(1, 101))
    summary, returned = _read_file_tool_response(
        {"path": "parser.py"},
        f"{source}[CLEARWING_READ_METADATA total_lines=100]",
        [],
    )

    assert returned is not None
    assert returned[0] == 1
    assert returned[1] < 100
    assert "Requested: 1-100" in summary
    assert "Total lines: 100" in summary
    assert "EOF: False" in summary
    assert "Truncated: True" in summary
    assert f"Next line: {returned[1] + 1}" in summary
    assert f"{returned[1] + 1:6d}\t" not in summary
    assert f"{returned[1]:6d}\t{'x' * 220}" in summary


def test_read_metadata_reports_eof_only_after_last_line_is_delivered():
    summary, returned = _read_file_tool_response(
        {"path": "parser.py", "offset": 98, "limit": 100},
        "    99\tlast but one\n   100\tlast\n[CLEARWING_READ_METADATA total_lines=100]",
        [],
    )

    assert returned == (99, 100)
    assert "EOF: True" in summary
    assert "Next line: None" in summary


def test_read_metadata_reports_eof_for_request_past_end():
    summary, returned = _read_file_tool_response(
        {"path": "parser.py", "offset": 100},
        "\n[CLEARWING_READ_METADATA total_lines=100]",
        [],
    )

    assert returned is None
    assert "EOF: True" in summary
    assert "Next line: None" in summary


def test_read_metadata_does_not_claim_eof_after_raw_output_cap():
    summary, returned = _read_file_tool_response(
        {"path": "parser.py"},
        "     1\tfirst\n     2\tsecond\n\n[file truncated at 100000 characters]"
        "\n[CLEARWING_READ_METADATA total_lines=100]",
        [],
    )

    assert returned == (1, 2)
    assert "EOF: False" in summary
    assert "Truncated: True" in summary
    assert "Next line: 3" in summary
    assert "[file truncated" not in summary


def test_read_metadata_preserves_an_oversized_source_line():
    long_line = "x" * 12_100
    summary, returned = _read_file_tool_response(
        {"path": "parser.py"},
        f"     1\t{long_line}\n     2\ttail\n[CLEARWING_READ_METADATA total_lines=2]",
        [],
    )

    assert returned == (1, 1)
    assert f"     1\t{long_line}" in summary
    assert "     2\ttail" not in summary
    assert "EOF: False" in summary
    assert "Next line: 2" in summary


def test_structured_search_summary_preserves_status_and_next_action():
    result = {
        "status": "truncated",
        "scope": "src",
        "truncated": True,
        "matches": [
            {"file": "src/gfx.c", "line_number": i, "matched_text": "x" * 240} for i in range(40)
        ],
        "next_action": "Read a relevant hit with read_file.",
    }

    summary = _tool_output_text("grep_source", {}, result)

    assert summary.startswith("grep_source: status=truncated")
    assert "additional hits omitted" in summary
    assert "read_file" in summary


@pytest.mark.asyncio
async def test_near_limit_synthesis_requires_a_tool_free_final_response():
    hunter, llm = _make_hunter(agent_mode="constrained", max_steps=3)
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("think", {"notes": "inspect"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("think", {"notes": "report"})]),
        FakeResponse(text="Investigation complete."),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "completed"
    second_messages = llm.achat.call_args_list[1].kwargs["messages"]
    synthesis = next(
        str(message.to_dict().get("content", ""))
        for message in second_messages
        if "approaching the end of your budget" in str(message.to_dict().get("content", ""))
    )
    assert "final response containing no tool calls" in synthesis
    assert "required before the step limit" in synthesis
    final_call = llm.achat.call_args_list[2]
    assert final_call.kwargs["tools"] == []
    final_messages = [message.to_dict() for message in final_call.kwargs["messages"]]
    assert any(
        "This is the final synthesis turn" in str(message.get("content", ""))
        for message in final_messages
    )


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
async def test_overlapping_read_file_refreshes_return_content_with_direction():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=6, budget_usd=0.0)
    hunter.tools[0].name = "read_file"
    hunter.tools[0].schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer"},
            "limit": {"type": "integer"},
        },
        "required": ["path"],
    }

    def read_handler(offset=0, limit=2000, **kwargs):
        start = offset + 1
        end = min(offset + limit, 52)
        body = "\n".join(f"{line:6d}\tline {line}" for line in range(start, end + 1))
        return f"{body}\n[CLEARWING_READ_METADATA total_lines=52]"

    hunter.tools[0].handler = read_handler
    llm.achat.side_effect = [
        FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "read_file",
                    {"path": "views.py", "offset": 0, "limit": 50},
                )
            ]
        ),
        FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "read_file",
                    {"path": "views.py", "offset": 40, "limit": 12},
                )
            ]
        ),
        FakeResponse(
            tool_calls_list=[
                _make_tool_call(
                    "read_file",
                    {"path": "views.py", "offset": 10, "limit": 10},
                )
            ]
        ),
        FakeResponse(text="done"),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_logger = MagicMock()
        mock_traj.for_hunter.return_value = mock_logger
        await hunter.arun()

    tool_results = [
        call.args[1]["tool_summary"]
        for call in mock_logger.log.call_args_list
        if call.args and call.args[0] == "tool_result"
    ]
    assert len(tool_results) == 3
    assert "Requested: 1-50" in tool_results[0]
    assert "Returned: 1-50" in tool_results[0]
    assert "EOF: False" in tool_results[0]
    assert "Overlap: 0%" in tool_results[0]
    assert "Requested: 41-52" in tool_results[1]
    assert "Returned: 41-52" in tool_results[1]
    assert "EOF: True" in tool_results[1]
    assert "Overlap: 83%" in tool_results[1]
    assert "New lines: 51-52" in tool_results[1]
    assert "Requested: 11-20" in tool_results[2]
    assert "Returned: 11-20" in tool_results[2]
    assert "EOF: False" in tool_results[2]
    assert "Overlap: 100%" in tool_results[2]
    assert "New lines: None" in tool_results[2]
    assert not any(
        isinstance(output, dict) and output.get("status") == "read_already_recent"
        for output in tool_results
    )


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


def _stub_sandbox_for_deep_read_ranges():
    sandbox = MagicMock()

    def execute(command, **_):
        start = int(command.split("-v s=", 1)[1].split()[0])
        result = MagicMock()
        result.exit_code = 0
        result.stdout = f"{start:6}\tline {start}\n{start + 1:6}\tline {start + 1}\n"
        result.stderr = f"__CLEARWING_TOTAL_LINES__={start + 100}\n"
        result.timed_out = False
        result.duration_seconds = 0.01
        return result

    sandbox.exec.side_effect = execute
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
async def test_deep_read_new_ranges_count_as_progress():
    hunter, llm, ctx = _build_deep_hunter(_stub_sandbox_for_deep_read_ranges())
    hunter.max_steps_without_progress = 3

    offsets = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call(
                "read_file",
                {"path": "/workspace/only_file.c", "offset": next(offsets) * 2, "limit": 2},
            )
        ],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "max_steps"
    assert llm.achat.call_count == 20
    assert ctx.deep_files_read == {"/workspace/only_file.c"}


@pytest.mark.asyncio
async def test_deep_read_repeated_range_does_not_reset_stall():
    # Requests vary so the duplicate-call guard does not preempt this check,
    # but the tool keeps returning the same two lines. That repeated range is
    # not progress and must still let the stall guard terminate the hunt.
    hunter, llm, ctx = _build_deep_hunter(_stub_sandbox_for_deep_read())
    hunter.max_steps_without_progress = 3

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("symbol", "filename"),
    [
        ("RDPGFX_SURFACE_COMMAND", "gfx.c"),
        ("struct sc_file", "profile.c"),
    ],
)
async def test_repeated_source_searches_stall_without_shell_loops(tmp_path, symbol, filename):
    """FreeRDP/OpenSC pattern: varied queries returning the same source hit."""
    source = tmp_path / filename
    source.write_text(f"{symbol}\n")
    llm = AsyncMock()
    ctx = HunterContext(repo_path=str(tmp_path))
    hunter = NativeHunter(
        llm=llm,
        prompt="test prompt",
        tools=build_deep_agent_tools(ctx),
        ctx=ctx,
        max_steps=100,
        agent_mode="deep",
    )
    assert hunter.max_steps_without_progress == 8
    queries = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[
            _make_tool_call("grep_source", {"pattern": f"{symbol}{'(?:)' * next(queries)}"})
        ]
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert result.findings == []
    assert llm.achat.call_count <= 12
    assert all(
        "grep_source" in {tool.name for tool in call.kwargs["tools"]}
        for call in llm.achat.call_args_list
    )
    assert all("find /" not in str(call.kwargs["messages"]) for call in llm.achat.call_args_list)


@pytest.mark.asyncio
async def test_only_two_new_search_locations_can_reset_stall():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    search = NativeToolSpec(
        name="grep_source",
        description="search",
        schema={"type": "object", "properties": {"pattern": {"type": "string"}}},
        handler=lambda pattern: {
            "status": "matches",
            "matches": [{"file": f"src/{pattern}.c", "line_number": 1}],
        },
    )
    hunter = NativeHunter(
        llm=llm, prompt="test", tools=[search], ctx=ctx, max_steps=100, agent_mode="deep"
    )
    queries = itertools.count()
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[_make_tool_call("grep_source", {"pattern": chr(97 + next(queries))})]
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert llm.achat.call_count == 10  # 2 discoveries plus the eight-step guard


@pytest.mark.asyncio
async def test_exact_repeated_search_still_reaches_eight_step_guard():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    search = NativeToolSpec(
        name="grep_source",
        description="search",
        schema={"type": "object", "properties": {"pattern": {"type": "string"}}},
        handler=lambda pattern: {
            "status": "matches",
            "matches": [{"file": "src/gfx.c", "line_number": 12}],
        },
    )
    hunter = NativeHunter(
        llm=llm, prompt="test", tools=[search], ctx=ctx, max_steps=100, agent_mode="deep"
    )
    llm.achat.side_effect = lambda **_: FakeResponse(
        tool_calls_list=[_make_tool_call("grep_source", {"pattern": "RDPGFX_SURFACE_COMMAND"})]
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert llm.achat.call_count <= 10


def _decision_hunter():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    ctx.potentials.append({"id": "lead-1", "file": "src/Archive.java", "status": "open"})
    executed: list[str] = []

    def execute(command):
        executed.append(command)
        return "PATH TRAVERSAL BYPASS CONFIRMED"

    def record_finding(description):
        ctx.findings.append({"description": description})
        return "Finding recorded"

    tools = [
        NativeToolSpec(
            name=name,
            description=name,
            schema={"type": "object", "properties": {field: {"type": "string"}}},
            handler=handler,
        )
        for name, field, handler in (
            ("execute", "command", execute),
            ("update_potential", "observation", lambda observation: "Updated potential"),
            ("record_finding", "description", record_finding),
            ("defer_potential", "reason", lambda reason: "Deferred potential"),
            ("dismiss_potential", "resolution", lambda resolution: "Dismissed potential"),
        )
    ]
    hunter = NativeHunter(
        llm=llm, prompt="test", tools=tools, ctx=ctx, max_steps=50, agent_mode="deep"
    )
    hunter.max_steps_without_progress = 4
    return hunter, llm, executed


@pytest.mark.asyncio
async def test_junrar_pattern_gets_final_record_finding_choice():
    hunter, llm, executed = _decision_hunter()
    llm.achat.side_effect = [
        FakeResponse(
            tool_calls_list=[_make_tool_call("execute", {"command": "javac PoC.java && java PoC"})]
        ),
        FakeResponse(
            tool_calls_list=[_make_tool_call("update_potential", {"observation": "PoC confirmed"})]
        ),
        FakeResponse(
            tool_calls_list=[
                _make_tool_call("record_finding", {"description": "Confirmed path traversal"})
            ]
        ),
        FakeResponse(text="Finding recorded and investigation complete."),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "completed"
    assert len(result.findings) == 1
    assert executed == ["javac PoC.java && java PoC"]
    decision_call = llm.achat.call_args_list[2]
    assert {tool.name for tool in decision_call.kwargs["tools"]} == {
        "record_finding",
        "dismiss_potential",
        "defer_potential",
    }
    assert any(
        "FINAL LEAD DECISION" in str(message.to_dict().get("content", ""))
        for message in decision_call.kwargs["messages"]
    )


@pytest.mark.asyncio
async def test_uncertain_final_lead_is_explained_without_promotion():
    hunter, llm, _ = _decision_hunter()
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("execute", {"command": "inspect one"})]),
        FakeResponse(
            tool_calls_list=[_make_tool_call("update_potential", {"observation": "unknown"})]
        ),
        FakeResponse(text="UNVERIFIED: The caller's path to this sink is not established."),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "completed"
    assert result.findings == []
    assert result.potentials[0]["id"] == "lead-1"
    assert "not established" in result.transcript_summary


@pytest.mark.asyncio
async def test_generic_final_reply_keeps_unresolved_lead_stalled():
    hunter, llm, _ = _decision_hunter()
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("execute", {"command": "inspect one"})]),
        FakeResponse(
            tool_calls_list=[_make_tool_call("update_potential", {"observation": "unknown"})]
        ),
        FakeResponse(text="done"),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert result.findings == []


@pytest.mark.asyncio
async def test_final_decision_rejects_another_potential_update():
    hunter, llm, _ = _decision_hunter()
    update = next(tool for tool in hunter.tools if tool.name == "update_potential")
    original_handler = update.handler
    update.handler = MagicMock(side_effect=original_handler)
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("execute", {"command": "inspect one"})]),
        FakeResponse(
            tool_calls_list=[_make_tool_call("update_potential", {"observation": "PoC confirmed"})]
        ),
        FakeResponse(
            tool_calls_list=[_make_tool_call("update_potential", {"observation": "same claim"})]
        ),
    ]

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "stalled"
    assert result.findings == []
    assert update.handler.call_count == 1
