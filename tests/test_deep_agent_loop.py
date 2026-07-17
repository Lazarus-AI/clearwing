"""Tests for NativeHunter agent loop with deep agent mode."""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from genai_pyo3 import ToolCall

from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.llm.native import NativeToolSpec
from clearwing.sourcehunt.hunter import NativeHunter


@dataclass
class FakeUsage:
    prompt_tokens: int = 100
    completion_tokens: int = 50
    total_tokens: int = 150


class FakeResponse:
    def __init__(self, text="", tool_calls_list=None, usage=None):
        self._text = text
        self._tool_calls = tool_calls_list or []
        self.usage = usage or FakeUsage()
        self.provider_model_name = "test-model"
        self.reasoning_content = None

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
        result = await hunter.arun()

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
async def test_hunter_completes_when_no_tool_calls():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=500, budget_usd=100.0)

    llm.achat.return_value = FakeResponse(text="No vulnerabilities found.")

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert llm.achat.call_count == 1
    assert len(result.findings) == 0
    assert result.stop_reason == "completed"
