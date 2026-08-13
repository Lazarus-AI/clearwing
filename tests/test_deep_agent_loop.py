"""Tests for NativeHunter agent loop with deep agent mode."""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from genai_pyo3 import ToolCall

from clearwing.agent.tools.hunt import build_reporting_tools
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
async def test_closure_countdown_is_only_added_near_step_cap():
    hunter, llm = _make_hunter(agent_mode="constrained", max_steps=4)
    hunter.closing_steps = 3
    llm.achat.return_value = FakeResponse(
        tool_calls_list=[_make_tool_call("think", {"notes": "thinking"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    systems = [call.kwargs["system"] for call in llm.achat.call_args_list]
    assert systems[0] == "test prompt"
    assert "3 model call(s) remain" in systems[1]
    assert "2 model call(s) remain" in systems[2]
    assert "1 model call(s) remain" in systems[3]
    assert all("Do not start broad exploration" in system for system in systems[1:])
    assert result.stop_reason == "max_steps"


@pytest.mark.asyncio
async def test_initial_source_action_gets_one_bounded_retry():
    llm = AsyncMock()
    source_calls = 0

    def read_source_file(**_kwargs):
        nonlocal source_calls
        source_calls += 1
        return "source"

    tool = NativeToolSpec(
        name="read_source_file",
        description="read",
        schema={"type": "object", "properties": {}},
        handler=read_source_file,
    )
    responses = iter(
        [
        FakeResponse(text="I'll read it now."),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file")]),
        FakeResponse(text="done"),
        ]
    )
    message_snapshots = []

    async def respond(**kwargs):
        message_snapshots.append([(message.role, message.content) for message in kwargs["messages"]])
        return next(responses)

    llm.achat.side_effect = respond
    hunter = NativeHunter(
        llm=llm,
        prompt="test",
        tools=[tool],
        ctx=HunterContext(repo_path="/tmp/repo"),
        max_steps=4,
        initial_source_action_retries=1,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert message_snapshots[1][-1][0] == "user"
    assert "Do not write or simulate" in message_snapshots[1][-1][1]
    assert source_calls == 1
    assert result.stop_reason == "completed"


@pytest.mark.asyncio
async def test_initial_source_action_retry_exhaustion_is_not_completed_coverage():
    hunter, llm = _make_hunter(agent_mode="constrained", max_steps=4)
    hunter.initial_source_action_retries = 1
    llm.achat.return_value = FakeResponse(text="I will call the tool now.")

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert llm.achat.call_count == 2
    assert result.stop_reason == "no_source_action"


@pytest.mark.asyncio
async def test_failed_source_tool_does_not_satisfy_initial_source_action():
    llm = AsyncMock()
    tool = NativeToolSpec(
        name="read_source_file",
        description="read",
        schema={"type": "object", "properties": {}},
        handler=lambda **_kwargs: {"error": "file not found"},
    )
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file")]),
        FakeResponse(text="I will retry with the tool."),
        FakeResponse(text="Still trying."),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test",
        tools=[tool],
        ctx=HunterContext(repo_path="/tmp/repo"),
        max_steps=4,
        initial_source_action_retries=1,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert llm.achat.call_count == 3
    assert result.stop_reason == "no_source_action"


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
async def test_zero_price_override_uses_step_cap_instead_of_nominal_cost():
    hunter, llm = _make_hunter(agent_mode="deep", max_steps=3, budget_usd=0.01)
    hunter.input_price_per_million = 0.0
    hunter.output_price_per_million = 0.0
    llm.achat.return_value = FakeResponse(
        tool_calls_list=[_make_tool_call("think", {"notes": "thinking"})],
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        with patch("clearwing.sourcehunt.hunter._estimate_cost_usd", return_value=10.0):
            result = await hunter.arun()

    assert llm.achat.call_count == 3
    assert result.stop_reason == "max_steps"
    assert result.cost_usd == 0.0


@pytest.mark.asyncio
async def test_candidate_gate_blocks_source_sweep_until_ledger_update():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    source_calls = 0

    def read_source_file(**_kwargs):
        nonlocal source_calls
        source_calls += 1
        return "source"

    def record_candidate(candidate_id, **_kwargs):
        ctx.candidates[candidate_id] = {"status": "investigating"}
        ctx.candidate_revision += 1
        return "candidate saved"

    tools = [
        NativeToolSpec(
            name="read_source_file",
            description="read",
            schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            handler=read_source_file,
        ),
        NativeToolSpec(
            name="record_candidate",
            description="candidate",
            schema={
                "type": "object",
                "properties": {"candidate_id": {"type": "string"}},
                "required": ["candidate_id"],
            },
            handler=record_candidate,
        ),
    ]
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "a.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "b.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "c.c"})]),
        FakeResponse(
            tool_calls_list=[_make_tool_call("record_candidate", {"candidate_id": "C1"})]
        ),
        FakeResponse(text="done"),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test",
        tools=tools,
        ctx=ctx,
        max_steps=6,
        candidate_gate_after_source_actions=2,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "completed"
    assert source_calls == 2
    assert ctx.candidates == {"C1": {"status": "investigating"}}


@pytest.mark.asyncio
async def test_domain_candidate_checkpoint_requires_structured_proof():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    ctx.value_domains["D1"] = {
        "assessment": "overlap_possible",
        "blocking_guard_locations": [],
    }
    ctx.domain_consequences["D1"] = {"assessment": "unresolved"}
    ctx.domain_consequence_plans["D1"] = {
        "boundary_facts": [{"line": 9, "token": "i", "expression": "i - 1"}]
    }
    ctx.domain_candidate_ids["D1"] = "C1"
    ctx.candidates["C1"] = {"status": "investigating"}
    source_calls = 0
    candidate_calls = 0
    proof_calls = 0

    def read_source_file(**_kwargs):
        nonlocal source_calls
        source_calls += 1
        return "source"

    def record_candidate(**_kwargs):
        nonlocal candidate_calls
        candidate_calls += 1
        return "candidate saved"

    def record_domain_proof(**_kwargs):
        nonlocal proof_calls
        proof_calls += 1
        ctx.candidate_revision += 1
        return "proof narrowed"

    def tool(name, handler):
        return NativeToolSpec(
            name=name,
            description=name,
            schema={"type": "object", "properties": {}},
            handler=handler,
        )

    tools = [
        tool("read_source_file", read_source_file),
        tool("record_candidate", record_candidate),
        tool("record_domain_proof", record_domain_proof),
    ]
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file")]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file")]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file")]),
        FakeResponse(tool_calls_list=[_make_tool_call("record_candidate")]),
        FakeResponse(tool_calls_list=[_make_tool_call("record_domain_proof")]),
        FakeResponse(text="done"),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test",
        tools=tools,
        ctx=ctx,
        max_steps=7,
        candidate_gate_after_source_actions=2,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        logger = MagicMock()
        mock_traj.for_hunter.return_value = logger
        result = await hunter.arun()

    proof_gates = [
        call
        for call in logger.log.call_args_list
        if len(call.args) > 1
        and isinstance(call.args[1], dict)
        and call.args[1].get("domain_proof_gate")
    ]
    assert result.stop_reason == "completed"
    assert source_calls == 2
    assert candidate_calls == 0
    assert proof_calls == 1
    assert len(proof_gates) == 2


@pytest.mark.asyncio
async def test_unresolved_domain_proof_allows_one_refinement_then_requires_proof():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    ctx.value_domains["D1"] = {
        "assessment": "overlap_possible",
        "blocking_guard_locations": [],
    }
    ctx.domain_consequences["D1"] = {"assessment": "unresolved"}
    ctx.domain_consequence_plans["D1"] = {
        "boundary_facts": [{"line": 9, "token": "i", "expression": "i - 1"}]
    }
    ctx.domain_candidate_ids["D1"] = "C1"
    ctx.candidates["C1"] = {"status": "investigating"}
    source_calls = 0
    proof_calls = 0
    refinement_calls = 0

    def read_source_file(**_kwargs):
        nonlocal source_calls
        source_calls += 1
        return "source"

    def record_domain_proof(**_kwargs):
        nonlocal proof_calls
        proof_calls += 1
        ctx.candidate_revision += 1
        ctx.domain_refinement_pending_proof.discard("D1")
        if proof_calls == 1:
            ctx.domain_proof_obligations["D1"] = ["attacker_reaches_producer"]
            return "proof narrowed"
        ctx.domain_proof_obligations.pop("D1", None)
        ctx.candidates["C1"]["status"] = "validated"
        return "proof validated"

    def read_domain_proof_refinement(**_kwargs):
        nonlocal refinement_calls
        refinement_calls += 1
        ctx.domain_refinements_read.add(("D1", "attacker_reaches_producer"))
        ctx.domain_refinement_pending_proof.add("D1")
        return "bounded refinement"

    def tool(name, handler):
        return NativeToolSpec(
            name=name,
            description=name,
            schema={"type": "object", "properties": {}},
            handler=handler,
        )

    tools = [
        tool("read_source_file", read_source_file),
        tool("record_domain_proof", record_domain_proof),
        tool("read_domain_proof_refinement", read_domain_proof_refinement),
    ]
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "a.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "b.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "c.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("record_domain_proof")]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "d.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_domain_proof_refinement")]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "e.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("record_domain_proof")]),
        FakeResponse(text="done"),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test",
        tools=tools,
        ctx=ctx,
        max_steps=10,
        candidate_gate_after_source_actions=2,
        enable_domain_proof_refinement=True,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        logger = MagicMock()
        mock_traj.for_hunter.return_value = logger
        result = await hunter.arun()

    logged_payloads = [
        call.args[1]
        for call in logger.log.call_args_list
        if len(call.args) > 1 and isinstance(call.args[1], dict)
    ]
    gate_keys = sorted(
        key
        for payload in logged_payloads
        for key in payload
        if key.endswith("_gate")
    )
    assert result.stop_reason == "completed"
    assert source_calls == 2
    assert proof_calls == 2
    assert refinement_calls == 1
    assert any(
        payload.get("domain_proof_refinement_gate") for payload in logged_payloads
    ), gate_keys
    assert any(payload.get("domain_refinement_proof_gate") for payload in logged_payloads)


@pytest.mark.asyncio
async def test_window_gate_blocks_reads_until_generic_ranking_runs():
    llm = AsyncMock()
    ctx = HunterContext(repo_path="/tmp/repo")
    source_calls = 0

    def read_source_file(**_kwargs):
        nonlocal source_calls
        source_calls += 1
        return "source"

    def rank_source_windows(**_kwargs):
        ctx.source_windows_ranked = True
        return {"windows": []}

    tools = [
        NativeToolSpec(
            name="read_source_file",
            description="read",
            schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            handler=read_source_file,
        ),
        NativeToolSpec(
            name="rank_source_windows",
            description="rank",
            schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            handler=rank_source_windows,
        ),
    ]
    llm.achat.side_effect = [
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "a.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("rank_source_windows", {"path": "a.c"})]),
        FakeResponse(tool_calls_list=[_make_tool_call("read_source_file", {"path": "a.c"})]),
        FakeResponse(text="done"),
    ]
    hunter = NativeHunter(
        llm=llm,
        prompt="test",
        tools=tools,
        ctx=ctx,
        max_steps=5,
        require_source_windows=True,
    )

    with patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
        mock_traj.for_hunter.return_value = MagicMock()
        result = await hunter.arun()

    assert result.stop_reason == "completed"
    assert source_calls == 1
    assert ctx.source_windows_ranked is True


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
