"""Tests for band promotion and staged budget (spec 003)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clearwing.sourcehunt.pool import (
    BAND_ORDER,
    BandBudget,
    HunterPool,
    HuntPoolConfig,
    WorkItem,
    _file_rank,
    _redundancy_for_rank,
    promotion_decision,
)
from clearwing.sourcehunt.state import FileTarget


def _make_file_target(
    path: str = "src/main.c",
    tier: str = "B",
    tags: list[str] | None = None,
    language: str = "c",
    priority: float = 2.5,
) -> FileTarget:
    return {
        "path": path,
        "absolute_path": f"/repo/{path}",
        "language": language,
        "loc": 100,
        "tags": tags or [],
        "tier": tier,
        "surface": 3,
        "influence": 2,
        "reachability": 3,
        "priority": priority,
    }


# --- Promotion decision tests -----------------------------------------------


class TestPromotionDecision:
    def test_fast_to_standard_on_findings(self):
        findings = [{"description": "buffer overflow", "evidence_level": "suspicion"}]
        result = promotion_decision(findings, "completed", "fast", "standard")
        assert result == "standard"

    def test_fast_to_standard_on_budget_exhausted(self):
        result = promotion_decision([], "budget_exhausted", "fast", "standard")
        assert result == "standard"

    def test_no_promotion_fast_completed_no_findings(self):
        result = promotion_decision([], "completed", "fast", "standard")
        assert result is None

    def test_no_promotion_fast_max_steps_no_findings(self):
        result = promotion_decision([], "max_steps", "fast", "standard")
        assert result is None

    def test_standard_to_deep_on_confirmed_signal(self):
        findings = [{"evidence_level": "crash_reproduced"}]
        result = promotion_decision(findings, "budget_exhausted", "standard", "deep")
        assert result == "deep"

    def test_standard_to_deep_static_corroboration(self):
        findings = [{"evidence_level": "static_corroboration"}]
        result = promotion_decision(findings, "budget_exhausted", "standard", "deep")
        assert result == "deep"

    def test_no_promotion_standard_unconfirmed(self):
        findings = [{"evidence_level": "suspicion"}]
        result = promotion_decision(findings, "budget_exhausted", "standard", "deep")
        assert result is None

    def test_no_promotion_standard_confirmed_but_completed(self):
        findings = [{"evidence_level": "crash_reproduced"}]
        result = promotion_decision(findings, "completed", "standard", "deep")
        assert result is None

    def test_no_promotion_at_max_band(self):
        findings = [{"evidence_level": "crash_reproduced"}]
        result = promotion_decision(findings, "budget_exhausted", "standard", "standard")
        assert result is None

    def test_no_promotion_beyond_max_band(self):
        findings = [{"evidence_level": "crash_reproduced"}]
        result = promotion_decision(findings, "budget_exhausted", "deep", "deep")
        assert result is None

    def test_fast_to_deep_skips_standard(self):
        """max_band=deep, current=fast → promotes to standard, not deep."""
        findings = [{"description": "found something"}]
        result = promotion_decision(findings, "completed", "fast", "deep")
        assert result == "standard"


# --- File rank and redundancy tests ------------------------------------------


class TestFileRankAndRedundancy:
    def test_rank_5_high_priority(self):
        ft = _make_file_target(priority=4.5)
        assert _file_rank(ft) == 5

    def test_rank_4(self):
        ft = _make_file_target(priority=3.5)
        assert _file_rank(ft) == 4

    def test_rank_3(self):
        ft = _make_file_target(priority=2.5)
        assert _file_rank(ft) == 3

    def test_rank_2(self):
        ft = _make_file_target(priority=1.5)
        assert _file_rank(ft) == 2

    def test_rank_1_low_priority(self):
        ft = _make_file_target(priority=0.5)
        assert _file_rank(ft) == 1

    def test_rank_boundary_4_0(self):
        ft = _make_file_target(priority=4.0)
        assert _file_rank(ft) == 5

    def test_redundancy_rank_5_default(self):
        assert _redundancy_for_rank(5) == 3

    def test_redundancy_rank_4_default(self):
        assert _redundancy_for_rank(4) == 2

    def test_redundancy_rank_3_default(self):
        assert _redundancy_for_rank(3) == 1

    def test_redundancy_rank_1_default(self):
        assert _redundancy_for_rank(1) == 1

    def test_redundancy_override_honored(self):
        assert _redundancy_for_rank(5, override=2) == 2
        assert _redundancy_for_rank(1, override=4) == 4

    def test_redundancy_override_capped_at_5(self):
        assert _redundancy_for_rank(5, override=10) == 5


# --- BandBudget tests -------------------------------------------------------


class TestBandBudget:
    def test_defaults(self):
        bb = BandBudget()
        assert bb.fast_usd == 5.0
        assert bb.standard_usd == 25.0
        assert bb.deep_usd == 100.0

    def test_for_band(self):
        bb = BandBudget(fast_usd=1.0, standard_usd=10.0, deep_usd=50.0)
        assert bb.for_band("fast") == 1.0
        assert bb.for_band("standard") == 10.0
        assert bb.for_band("deep") == 50.0

    def test_for_band_invalid_raises(self):
        bb = BandBudget()
        with pytest.raises(KeyError):
            bb.for_band("turbo")


# --- WorkItem expansion tests -----------------------------------------------


class TestWorkItemExpansion:
    def test_rank_5_produces_3_work_items(self):
        ft = _make_file_target(priority=4.5)
        pool = HunterPool(
            HuntPoolConfig(files=[ft], repo_path="/tmp/repo", starting_band="fast")
        )
        items = pool._expand_to_work_items([ft], "fast")
        assert len(items) == 3
        assert all(wi.band == "fast" for wi in items)
        assert [wi.attempt for wi in items] == [0, 1, 2]

    def test_rank_3_produces_1_work_item(self):
        ft = _make_file_target(priority=2.5)
        pool = HunterPool(
            HuntPoolConfig(files=[ft], repo_path="/tmp/repo", starting_band="fast")
        )
        items = pool._expand_to_work_items([ft], "standard")
        assert len(items) == 1
        assert items[0].band == "standard"

    def test_redundancy_override(self):
        ft = _make_file_target(priority=4.5)
        pool = HunterPool(
            HuntPoolConfig(
                files=[ft],
                repo_path="/tmp/repo",
                starting_band="fast",
                redundancy_override=1,
            )
        )
        items = pool._expand_to_work_items([ft], "fast")
        assert len(items) == 1


# --- HunterRunResult integration tests --------------------------------------


class TestHunterRunResult:
    @pytest.mark.asyncio
    async def test_arun_returns_hunter_run_result(self):
        from dataclasses import dataclass
        from unittest.mock import patch as mock_patch

        from clearwing.agent.tools.hunt.sandbox import HunterContext
        from clearwing.llm.native import NativeToolSpec
        from clearwing.sourcehunt.hunter import NativeHunter

        @dataclass
        class FakeUsage:
            prompt_tokens: int = 100
            completion_tokens: int = 50
            total_tokens: int = 150

        class FakeResponse:
            def __init__(self):
                self.usage = FakeUsage()
                self.provider_model_name = "test-model"

            def first_text(self):
                return "No vulnerabilities found."

            def tool_calls(self):
                return []

        llm = AsyncMock()
        llm.achat.return_value = FakeResponse()
        ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())

        hunter = NativeHunter(
            llm=llm,
            prompt="test",
            tools=[],
            ctx=ctx,
            max_steps=10,
            agent_mode="constrained",
            budget_usd=5.0,
        )

        with mock_patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
            mock_traj.for_hunter.return_value = MagicMock()
            result = await hunter.arun()

        assert result.stop_reason == "completed"
        assert result.cost_usd >= 0
        assert result.tokens_used >= 0
        assert isinstance(result.findings, list)
        assert result.transcript_summary == "No vulnerabilities found."


# --- Budget enforcement in constrained mode ----------------------------------


class TestBudgetEnforcement:
    @pytest.mark.asyncio
    async def test_budget_enforced_in_constrained_mode(self):
        from dataclasses import dataclass
        from unittest.mock import patch as mock_patch

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
            def __init__(self):
                self.usage = FakeUsage()
                self.provider_model_name = "test-model"

            def first_text(self):
                return ""

            def tool_calls(self):
                return [ToolCall("call_1", "think", '{"notes": "thinking"}')]

        llm = AsyncMock()
        llm.achat.return_value = FakeResponse()
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
            prompt="test",
            tools=tools,
            ctx=ctx,
            max_steps=100,
            agent_mode="constrained",
            budget_usd=0.01,
        )

        with mock_patch("clearwing.sourcehunt.hunter.HunterTrajectoryLogger") as mock_traj:
            mock_traj.for_hunter.return_value = MagicMock()
            with mock_patch(
                "clearwing.sourcehunt.hunter._estimate_cost_usd", return_value=0.005
            ):
                result = await hunter.arun()

        assert result.stop_reason == "budget_exhausted"
        assert llm.achat.call_count < 100


# --- Seed transcript tests ---------------------------------------------------


class TestSeedTranscript:
    def test_seed_transcript_appended_to_prompt(self):
        from clearwing.sourcehunt.hunter import build_hunter_agent

        llm = MagicMock()
        ft = _make_file_target()
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            seed_transcript="Found a potential buffer overflow at line 42.",
        )
        assert "Found a potential buffer overflow at line 42." in hunter.prompt
        assert "previous investigation" in hunter.prompt
        assert "Do not repeat" in hunter.prompt

    def test_no_seed_transcript_no_block(self):
        from clearwing.sourcehunt.hunter import build_hunter_agent

        llm = MagicMock()
        ft = _make_file_target()
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
        )
        assert "previous investigation" not in hunter.prompt


# --- Pool band wiring tests --------------------------------------------------


class TestPoolBandWiring:
    def test_pool_tracks_band_stats(self):
        pool = HunterPool(
            HuntPoolConfig(
                files=[],
                repo_path="/tmp/repo",
                starting_band="fast",
            )
        )
        assert pool.spent_per_band == {"fast": 0.0, "standard": 0.0, "deep": 0.0}
        assert pool.runs_per_band == {"fast": 0, "standard": 0, "deep": 0}
        assert pool.promotion_counts == {"fast→standard": 0, "standard→deep": 0}

    def test_band_order_tuple(self):
        assert BAND_ORDER == ("fast", "standard", "deep")
        assert BAND_ORDER.index("fast") < BAND_ORDER.index("standard")
        assert BAND_ORDER.index("standard") < BAND_ORDER.index("deep")
