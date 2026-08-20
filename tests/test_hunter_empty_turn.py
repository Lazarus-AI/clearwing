"""Regression tests for honest handling of empty/truncated hunter turns.

A turn with no tool calls AND no visible text is the fingerprint of a truncated
or empty provider response, not a genuine "I'm done" turn (which always carries
a summary). The hunter nudges such a turn (up to 3 times, finish_reason-aware)
and, if it is *still* empty, records the honest ``stop_reason="empty_response"``
rather than scoring it as a clean ``completed`` 0-finding miss. See the QA review
that surfaced the 4096-token truncation defect.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from genai_pyo3 import ChatResponse, Usage

from clearwing.agent.tools.hunt import HunterContext
from clearwing.sourcehunt.hunter import NativeHunter

FIXTURE = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"


def _usage() -> Usage:
    return Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15)


class _CountingLLM:
    """Stub LLM returning a fixed response and counting achat invocations."""

    model_name = "stub-model"

    def __init__(self, content: list):
        self._content = content
        self.calls = 0

    async def achat(self, *, messages, system, tools, **kwargs):
        self.calls += 1
        return ChatResponse(
            content=self._content,
            usage=_usage(),
            provider_model_name="stub-provider",
        )


def _ctx() -> HunterContext:
    return HunterContext(
        repo_path=str(FIXTURE),
        findings=[],
        file_path="src/codec_a.c",
        session_id="empty-turn-test",
        specialist="general",
    )


class TestEmptyTurnHandling:
    def test_empty_turn_nudges_then_empty_response(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
        monkeypatch.delenv("CLEARWING_SOURCEHUNT_TRACE_DIR", raising=False)
        # No text, no tool calls — the truncation/empty-response fingerprint.
        llm = _CountingLLM(content=[])
        hunter = NativeHunter(
            llm=llm,
            prompt="system prompt",
            tools=[],
            ctx=_ctx(),
            max_steps=20,
        )

        result = asyncio.run(hunter.arun())

        assert result.stop_reason == "empty_response"
        # Initial turn + 3 nudges, all empty, before the honest terminal state.
        assert llm.calls == 4, "should nudge 3 times before giving up"
        assert result.findings == []

    def test_text_only_turn_is_completed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLEARWING_HOME", str(tmp_path))
        monkeypatch.delenv("CLEARWING_SOURCEHUNT_TRACE_DIR", raising=False)
        # A legitimate final summary (text, no tool calls) still completes.
        llm = _CountingLLM(content=[{"text": "Analysis complete: no vulnerabilities."}])
        hunter = NativeHunter(
            llm=llm,
            prompt="system prompt",
            tools=[],
            ctx=_ctx(),
            max_steps=20,
        )

        result = asyncio.run(hunter.arun())

        assert result.stop_reason == "completed"
        assert llm.calls == 1, "a text-bearing turn must not trigger the empty nudge"
