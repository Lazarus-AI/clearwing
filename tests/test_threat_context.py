from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.agent.tools.hunt.threat_context import (
    THREAT_KNOWLEDGE,
    _resolve_static,
    build_threat_context_tool,
)


def test_resolve_static_matches_alias_at_word_boundary() -> None:
    assert _resolve_static("network packet parser") == THREAT_KNOWLEDGE["parser"]


def test_resolve_static_does_not_match_alias_inside_word() -> None:
    assert _resolve_static("machine learning configuration") == THREAT_KNOWLEDGE["config_trust"]


@pytest.mark.asyncio
async def test_threat_context_uses_static_fallback_without_llm(tmp_path) -> None:
    tool = build_threat_context_tool(HunterContext(repo_path=str(tmp_path)))

    result = await tool.ainvoke({"context": "SQL query construction"})

    assert "parameterized" in result


@pytest.mark.asyncio
async def test_threat_context_falls_back_when_oracle_fails(tmp_path) -> None:
    llm = AsyncMock()
    llm.achat.side_effect = RuntimeError("offline")
    tool = build_threat_context_tool(HunterContext(repo_path=str(tmp_path), llm=llm))

    result = await tool.ainvoke({"context": "file path"})

    assert "Directory traversal" in result
    llm.achat.assert_awaited_once()


@pytest.mark.asyncio
async def test_threat_context_returns_oracle_response(tmp_path) -> None:
    llm = AsyncMock()
    llm.achat.return_value = SimpleNamespace(text="1. CWE-787: inspect the length")
    tool = build_threat_context_tool(HunterContext(repo_path=str(tmp_path), llm=llm))

    result = await tool.ainvoke({"context": "packet parser"})

    assert result == "1. CWE-787: inspect the length"
