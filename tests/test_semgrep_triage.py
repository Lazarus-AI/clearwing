from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from clearwing.sourcehunt.semgrep_triage import triage_semgrep_findings

FINDINGS = [
    {"file": "a.c", "line": 10, "severity": "high", "cwe": "CWE-787", "message": "copy"},
    {"file": "b.c", "line": 20, "severity": "medium", "cwe": "CWE-22", "message": "path"},
]


@pytest.mark.asyncio
async def test_triage_returns_only_matching_picks_with_rationale() -> None:
    llm = AsyncMock()
    llm.achat.return_value = SimpleNamespace(
        text='```json\n[{"file":"b.c","line":20,"category":"path traversal",'
        '"cwe":"CWE-22","rationale":"attacker-controlled path"}]\n```'
    )

    result = await triage_semgrep_findings(FINDINGS, "parser", llm)

    assert result == [{**FINDINGS[1], "rationale": "attacker-controlled path"}]


@pytest.mark.asyncio
async def test_triage_without_llm_returns_raw_findings() -> None:
    assert await triage_semgrep_findings(FINDINGS, "parser", None) == FINDINGS


@pytest.mark.asyncio
async def test_triage_malformed_response_returns_raw_findings() -> None:
    llm = AsyncMock()
    llm.achat.return_value = SimpleNamespace(text="not json")

    assert await triage_semgrep_findings(FINDINGS, "parser", llm) == FINDINGS


@pytest.mark.asyncio
async def test_triage_unmatched_pick_returns_raw_findings() -> None:
    llm = AsyncMock()
    llm.achat.return_value = SimpleNamespace(
        text='[{"file":"invented.c","line":99,"category":"memory",'
        '"cwe":"CWE-787","rationale":"invented"}]'
    )

    assert await triage_semgrep_findings(FINDINGS, "parser", llm) == FINDINGS
