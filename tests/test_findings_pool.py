"""Tests for spec 005 — shared findings pool, historical DB, and pool query tool."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.findings.types import Finding
from clearwing.sourcehunt.findings_pool import (
    PRIMITIVE_TYPES,
    FindingCluster,
    FindingsPool,
    _CWE_PRIMITIVE_MAP,
    _FINDING_TYPE_PRIMITIVE_MAP,
)
from clearwing.sourcehunt.historical_findings_db import HistoricalFindingsDB


def _make_finding(**overrides) -> Finding:
    defaults = {
        "id": f"f-{uuid.uuid4().hex[:8]}",
        "file": "src/parser.c",
        "line_number": 42,
        "finding_type": "buffer_overflow",
        "cwe": "CWE-787",
        "severity": "high",
        "description": "Heap buffer overflow in parse_header",
        "code_snippet": "memcpy(buf, src, len);",
        "evidence_level": "static_corroboration",
        "hunter_session_id": "session-a",
    }
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# FindingsPool — primitive classification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_sets_primitive_type_from_cwe():
    pool = FindingsPool()
    f = _make_finding(cwe="CWE-787")
    result = await pool.add(f)
    assert result.primitive_type == "bounded_write"


@pytest.mark.asyncio
async def test_add_sets_primitive_from_finding_type():
    pool = FindingsPool()
    f = _make_finding(cwe="CWE-999", finding_type="sql_injection")
    result = await pool.add(f)
    assert result.primitive_type == "sql_injection"


@pytest.mark.asyncio
async def test_add_unknown_cwe_no_llm_falls_back_to_unknown():
    pool = FindingsPool()
    f = _make_finding(cwe="CWE-999", finding_type="exotic_bug")
    result = await pool.add(f)
    assert result.primitive_type == "unknown"


@pytest.mark.asyncio
async def test_add_with_llm_classification():
    mock_llm = AsyncMock()
    mock_response = MagicMock()
    mock_response.first_text = '{"primitive_type": "race_condition"}'
    mock_llm.achat.return_value = mock_response

    pool = FindingsPool(llm=mock_llm)
    f = _make_finding(cwe="CWE-999", finding_type="exotic_bug")
    result = await pool.add(f)
    assert result.primitive_type == "race_condition"


@pytest.mark.asyncio
async def test_add_preserves_existing_primitive_type():
    pool = FindingsPool()
    f = _make_finding(primitive_type="info_leak")
    result = await pool.add(f)
    assert result.primitive_type == "info_leak"


# ---------------------------------------------------------------------------
# FindingsPool — clustering & dedup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_sets_cluster_id():
    pool = FindingsPool()
    f = _make_finding()
    result = await pool.add(f)
    assert result.cluster_id
    assert result.cluster_id.startswith("cluster-")


@pytest.mark.asyncio
async def test_dedup_same_root_cause():
    mock_llm = AsyncMock()
    call_count = 0

    async def mock_achat(**kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        if call_count <= 2:
            # Classification calls
            resp.first_text = '{"primitive_type": "bounded_write"}'
        else:
            # Dedup call — return the cluster of the first finding
            cluster_id = list(pool._clusters.keys())[0]
            resp.first_text = f'{{"duplicate_of": "{cluster_id}"}}'
        return resp

    mock_llm.achat = mock_achat

    pool = FindingsPool(llm=mock_llm)
    f1 = _make_finding(id="f1", cwe="CWE-999", finding_type="exotic")
    f2 = _make_finding(id="f2", cwe="CWE-999", finding_type="exotic")

    await pool.add(f1)
    await pool.add(f2)

    assert f1.cluster_id == f2.cluster_id
    assert len(pool.clusters()) == 1


@pytest.mark.asyncio
async def test_dedup_different_root_cause():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", file="src/a.c", cwe="CWE-787")
    f2 = _make_finding(id="f2", file="src/b.c", cwe="CWE-416")

    await pool.add(f1)
    await pool.add(f2)

    assert f1.cluster_id != f2.cluster_id
    assert len(pool.clusters()) == 2


@pytest.mark.asyncio
async def test_dedup_skipped_without_llm():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", cwe="CWE-787")
    f2 = _make_finding(id="f2", cwe="CWE-787")

    await pool.add(f1)
    await pool.add(f2)

    # Without LLM, each finding gets its own cluster even if they overlap
    assert f1.cluster_id != f2.cluster_id


# ---------------------------------------------------------------------------
# FindingsPool — query
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_by_primitive_type():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", cwe="CWE-200", finding_type="info_leak")
    f2 = _make_finding(id="f2", cwe="CWE-787", finding_type="buffer_overflow")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(primitive_type="info_leak")
    assert len(results) == 1
    assert results[0].id == "f1"


@pytest.mark.asyncio
async def test_query_by_cwe():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", cwe="CWE-89")
    f2 = _make_finding(id="f2", cwe="CWE-787")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(cwe="CWE-89")
    assert len(results) == 1
    assert results[0].id == "f1"


@pytest.mark.asyncio
async def test_query_by_file_path():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", file="src/a.c")
    f2 = _make_finding(id="f2", file="src/b.c")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(file_path="src/a.c")
    assert len(results) == 1
    assert results[0].id == "f1"


@pytest.mark.asyncio
async def test_query_exclude_session():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", hunter_session_id="session-a")
    f2 = _make_finding(id="f2", hunter_session_id="session-b")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(exclude_session="session-a")
    assert len(results) == 1
    assert results[0].id == "f2"


@pytest.mark.asyncio
async def test_query_no_filters_returns_all():
    pool = FindingsPool()
    for i in range(5):
        await pool.add(_make_finding(id=f"f{i}"))
    assert len(pool.query()) == 5


# ---------------------------------------------------------------------------
# FindingsPool — all_findings, deduplicated, summary, pool_stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_findings():
    pool = FindingsPool()
    for i in range(3):
        await pool.add(_make_finding(id=f"f{i}"))
    assert len(pool.all_findings()) == 3


@pytest.mark.asyncio
async def test_deduplicated_findings():
    pool = FindingsPool()
    f1 = _make_finding(id="f1")
    f2 = _make_finding(id="f2")
    await pool.add(f1)
    await pool.add(f2)

    # Force f2 into same cluster as f1
    f2.cluster_id = f1.cluster_id
    pool._findings["f2"] = f2

    deduped = pool.deduplicated_findings()
    assert len(deduped) == 1


@pytest.mark.asyncio
async def test_summary_output():
    pool = FindingsPool()
    await pool.add(_make_finding())
    summary = pool.summary()
    assert "bounded_write" in summary or "CWE-787" in summary


@pytest.mark.asyncio
async def test_pool_stats():
    pool = FindingsPool()
    await pool.add(_make_finding(id="f1"))
    await pool.add(_make_finding(id="f2"))
    stats = pool.pool_stats()
    assert stats["total_findings"] == 2
    assert stats["total_clusters"] >= 1


# ---------------------------------------------------------------------------
# FindingsPool — checkpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkpoint_roundtrip(tmp_path):
    cp = tmp_path / "pool.jsonl"
    pool = FindingsPool(checkpoint_path=cp)
    f1 = _make_finding(id="f1", cwe="CWE-787")
    f2 = _make_finding(id="f2", cwe="CWE-416")
    await pool.add(f1)
    await pool.add(f2)

    assert cp.exists()
    lines = cp.read_text().strip().splitlines()
    assert len(lines) == 2

    restored = FindingsPool.from_checkpoint(cp)
    assert len(restored.all_findings()) == 2
    ids = {f.id for f in restored.all_findings()}
    assert "f1" in ids and "f2" in ids


@pytest.mark.asyncio
async def test_checkpoint_not_written_without_path():
    pool = FindingsPool(checkpoint_path=None)
    await pool.add(_make_finding())
    # No error — checkpoint silently skipped


# ---------------------------------------------------------------------------
# FindingsPool — concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_adds():
    pool = FindingsPool()
    findings = [_make_finding(id=f"f{i}") for i in range(10)]
    await asyncio.gather(*[pool.add(f) for f in findings])
    assert len(pool.all_findings()) == 10
    assert all(f.cluster_id for f in pool.all_findings())


# ---------------------------------------------------------------------------
# HistoricalFindingsDB
# ---------------------------------------------------------------------------


def test_schema_creation(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    assert (tmp_path / "test.db").exists()
    db.close()


def test_ingest_and_query(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    findings = [
        _make_finding(id="f1", cwe="CWE-787", file="src/a.c"),
        _make_finding(id="f2", cwe="CWE-89", file="src/b.c"),
    ]
    count = db.ingest_campaign(findings, "https://github.com/test/repo", "session-1")
    assert count == 2

    results = db.query_prior("https://github.com/test/repo")
    assert len(results) == 2

    results = db.query_prior("https://github.com/test/repo", cwe="CWE-89")
    assert len(results) == 1
    assert results[0]["cwe"] == "CWE-89"

    results = db.query_prior("https://github.com/test/repo", file="src/a.c")
    assert len(results) == 1
    db.close()


def test_is_known(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f = _make_finding(cwe="CWE-787", file="src/a.c", line_number=42)
    db.ingest_campaign([f], "https://github.com/test/repo", "session-1")

    assert db.is_known(f, "https://github.com/test/repo")
    assert not db.is_known(
        _make_finding(cwe="CWE-89", file="src/b.c"),
        "https://github.com/test/repo",
    )
    db.close()


def test_cross_campaign(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f1 = _make_finding(id="f1", cwe="CWE-787")
    f2 = _make_finding(id="f2", cwe="CWE-89")
    db.ingest_campaign([f1], "https://github.com/test/repo", "session-1")
    db.ingest_campaign([f2], "https://github.com/test/repo", "session-2")

    results = db.query_prior("https://github.com/test/repo")
    assert len(results) == 2
    db.close()


def test_findings_without_id_skipped(tmp_path):
    # __post_init__ now auto-generates an id when id="" is passed, so a
    # Finding constructed with id="" will have an auto-generated id and be
    # ingested successfully.
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f = _make_finding(id="")
    assert f.id.startswith("f-")  # auto-generated
    count = db.ingest_campaign([f], "https://github.com/test/repo", "session-1")
    assert count == 1
    db.close()


# ---------------------------------------------------------------------------
# Pool query tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_tool_returns_findings():
    from clearwing.agent.tools.hunt.pool_query import build_pool_query_tools
    from clearwing.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    await pool.add(_make_finding(cwe="CWE-200", finding_type="info_leak"))

    ctx = HunterContext(
        repo_path="/tmp/repo",
        findings_pool=pool,
        session_id="session-b",
    )
    tools = build_pool_query_tools(ctx)
    assert len(tools) == 1
    assert tools[0].name == "query_findings_pool"

    result = tools[0].handler(primitive_type="info_leak")
    assert "Found 1 matching findings" in result


@pytest.mark.asyncio
async def test_query_tool_no_pool():
    from clearwing.agent.tools.hunt.pool_query import build_pool_query_tools
    from clearwing.agent.tools.hunt.sandbox import HunterContext

    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=None)
    tools = build_pool_query_tools(ctx)
    result = tools[0].handler()
    assert "not available" in result


def test_pool_tool_in_hunter_tools():
    from clearwing.agent.tools.hunt import build_hunter_tools
    from clearwing.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=pool)
    tools = build_hunter_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" in names


def test_pool_tool_not_in_hunter_tools_without_pool():
    from clearwing.agent.tools.hunt import build_hunter_tools
    from clearwing.agent.tools.hunt.sandbox import HunterContext

    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=None)
    tools = build_hunter_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" not in names


def test_pool_tool_in_deep_agent_tools():
    from clearwing.agent.tools.hunt import build_deep_agent_tools
    from clearwing.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=pool)
    tools = build_deep_agent_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" in names


def test_pool_tool_in_propagation_tools():
    from clearwing.agent.tools.hunt import build_propagation_auditor_tools
    from clearwing.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=pool)
    tools = build_propagation_auditor_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" in names


# ---------------------------------------------------------------------------
# Integration — prompt includes pool block
# ---------------------------------------------------------------------------


def test_prompt_includes_pool_block():
    from clearwing.sourcehunt.hunter import POOL_ACCESS_BLOCK

    pool = FindingsPool()
    pool._findings["f1"] = _make_finding(id="f1")

    from clearwing.sourcehunt.hunter import _build_unconstrained_prompt

    prompt = _build_unconstrained_prompt(
        file_target={"path": "src/a.c", "language": "c", "tags": []},
        project_name="test-project",
        seeded_crash=None,
        semgrep_hints=None,
        findings_pool=pool,
    )
    assert "query_findings_pool" in prompt


def test_prompt_no_pool_block_when_empty():
    from clearwing.sourcehunt.hunter import _build_unconstrained_prompt

    pool = FindingsPool()

    prompt = _build_unconstrained_prompt(
        file_target={"path": "src/a.c", "language": "c", "tags": []},
        project_name="test-project",
        seeded_crash=None,
        semgrep_hints=None,
        findings_pool=pool,
    )
    assert "query_findings_pool" not in prompt


def test_prompt_no_pool_block_without_pool():
    from clearwing.sourcehunt.hunter import _build_unconstrained_prompt

    prompt = _build_unconstrained_prompt(
        file_target={"path": "src/a.c", "language": "c", "tags": []},
        project_name="test-project",
        seeded_crash=None,
        semgrep_hints=None,
    )
    assert "query_findings_pool" not in prompt


# ---------------------------------------------------------------------------
# CWE / finding-type map coverage sanity checks
# ---------------------------------------------------------------------------


def test_cwe_map_values_are_valid_primitives():
    for prim in _CWE_PRIMITIVE_MAP.values():
        assert prim in PRIMITIVE_TYPES, f"{prim} not in PRIMITIVE_TYPES"


def test_finding_type_map_values_are_valid_primitives():
    for prim in _FINDING_TYPE_PRIMITIVE_MAP.values():
        assert prim in PRIMITIVE_TYPES, f"{prim} not in PRIMITIVE_TYPES"
