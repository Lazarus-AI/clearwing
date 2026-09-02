"""Tests for SourceHuntConfig field defaults and wiring."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.sourcehunt.config import HuntTuning, SourceHuntConfig, TargetConfig
from clearwing.sourcehunt.nday import NdayPipeline
from clearwing.sourcehunt.nday_filter import NdayCandidate
from clearwing.sourcehunt.reveng import RevengPipeline


def test_hunt_tuning_batch_size_defaults():
    t = HuntTuning()
    assert t.nday_filter_batch_size == 10
    assert t.reveng_batch_size == 8


def test_hunt_tuning_batch_size_override():
    t = HuntTuning(nday_filter_batch_size=3, reveng_batch_size=2)
    assert t.nday_filter_batch_size == 3
    assert t.reveng_batch_size == 2


def test_source_hunt_config_exposes_batch_sizes_via_tuning():
    cfg = SourceHuntConfig(target=TargetConfig(repo_url="https://example.com/repo"))
    assert cfg.tuning.nday_filter_batch_size == 10
    assert cfg.tuning.reveng_batch_size == 8


@pytest.mark.asyncio
async def test_nday_pipeline_threads_filter_batch_size():
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.first_text = "[]"
    mock_llm.aask_text = AsyncMock(return_value=mock_response)

    pipeline = NdayPipeline(llm=mock_llm, filter_batch_size=3)
    candidates = [NdayCandidate(cve_id=f"CVE-2024-{i:04d}") for i in range(10)]
    await pipeline.arun(candidates)
    # 10 candidates / batch 3 = 4 LLM calls
    assert mock_llm.aask_text.call_count == 4


def test_reveng_pipeline_stores_reconstruction_batch_size():
    pipeline = RevengPipeline(llm=MagicMock(), reconstruction_batch_size=2)
    assert pipeline._reconstruction_batch_size == 2


def test_reveng_pipeline_default_batch_size_from_tuning():
    pipeline = RevengPipeline(llm=MagicMock())
    assert pipeline._reconstruction_batch_size == HuntTuning().reveng_batch_size
