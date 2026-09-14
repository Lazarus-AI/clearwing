"""Tests for SourceHuntConfig field defaults and wiring."""

from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.sourcehunt.config import HuntTuning, SourceHuntConfig, TargetConfig
from clearwing.sourcehunt.nday import NdayPipeline
from clearwing.sourcehunt.nday_filter import NdayCandidate, NdayFilter
from clearwing.sourcehunt.reveng import RevengPipeline
from clearwing.sourcehunt.reveng_reconstructor import RevengReconstructor
from clearwing.ui.commands import sourcehunt


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


@pytest.mark.asyncio
async def test_nday_pipeline_consumes_tuning():
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.first_text = "[]"
    mock_llm.aask_text = AsyncMock(return_value=mock_response)
    tuning = HuntTuning(nday_filter_batch_size=3)

    pipeline = NdayPipeline(llm=mock_llm, tuning=tuning)
    candidates = [NdayCandidate(cve_id=f"CVE-2024-{i:04d}") for i in range(10)]
    await pipeline.arun(candidates)

    assert mock_llm.aask_text.call_count == 4


def test_nday_pipeline_explicit_size_wins_over_tuning():
    tuning = HuntTuning(nday_filter_batch_size=2)

    pipeline = NdayPipeline(llm=MagicMock(), filter_batch_size=4, tuning=tuning)

    assert pipeline._filter_batch_size == 4


def test_nday_pipeline_rejects_invalid_tuning_during_construction():
    tuning = HuntTuning(nday_filter_batch_size=0)

    with pytest.raises(ValueError, match="batch_size must be >= 1"):
        NdayPipeline(llm=MagicMock(), tuning=tuning)


@pytest.mark.parametrize("batch_size", [True, 1.5, "2"])
def test_nday_filter_batch_size_requires_an_integer(batch_size):
    with pytest.raises(ValueError, match="batch_size must be >= 1"):
        NdayFilter(AsyncMock(), batch_size=batch_size)


def test_reveng_pipeline_stores_reconstruction_batch_size():
    pipeline = RevengPipeline(llm=MagicMock(), reconstruction_batch_size=2)
    assert pipeline._reconstruction_batch_size == 2


def test_reveng_pipeline_uses_reconstructor_default_without_tuning():
    pipeline = RevengPipeline(llm=MagicMock())
    assert pipeline._reconstruction_batch_size == RevengReconstructor.BATCH_SIZE


def test_reveng_pipeline_consumes_tuning_and_explicit_value_wins():
    tuning = HuntTuning(reveng_batch_size=3)

    configured = RevengPipeline(llm=MagicMock(), tuning=tuning)
    overridden = RevengPipeline(
        llm=MagicMock(),
        reconstruction_batch_size=2,
        tuning=tuning,
    )

    assert configured._reconstruction_batch_size == 3
    assert overridden._reconstruction_batch_size == 2


def test_reveng_pipeline_rejects_invalid_tuning_during_construction():
    tuning = HuntTuning(reveng_batch_size=-1)

    with pytest.raises(ValueError, match="batch_size must be >= 1"):
        RevengPipeline(llm=MagicMock(), tuning=tuning)


def test_reveng_reconstructor_subclass_batch_size_remains_the_default():
    class SmallBatchReconstructor(RevengReconstructor):
        BATCH_SIZE = 3

    reconstructor = SmallBatchReconstructor(AsyncMock())

    assert reconstructor._batch_size == 3


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--nday-filter-batch-size", "0"),
        ("--reveng-batch-size", "-2"),
        ("--reveng-batch-size", "1.5"),
    ],
)
def test_cli_rejects_invalid_batch_sizes(option, value):
    parser = argparse.ArgumentParser()
    sourcehunt.add_parser(parser.add_subparsers())

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["sourcehunt", "repo", option, value])

    assert exc_info.value.code == 2


def test_cli_accepts_positive_batch_sizes():
    parser = argparse.ArgumentParser()
    sourcehunt.add_parser(parser.add_subparsers())

    args = parser.parse_args(
        [
            "sourcehunt",
            "repo",
            "--nday-filter-batch-size",
            "3",
            "--reveng-batch-size",
            "2",
        ]
    )

    assert args.nday_filter_batch_size == 3
    assert args.reveng_batch_size == 2
