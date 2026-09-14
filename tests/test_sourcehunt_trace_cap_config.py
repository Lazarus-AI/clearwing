"""Trace-step cap wiring: SourceHuntConfig → HuntPoolConfig → HunterContext."""

from __future__ import annotations

from unittest.mock import MagicMock

from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.sourcehunt.config import HuntTuning, SourceHuntConfig, TargetConfig
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig
from clearwing.sourcehunt.runner import SourceHuntRunner


def test_hunt_tuning_trace_step_default():
    assert HuntTuning().trace_step_max_chars == 4096


def test_source_hunt_config_exposes_trace_step():
    cfg = SourceHuntConfig(
        target=TargetConfig(repo_url="https://example/repo"),
        tuning=HuntTuning(trace_step_max_chars=0),
    )
    assert cfg.tuning.trace_step_max_chars == 0


def test_runner_resolves_trace_cap_from_config_and_allows_explicit_override(tmp_path):
    cfg = SourceHuntConfig(
        target=TargetConfig(repo_url="https://example/repo"),
        tuning=HuntTuning(trace_step_max_chars=0),
    )

    runner_kwargs = {
        "config": cfg,
        "output_dir": str(tmp_path),
        "enable_mechanism_memory": False,
        "enable_calibration": False,
        "enable_knowledge_graph": False,
    }
    assert SourceHuntRunner(**runner_kwargs)._trace_step_max_chars == 0
    assert (
        SourceHuntRunner(**runner_kwargs, trace_step_max_chars=4096)._trace_step_max_chars == 4096
    )
    assert SourceHuntRunner(**runner_kwargs, trace_step_max_chars=-1)._trace_step_max_chars == 0


def test_pool_configures_trace_step_on_context():
    pool_cfg = HuntPoolConfig(
        files=[],
        repo_path="/tmp/repo",
        trace_step_max_chars=0,
    )
    pool = HunterPool(pool_cfg)
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())
    assert ctx.trace_step_max_chars == 4096
    pool._configure_hunter_context((MagicMock(), ctx), work_item_id="wi-1")
    assert ctx.trace_step_max_chars == 0
    assert ctx.work_item_id == "wi-1"


def test_pool_trace_step_default_preserved():
    pool_cfg = HuntPoolConfig(files=[], repo_path="/tmp/repo")
    pool = HunterPool(pool_cfg)
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=MagicMock())
    pool._configure_hunter_context((MagicMock(), ctx), work_item_id="wi-2")
    assert ctx.trace_step_max_chars == 4096
