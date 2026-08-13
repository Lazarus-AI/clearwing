"""Leakage-boundary tests for LAIR validator GEPA."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from test_sourcehunt_lair_validator import _replay_golden, _verdict

from clearwing.eval.sourcehunt_lair_gepa import (
    VALIDATOR_PROMPT_COMPONENT,
    VALIDATOR_REFLECTION_TEMPLATE,
    LairValidatorGEPAAdapter,
    LairValidatorMetricBudgetStopper,
    require_generic_validator_prompt,
)
from clearwing.sourcehunt.validator import VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT


class _UnusedClient:
    pass


def test_prompt_linter_rejects_answer_bearing_and_oversized_text(tmp_path: Path) -> None:
    golden = _replay_golden(tmp_path / "repo")

    require_generic_validator_prompt(VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT, [golden])
    with pytest.raises(ValueError, match="leaks LAIR"):
        require_generic_validator_prompt(
            f"Inspect {golden.chain.discovery.candidate.location}", [golden]
        )
    with pytest.raises(ValueError, match="exceeds"):
        require_generic_validator_prompt("x" * 2001, [golden])
    with pytest.raises(ValueError, match="evaluation-protocol"):
        require_generic_validator_prompt("Compare paired snapshots.", [golden])
    with pytest.raises(ValueError, match="evaluation-protocol"):
        require_generic_validator_prompt(
            "Set rejected_source_contradicted_claim=true.", [golden]
        )
    assert "<curr_param>" in VALIDATOR_REFLECTION_TEMPLATE
    assert "<side_info>" in VALIDATOR_REFLECTION_TEMPLATE
    assert "case identities" in VALIDATOR_REFLECTION_TEMPLATE


def test_adapter_exposes_only_opaque_examples_and_abstract_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "workspaces" / "CVE-2099-1001" / "repo"
    repo.parent.mkdir(parents=True)
    golden = _replay_golden(repo)
    adapter = LairValidatorGEPAAdapter(
        _UnusedClient(),  # type: ignore[arg-type]
        [golden],
        tmp_path,
        model="small-model",
    )

    async def replay(_golden, _repo, _call, **_kwargs):
        from clearwing.eval.sourcehunt_lair_validator import (
            LairValidatorCaseResult,
            _verdict_payload,
        )

        vulnerable = _verdict_payload(_verdict(True))
        fixed = _verdict_payload(_verdict(False))
        return LairValidatorCaseResult(
            cve=golden.cve,
            repository=golden.repo,
            finding_digest="a" * 64,
            source_window_digest="b" * 64,
            vulnerable=vulnerable,
            fixed=fixed,
            vulnerable_correct=True,
            fixed_correct=True,
            pair_correct=True,
        )

    monkeypatch.setattr(
        "clearwing.eval.sourcehunt_lair_gepa.replay_lair_validator_case", replay
    )
    result = adapter.evaluate(
        list(adapter.examples),
        {VALIDATOR_PROMPT_COMPONENT: VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT},
        capture_traces=True,
    )
    reflective = adapter.make_reflective_dataset(
        {VALIDATOR_PROMPT_COMPONENT: VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT},
        result,
        [VALIDATOR_PROMPT_COMPONENT],
    )

    assert len(adapter.examples) == 1
    assert adapter.propose_new_texts is None
    assert adapter.examples[0].case_id.startswith("case-")
    assert result.scores == [1.0]
    rendered = repr(adapter.examples) + repr(reflective)
    assert golden.cve not in rendered
    assert golden.repo not in rendered
    assert golden.chain.discovery.candidate.location not in rendered
    assert "source-supported behavior" in rendered
    assert "snapshot" not in rendered
    assert "_correct" not in rendered
    assert "axis_pattern" not in rendered


def test_adapter_cannot_run_inside_event_loop(tmp_path: Path) -> None:
    repo = tmp_path / "workspaces" / "CVE-2099-1001" / "repo"
    repo.parent.mkdir(parents=True)
    golden = _replay_golden(repo)
    adapter = LairValidatorGEPAAdapter(
        _UnusedClient(),  # type: ignore[arg-type]
        [golden],
        tmp_path,
        model="small-model",
    )

    async def invoke() -> None:
        with pytest.raises(RuntimeError, match="cannot run in an event loop"):
            adapter.evaluate(
                list(adapter.examples),
                {VALIDATOR_PROMPT_COMPONENT: VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT},
            )

    asyncio.run(invoke())


def test_adapter_enforces_hard_metric_call_budget(tmp_path: Path) -> None:
    repo = tmp_path / "workspaces" / "CVE-2099-1001" / "repo"
    repo.parent.mkdir(parents=True)
    golden = _replay_golden(repo)
    adapter = LairValidatorGEPAAdapter(
        _UnusedClient(),  # type: ignore[arg-type]
        [golden],
        tmp_path,
        model="small-model",
        max_metric_calls=1,
    )
    adapter.metric_calls = 1

    with pytest.raises(RuntimeError, match="budget exhausted"):
        adapter.evaluate(
            list(adapter.examples),
            {VALIDATOR_PROMPT_COMPONENT: VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT},
        )


def test_budget_stopper_reserves_worst_case_iteration() -> None:
    adapter = object.__new__(LairValidatorGEPAAdapter)
    adapter.metric_calls = 58
    stopper = LairValidatorMetricBudgetStopper(
        adapter,
        max_metric_calls=72,
        max_iteration_calls=14,
    )

    assert stopper(object()) is False
    adapter.metric_calls = 59
    assert stopper(object()) is True
