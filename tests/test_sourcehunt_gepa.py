"""Core-GEPA adapter tests without requiring the optional GEPA package."""

from __future__ import annotations

from pathlib import Path

import pytest

from clearwing.eval.sourcehunt import (
    AblationLevel,
    AblationRunSpec,
    GroundTruthManifest,
    RunObservation,
    StageFunnel,
    include_fixed_negative_cases,
)
from clearwing.eval.sourcehunt_gepa import (
    PROMPT_COMPONENT,
    SourceHuntGEPAAdapter,
    SourceHuntOptimizationExample,
    score_sourcehunt_observation,
)
from clearwing.sourcehunt.optimization import GENERIC_INSTRUCTIONS_V1


def _spec(case) -> AblationRunSpec:
    return AblationRunSpec(
        case_id=case.id,
        repository=case.repository,
        vulnerable_commit=case.vulnerable_commit,
        case_digest=case.digest,
        flow="legacy",
        model_tier="local",
        model="deepseek-local",
        prompt_bundle="generic-security-v1",
        scaffold_profile="minimal-linear-v1",
        level=AblationLevel.REPOSITORY,
    )


def _observation(spec, *, positive: bool, session_dir: Path) -> RunObservation:
    return RunObservation(
        run_id=spec.id,
        context_id=spec.context_id,
        case_id=spec.case_id,
        flow=spec.flow,
        model_tier=spec.model_tier,
        model=spec.model,
        prompt_bundle=spec.prompt_bundle,
        scaffold_profile=spec.scaffold_profile,
        context_profile=spec.context_profile,
        level=spec.level,
        replicate=spec.replicate,
        session_dir=str(session_dir),
        status="completed",
        funnel=StageFunnel(
            target_in_working_set=True,
            true_candidate_generated=positive,
            correct_certificate_compiled=positive,
        ),
        true_positives=int(positive),
        false_negatives=int(not positive),
        finding_count=int(positive),
        report_claim_count=int(positive),
    )


def test_adapter_requires_negative_controls() -> None:
    manifest = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")

    with pytest.raises(ValueError, match="fixed/clean negatives"):
        SourceHuntGEPAAdapter(manifest)


def test_adapter_evaluates_generic_candidate_and_emits_reflection_data(tmp_path) -> None:
    manifest = include_fixed_negative_cases(
        GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")
    )
    positive_case = manifest.cases[0]
    negative_case = manifest.case(f"{positive_case.id}-fixed-negative")
    calls: list[dict] = []

    async def execute(spec, case, **kwargs):
        calls.append(kwargs)
        expected_positive = case.ground_truth.expected_decision == "confirmed"
        return _observation(
            spec,
            positive=expected_positive,
            session_dir=tmp_path / kwargs["session_id"],
        )

    adapter = SourceHuntGEPAAdapter(manifest, executor=execute)
    examples = [
        SourceHuntOptimizationExample(
            spec=_spec(case),
            case=case,
            checkout=tmp_path,
            output_dir=tmp_path,
            provider_manager=object(),
            input_price_per_million=0.0,
            output_price_per_million=0.0,
            max_hunt_files=24,
            max_hunter_steps=40,
        )
        for case in (positive_case, negative_case)
    ]

    result = adapter.evaluate(
        examples,
        {PROMPT_COMPONENT: GENERIC_INSTRUCTIONS_V1},
        capture_traces=True,
    )

    assert result.scores == [1.0, 1.0]
    assert result.num_metric_calls == 2
    assert len(result.trajectories) == 2
    assert all(call["prompt_candidate"] == GENERIC_INSTRUCTIONS_V1 for call in calls)
    assert all(call["input_price_per_million"] == 0.0 for call in calls)
    assert all(call["output_price_per_million"] == 0.0 for call in calls)
    assert all(call["max_hunt_files"] == 24 for call in calls)
    assert all(call["max_hunter_steps"] == 40 for call in calls)
    assert all(call["ranker_chunk_size"] == 25 for call in calls)
    assert all(call["ranker_max_inflight_chunks"] == 1 for call in calls)
    assert all(call["ranker_chunk_max_retries"] == 1 for call in calls)
    assert all(call["max_parallel"] == 4 for call in calls)
    assert all(call["starting_band"] == "fast" for call in calls)
    assert all(call["redundancy_override"] == 1 for call in calls)
    assert all(call["depth"] == "standard" for call in calls)
    assert all(call["no_rank"] is True for call in calls)
    assert len({call["session_id"] for call in calls}) == 2
    reflective = adapter.make_reflective_dataset(
        {PROMPT_COMPONENT: GENERIC_INSTRUCTIONS_V1},
        result,
        [PROMPT_COMPONENT],
    )
    assert len(reflective[PROMPT_COMPONENT]) == 2
    assert "Do not add repository names" in reflective[PROMPT_COMPONENT][0]["Feedback"]


def test_adapter_rejects_solution_leaking_candidate(tmp_path) -> None:
    manifest = include_fixed_negative_cases(
        GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")
    )
    case = manifest.cases[0]
    adapter = SourceHuntGEPAAdapter(manifest, executor=None)  # type: ignore[arg-type]
    example = SourceHuntOptimizationExample(
        spec=_spec(case),
        case=case,
        checkout=tmp_path,
        output_dir=tmp_path,
        provider_manager=object(),
    )

    with pytest.raises(ValueError, match="leaks benchmark answers"):
        adapter.evaluate(
            [example],
            {PROMPT_COMPONENT: f"Start in {case.ground_truth.target_files[0]}"},
        )


def test_optimization_examples_reject_assisted_ablation_levels(tmp_path) -> None:
    case = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml").cases[0]
    spec = AblationRunSpec(
        case_id=case.id,
        repository=case.repository,
        vulnerable_commit=case.vulnerable_commit,
        case_digest=case.digest,
        flow="legacy",
        model_tier="local",
        model="deepseek-local",
        prompt_bundle="generic-security-v1",
        scaffold_profile="minimal-linear-v1",
        level=AblationLevel.TARGET_FILE,
        hints={"target_files": case.ground_truth.target_files},
    )

    with pytest.raises(ValueError, match="blind repository-level"):
        SourceHuntOptimizationExample(
            spec=spec,
            case=case,
            checkout=tmp_path,
            output_dir=tmp_path,
            provider_manager=object(),
        )


def test_optimization_examples_reject_proof_flow_until_prompt_is_wired(tmp_path) -> None:
    case = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml").cases[0]
    spec = AblationRunSpec(
        case_id=case.id,
        repository=case.repository,
        vulnerable_commit=case.vulnerable_commit,
        case_digest=case.digest,
        flow="proof",
        model_tier="local",
        model="deepseek-local",
        prompt_bundle="generic-security-v1",
        scaffold_profile="minimal-linear-v1",
        level=AblationLevel.REPOSITORY,
    )

    with pytest.raises(ValueError, match="legacy discovery flow"):
        SourceHuntOptimizationExample(
            spec=spec,
            case=case,
            checkout=tmp_path,
            output_dir=tmp_path,
            provider_manager=object(),
        )


def test_score_penalizes_unvalidated_extra_findings(tmp_path) -> None:
    case = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml").cases[0]
    spec = _spec(case)
    observation = _observation(spec, positive=True, session_dir=tmp_path).model_copy(
        update={"false_positives": 2, "finding_count": 3}
    )

    score, objectives = score_sourcehunt_observation(observation, case)

    assert score < 1.0
    assert objectives["precision"] == pytest.approx(1 / 3)
