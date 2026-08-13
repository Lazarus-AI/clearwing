"""GEPA adapter for leakage-safe SourceHunt prompt optimization.

GEPA remains an optional dependency.  The adapter itself can be imported and
unit-tested without GEPA; when GEPA is installed it returns the framework's
native ``EvaluationBatch`` object.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.llm import AsyncLLMClient, ChatMessage
from clearwing.sourcehunt.instrumentation import stable_run_id
from clearwing.sourcehunt.optimization import (
    GENERIC_INSTRUCTIONS_V1,
    redact_benchmark_terms,
    require_generic_prompt,
)

from .sourcehunt import (
    AblationLevel,
    AblationRunSpec,
    GroundTruthManifest,
    RunObservation,
    SourceHuntCase,
    execute_sourcehunt_run,
)

PROMPT_COMPONENT = "discovery_prompt"


class ClearwingReflectionLM:
    """Expose Clearwing's native client as GEPA's synchronous LM callable."""

    def __init__(self, client: AsyncLLMClient, *, max_tokens: int = 8192) -> None:
        self.client = client
        self.max_tokens = max_tokens

    def __call__(self, prompt: str | list[dict[str, Any]]) -> str:
        if isinstance(prompt, str):
            system = "You improve generic source-code security audit instructions."
            messages = [ChatMessage("user", prompt)]
        else:
            system_parts = [
                str(item.get("content") or "") for item in prompt if item.get("role") == "system"
            ]
            system = "\n".join(system_parts) or (
                "You improve generic source-code security audit instructions."
            )
            messages = [
                ChatMessage(str(item.get("role") or "user"), str(item.get("content") or ""))
                for item in prompt
                if item.get("role") != "system"
            ]

        async def invoke() -> str:
            response = await self.client.achat(
                messages=messages,
                system=system,
                max_tokens=self.max_tokens,
            )
            return response.first_text or "\n".join(response.texts)

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(invoke())
        raise RuntimeError("ClearwingReflectionLM must run outside an active event loop")


@dataclass(frozen=True)
class SourceHuntOptimizationExample:
    """One immutable benchmark checkout and its execution configuration."""

    spec: AblationRunSpec
    case: SourceHuntCase
    checkout: str | Path
    output_dir: str | Path
    provider_manager: Any = field(repr=False, compare=False)
    budget_usd: float = 1.0
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None
    max_hunt_files: int | None = None
    max_hunter_steps: int | None = None
    ranker_chunk_size: int = 25
    ranker_max_inflight_chunks: int = 1
    ranker_chunk_max_retries: int = 1
    max_parallel: int = 4
    sandbox_cpus: float | None = None
    starting_band: str = "fast"
    redundancy_override: int = 1
    depth: str = "standard"
    no_rank: bool = True
    compile_commands: str | None = None
    validation_manifest: str | None = None
    scheduler_calibration: str | None = None
    learning_registry: str | None = None
    proof_max_actions: int = 200
    proof_max_model_calls: int = 40
    proof_max_dynamic_actions: int = 20

    def __post_init__(self) -> None:
        if self.spec.case_id != self.case.id or self.spec.case_digest != self.case.digest:
            raise ValueError("Optimization example plan and case do not match")
        if self.spec.prompt_bundle != "generic-security-v1":
            raise ValueError("GEPA examples must use the generic-security-v1 prompt bundle")
        if self.spec.flow != "legacy":
            raise ValueError("GEPA prompt examples must use the legacy discovery flow")
        if self.spec.level != AblationLevel.REPOSITORY or self.spec.hints:
            raise ValueError("GEPA examples must use blind repository-level ablations")
        if self.budget_usd <= 0:
            raise ValueError("Optimization examples require a positive budget")
        if (self.input_price_per_million is None) != (
            self.output_price_per_million is None
        ):
            raise ValueError("Optimization examples require both token prices or neither")
        if self.max_hunt_files is not None and self.max_hunt_files < 1:
            raise ValueError("Optimization examples require a positive max_hunt_files")
        if self.max_hunter_steps is not None and self.max_hunter_steps < 1:
            raise ValueError("Optimization examples require positive max_hunter_steps")
        if self.ranker_chunk_size < 1 or self.ranker_max_inflight_chunks < 1:
            raise ValueError("Optimization example ranker bounds must be positive")
        if self.ranker_chunk_max_retries < 0:
            raise ValueError("Optimization example ranker retries cannot be negative")
        if self.max_parallel < 1 or self.redundancy_override < 1:
            raise ValueError("Optimization example concurrency and redundancy must be positive")
        if self.sandbox_cpus is not None and self.sandbox_cpus < 0:
            raise ValueError("Optimization example sandbox_cpus cannot be negative")
        if self.depth not in {"standard", "deep"}:
            raise ValueError("Optimization example depth must be standard or deep")


@dataclass
class _CompatEvaluationBatch:
    outputs: list[dict[str, Any]]
    scores: list[float]
    trajectories: list[dict[str, Any]] | None = None
    objective_scores: list[dict[str, float]] | None = None
    num_metric_calls: int | None = None


def _evaluation_batch(**kwargs: Any) -> Any:
    try:
        from gepa.core.adapter import EvaluationBatch
    except ImportError:
        return _CompatEvaluationBatch(**kwargs)
    return EvaluationBatch(**kwargs)


def _funnel_fraction(observation: RunObservation) -> float:
    values = [value for value in observation.funnel.model_dump().values() if value is not None]
    return sum(value is True for value in values) / len(values) if values else 0.0


def score_sourcehunt_observation(
    observation: RunObservation,
    case: SourceHuntCase,
) -> tuple[float, dict[str, float]]:
    """Score correctness first, then evidence quality and diagnostic progress."""

    expected_positive = case.ground_truth.expected_decision == "confirmed"
    claims = max(1, observation.report_claim_count)
    evidence_quality = max(0.0, 1.0 - observation.unsupported_claims / claims)
    report_health = float(observation.report_failures == 0)
    if expected_positive:
        correctness = float(observation.true_positives > 0)
        precision = (
            observation.true_positives / (observation.true_positives + observation.false_positives)
            if observation.true_positives + observation.false_positives
            else 0.0
        )
        score = (
            0.70 * correctness
            + 0.15 * _funnel_fraction(observation)
            + 0.10 * evidence_quality
            + 0.05 * report_health
        )
    else:
        correctness = float(observation.finding_count == 0)
        precision = correctness
        score = 0.85 * correctness + 0.10 * evidence_quality + 0.05 * report_health

    score = max(0.0, min(1.0, score - min(0.25, 0.05 * observation.false_positives)))
    objectives = {
        "correctness": correctness,
        "precision": precision,
        "evidence_quality": evidence_quality,
        "funnel_progress": _funnel_fraction(observation),
        "report_health": report_health,
    }
    return score, objectives


def _trajectory_excerpt(session_dir: str | Path, manifest: GroundTruthManifest) -> str:
    root = Path(session_dir)
    records: list[str] = []
    for path in sorted(root.rglob("transcript.jsonl"))[:4]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines[-24:]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") == "start":
                continue
            compact = {
                key: record.get(key)
                for key in (
                    "event",
                    "step",
                    "message",
                    "reasoning_content",
                    "tool_call",
                    "tool_output",
                    "status",
                )
                if record.get(key) not in (None, "", [], {})
            }
            records.append(json.dumps(compact, sort_keys=True, default=str))
    excerpt = "\n".join(records)[-8000:]
    return redact_benchmark_terms(excerpt, manifest)


_STAGE_FEEDBACK = {
    "target_in_working_set": "The run did not focus its exploration on the relevant attack surface.",
    "relevant_facts_extracted": "The run read code but missed the state or data facts needed for a concrete hypothesis.",
    "true_candidate_generated": "The run failed to turn observations into the relevant vulnerability mechanism.",
    "correct_proof_plan_selected": "The candidate lacked a complete set of proof obligations.",
    "reachability_dataflow_resolved": "The run did not establish attacker-to-effect reachability.",
    "guards_counterevidence_handled": "The run did not resolve guards or the strongest counterevidence.",
    "validation_plan_constructed": "The run did not construct a realistic validation plan.",
    "expected_evidence_acquired": "The run stopped before acquiring strong supporting evidence.",
    "threat_model_classified": "The security boundary and attacker capability remained unclear.",
    "correct_certificate_compiled": "The final report did not preserve the proven mechanism and evidence.",
}


class SourceHuntGEPAAdapter:
    """Execute candidate prompts through Clearwing and emit reflective feedback."""

    def __init__(
        self,
        manifest: GroundTruthManifest,
        *,
        executor: Callable[..., Awaitable[RunObservation]] = execute_sourcehunt_run,
        require_negative_controls: bool = True,
    ) -> None:
        decisions = {case.ground_truth.expected_decision for case in manifest.cases}
        if require_negative_controls and not {"confirmed", "disproven"} <= decisions:
            raise ValueError(
                "GEPA optimization requires both vulnerable positives and fixed/clean negatives"
            )
        self.manifest = manifest
        self.executor = executor

    def evaluate(
        self,
        batch: list[SourceHuntOptimizationExample],
        candidate: dict[str, str],
        capture_traces: bool = False,
    ) -> Any:
        prompt = candidate.get(PROMPT_COMPONENT, "")
        if not prompt.strip():
            raise ValueError(f"Candidate is missing non-empty {PROMPT_COMPONENT!r}")
        require_generic_prompt(prompt, manifest=self.manifest)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._evaluate_async(batch, prompt, capture_traces))
        raise RuntimeError("SourceHuntGEPAAdapter.evaluate must run outside an active event loop")

    async def _evaluate_async(
        self,
        batch: list[SourceHuntOptimizationExample],
        prompt: str,
        capture_traces: bool,
    ) -> Any:
        outputs: list[dict[str, Any]] = []
        scores: list[float] = []
        objectives: list[dict[str, float]] = []
        trajectories: list[dict[str, Any]] = []
        candidate_id = stable_run_id("promptcandidate", prompt)

        for example in batch:
            session_id = stable_run_id(
                "geparun",
                {
                    "candidate_id": candidate_id,
                    "run_id": example.spec.id,
                    "scaffold_profile": example.spec.scaffold_profile,
                    "context_profile": example.spec.context_profile,
                    "execution_bounds": {
                        "max_hunt_files": example.max_hunt_files,
                        "max_hunter_steps": example.max_hunter_steps,
                        "ranker_chunk_size": example.ranker_chunk_size,
                        "ranker_max_inflight_chunks": example.ranker_max_inflight_chunks,
                        "ranker_chunk_max_retries": example.ranker_chunk_max_retries,
                        "max_parallel": example.max_parallel,
                        "sandbox_cpus": example.sandbox_cpus,
                        "starting_band": example.starting_band,
                        "redundancy_override": example.redundancy_override,
                        "depth": example.depth,
                        "no_rank": example.no_rank,
                    },
                },
            )
            try:
                observation = await self.executor(
                    example.spec,
                    example.case,
                    checkout=example.checkout,
                    output_dir=example.output_dir,
                    provider_manager=example.provider_manager,
                    budget_usd=example.budget_usd,
                    input_price_per_million=example.input_price_per_million,
                    output_price_per_million=example.output_price_per_million,
                    max_hunt_files=example.max_hunt_files,
                    max_hunter_steps=example.max_hunter_steps,
                    ranker_chunk_size=example.ranker_chunk_size,
                    ranker_max_inflight_chunks=example.ranker_max_inflight_chunks,
                    ranker_chunk_max_retries=example.ranker_chunk_max_retries,
                    max_parallel=example.max_parallel,
                    sandbox_cpus=example.sandbox_cpus,
                    starting_band=example.starting_band,
                    redundancy_override=example.redundancy_override,
                    depth=example.depth,
                    no_rank=example.no_rank,
                    compile_commands=example.compile_commands,
                    validation_manifest=example.validation_manifest,
                    scheduler_calibration=example.scheduler_calibration,
                    learning_registry=example.learning_registry,
                    proof_max_actions=example.proof_max_actions,
                    proof_max_model_calls=example.proof_max_model_calls,
                    proof_max_dynamic_actions=example.proof_max_dynamic_actions,
                    prompt_candidate=prompt,
                    session_id=session_id,
                )
                score, objective = score_sourcehunt_observation(observation, example.case)
                output = observation.model_dump(mode="json")
                trajectory = {
                    "status": "completed",
                    "score": score,
                    "objective_scores": objective,
                    "first_failure": observation.first_failure,
                    "metrics": {
                        "true_positives": observation.true_positives,
                        "false_positives": observation.false_positives,
                        "false_negatives": observation.false_negatives,
                        "unsupported_claims": observation.unsupported_claims,
                        "report_failures": observation.report_failures,
                        "model_calls": observation.model_calls,
                        "compaction_count": observation.compaction_count,
                        "peak_context_tokens": observation.peak_context_tokens,
                        "peak_input_tokens": observation.peak_input_tokens,
                        "input_tokens": observation.input_tokens,
                    },
                    "trace_excerpt": _trajectory_excerpt(observation.session_dir, self.manifest),
                    "language": example.case.language,
                    "flow": example.spec.flow,
                    "scaffold_profile": example.spec.scaffold_profile,
                    "context_profile": example.spec.context_profile,
                }
            except Exception as exc:
                score = 0.0
                objective = {
                    "correctness": 0.0,
                    "precision": 0.0,
                    "evidence_quality": 0.0,
                    "funnel_progress": 0.0,
                    "report_health": 0.0,
                }
                error = redact_benchmark_terms(str(exc), self.manifest)
                output = {"status": "failed", "error": error, "session_id": session_id}
                trajectory = {
                    "status": "failed",
                    "score": score,
                    "objective_scores": objective,
                    "first_failure": "execution_error",
                    "error": error,
                    "trace_excerpt": "",
                    "language": example.case.language,
                    "flow": example.spec.flow,
                    "scaffold_profile": example.spec.scaffold_profile,
                    "context_profile": example.spec.context_profile,
                }
            outputs.append(output)
            scores.append(score)
            objectives.append(objective)
            trajectories.append(trajectory)

        return _evaluation_batch(
            outputs=outputs,
            scores=scores,
            trajectories=trajectories if capture_traces else None,
            objective_scores=objectives,
            num_metric_calls=len(batch),
        )

    def make_reflective_dataset(
        self,
        candidate: dict[str, str],
        eval_batch: Any,
        components_to_update: list[str],
    ) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        del candidate
        trajectories = eval_batch.trajectories or []
        records: list[dict[str, Any]] = []
        for trajectory in trajectories:
            failure = str(trajectory.get("first_failure") or "")
            feedback = _STAGE_FEEDBACK.get(failure, "The run completed without a staged failure.")
            if trajectory.get("status") == "failed":
                feedback = "The candidate caused an execution failure: " + str(
                    trajectory.get("error") or "unknown error"
                )
            feedback += (
                " Improve only generic audit behavior. Do not add repository names, file paths, "
                "symbols, commits, CVEs, known mechanisms, or trigger-specific hints."
            )
            records.append(
                {
                    "Inputs": {
                        "language": trajectory.get("language", "unknown"),
                        "flow": trajectory.get("flow", "unknown"),
                        "scaffold_profile": trajectory.get("scaffold_profile", "unknown"),
                        "context_profile": trajectory.get("context_profile", "unknown"),
                    },
                    "Generated Outputs": {
                        "metrics": trajectory.get("metrics", {}),
                        "trace_excerpt": trajectory.get("trace_excerpt", ""),
                    },
                    "Feedback": feedback,
                    "score": trajectory.get("score", 0.0),
                    "objective_scores": trajectory.get("objective_scores", {}),
                }
            )
        return {
            component: records
            for component in components_to_update
            if component == PROMPT_COMPONENT
        }


def optimize_sourcehunt_prompt(
    *,
    manifest: GroundTruthManifest,
    trainset: list[SourceHuntOptimizationExample],
    valset: list[SourceHuntOptimizationExample],
    reflection_lm: Any,
    max_metric_calls: int,
    run_dir: str | Path,
    seed_prompt: str = GENERIC_INSTRUCTIONS_V1,
    seed: int = 0,
) -> Any:
    """Run core GEPA without rewriting SourceHunt as a DSPy agent."""

    try:
        import gepa
    except ImportError as exc:
        raise RuntimeError(
            "GEPA is not installed; install Clearwing's 'optimization' extra"
        ) from exc
    require_generic_prompt(seed_prompt, manifest=manifest)
    adapter = SourceHuntGEPAAdapter(manifest)
    return gepa.optimize(
        seed_candidate={PROMPT_COMPONENT: seed_prompt},
        trainset=trainset,
        valset=valset,
        adapter=adapter,
        reflection_lm=reflection_lm,
        max_metric_calls=max_metric_calls,
        run_dir=str(run_dir),
        seed=seed,
        write_agent_state=True,
        cache_evaluation=True,
    )


__all__ = [
    "ClearwingReflectionLM",
    "PROMPT_COMPONENT",
    "SourceHuntGEPAAdapter",
    "SourceHuntOptimizationExample",
    "optimize_sourcehunt_prompt",
    "score_sourcehunt_observation",
]
