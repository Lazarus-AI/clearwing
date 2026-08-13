"""Leakage-safe GEPA adapter for the LAIR validator development fold."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from clearwing.llm import AsyncLLMClient
from clearwing.sourcehunt.validator import Validator

from .sourcehunt_gepa import ClearwingReflectionLM, _evaluation_batch
from .sourcehunt_lair import LairGoldenChain, answer_bearing_terms
from .sourcehunt_lair_validator import replay_lair_validator_case

VALIDATOR_PROMPT_COMPONENT = "validator_system_prompt"
MAX_VALIDATOR_PROMPT_CHARS = 2_000
_FORBIDDEN_PROTOCOL_TERMS = (
    "paired",
    "snapshot",
    "benchmark",
    "development fold",
    "vulnerable_correct",
    "fixed_correct",
    "pair_correct",
    "model_health",
    "source_supported_claim",
    "source_contradicted_claim",
)
VALIDATOR_REFLECTION_TEMPLATE = """Improve a compact, generic source-code vulnerability validator instruction.

Current instruction:
```
<curr_param>
```

Abstract evaluation outcomes:
```
<side_info>
```

Preserve source-first discrimination: accept a flaw present in current source and
reject an allegation when current source breaks its causal chain. Keep
reachability, impact, and deployment judgments independent. Return only a revised
instruction inside ``` blocks. It must be under 2000 characters and must never add
case identities, repositories, CVEs, commits, paths, symbols, excerpts, fixes, known
mechanisms, triggers, or other benchmark-specific content."""


@dataclass(frozen=True)
class LairValidatorOptimizationExample:
    """One opaque reference to a private LAIR source pair."""

    case_id: str


class LairValidatorGEPAAdapter:
    """Score source-pair discrimination without reflecting benchmark answers."""

    propose_new_texts = None

    def __init__(
        self,
        client: AsyncLLMClient,
        goldens: Sequence[LairGoldenChain],
        campaign_root: str | Path,
        *,
        model: str,
        max_output_tokens: int = 16_384,
        temperature: float = 0.0,
        max_parallel: int = 2,
        context_radius: int = 18,
        max_context_chars: int = 20_000,
        max_metric_calls: int | None = None,
    ) -> None:
        if max_parallel < 1:
            raise ValueError("GEPA validator max_parallel must be positive")
        self.client = client
        self.goldens = tuple(goldens)
        root = Path(campaign_root)
        self._private_cases = {
            _opaque_id(golden): (golden, root / "workspaces" / golden.cve / "repo")
            for golden in self.goldens
        }
        if len(self._private_cases) != len(self.goldens):
            raise ValueError("LAIR optimization cases must have unique opaque ids")
        self.examples = tuple(
            LairValidatorOptimizationExample(case_id=case_id)
            for case_id in sorted(self._private_cases)
        )
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self.max_parallel = max_parallel
        self.context_radius = context_radius
        self.max_context_chars = max_context_chars
        if max_metric_calls is not None and max_metric_calls < 1:
            raise ValueError("GEPA validator metric-call budget must be positive")
        self.max_metric_calls = max_metric_calls
        self.metric_calls = 0

    def evaluate(
        self,
        batch: list[LairValidatorOptimizationExample],
        candidate: dict[str, str],
        capture_traces: bool = False,
    ) -> Any:
        prompt = candidate.get(VALIDATOR_PROMPT_COMPONENT, "")
        require_generic_validator_prompt(prompt, self.goldens)
        if (
            self.max_metric_calls is not None
            and self.metric_calls + len(batch) > self.max_metric_calls
        ):
            raise RuntimeError("GEPA validator metric-call budget exhausted")
        self.metric_calls += len(batch)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._evaluate_async(batch, prompt, capture_traces))
        raise RuntimeError("LairValidatorGEPAAdapter.evaluate cannot run in an event loop")

    async def _evaluate_async(
        self,
        batch: list[LairValidatorOptimizationExample],
        prompt: str,
        capture_traces: bool,
    ) -> Any:
        validator = Validator(
            self.client,
            gate_threshold=None,
            enable_quick_pass=False,
            prompt_profile="source-first-compact-v2",
            system_prompt=prompt,
            max_output_tokens=self.max_output_tokens,
            temperature=self.temperature,
        )
        semaphore = asyncio.Semaphore(self.max_parallel)

        async def run_one(example: LairValidatorOptimizationExample) -> Any:
            async with semaphore:
                try:
                    golden, repo = self._private_cases[example.case_id]
                except KeyError as exc:
                    raise ValueError("unknown opaque LAIR optimization case") from exc
                return await replay_lair_validator_case(
                    golden,
                    repo,
                    lambda finding, context: validator.avalidate(
                        finding, source_context=context
                    ),
                    context_radius=self.context_radius,
                    max_context_chars=self.max_context_chars,
                )

        cases = await asyncio.gather(*(run_one(example) for example in batch))
        outputs: list[dict[str, Any]] = []
        scores: list[float] = []
        objectives: list[dict[str, float]] = []
        trajectories: list[dict[str, Any]] = []
        for case in cases:
            error = case.vulnerable.model_error or case.fixed.model_error
            vulnerable_score = float(case.vulnerable_correct)
            fixed_score = float(case.fixed_correct)
            pair_score = float(case.pair_correct)
            score = (
                0.0
                if error
                else 0.35 * vulnerable_score
                + 0.35 * fixed_score
                + 0.30 * pair_score
            )
            objective = {
                "vulnerable_correct": vulnerable_score,
                "fixed_correct": fixed_score,
                "pair_correct": pair_score,
                "model_health": float(not error),
            }
            outcome = {
                "vulnerable_correct": case.vulnerable_correct,
                "fixed_correct": case.fixed_correct,
                "pair_correct": case.pair_correct,
                "model_error": error,
            }
            outputs.append(outcome)
            scores.append(score)
            objectives.append(objective)
            trajectories.append(
                {
                    "lesson": _abstract_feedback(
                        vulnerable_correct=case.vulnerable_correct,
                        fixed_correct=case.fixed_correct,
                        model_error=error,
                    )
                }
            )
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
        records = []
        for trajectory in eval_batch.trajectories or []:
            records.append(
                {
                    "Inputs": {"task": "source-backed vulnerability validation"},
                    "Generated Outputs": "A bounded structured verdict was returned.",
                    "Feedback": trajectory["lesson"],
                }
            )
        return {
            component: records
            for component in components_to_update
            if component == VALIDATOR_PROMPT_COMPONENT
        }


class LairValidatorMetricBudgetStopper:
    """Stop before an iteration whose maximum rollout cost exceeds the budget."""

    def __init__(
        self,
        adapter: LairValidatorGEPAAdapter,
        *,
        max_metric_calls: int,
        max_iteration_calls: int,
    ) -> None:
        self.adapter = adapter
        self.max_metric_calls = max_metric_calls
        self.max_iteration_calls = max_iteration_calls

    def __call__(self, _state: Any) -> bool:
        return (
            self.adapter.metric_calls + self.max_iteration_calls
            > self.max_metric_calls
        )


def require_generic_validator_prompt(
    prompt: str,
    goldens: Sequence[LairGoldenChain],
) -> None:
    """Reject empty, oversized, or answer-bearing validator candidates."""

    stripped = prompt.strip()
    if not stripped:
        raise ValueError("validator prompt must be non-empty")
    if len(stripped) > MAX_VALIDATOR_PROMPT_CHARS:
        raise ValueError(
            f"validator prompt exceeds {MAX_VALIDATOR_PROMPT_CHARS} characters"
        )
    folded = stripped.casefold()
    protocol_leaks = {term for term in _FORBIDDEN_PROTOCOL_TERMS if term in folded}
    if protocol_leaks:
        raise ValueError("validator prompt leaks evaluation-protocol language")
    forbidden = set().union(*(answer_bearing_terms(golden) for golden in goldens))
    leaks = {value for value in forbidden if value in folded}
    if leaks:
        raise ValueError("validator prompt leaks LAIR benchmark answers")


def optimize_lair_validator_prompt(
    *,
    adapter: LairValidatorGEPAAdapter,
    trainset: list[LairValidatorOptimizationExample],
    valset: list[LairValidatorOptimizationExample],
    reflection_lm: ClearwingReflectionLM,
    seed_prompt: str,
    max_metric_calls: int,
    run_dir: str | Path,
    seed: int = 0,
) -> Any:
    """Run bounded core GEPA over the opened LAIR development cases."""

    try:
        import gepa
    except ImportError as exc:
        raise RuntimeError("GEPA is not installed") from exc
    require_generic_validator_prompt(seed_prompt, adapter.goldens)
    minibatch_size = min(4, len(trainset))
    budget_stopper = LairValidatorMetricBudgetStopper(
        adapter,
        max_metric_calls=max_metric_calls,
        max_iteration_calls=2 * minibatch_size + len(valset),
    )
    return gepa.optimize(
        seed_candidate={VALIDATOR_PROMPT_COMPONENT: seed_prompt},
        trainset=trainset,
        valset=valset,
        adapter=adapter,
        reflection_lm=reflection_lm,
        max_metric_calls=max_metric_calls,
        reflection_minibatch_size=minibatch_size,
        reflection_prompt_template=VALIDATOR_REFLECTION_TEMPLATE,
        run_dir=str(run_dir),
        seed=seed,
        cache_evaluation=True,
        display_progress_bar=True,
        frontier_type="objective",
        acceptance_criterion="strict_improvement",
        raise_on_exception=False,
        stop_callbacks=budget_stopper,
    )


def _opaque_id(golden: LairGoldenChain) -> str:
    material = f"{golden.repo}\0{golden.cve}".encode()
    return f"case-{hashlib.sha256(material).hexdigest()[:16]}"


def _abstract_feedback(
    *,
    vulnerable_correct: bool,
    fixed_correct: bool,
    model_error: bool,
) -> str:
    if model_error:
        return (
            "The candidate failed to return valid bounded structured output. "
            "Make the instruction shorter and make immediate schema compliance explicit. "
            "Use only generic validation rules; add no case-specific details."
        )
    if vulnerable_correct and fixed_correct:
        result = (
            "The candidate correctly accepted source-supported behavior and rejected "
            "source-contradicted behavior."
        )
    elif not vulnerable_correct and fixed_correct:
        result = (
            "The candidate rejected a source-present flaw. Keep source-level reality "
            "separate from uncertainty about reachability or deployment prevalence."
        )
    elif vulnerable_correct and not fixed_correct:
        result = (
            "The candidate accepted a report after current source broke its causal chain. "
            "Treat current guards and invariants as authoritative counterevidence."
        )
    else:
        result = (
            "The candidate failed both source-supported and source-contradicted "
            "decisions. Ground REAL in the complete causal chain before judging the "
            "remaining axes."
        )
    return result + " Improve only generic rules and keep the prompt concise."


__all__ = [
    "LairValidatorGEPAAdapter",
    "LairValidatorMetricBudgetStopper",
    "LairValidatorOptimizationExample",
    "MAX_VALIDATOR_PROMPT_CHARS",
    "VALIDATOR_PROMPT_COMPONENT",
    "VALIDATOR_REFLECTION_TEMPLATE",
    "optimize_lair_validator_prompt",
    "require_generic_validator_prompt",
]
