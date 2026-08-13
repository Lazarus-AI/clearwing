"""Reproducible aggregation for replicated LAIR validator replays."""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from .sourcehunt_lair_validator import (
    REPLAY_CONTEXT_PROFILE,
    LairValidatorCaseResult,
    LairValidatorReplaySummary,
    summarize_lair_validator_replay,
)

REPLICATION_SCHEMA_VERSION = "cw.sourcehunt.lair-validator-replicates.v1"
_WILSON_95_Z = 1.959963984540054


def file_sha256(path: str | Path) -> str:
    """Return the SHA-256 digest of a result exactly as stored."""

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_replay(path: str | Path) -> LairValidatorReplaySummary:
    """Load one replay and reject inconsistent stored metrics or case flags."""

    result = cast(
        LairValidatorReplaySummary,
        LairValidatorReplaySummary.model_validate_json(Path(path).read_text()),
    )
    _validate_case_flags(result.cases)
    calculated = summarize_lair_validator_replay(
        result.cases,
        model=result.model,
        prompt_profile=result.prompt_profile,
        max_output_tokens=result.max_output_tokens,
        temperature=result.temperature,
    )
    for field in (
        "case_count",
        "vulnerable_recall",
        "fixed_rejection_rate",
        "pair_accuracy",
        "vulnerable_false_negatives",
        "fixed_false_positives",
        "model_errors",
        "axis_pass_counts",
    ):
        if getattr(result, field) != getattr(calculated, field):
            raise ValueError(f"replay has inconsistent {field}: {path}")
    return result


def validate_replicate_set(
    runs_by_profile: Mapping[str, Sequence[LairValidatorReplaySummary]],
    *,
    model: str,
    replicates: int,
    max_output_tokens: int,
    temperature: float,
) -> None:
    """Require a complete, coordinate-identical replication matrix."""

    if replicates < 1:
        raise ValueError("replicates must be positive")
    if not runs_by_profile:
        raise ValueError("at least one prompt profile is required")

    expected_coordinates: dict[str, tuple[str, str]] | None = None
    expected_cases: set[str] | None = None
    for profile, runs in runs_by_profile.items():
        if len(runs) != replicates:
            raise ValueError(
                f"profile {profile!r} has {len(runs)} runs; expected {replicates}"
            )
        for run in runs:
            if run.model != model:
                raise ValueError(f"replicate model drift: {run.model!r} != {model!r}")
            if run.prompt_profile != profile:
                raise ValueError(
                    f"replicate prompt drift: {run.prompt_profile!r} != {profile!r}"
                )
            if run.context_profile != REPLAY_CONTEXT_PROFILE:
                raise ValueError(f"replicate context drift: {run.context_profile!r}")
            if run.max_output_tokens != max_output_tokens:
                raise ValueError("replicate output-token cap drift")
            if run.temperature != temperature:
                raise ValueError("replicate temperature drift")

            cases = {_case_key(case): case for case in run.cases}
            if len(cases) != len(run.cases):
                raise ValueError("replicate contains duplicate cases")
            case_keys = set(cases)
            coordinates = {
                key: (case.finding_digest, case.source_window_digest)
                for key, case in cases.items()
            }
            if expected_cases is None:
                expected_cases = case_keys
                expected_coordinates = coordinates
            elif case_keys != expected_cases:
                raise ValueError("replicate case membership drift")
            elif coordinates != expected_coordinates:
                raise ValueError("replicate finding or source-coordinate drift")


def aggregate_replicates(
    run_paths_by_profile: Mapping[str, Sequence[str | Path]],
    *,
    model: str,
    max_output_tokens: int,
    temperature: float,
    context_radius: int,
    max_context_chars: int,
    max_parallel: int,
    provenance: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Aggregate replicated binomial metrics and opaque per-case stability."""

    normalized_paths = {
        profile: [Path(path).resolve() for path in paths]
        for profile, paths in run_paths_by_profile.items()
    }
    loaded = {
        profile: [load_replay(path) for path in paths]
        for profile, paths in normalized_paths.items()
    }
    replicates = len(next(iter(loaded.values()), ()))
    validate_replicate_set(
        loaded,
        model=model,
        replicates=replicates,
        max_output_tokens=max_output_tokens,
        temperature=temperature,
    )

    inputs: list[dict[str, Any]] = []
    for profile, paths in normalized_paths.items():
        for index, path in enumerate(paths, start=1):
            inputs.append(
                {
                    "prompt_profile": profile,
                    "replicate": index,
                    "path": str(path),
                    "sha256": file_sha256(path),
                    "provenance": (provenance or {}).get(str(path), "generated"),
                }
            )

    arms = {profile: _aggregate_arm(runs) for profile, runs in loaded.items()}
    return {
        "schema_version": REPLICATION_SCHEMA_VERSION,
        "model": model,
        "configuration": {
            "replicates": replicates,
            "context_profile": REPLAY_CONTEXT_PROFILE,
            "context_radius": context_radius,
            "max_context_chars": max_context_chars,
            "max_output_tokens": max_output_tokens,
            "temperature": temperature,
            "max_parallel": max_parallel,
        },
        "input_results": inputs,
        "arms": arms,
    }


def wilson_interval(successes: int, trials: int) -> dict[str, float]:
    """Return a two-sided 95% Wilson score interval for a binomial rate."""

    if trials < 1:
        raise ValueError("Wilson interval requires at least one trial")
    if not 0 <= successes <= trials:
        raise ValueError("successes must fall between zero and trials")
    proportion = successes / trials
    z_squared = _WILSON_95_Z**2
    denominator = 1 + z_squared / trials
    center = (proportion + z_squared / (2 * trials)) / denominator
    margin = (
        _WILSON_95_Z
        * math.sqrt(
            proportion * (1 - proportion) / trials
            + z_squared / (4 * trials**2)
        )
        / denominator
    )
    return {
        "confidence": 0.95,
        "lower": max(0.0, center - margin),
        "upper": min(1.0, center + margin),
    }


def _aggregate_arm(runs: Sequence[LairValidatorReplaySummary]) -> dict[str, Any]:
    cases_by_key: dict[str, list[LairValidatorCaseResult]] = defaultdict(list)
    replicate_metrics: list[dict[str, Any]] = []
    for index, run in enumerate(runs, start=1):
        replicate_metrics.append(
            {
                "replicate": index,
                "vulnerable_recall": run.vulnerable_recall,
                "fixed_rejection_rate": run.fixed_rejection_rate,
                "pair_accuracy": run.pair_accuracy,
                "model_errors": run.model_errors,
            }
        )
        for case in run.cases:
            cases_by_key[_case_key(case)].append(case)

    flattened = [case for run in runs for case in run.cases]
    decision_count = 2 * len(flattened)
    per_case = []
    for key in sorted(cases_by_key):
        cases = cases_by_key[key]
        vulnerable = [case.vulnerable_correct for case in cases]
        fixed = [case.fixed_correct for case in cases]
        pairs = [case.pair_correct for case in cases]
        errors = [case.vulnerable.model_error or case.fixed.model_error for case in cases]
        per_case.append(
            {
                "case_id": _opaque_case_id(cases[0]),
                "vulnerable_correct_rate": sum(vulnerable) / len(cases),
                "fixed_correct_rate": sum(fixed) / len(cases),
                "pair_correct_rate": sum(pairs) / len(cases),
                "error_run_rate": sum(errors) / len(cases),
                "vulnerable_pattern": _bit_pattern(vulnerable),
                "fixed_pattern": _bit_pattern(fixed),
                "pair_pattern": _bit_pattern(pairs),
                "unanimous": len(set(zip(vulnerable, fixed, strict=True))) == 1,
            }
        )

    return {
        "replicate_metrics": replicate_metrics,
        "aggregate": {
            "vulnerable_recall": _binomial_metric(
                sum(case.vulnerable_correct for case in flattened), len(flattened)
            ),
            "fixed_rejection_rate": _binomial_metric(
                sum(case.fixed_correct for case in flattened), len(flattened)
            ),
            "pair_accuracy": _binomial_metric(
                sum(case.pair_correct for case in flattened), len(flattened)
            ),
            "model_error_rate": _binomial_metric(
                sum(
                    case.vulnerable.model_error + case.fixed.model_error
                    for case in flattened
                ),
                decision_count,
            ),
        },
        "unanimous_case_count": sum(case["unanimous"] for case in per_case),
        "case_count": len(per_case),
        "per_case_stability": per_case,
    }


def _binomial_metric(successes: int, trials: int) -> dict[str, Any]:
    return {
        "successes": successes,
        "trials": trials,
        "rate": successes / trials,
        "wilson_95": wilson_interval(successes, trials),
    }


def _validate_case_flags(cases: Sequence[LairValidatorCaseResult]) -> None:
    for case in cases:
        vulnerable_correct = case.vulnerable.advance and not case.vulnerable.model_error
        fixed_correct = not case.fixed.advance and not case.fixed.model_error
        if case.vulnerable_correct != vulnerable_correct:
            raise ValueError("replay has inconsistent vulnerable correctness flag")
        if case.fixed_correct != fixed_correct:
            raise ValueError("replay has inconsistent fixed correctness flag")
        if case.pair_correct != (vulnerable_correct and fixed_correct):
            raise ValueError("replay has inconsistent pair correctness flag")


def _case_key(case: LairValidatorCaseResult) -> str:
    return f"{case.repository}\0{case.cve}"


def _opaque_case_id(case: LairValidatorCaseResult) -> str:
    material = f"{case.finding_digest}\0{case.source_window_digest}".encode()
    return f"case-{hashlib.sha256(material).hexdigest()[:16]}"


def _bit_pattern(values: Sequence[bool]) -> str:
    return "".join("1" if value else "0" for value in values)


__all__ = [
    "REPLICATION_SCHEMA_VERSION",
    "aggregate_replicates",
    "file_sha256",
    "load_replay",
    "validate_replicate_set",
    "wilson_interval",
]
