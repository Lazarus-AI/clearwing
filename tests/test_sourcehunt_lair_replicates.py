"""Tests for replicated LAIR validator aggregation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clearwing.eval.sourcehunt_lair_replicates import (
    aggregate_replicates,
    load_replay,
    wilson_interval,
)
from clearwing.eval.sourcehunt_lair_validator import (
    LairValidatorCaseResult,
    ReplayVerdict,
    summarize_lair_validator_replay,
)


def _verdict(advance: bool, *, error: bool = False) -> ReplayVerdict:
    return ReplayVerdict(
        advance=advance,
        severity_validated="high" if advance else None,
        evidence_level="static_corroboration",
        axes={} if error else {"real": {"passed": advance}},
        pro_argument="",
        counter_argument="",
        tie_breaker="",
        model_error=error,
    )


def _case(name: str, vulnerable: bool, fixed: bool) -> LairValidatorCaseResult:
    return LairValidatorCaseResult(
        cve=f"CVE-2099-{name}",
        repository=f"example/{name}",
        finding_digest=name.zfill(64),
        source_window_digest=(name + "f").zfill(64),
        vulnerable=_verdict(vulnerable),
        fixed=_verdict(not fixed),
        vulnerable_correct=vulnerable,
        fixed_correct=fixed,
        pair_correct=vulnerable and fixed,
    )


def _write_run(path: Path, profile: str, cases: list[LairValidatorCaseResult]) -> None:
    summary = summarize_lair_validator_replay(
        cases,
        model="small-model",
        prompt_profile=profile,
        max_output_tokens=1024,
        temperature=0.0,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(summary.model_dump_json(indent=2) + "\n", encoding="utf-8")


def test_wilson_interval_bounds_rate() -> None:
    interval = wilson_interval(9, 10)

    assert interval["confidence"] == 0.95
    assert interval["lower"] < 0.9 < interval["upper"]
    assert wilson_interval(0, 10)["lower"] == 0.0


def test_aggregate_reports_pooled_metrics_and_opaque_stability(tmp_path: Path) -> None:
    paths: list[Path] = []
    for replicate, cases in enumerate(
        (
            [_case("1", True, True), _case("2", False, True)],
            [_case("1", True, False), _case("2", True, True)],
        ),
        start=1,
    ):
        path = tmp_path / f"run-{replicate:02d}.json"
        _write_run(path, "legacy-v1", cases)
        paths.append(path)

    result = aggregate_replicates(
        {"legacy-v1": paths},
        model="small-model",
        max_output_tokens=1024,
        temperature=0.0,
        context_radius=18,
        max_context_chars=20_000,
        max_parallel=2,
    )

    arm = result["arms"]["legacy-v1"]
    assert arm["aggregate"]["vulnerable_recall"]["rate"] == 0.75
    assert arm["aggregate"]["fixed_rejection_rate"]["rate"] == 0.75
    assert arm["aggregate"]["pair_accuracy"]["rate"] == 0.5
    assert arm["unanimous_case_count"] == 0
    serialized = json.dumps(result)
    assert "CVE-" not in serialized
    assert "example/" not in serialized
    assert all(
        case["case_id"].startswith("case-")
        for case in arm["per_case_stability"]
    )


def test_aggregate_rejects_coordinate_drift(tmp_path: Path) -> None:
    first = tmp_path / "run-01.json"
    second = tmp_path / "run-02.json"
    _write_run(first, "legacy-v1", [_case("1", True, True)])
    changed = _case("1", True, True).model_copy(
        update={"source_window_digest": "e" * 64}
    )
    _write_run(second, "legacy-v1", [changed])

    with pytest.raises(ValueError, match="coordinate drift"):
        aggregate_replicates(
            {"legacy-v1": [first, second]},
            model="small-model",
            max_output_tokens=1024,
            temperature=0.0,
            context_radius=18,
            max_context_chars=20_000,
            max_parallel=2,
        )


def test_load_replay_rejects_tampered_metrics(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    _write_run(path, "legacy-v1", [_case("1", True, True)])
    payload = json.loads(path.read_text())
    payload["pair_accuracy"] = 0.0
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="inconsistent pair_accuracy"):
        load_replay(path)
