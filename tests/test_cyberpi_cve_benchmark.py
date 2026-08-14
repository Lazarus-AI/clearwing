"""Blind CVE suite, scorer, snapshot, and artifact regressions."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from clearwing.bench.cyberpi_cves import (
    CaseOracle,
    CVEBenchmarkObservation,
    CVECaseScore,
    CyberPiCVEBenchmark,
    CyberPiCVEBenchmarkReport,
    CyberPiCVECase,
    CyberPiCVESuite,
    CyberPiSnapshotMaterializer,
    SourceLocation,
    sanitize_trajectory,
    score_case,
)


def test_builtin_suites_are_disjoint_and_cover_distinct_cwes():
    tuning = CyberPiCVESuite.load("tuning-cves")
    held_out = CyberPiCVESuite.load("held-out-cves")

    assert tuning.role == "tuning"
    assert held_out.role == "held_out"
    assert tuning.minimum_runs == held_out.minimum_runs == 3
    assert {case.id for case in tuning.cases}.isdisjoint(case.id for case in held_out.cases)
    assert {case.repository for case in tuning.cases}.isdisjoint(
        case.repository for case in held_out.cases
    )
    assert {
        cwe
        for suite in (tuning, held_out)
        for case in suite.cases
        for cwe in case.oracle.accepted_cwes
    } >= {"CWE-22", "CWE-95", "CWE-787", "CWE-863"}
    assert all(
        case.vulnerable_commit != case.fixed_commit for case in (*tuning.cases, *held_out.cases)
    )


def test_suite_loader_rejects_target_outside_exported_context(tmp_path):
    payload = json.loads(
        Path("clearwing/bench/cyberpi_suites/tuning-cves.json").read_text(encoding="utf-8")
    )
    payload["cases"][0]["target_file"] = "../answer-key.txt"
    suite_path = tmp_path / "unsafe.json"
    suite_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe benchmark source path"):
        CyberPiCVESuite.load(suite_path)


@pytest.mark.parametrize(("field", "value"), [("name", "../escape"), ("id", "case/escape")])
def test_suite_loader_rejects_identifiers_that_could_escape_artifact_paths(
    tmp_path, field, value
):
    payload = json.loads(
        Path("clearwing/bench/cyberpi_suites/tuning-cves.json").read_text(encoding="utf-8")
    )
    if field == "name":
        payload["name"] = value
    else:
        payload["cases"][0]["id"] = value
    suite_path = tmp_path / "unsafe-identifier.json"
    suite_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="filesystem-safe identifier"):
        CyberPiCVESuite.load(suite_path)


def test_case_scoring_keeps_recall_cwe_location_and_evidence_independent():
    case = CyberPiCVESuite.load("tuning-cves").cases[0]
    supported = (
        {
            "file": f"/workspace/{case.target_file}",
            "line_number": 58,
            "finding_type": "archive path traversal",
            "cwe": "22",
            "description": (
                "An archive entry name containing backslash separators is not normalized before "
                "the canonical destination check, allowing path traversal outside the destination."
            ),
        },
    )

    score = score_case(case, "vulnerable", supported)

    assert score.detected is True
    assert score.false_positive is False
    assert score.cwe_accuracy == 1.0
    assert score.source_location_accuracy == 1.0
    assert score.evidence_quality == 1.0

    unsupported = (
        {
            "file": case.target_file,
            "line_number": 58,
            "finding_type": "unsafe code",
            "cwe": "CWE-22",
            "description": "This code may be unsafe.",
        },
    )
    assert score_case(case, "vulnerable", unsupported).detected is False
    assert score_case(case, "fixed", supported).false_positive is True


def test_hunter_context_excludes_oracle_commit_and_cve_metadata(tmp_path):
    case = CyberPiCVESuite.load("held-out-cves").cases[0]
    target = tmp_path / case.target_file
    target.parent.mkdir(parents=True)
    target.write_text("package private\n", encoding="utf-8")
    benchmark = CyberPiCVEBenchmark(
        SimpleNamespace(model_name="model", api_key="", base_url="https://example.test"),
        CyberPiCVESuite.load("held-out-cves"),
        output_dir=tmp_path / "results",
    )

    hunter, _context = benchmark._build_hunter(
        case,
        tmp_path,
        tmp_path / "trajectory",
        session_id="run-1",
        work_item_id="work-1",
    )
    model_visible = " ".join(
        [
            hunter.prompt,
            hunter.initial_user_message,
            *(tool.description + json.dumps(tool.schema) for tool in hunter.tools),
        ]
    )

    assert case.cve not in model_visible
    assert case.id not in model_visible
    assert case.vulnerable_commit not in model_visible
    assert case.fixed_commit not in model_visible


def test_trajectory_sanitizer_preserves_jsonl_and_removes_credentials(tmp_path):
    trajectory = tmp_path / "transcript.jsonl"
    trajectory.write_text(
        json.dumps(
            {
                "event": "message",
                "content": "top-secret Authorization: Bearer visible",
                "url": "https://user:password@example.test/v1",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    digest, redactions = sanitize_trajectory(trajectory, secrets=("top-secret",))
    payload = trajectory.read_text(encoding="utf-8")

    assert len(digest) == 64
    assert redactions == 3
    assert "top-secret" not in payload
    assert "password" not in payload
    assert "Bearer visible" not in payload
    assert json.loads(payload)["event"] == "message"


def test_snapshot_materializer_exports_only_pinned_source_without_git_metadata(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init")
    (repository / "src").mkdir()
    target = repository / "src" / "parser.c"
    target.write_text("void parse(char *p) { sink(p); }\n", encoding="utf-8")
    _git(repository, "add", "src/parser.c")
    _git(
        repository,
        "-c",
        "user.name=Benchmark",
        "-c",
        "user.email=test@example.test",
        "commit",
        "-m",
        "vulnerable",
    )
    vulnerable = _git(repository, "rev-parse", "HEAD").strip()
    target.write_text("void parse(char *p) { if (safe(p)) sink(p); }\n", encoding="utf-8")
    _git(repository, "add", "src/parser.c")
    _git(
        repository,
        "-c",
        "user.name=Benchmark",
        "-c",
        "user.email=test@example.test",
        "commit",
        "-m",
        "fixed",
    )
    fixed = _git(repository, "rev-parse", "HEAD").strip()
    case = CyberPiCVECase(
        id="local-case",
        cve="CVE-2026-99999",
        repository=str(repository),
        vulnerable_commit=vulnerable,
        fixed_commit=fixed,
        target_file="src/parser.c",
        context_roots=("src",),
        language="c",
        oracle=CaseOracle(
            accepted_cwes=("CWE-20",),
            locations=(SourceLocation("src/parser.c", 1, "parse"),),
            evidence_groups=(("sink",),),
        ),
    )
    materializer = CyberPiSnapshotMaterializer(tmp_path / "cache")

    vulnerable_snapshot = materializer.materialize(case, "vulnerable")
    fixed_snapshot = materializer.materialize(case, "fixed")

    assert vulnerable_snapshot.commit == vulnerable
    assert fixed_snapshot.commit == fixed
    assert vulnerable_snapshot.digest != fixed_snapshot.digest
    assert "safe" not in (vulnerable_snapshot.path / "src/parser.c").read_text()
    assert "safe" in (fixed_snapshot.path / "src/parser.c").read_text()
    assert not (vulnerable_snapshot.path / ".git").exists()
    assert not (vulnerable_snapshot.path / "answer-key.txt").exists()

    marker = next((tmp_path / "cache" / "snapshots").glob(".*-vulnerable-*.json"))
    marker_payload = json.loads(marker.read_text(encoding="utf-8"))
    marker_payload["repository"] = "https://example.test/different.git"
    marker.write_text(json.dumps(marker_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="failed integrity check"):
        materializer.materialize(case, "vulnerable")


def test_report_aggregates_false_positives_efficiency_and_stability():
    observations = (
        _observation("native", "vulnerable", 1, detected=False),
        _observation("native", "vulnerable", 2, detected=False),
        _observation("native", "fixed", 1),
        _observation("native", "fixed", 2),
        _observation("cyberpi", "vulnerable", 1, detected=True, with_finding=True),
        _observation("cyberpi", "vulnerable", 2, detected=True, with_finding=True),
        _observation("cyberpi", "fixed", 1),
        _observation("cyberpi", "fixed", 2, false_positive=True, with_finding=True),
    )
    report = CyberPiCVEBenchmarkReport(
        benchmark_id="cyberpi-held-out-test",
        created_at="2026-08-13T00:00:00+00:00",
        suite="held-out-cves",
        suite_role="held_out",
        suite_digest="a" * 64,
        model="DeepSeek-v4-Flash-0731",
        base_url="https://example.test/v1",
        max_turns=8,
        max_output_tokens=4096,
        observations=observations,
    )

    metrics = report.metrics()

    assert metrics["native"]["vulnerable_recall"] == 0.0
    assert metrics["cyberpi"]["vulnerable_recall"] == 1.0
    assert metrics["cyberpi"]["fixed_false_positive_rate"] == 0.5
    assert metrics["cyberpi"]["decision_stability"] == 0.75
    assert report.to_dict()["cyberpi_minus_native"]["vulnerable_recall"] == 1.0


def _observation(
    engine: str,
    variant: str,
    replicate: int,
    *,
    detected: bool = False,
    false_positive: bool = False,
    with_finding: bool = False,
) -> CVEBenchmarkObservation:
    findings = ({"file": "src/x.c", "line_number": 10, "cwe": "CWE-787"},) if with_finding else ()
    return CVEBenchmarkObservation(
        engine=engine,  # type: ignore[arg-type]
        case_id="case-1",
        cve="CVE-2026-99999",
        variant=variant,  # type: ignore[arg-type]
        commit="a" * 40,
        snapshot_digest="b" * 64,
        replicate=replicate,
        arm_position=1,
        findings=findings,
        trace_steps=(),
        score=CVECaseScore(
            detected=detected,
            false_positive=false_positive,
            cwe_accuracy=float(detected),
            source_location_accuracy=float(detected),
            evidence_quality=float(detected),
        ),
        tokens_used=100,
        cost_usd=0.01,
        cost_basis="test",
        duration_seconds=1.0,
        stop_reason="completed",
        trajectory="transcript.jsonl",
        trajectory_sha256="c" * 64,
        trajectory_redactions=0,
    )


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
