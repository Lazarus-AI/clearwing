import json
from pathlib import Path

from clearwing.sourcehunt.reporter import write_sourcehunt_report


def test_json_report_preserves_unresolved_potentials(tmp_path) -> None:
    potentials = [
        {
            "id": "lead-1",
            "file": "src/parser.c",
            "line": 42,
            "note": "unchecked length",
            "hypothesis": "CWE-787",
            "priority": "high",
        },
    ]

    paths = write_sourcehunt_report(
        output_dir=str(tmp_path),
        session_id="session",
        repo_url="example/repo",
        findings=[],
        verified_findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        formats=["json"],
        potentials=potentials,
    )

    report = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert report["potentials"] == potentials


def test_json_report_omits_empty_potential_collection(tmp_path) -> None:
    paths = write_sourcehunt_report(
        output_dir=str(tmp_path),
        session_id="session",
        repo_url="example/repo",
        findings=[],
        verified_findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        formats=["json"],
        potentials=[],
    )

    report = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert "potentials" not in report
