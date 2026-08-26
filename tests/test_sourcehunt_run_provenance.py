import json
from pathlib import Path

from clearwing.sourcehunt.reporter import write_sourcehunt_report


def test_json_report_includes_sourcehunt_trace_and_build_provenance(
    tmp_path, monkeypatch
) -> None:
    trace_id = "656901efba4302f09db3999290711fb0"
    commit_sha = "a" * 40
    monkeypatch.setenv("CLEARWING_COMMIT_SHA", commit_sha)

    paths = write_sourcehunt_report(
        output_dir=str(tmp_path),
        session_id="session",
        repo_url="example/repo",
        findings=[],
        verified_findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        formats=["json"],
        trace_id=trace_id,
        run_started_at="2026-08-26T12:00:00+00:00",
        run_ended_at="2026-08-26T12:05:00+00:00",
    )

    report = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert report["trace_id"] == trace_id
    assert report["clearwing"]["commit_sha"] == commit_sha
    assert report["clearwing"]["start-time"] == "2026-08-26T12:00:00+00:00"
    assert report["clearwing"]["end-time"] == "2026-08-26T12:05:00+00:00"
    assert report["clearwing"]["version"]
