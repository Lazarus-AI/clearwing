"""Tests for SourceHuntRunner stage checkpoints and budget carry-forward.

Covers the standalone checkpoint module (lossless finding round-trip, latest
checkpoint priority, prior-spend reconstruction, session-dir resolution) and the
``SpendLedger`` seeding that lets a resumed run honor the original dollar cap.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from genai_pyo3 import ChatResponse

from clearwing.findings.types import Finding
from clearwing.llm.budget import BudgetConfigurationError, SpendLedger
from clearwing.sourcehunt.checkpoints import (
    latest_checkpoint,
    load_stage_checkpoint,
    resolve_session_dir,
    sum_prior_spend,
    write_stage_checkpoint,
)
from clearwing.sourcehunt.runner import SourceHuntRunner

FIXTURE_C_PROPAGATION = (
    Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"
)


def _make_ranker_llm() -> AsyncMock:
    llm = AsyncMock()
    llm.aask_json.return_value = ({"results": []}, ChatResponse())
    return llm


def _make_hunter_llm() -> MagicMock:
    llm = MagicMock()
    bound = MagicMock()
    response = MagicMock()
    response.content = "No vulnerabilities found."
    response.tool_calls = []
    bound.invoke.return_value = response
    llm.bind_tools.return_value = bound
    return llm


def _make_verifier_llm() -> AsyncMock:
    llm = AsyncMock()
    llm.aask_text.return_value = ChatResponse(
        content=[{"text": json.dumps({"is_real": True, "severity": "high"})}]
    )
    return llm


def _fully_populated_finding() -> Finding:
    """A finding carrying hunter + verify + exploit + nested-dict fields."""
    return Finding(
        id="find-001",
        finding_type="sql-injection",
        cwe="CWE-89",
        file="src/db.py",
        line_number=42,
        end_line=48,
        code_snippet="cursor.execute(q)",
        severity="high",
        severity_verified="critical",
        confidence="high",
        description="Unsanitized query",
        crash_evidence="stack trace here",
        poc="' OR 1=1 --",
        discovered_by="hunter",
        evidence_level="crash_reproduced",
        related_cve="CVE-2026-9999",
        primitive_type="oob_write",
        verified=True,
        verifier_pro_argument="reaches sink",
        verifier_counter_argument="input is validated upstream",
        verifier_tie_breaker="not on this path",
        patch_oracle_passed=True,
        exploit="payload",
        exploit_success=True,
        auto_patch="--- a/db.py",
        auto_patch_validated=True,
        hunter_session_id="sh-abc",
        verifier_session_id="sh-def",
        crypto_evidence={"nested": {"a": 1}, "list": [1, 2, 3]},
        extra={"exploit_cost_usd": 0.12, "stable_finding_id": "stable-1"},
    )


# --- checkpoint round-trip --------------------------------------------------


def test_write_then_load_is_lossless(tmp_path):
    finding = _fully_populated_finding()
    write_stage_checkpoint(
        tmp_path,
        "hunt",
        findings=[finding],
        budget_spent_usd=1.23,
    )

    loaded = load_stage_checkpoint(tmp_path, "hunt")
    assert loaded is not None
    assert loaded["stage"] == "hunt"
    assert loaded["session_id"] == tmp_path.name
    assert loaded["budget_spent_usd"] == pytest.approx(1.23)
    assert len(loaded["findings"]) == 1

    # No field loss: the round-tripped dataclass equals the original.
    assert asdict(loaded["findings"][0]) == asdict(finding)


def test_checkpoint_file_is_plain_json(tmp_path):
    write_stage_checkpoint(
        tmp_path,
        "hunt",
        findings=[_fully_populated_finding()],
        budget_spent_usd=0.5,
    )
    path = tmp_path / "checkpoints" / "hunt.json"
    assert path.exists()
    # json.load-simple, as required for eval transparency.
    data = json.loads(path.read_text())
    assert data["stage"] == "hunt"
    assert isinstance(data["findings"], list)
    assert data["findings"][0]["id"] == "find-001"


def test_verify_stage_carries_verified_and_rejected(tmp_path):
    good = Finding(id="ok", verified=True)
    bad = Finding(id="no", verified=False)
    write_stage_checkpoint(
        tmp_path,
        "verify",
        findings=[good, bad],
        verified=[good],
        rejected=[bad],
        budget_spent_usd=2.0,
    )
    loaded = load_stage_checkpoint(tmp_path, "verify")
    assert [f.id for f in loaded["verified"]] == ["ok"]
    assert [f.id for f in loaded["rejected"]] == ["no"]


def test_exploit_stage_carries_exploited(tmp_path):
    f = Finding(id="e", exploit_success=True)
    write_stage_checkpoint(
        tmp_path,
        "exploit",
        findings=[f],
        verified=[f],
        rejected=[],
        exploited=[f],
        budget_spent_usd=3.0,
    )
    loaded = load_stage_checkpoint(tmp_path, "exploit")
    assert [f.id for f in loaded["exploited"]] == ["e"]
    assert loaded["rejected"] == []


def test_unknown_stage_rejected(tmp_path):
    with pytest.raises(ValueError):
        write_stage_checkpoint(
            tmp_path, "bogus", findings=[], budget_spent_usd=0.0
        )


def test_load_absent_checkpoint_returns_none(tmp_path):
    assert load_stage_checkpoint(tmp_path, "hunt") is None


def test_reload_ignores_unknown_keys(tmp_path):
    ckpt_dir = tmp_path / "checkpoints"
    ckpt_dir.mkdir()
    (ckpt_dir / "hunt.json").write_text(
        json.dumps(
            {
                "stage": "hunt",
                "session_id": "sh-x",
                "budget_spent_usd": 0.0,
                "findings": [{"id": "f1", "not_a_real_field": "ignore me"}],
            }
        )
    )
    loaded = load_stage_checkpoint(tmp_path, "hunt")
    assert loaded["findings"][0].id == "f1"
    assert not hasattr(loaded["findings"][0], "not_a_real_field")


def test_write_is_atomic_no_tmp_left_behind(tmp_path):
    write_stage_checkpoint(
        tmp_path, "hunt", findings=[Finding(id="a")], budget_spent_usd=0.0
    )
    ckpt_dir = tmp_path / "checkpoints"
    leftovers = [p for p in ckpt_dir.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


# --- latest_checkpoint priority ---------------------------------------------


def test_latest_checkpoint_priority_order(tmp_path):
    assert latest_checkpoint(tmp_path) is None

    write_stage_checkpoint(tmp_path, "hunt", findings=[], budget_spent_usd=0.0)
    assert latest_checkpoint(tmp_path) == "hunt"

    write_stage_checkpoint(
        tmp_path, "verify", findings=[], verified=[], rejected=[], budget_spent_usd=0.0
    )
    assert latest_checkpoint(tmp_path) == "verify"

    write_stage_checkpoint(
        tmp_path,
        "exploit",
        findings=[],
        verified=[],
        rejected=[],
        exploited=[],
        budget_spent_usd=0.0,
    )
    assert latest_checkpoint(tmp_path) == "exploit"


# --- sum_prior_spend --------------------------------------------------------


def test_sum_prior_spend_sums_settled_only(tmp_path):
    ledger = tmp_path / "spend-ledger.jsonl"
    ledger.write_text(
        "\n".join(
            [
                json.dumps({"event": "run_started"}),
                json.dumps({"event": "call_reserved", "cost_usd": 99.0}),
                json.dumps({"event": "call_settled", "cost_usd": 0.5}),
                json.dumps({"event": "call_settled", "cost_usd": 1.25}),
                json.dumps({"event": "budget_snapshot", "cost_usd": 0.0}),
            ]
        )
    )
    assert sum_prior_spend(tmp_path) == pytest.approx(1.75)


def test_sum_prior_spend_absent_ledger(tmp_path):
    assert sum_prior_spend(tmp_path) == 0.0


def test_sum_prior_spend_tolerates_malformed_lines(tmp_path):
    ledger = tmp_path / "spend-ledger.jsonl"
    ledger.write_text(
        "\n".join(
            [
                "not json at all",
                json.dumps({"event": "call_settled", "cost_usd": 2.0}),
                json.dumps({"event": "call_settled", "cost_usd": None}),
                json.dumps({"event": "call_settled"}),  # missing cost
                "",
            ]
        )
    )
    assert sum_prior_spend(tmp_path) == pytest.approx(2.0)


# --- resolve_session_dir ----------------------------------------------------


def test_resolve_session_dir_bare_name(tmp_path):
    resolved = resolve_session_dir("sh-1234abcd", tmp_path)
    assert resolved == tmp_path / "sh-1234abcd"


def test_resolve_session_dir_explicit_path(tmp_path):
    session = tmp_path / "runs" / "sh-9999"
    session.mkdir(parents=True)
    resolved = resolve_session_dir(str(session), "/some/other/output")
    assert resolved == session


# --- budget carry-forward ---------------------------------------------------


def _seeded_ledger(tmp_path, *, initial: float, budget: float) -> SpendLedger:
    return SpendLedger(
        limit_usd=budget,
        session_id="resume-test",
        repo_url="/tmp/repo",
        output_dir=tmp_path,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
        initial_spent_usd=initial,
    )


def test_initial_spent_seeds_spent_and_remaining(tmp_path):
    ledger = _seeded_ledger(tmp_path, initial=5.0, budget=10.0)
    assert ledger.spent_usd == pytest.approx(5.0)
    assert ledger.remaining_usd == pytest.approx(5.0)


def test_initial_spent_recorded_in_run_started_event(tmp_path):
    _seeded_ledger(tmp_path, initial=3.0, budget=10.0)
    ledger_file = tmp_path / "resume-test" / "spend-ledger.jsonl"
    events = [json.loads(line) for line in ledger_file.read_text().splitlines() if line]
    run_started = next(e for e in events if e["event"] == "run_started")
    assert run_started["carried_forward_usd"] == pytest.approx(3.0)


def test_resume_seeded_past_cap_reports_exhausted_on_reserve(tmp_path):
    # Prior run already spent the whole cap; the next reservation must fail.
    ledger = _seeded_ledger(tmp_path, initial=10.0, budget=10.0)
    assert ledger.remaining_usd == pytest.approx(0.0)
    from clearwing.llm.budget import BudgetExceeded

    with pytest.raises(BudgetExceeded):
        ledger.reserve_call(
            model="test-model",
            provider="test",
            stage="verify",
            input_token_upper_bound=0,
            requested_max_output_tokens=1,
            supports_output_limit=True,
        )
    assert ledger.exhausted is True


def test_negative_initial_spent_rejected(tmp_path):
    with pytest.raises(BudgetConfigurationError):
        _seeded_ledger(tmp_path, initial=-1.0, budget=10.0)


def test_non_finite_initial_spent_rejected(tmp_path):
    with pytest.raises(BudgetConfigurationError):
        _seeded_ledger(tmp_path, initial=float("inf"), budget=10.0)


# --- runner resume wiring (deliberate exit) ---------------------------------


def test_runner_resume_without_checkpoint_raises(tmp_path):
    """Resume is deliberate: a session dir with no checkpoint exits, not restarts."""
    from clearwing.sourcehunt.runner import SourceHuntRunner

    empty_session = tmp_path / "sh-empty"
    empty_session.mkdir()
    with pytest.raises(ValueError, match="no stage checkpoint"):
        SourceHuntRunner(
            repo_url="/tmp/repo",
            output_dir=str(tmp_path),
            resume_session=str(empty_session),
        )


def test_runner_resume_nonexistent_session_raises(tmp_path):
    from clearwing.sourcehunt.runner import SourceHuntRunner

    with pytest.raises(ValueError, match="no stage checkpoint"):
        SourceHuntRunner(
            repo_url="/tmp/repo",
            output_dir=str(tmp_path),
            resume_session="sh-does-not-exist",
        )


def test_runner_resume_adopts_session_id_and_detects_stage(tmp_path):
    """A present checkpoint sets the resumed session id and the resume stage."""
    from clearwing.sourcehunt.runner import SourceHuntRunner

    session = tmp_path / "sh-resume01"
    write_stage_checkpoint(
        session,
        "verify",
        findings=[Finding(id="f")],
        verified=[Finding(id="f")],
        rejected=[],
        budget_spent_usd=1.0,
    )
    runner = SourceHuntRunner(
        repo_url="/tmp/repo",
        output_dir=str(tmp_path),
        resume_session=str(session),
    )
    assert runner._session_id == "sh-resume01"
    assert runner._resume_from == "verify"


def test_runner_resume_by_bare_name(tmp_path):
    from clearwing.sourcehunt.runner import SourceHuntRunner

    session = tmp_path / "sh-bare"
    write_stage_checkpoint(
        session, "hunt", findings=[Finding(id="f")], budget_spent_usd=0.0
    )
    runner = SourceHuntRunner(
        repo_url="/tmp/repo",
        output_dir=str(tmp_path),
        resume_session="sh-bare",
    )
    assert runner._session_id == "sh-bare"
    assert runner._resume_from == "hunt"


def test_runner_no_resume_leaves_state_clean(tmp_path):
    from clearwing.sourcehunt.runner import SourceHuntRunner

    runner = SourceHuntRunner(
        repo_url="/tmp/repo",
        output_dir=str(tmp_path),
    )
    assert runner._resume_session is None
    assert runner._resume_from is None
    assert runner._session_id.startswith("sh-")


# --- end-to-end: checkpoints written, then resumed --------------------------


def _standard_runner(tmp_path, **overrides):
    kwargs = dict(
        repo_url=str(FIXTURE_C_PROPAGATION),
        local_path=str(FIXTURE_C_PROPAGATION),
        depth="standard",
        budget_usd=1.0,
        max_parallel=2,
        output_dir=str(tmp_path),
        ranker_llm=_make_ranker_llm(),
        hunter_llm=_make_hunter_llm(),
        verifier_llm=_make_verifier_llm(),
        no_exploit=True,
    )
    kwargs.update(overrides)
    return SourceHuntRunner(**kwargs)


def test_full_run_writes_all_stage_checkpoints(tmp_path):
    runner = _standard_runner(tmp_path)
    result = runner.run()
    session_dir = tmp_path / result.session_id
    # hunt + verify are always reached; exploit is reached even with no_exploit
    # (the stage runs and simply exploits nothing).
    assert (session_dir / "checkpoints" / "hunt.json").exists()
    assert (session_dir / "checkpoints" / "verify.json").exists()
    assert (session_dir / "checkpoints" / "exploit.json").exists()
    # Each is plain, loadable JSON with the documented shape.
    hunt = json.loads((session_dir / "checkpoints" / "hunt.json").read_text())
    assert hunt["stage"] == "hunt"
    assert "findings" in hunt
    verify = json.loads((session_dir / "checkpoints" / "verify.json").read_text())
    assert "verified" in verify and "rejected" in verify


def test_resume_from_verify_skips_hunt_and_verify(tmp_path):
    # First: a full run to produce real checkpoints.
    first = _standard_runner(tmp_path)
    result = first.run()
    session_dir = tmp_path / result.session_id
    assert (session_dir / "checkpoints" / "verify.json").exists()

    # Delete the exploit checkpoint so the highest present is verify.
    (session_dir / "checkpoints" / "exploit.json").unlink()

    # Resume: hunter + verifier must never be invoked; report still runs.
    hunter = _make_hunter_llm()
    verifier = _make_verifier_llm()
    resumed = _standard_runner(
        tmp_path,
        hunter_llm=hunter,
        verifier_llm=verifier,
        resume_session=str(session_dir),
    )
    assert resumed._resume_from == "verify"
    resumed_result = resumed.run()

    assert resumed_result.session_id == result.session_id
    # Skipped phases never touched their models.
    hunter.bind_tools.assert_not_called()
    verifier.aask_text.assert_not_called()
    # Report re-ran: outputs exist.
    for path in resumed_result.output_paths.values():
        assert Path(path).exists()


def test_resume_budget_carries_forward(tmp_path):
    first = _standard_runner(tmp_path)
    result = first.run()
    session_dir = tmp_path / result.session_id
    prior_spend = sum_prior_spend(session_dir)

    resumed = _standard_runner(tmp_path, resume_session=str(session_dir))
    ledger = resumed._ensure_spend_ledger()
    # The resumed ledger starts already having "spent" the prior run's cost.
    assert ledger.spent_usd == pytest.approx(prior_spend)
