"""End-to-end tests for SourceHuntRunner.

Mocks the ranker / hunter / verifier / exploiter LLMs and runs against the
local c_propagation fixture. Verifies:
- Pipeline runs to completion in `quick`, `standard`, and `deep` depth modes
- SARIF output is generated and includes file + line_number
- The propagation file (codec_limits.h) lands in Tier B (not Tier C)
- evidence_level is set on every finding
- spent_per_tier breakdown is recorded in the manifest
- The `quick` depth path runs without any LLM hunters
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from genai_pyo3 import ChatResponse

from clearwing.analysis import SourceAnalyzer
from clearwing.findings.types import Finding
from clearwing.sourcehunt.checkpoints import HuntResult, SourceHuntCheckpoint
from clearwing.sourcehunt.pool import assign_tier
from clearwing.sourcehunt.preprocessor import Preprocessor
from clearwing.sourcehunt.ranker import Ranker
from clearwing.sourcehunt.runner import SourceHuntResult, SourceHuntRunner
from clearwing.sourcehunt.state import PipelineStatus, StageOutcome

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"
FIXTURE_PY_SQLI = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"


def test_runner_is_available_from_the_public_sourcehunt_package():
    from clearwing.sourcehunt import SourceHuntRunner as PublicSourceHuntRunner

    assert PublicSourceHuntRunner is SourceHuntRunner


def test_terminal_run_status_preserves_stage_budget_exhaustion(tmp_path):
    runner = SourceHuntRunner(
        repo_url="repo",
        output_dir=str(tmp_path),
        enable_mechanism_memory=False,
    )

    assert runner._terminal_run_status("completed", "skipped") == "completed"
    assert runner._terminal_run_status("completed", "budget_exhausted") == "budget_exhausted"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("subsystem_status", "expected_status", "expected_outcome"),
    [
        ("completed", "completed", StageOutcome.SUCCEEDED),
        ("degraded", "degraded", StageOutcome.DEGRADED),
        ("budget_exhausted", "budget_exhausted", StageOutcome.SKIPPED),
    ],
)
async def test_subsystem_terminal_status_updates_hunt_status_and_event(
    monkeypatch,
    tmp_path,
    subsystem_status,
    expected_status,
    expected_outcome,
):
    import clearwing.sourcehunt.subsystem as subsystem_module

    class BudgetExhaustedSubsystemRunner:
        def __init__(self, config):
            self.total_spent = 1.0
            self.subsystems_completed = 1
            self.status = subsystem_status

        async def arun(self):
            return []

    monkeypatch.setattr(
        subsystem_module,
        "SubsystemHuntRunner",
        BudgetExhaustedSubsystemRunner,
    )
    progress = []
    runner = SourceHuntRunner(
        repo_url="repo",
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        hunter_llm=MagicMock(),
        enable_subsystem_hunt=True,
        subsystem_paths=["src"],
        no_per_file_hunt=True,
        enable_mechanism_memory=False,
        on_progress=progress.append,
    )
    result = HuntResult(
        findings=[],
        files_hunted=0,
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        status="skipped",
    )
    pipeline_status = PipelineStatus()

    await runner._hunt_subsystems(
        result,
        files=[{"path": "src/jv.c", "priority": 1.0}],
        repo_path=str(tmp_path),
        callgraph=None,
        entry_points_by_file={},
        findings_pool=None,
        pipeline_status=pipeline_status,
    )

    assert result.status == expected_status
    assert result.subsystem_status == subsystem_status
    assert result.subsystems_hunted == 1
    assert pipeline_status.stages["subsystem_hunt"].outcome is expected_outcome
    assert progress[-1].stage == "subsystem_hunt"
    assert progress[-1].status == subsystem_status


@pytest.mark.asyncio
async def test_subsystem_prestart_budget_exhaustion_is_terminal(monkeypatch, tmp_path):
    progress = []
    runner = SourceHuntRunner(
        repo_url="repo",
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        enable_subsystem_hunt=True,
        no_per_file_hunt=True,
        enable_mechanism_memory=False,
        on_progress=progress.append,
    )
    monkeypatch.setattr(runner, "_budget_exhausted", lambda: True)
    result = HuntResult(
        findings=[],
        spent_per_tier={},
        status="skipped",
        per_file_status="skipped",
    )
    pipeline_status = PipelineStatus()

    await runner._hunt_subsystems(
        result,
        files=[],
        repo_path=str(tmp_path),
        callgraph=None,
        entry_points_by_file={},
        findings_pool=None,
        pipeline_status=pipeline_status,
    )

    assert result.status == "budget_exhausted"
    assert result.per_file_status == "skipped"
    assert result.subsystem_status == "budget_exhausted"
    assert pipeline_status.stages["subsystem_hunt"].outcome is StageOutcome.SKIPPED
    assert progress[-1].stage == "subsystem_hunt"
    assert progress[-1].status == "budget_exhausted"


@pytest.mark.asyncio
async def test_missing_subsystem_model_records_degraded_terminal_status(monkeypatch, tmp_path):
    progress = []
    runner = SourceHuntRunner(
        repo_url="repo",
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        enable_subsystem_hunt=True,
        enable_mechanism_memory=False,
        on_progress=progress.append,
    )
    monkeypatch.setattr(runner, "_budget_exhausted", lambda: False)
    monkeypatch.setattr(runner, "_get_native_client", lambda *args, **kwargs: None)
    result = HuntResult(findings=[], spent_per_tier={})
    pipeline_status = PipelineStatus()

    await runner._hunt_subsystems(
        result,
        files=[],
        repo_path=str(tmp_path),
        callgraph=None,
        entry_points_by_file={},
        findings_pool=None,
        pipeline_status=pipeline_status,
    )

    assert result.status == "degraded"
    assert result.per_file_status == "completed"
    assert result.subsystem_status == "degraded"
    assert pipeline_status.stages["subsystem_hunt"].outcome is StageOutcome.DEGRADED
    assert progress[-1].stage == "subsystem_hunt"
    assert progress[-1].status == "degraded"


@pytest.mark.asyncio
async def test_invalid_hunter_finding_path_is_dropped_and_degrades_stage(monkeypatch, tmp_path):
    import clearwing.sourcehunt.runner as runner_module

    class InvalidPathPool:
        def __init__(self, config):
            self.budget_exhausted = False
            self.total_spent = 0.25
            self.spent_per_tier = {"A": 0.25, "B": 0.0, "C": 0.0}
            self.runs_per_band = {"fast": 1}
            self.spent_per_band = {"fast": 0.25}
            self.promotion_counts = {}
            self.completed_target_count = 1

        async def arun(self):
            return [Finding(id="bad-path", file="../outside.c", severity="high")]

    monkeypatch.setattr(runner_module, "HunterPool", InvalidPathPool)
    progress = []
    runner = SourceHuntRunner(
        repo_url="repo",
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        hunter_llm=MagicMock(),
        enable_mechanism_memory=False,
        on_progress=progress.append,
    )
    runner._checkpoint = SourceHuntCheckpoint()
    monkeypatch.setattr(runner, "_get_native_client", lambda *args, **kwargs: MagicMock())
    pipeline_status = PipelineStatus()

    result = await runner._hunt(
        files=[{"path": "sample.c", "priority": 5.0}],
        repo_path=str(tmp_path),
        pipeline_status=pipeline_status,
        stage_files=["sample.c"],
        seeded_by_file={},
        semgrep_hints_by_file={},
        entry_points_by_file={},
        seed_corpus_by_file={},
        findings_pool=None,
        callgraph=None,
    )

    assert result.findings == []
    assert result.status == "degraded"
    assert result.per_file_status == "degraded"
    assert pipeline_status.stages["hunter_pool"].outcome is StageOutcome.DEGRADED
    assert progress[-1].status == "degraded"
    assert runner._checkpoint.hunt is not None


def test_reconcile_finding_snapshots_uses_stable_identity():
    upstream = Finding(
        id="static-random-a",
        file="sample.c",
        extra={"stable_finding_id": "static-semantic"},
    )
    restored = Finding(
        id="static-random-b",
        file="sample.c",
        verified=True,
        extra={"stable_finding_id": "static-semantic"},
    )

    reconciled = SourceHuntRunner._reconcile_finding_snapshots([upstream], [restored])

    assert reconciled == [restored]
    assert reconciled[0] is restored
    assert reconciled[0].verified is True


@pytest.mark.asyncio
async def test_v1_verification_returns_rejected_snapshots_for_resume(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int sample(void);\n", encoding="utf-8")
    verifier_llm = _make_verifier_llm()
    verifier_llm.aask_text.return_value = ChatResponse(
        content=[
            {
                "text": json.dumps(
                    {
                        "is_real": False,
                        "severity": "low",
                        "evidence_level": "suspicion",
                        "pro_argument": "weak signal",
                        "counter_argument": "not attacker controlled",
                        "tie_breaker": "reject",
                        "duplicate_cve": None,
                    }
                )
            }
        ]
    )
    runner = SourceHuntRunner(
        repo_url=str(tmp_path),
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        validator_mode="v1",
        enable_patch_oracle=False,
        enable_mechanism_memory=False,
    )
    upstream = Finding(
        id="finding-1",
        file="sample.c",
        severity="high",
        extra={"stable_finding_id": "finding-stable"},
    )

    verified, rejected, status = await runner._verify_v1(
        verifier_llm,
        [upstream],
        str(tmp_path),
    )

    assert verified == []
    assert rejected == [upstream]
    assert rejected[0].verified is False
    assert rejected[0].verifier_counter_argument == "not attacker controlled"
    assert status == "completed"


def _ranker_response(files: list[str]) -> str:
    """Build a JSON response covering the listed files."""
    entries = []
    for path in files:
        if "codec_limits.h" in path:
            # The propagation case: surface=1, influence=5
            entries.append(
                {
                    "path": path,
                    "surface": 1,
                    "influence": 5,
                    "surface_rationale": "just a constants header",
                    "influence_rationale": "MAX_FRAME_BYTES used in 3 memcpys",
                }
            )
        elif "codec_a.c" in path or "codec_b.c" in path or "codec_c.c" in path:
            entries.append(
                {
                    "path": path,
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "memcpy on user input",
                    "influence_rationale": "called by main",
                }
            )
        else:
            entries.append(
                {
                    "path": path,
                    "surface": 2,
                    "influence": 1,
                    "surface_rationale": "utility",
                    "influence_rationale": "isolated",
                }
            )
    return json.dumps(entries)


def _make_ranker_llm(file_paths: list[str]) -> AsyncMock:
    """Ranker LLM that responds via aask_json with a {results: [...]} payload."""
    llm = AsyncMock()
    entries = json.loads(_ranker_response(file_paths))
    llm.aask_json.return_value = ({"results": entries}, ChatResponse())
    return llm


def _make_hunter_llm() -> MagicMock:
    """A hunter LLM that immediately returns 'no findings' (no tool calls)."""
    llm = MagicMock()
    bound = MagicMock()
    response = MagicMock()
    response.content = "I analyzed the file but found no vulnerabilities."
    response.tool_calls = []
    bound.invoke.return_value = response
    llm.bind_tools.return_value = bound
    return llm


def _make_verifier_llm() -> AsyncMock:
    llm = AsyncMock()
    llm.aask_text.return_value = ChatResponse(
        content=[
            {
                "text": json.dumps(
                    {
                        "is_real": True,
                        "severity": "high",
                        "evidence_level": "static_corroboration",
                        "pro_argument": "regex matched",
                        "counter_argument": "",
                        "tie_breaker": "static analysis hit",
                        "duplicate_cve": None,
                    }
                )
            }
        ]
    )
    return llm


# --- depth=quick ------------------------------------------------------------


class TestQuickDepth:
    def test_session_dir_exists_even_if_run_fails_early(self, tmp_path, monkeypatch):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
        )
        monkeypatch.setattr(
            runner, "_preprocess", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        with pytest.raises(RuntimeError, match="boom"):
            runner.run()

        assert (tmp_path / runner.session_id).is_dir()

    def test_quick_runs_without_hunter_llm(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
            # No hunter/verifier/exploiter LLMs needed for quick
        )
        result = runner.run()
        assert isinstance(result, SourceHuntResult)
        # Quick mode returns whatever static findings SourceAnalyzer found
        # (possibly zero for this fixture; that's fine)
        assert result.files_ranked == 4
        assert result.files_hunted == 0
        assert result.cost_usd == 0.0
        # SARIF file exists
        assert "sarif" in result.output_paths
        sarif_path = Path(result.output_paths["sarif"])
        assert sarif_path.exists()


# --- depth=standard ---------------------------------------------------------


class TestStandardDepth:
    def test_standard_pipeline_completes(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            max_parallel=2,
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
            hunter_llm=_make_hunter_llm(),
            verifier_llm=_make_verifier_llm(),
            no_exploit=True,  # exploiter not needed for this test
        )
        result = runner.run()
        assert isinstance(result, SourceHuntResult)
        assert result.files_ranked == 4
        # Output paths exist
        for fmt, path in result.output_paths.items():
            assert Path(path).exists(), f"{fmt} not written"

    def test_codec_limits_h_lands_in_tier_b_not_c(self, tmp_path):
        ranker_llm = _make_ranker_llm(
            [
                "include/codec_limits.h",
                "src/codec_a.c",
                "src/codec_b.c",
                "src/codec_c.c",
            ]
        )
        SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            output_dir=str(tmp_path),
            ranker_llm=ranker_llm,
            hunter_llm=_make_hunter_llm(),
            verifier_llm=_make_verifier_llm(),
            no_exploit=True,
        )
        # Hook into the runner's preprocess + rank to inspect tiers without
        # running the full hunt
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        Ranker(ranker_llm).rank(result.file_targets)
        # Find the header
        header = next(ft for ft in result.file_targets if ft["path"].endswith("codec_limits.h"))
        # surface=1 from LLM, but defines_constants=True floors influence to 3.
        # Wait — the ranker LLM returns influence=5. defines_constants floor
        # of 3 doesn't downgrade. Let me check the actual values.
        # surface=1, influence=5, reach=3 → priority = 0.5 + 1.0 + 0.9 = 2.4 → B
        assert header["surface"] == 1
        assert header["influence"] == 5
        assert header["priority"] == pytest.approx(2.4)
        assert assign_tier(header) == "B"

    def test_manifest_has_spent_per_tier(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
            hunter_llm=_make_hunter_llm(),
            verifier_llm=_make_verifier_llm(),
            no_exploit=True,
        )
        result = runner.run()
        # Manifest exists and has spent_per_tier
        manifest_path = Path(result.output_paths["manifest"])
        manifest = json.loads(manifest_path.read_text())
        assert "spent_per_tier" in manifest
        assert "A" in manifest["spent_per_tier"]
        assert "B" in manifest["spent_per_tier"]
        assert "C" in manifest["spent_per_tier"]


# --- verification skipped --------------------------------------------------


class TestNoVerify:
    def test_no_verify_keeps_findings_unverified(self, tmp_path):
        hunter_llm = AsyncMock()
        hunter_llm.model_name = "test-model"
        hunter_llm.achat.return_value = ChatResponse(
            content=[{"text": "No vulnerabilities found."}]
        )
        verifier_llm = AsyncMock()
        stage_events = []
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="standard",
            budget_usd=1.0,
            max_parallel=1,
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["app.py"]),
            hunter_llm=hunter_llm,
            verifier_llm=verifier_llm,
            no_verify=True,
            no_exploit=True,
            enable_calibration=False,
            enable_mechanism_memory=False,
            enable_patch_oracle=False,
            enable_stability_verification=False,
            enable_variant_loop=True,
            enable_knowledge_graph=False,
            enable_findings_pool=False,
            enable_behavior_monitor=False,
        )
        runner._emit_stage = lambda stage, status, **data: stage_events.append(
            (stage, status, data)
        )

        result = runner.run()

        assert result.findings
        assert result.verified_findings == []
        assert all(finding.get("verified") is False for finding in result.findings)
        assert result.pipeline_status.stages["verifier"].outcome is StageOutcome.SKIPPED
        verifier_llm.aask_text.assert_not_awaited()

        verify_skipped = next(
            data
            for stage, status, data in stage_events
            if stage == "verify" and status == "skipped"
        )
        assert verify_skipped["detail"] == "Verification skipped (--no-verify)"

        manifest = json.loads(Path(result.output_paths["manifest"]).read_text())
        json_report = json.loads(Path(result.output_paths["json"]).read_text())
        markdown = Path(result.output_paths["markdown"]).read_text()
        assert manifest["verified_count"] == 0
        assert json_report["verified_findings"] == []
        assert f"- **Findings:** {len(result.findings)} (0 verified)" in markdown
        assert "verifier: skipped — Verification skipped (--no-verify)" in markdown
        assert "- **Verified:** yes" not in markdown

        # Skipping trust promotion must not suppress severity signaling.
        assert any(
            finding.get("severity") in {"critical", "high"}
            for finding in result.findings
        )
        assert result.exit_code == 2


# --- evidence_level on findings ---------------------------------------------


class TestEvidenceLevels:
    def test_static_findings_promoted_to_static_corroboration(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["app.py"]),
        )
        result = runner.run()
        # The py_sqli fixture has an f-string SQL injection — SourceAnalyzer
        # catches it via regex
        assert any(f.get("evidence_level") == "static_corroboration" for f in result.findings), (
            f"no static_corroboration findings: {[f.get('evidence_level') for f in result.findings]}"
        )
        static_findings = [
            finding for finding in result.findings if finding.discovered_by == "source_analyzer"
        ]
        assert static_findings
        for finding in static_findings:
            assert len(finding.id) == len("static-") + 8
            assert len(finding.extra["stable_finding_id"]) == len("static-") + 16

    def test_every_finding_has_evidence_level(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["app.py"]),
        )
        result = runner.run()
        for f in result.findings:
            assert f.get("evidence_level") is not None


# --- Output sanity ----------------------------------------------------------


class TestOutputs:
    def test_sarif_includes_file_and_line(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["app.py"]),
        )
        result = runner.run()
        sarif_path = Path(result.output_paths["sarif"])
        sarif = json.loads(sarif_path.read_text())
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1
        # Each result has a physicalLocation with a file URI
        for r in results:
            loc = r["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert loc["artifactLocation"]["uri"]
            # And a region with a startLine
            if "line_number" in r.get("message", {}).get("text", "") or "region" in loc:
                assert "region" in loc

    def test_markdown_is_written(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["app.py"]),
        )
        result = runner.run()
        md_path = Path(result.output_paths["markdown"])
        content = md_path.read_text()
        assert "Sourcehunt Report" in content
        assert "Severity Histogram" in content or "Findings" in content


# --- Error handling ---------------------------------------------------------


class TestAdversarialVerifierDefault:
    """v0.2: adversarial verifier is on by default."""

    def test_default_runner_constructs_adversarial_verifier(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
        )
        assert runner.adversarial_verifier is True

    def test_explicit_no_adversarial(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            adversarial_verifier=False,
        )
        assert runner.adversarial_verifier is False

    def test_runner_passes_adversarial_to_verifier(self, tmp_path):
        """When the verifier runs, it gets the adversarial flag from the runner.

        v0.3 note: the verifier_llm is also used for patch-oracle, mechanism
        extraction, and variant-loop pattern generation. So we look through
        ALL calls for the one with the adversarial system prompt.
        """
        verifier_llm = _make_verifier_llm()
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="standard",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["app.py"]),
            hunter_llm=_make_hunter_llm(),
            verifier_llm=verifier_llm,
            no_exploit=True,
            # Use v1 verifier which has the STEEL-MAN adversarial prompt
            validator_mode="v1",
            # Disable the evidence-level gate so the adversarial prompt is
            # used on every finding regardless of evidence_level
            adversarial_threshold=None,
            # Disable v0.3 features that re-use the verifier LLM so this
            # test only sees the verification call
            enable_mechanism_memory=False,
            enable_patch_oracle=False,
            enable_variant_loop=False,
        )
        runner.run()
        # Find the call whose system prompt contains STEEL-MAN
        found_adversarial = False
        for call in verifier_llm.aask_text.call_args_list:
            system_prompt = call.kwargs.get("system", "")
            if "STEEL-MAN" in system_prompt:
                found_adversarial = True
                break
        assert found_adversarial, (
            "Expected at least one verifier LLM call to use the adversarial "
            f"(STEEL-MAN) system prompt; got {len(verifier_llm.aask_text.call_args_list)} calls"
        )


class TestErrorHandling:
    def test_file_content_loader_rejects_untrusted_paths_and_large_files(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        source = repo / "source.py"
        source.write_text("print('safe')\n")
        (repo / "directory").mkdir()
        oversized = repo / "oversized.py"
        oversized.write_bytes(b"x" * (SourceAnalyzer.MAX_FILE_SIZE + 1))

        outside = tmp_path / "outside.py"
        outside.write_text("secret\n")
        (repo / "outside-link.py").symlink_to(outside)

        runner = SourceHuntRunner(
            repo_url=str(repo),
            local_path=str(repo),
            depth="quick",
            output_dir=str(tmp_path / "output"),
        )

        assert runner._load_file_content(str(repo), Finding(file="source.py")) == "print('safe')\n"
        rejected = [
            str(source),
            "nested/../source.py",
            "../outside.py",
            "outside-link.py",
            "directory",
            "oversized.py",
        ]
        for path in rejected:
            assert runner._load_file_content(str(repo), Finding(file=path)) == ""

    def test_no_llm_at_all_runs_quick_path(self, tmp_path):
        # No ranker LLM, no provider manager — fallback should kick in
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=None,
        )
        # Should not raise; falls back to default scores
        result = runner.run()
        assert result is not None
        assert result.files_ranked == 4

    def test_session_id_is_set(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm(["x"]),
        )
        assert runner.session_id.startswith("sh-")
        result = runner.run()
        assert result.session_id == runner.session_id
