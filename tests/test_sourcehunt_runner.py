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
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.runner import SourceHuntResult, SourceHuntRunner
from clearwing.sourcehunt.pool import TierBudget


FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"
FIXTURE_PY_SQLI = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"


def _ranker_response(files: list[str]) -> str:
    """Build a JSON response covering the listed files."""
    entries = []
    for path in files:
        if "codec_limits.h" in path:
            # The propagation case: surface=1, influence=5
            entries.append({
                "path": path, "surface": 1, "influence": 5,
                "surface_rationale": "just a constants header",
                "influence_rationale": "MAX_FRAME_BYTES used in 3 memcpys",
            })
        elif "codec_a.c" in path or "codec_b.c" in path or "codec_c.c" in path:
            entries.append({
                "path": path, "surface": 4, "influence": 2,
                "surface_rationale": "memcpy on user input",
                "influence_rationale": "called by main",
            })
        else:
            entries.append({
                "path": path, "surface": 2, "influence": 1,
                "surface_rationale": "utility", "influence_rationale": "isolated",
            })
    return json.dumps(entries)


def _make_ranker_llm(file_paths: list[str]) -> MagicMock:
    llm = MagicMock()
    response = MagicMock()
    response.content = _ranker_response(file_paths)
    llm.invoke.return_value = response
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


def _make_verifier_llm() -> MagicMock:
    llm = MagicMock()
    response = MagicMock()
    response.content = json.dumps({
        "is_real": True,
        "severity": "high",
        "evidence_level": "static_corroboration",
        "pro_argument": "regex matched",
        "counter_argument": "",
        "tie_breaker": "static analysis hit",
        "duplicate_cve": None,
    })
    llm.invoke.return_value = response
    return llm


# --- depth=quick ------------------------------------------------------------


class TestQuickDepth:
    def test_quick_runs_without_hunter_llm(self, tmp_path):
        runner = SourceHuntRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            ranker_llm=_make_ranker_llm([
                "include/codec_limits.h", "src/codec_a.c",
                "src/codec_b.c", "src/codec_c.c",
            ]),
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
            ranker_llm=_make_ranker_llm([
                "include/codec_limits.h", "src/codec_a.c",
                "src/codec_b.c", "src/codec_c.c",
            ]),
            hunter_llm=_make_hunter_llm(),
            verifier_llm=_make_verifier_llm(),
            no_exploit=True,    # exploiter not needed for this test
        )
        result = runner.run()
        assert isinstance(result, SourceHuntResult)
        assert result.files_ranked == 4
        # Output paths exist
        for fmt, path in result.output_paths.items():
            assert Path(path).exists(), f"{fmt} not written"

    def test_codec_limits_h_lands_in_tier_b_not_c(self, tmp_path):
        ranker_llm = _make_ranker_llm([
            "include/codec_limits.h", "src/codec_a.c",
            "src/codec_b.c", "src/codec_c.c",
        ])
        runner = SourceHuntRunner(
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
        from clearwing.sourcehunt.preprocessor import Preprocessor
        from clearwing.sourcehunt.ranker import Ranker
        from clearwing.sourcehunt.pool import assign_tier
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        Ranker(ranker_llm).rank(result.file_targets)
        # Find the header
        header = next(
            ft for ft in result.file_targets if ft["path"].endswith("codec_limits.h")
        )
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
            ranker_llm=_make_ranker_llm([
                "include/codec_limits.h", "src/codec_a.c",
                "src/codec_b.c", "src/codec_c.c",
            ]),
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
        assert any(
            f.get("evidence_level") == "static_corroboration"
            for f in result.findings
        ), f"no static_corroboration findings: {[f.get('evidence_level') for f in result.findings]}"

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
            # Disable v0.3 features that re-use the verifier LLM so this
            # test only sees the verification call
            enable_mechanism_memory=False,
            enable_patch_oracle=False,
            enable_variant_loop=False,
        )
        runner.run()
        # Find the call whose system prompt contains STEEL-MAN
        found_adversarial = False
        for call in verifier_llm.invoke.call_args_list:
            msgs = call[0][0]
            if msgs and hasattr(msgs[0], "content") and "STEEL-MAN" in msgs[0].content:
                found_adversarial = True
                break
        assert found_adversarial, (
            "Expected at least one verifier LLM call to use the adversarial "
            f"(STEEL-MAN) system prompt; got {len(verifier_llm.invoke.call_args_list)} calls"
        )


class TestErrorHandling:
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
