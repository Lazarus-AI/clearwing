"""Unit tests for the sourcehunt 4-axis validator (spec 009).

Critical assertions:
- ValidatorVerdict defaults and construction
- Prompt gate: suspicion → quick, static_corroboration → full
- Independent context: user message excludes hunter reasoning
- Response parsing: 4-axis JSON, partial pass, error fallback
- apply_validator_verdict: merges fields, evidence bump, tier disagreement
- Patch oracle integration
- Rejected finding archival
- Calibration record/store lifecycle
- Runner integration: validator_mode dispatch
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.sourcehunt.calibration import CalibrationRecord, CalibrationStore
from clearwing.sourcehunt.state import Axes, AxisResult, ValidatorVerdict
from clearwing.sourcehunt.validator import (
    VALIDATOR_QUICK_PROMPT,
    VALIDATOR_SYSTEM_PROMPT,
    Validator,
    _VerdictSchema,
    apply_validator_verdict,
)


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "finding_type": "memory_safety",
        "cwe": "CWE-787",
        "severity": "high",
        "description": "memcpy overflow",
        "code_snippet": "memcpy(frame, input, input_len);",
        "crash_evidence": "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        "poc": "AAAA...300...AAAA",
        "evidence_level": "crash_reproduced",
    }
    base.update(kwargs)
    return base


def _make_verdict(**kwargs) -> ValidatorVerdict:
    defaults = dict(
        finding_id="hunter-abc",
        axes=Axes(
            real=AxisResult(passed=True, confidence="high", rationale="confirmed"),
            triggerable=AxisResult(passed=True, confidence="high", rationale="reachable"),
            impactful=AxisResult(passed=True, confidence="high", rationale="crosses boundary", boundary_crossed="user"),
            general=AxisResult(passed=True, confidence="high", rationale="default config"),
        ),
        advance=True,
        severity_validated="high",
        evidence_level="crash_reproduced",
        pro_argument="strong evidence",
        counter_argument="no counter",
        tie_breaker="crash log",
        duplicate_cve=None,
    )
    defaults.update(kwargs)
    return ValidatorVerdict(**defaults)


# --- ValidatorVerdict tests --------------------------------------------------


class TestValidatorVerdict:
    def test_defaults(self):
        v = ValidatorVerdict(
            finding_id="x", axes=Axes(), advance=False,
            severity_validated=None, evidence_level="suspicion",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
        )
        assert v.raw_response == ""
        assert v.patch_oracle_attempted is False
        assert v.patch_oracle_passed is None

    def test_all_axes_pass(self):
        v = _make_verdict()
        assert v.advance is True
        assert len(list(v.axes.items())) == 4
        assert all(ax.passed for _, ax in v.axes.items())

    def test_to_verifier_result(self):
        v = _make_verdict()
        vr = v.to_verifier_result()
        assert vr.finding_id == "hunter-abc"
        assert vr.is_real is True
        assert vr.severity_verified == "high"
        assert vr.evidence_level == "crash_reproduced"
        assert vr.pro_argument == "strong evidence"


# --- Prompt gate tests -------------------------------------------------------


class TestPromptGate:
    def test_suspicion_gets_quick_prompt(self):
        val = Validator(MagicMock())
        f = _make_finding(evidence_level="suspicion")
        assert val._prompt_for_finding(f) is VALIDATOR_QUICK_PROMPT

    def test_static_corroboration_gets_full_prompt(self):
        val = Validator(MagicMock())
        f = _make_finding(evidence_level="static_corroboration")
        assert val._prompt_for_finding(f) is VALIDATOR_SYSTEM_PROMPT

    def test_crash_reproduced_gets_full_prompt(self):
        val = Validator(MagicMock())
        f = _make_finding(evidence_level="crash_reproduced")
        assert val._prompt_for_finding(f) is VALIDATOR_SYSTEM_PROMPT

    def test_gate_none_always_full(self):
        val = Validator(MagicMock(), gate_threshold=None)
        f = _make_finding(evidence_level="suspicion")
        assert val._prompt_for_finding(f) is VALIDATOR_SYSTEM_PROMPT

    def test_quick_pass_disabled(self):
        val = Validator(MagicMock(), enable_quick_pass=False)
        f = _make_finding(evidence_level="suspicion")
        assert val._prompt_for_finding(f) is VALIDATOR_SYSTEM_PROMPT


# --- Independent context tests -----------------------------------------------


class TestIndependentContext:
    def test_user_message_excludes_hunter_reasoning(self):
        val = Validator(MagicMock())
        f = _make_finding(hunter_reasoning="this is secret internal reasoning")
        msg = val._build_user_message(f, "")
        assert "hunter_reasoning" not in msg
        assert "secret internal reasoning" not in msg

    def test_user_message_includes_finding_metadata(self):
        val = Validator(MagicMock())
        f = _make_finding()
        msg = val._build_user_message(f, "")
        assert "CWE-787" in msg
        assert "src/codec_a.c" in msg
        assert "memcpy overflow" in msg


# --- Response parsing tests ---------------------------------------------------


class TestResponseParsing:
    def test_full_4axis_maps_to_verdict(self):
        schema = _VerdictSchema.model_validate({
            "axes": {
                "real": {"passed": True, "confidence": "high", "rationale": "confirmed"},
                "triggerable": {"passed": True, "confidence": "medium", "rationale": "likely"},
                "impactful": {"passed": True, "confidence": "high", "rationale": "boundary crossed", "boundary_crossed": "user"},
                "general": {"passed": True, "confidence": "high", "rationale": "default config"},
            },
            "advance": True,
            "severity": "high",
            "evidence_level": "crash_reproduced",
            "pro_argument": "strong case",
            "counter_argument": "weak counter",
            "tie_breaker": "crash log",
        })
        verdict = schema.to_verdict("hunter-abc")
        assert verdict.advance is True
        assert verdict.finding_id == "hunter-abc"
        assert len(list(verdict.axes.items())) == 4
        assert verdict.axes.real.passed is True
        assert verdict.axes.impactful.boundary_crossed == "user"
        assert verdict.severity_validated == "high"

    def test_partial_pass_clears_severity(self):
        schema = _VerdictSchema.model_validate({
            "axes": {
                "real": {"passed": True, "confidence": "high", "rationale": "confirmed"},
                "triggerable": {"passed": False, "confidence": "low", "rationale": "dead code"},
                "impactful": {"passed": True, "confidence": "high", "rationale": "yes"},
                "general": {"passed": True, "confidence": "medium", "rationale": "yes"},
            },
            "advance": False,
            "severity": "high",
            "evidence_level": "static_corroboration",
        })
        verdict = schema.to_verdict("hunter-abc")
        assert verdict.advance is False
        assert verdict.axes.triggerable.passed is False
        assert verdict.severity_validated is None  # cleared when advance is False

    def test_quick_pass_two_axes_only(self):
        # impactful/general are optional (quick-pass prompt); to_verdict maps
        # only the axes that are present.
        schema = _VerdictSchema.model_validate({
            "axes": {
                "real": {"passed": True, "confidence": "high", "rationale": "yes"},
                "triggerable": {"passed": True, "confidence": "high", "rationale": "yes"},
            },
            "advance": True,
            "severity": "critical",
            "evidence_level": "crash_reproduced",
        })
        verdict = schema.to_verdict("hunter-abc")
        assert verdict.advance is True
        assert {name for name, _ in verdict.axes.items()} == {"real", "triggerable"}
        assert verdict.axes.impactful is None

    def test_schema_rejects_invalid_enums(self):
        # Constrained decoding can't emit these; assert the schema enforces them
        # (so we never have to defensively re-validate downstream).
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            _VerdictSchema.model_validate({
                "axes": {
                    "real": {"passed": True, "confidence": "high", "rationale": "y"},
                    "triggerable": {"passed": True, "confidence": "high", "rationale": "y"},
                },
                "advance": True, "severity": "apocalyptic", "evidence_level": "crash_reproduced",
            })
        with pytest.raises(ValidationError):
            _VerdictSchema.model_validate({
                "axes": {
                    "real": {"passed": True, "confidence": "ultra_high", "rationale": "y"},
                    "triggerable": {"passed": True, "confidence": "high", "rationale": "y"},
                },
                "advance": True, "severity": "high", "evidence_level": "crash_reproduced",
            })


# --- apply_validator_verdict tests -------------------------------------------


class TestApplyValidatorVerdict:
    def test_merges_basic_fields(self):
        finding = _make_finding()
        verdict = _make_verdict()
        apply_validator_verdict(finding, verdict, session_id="sess-v")
        assert finding["verified"] is True
        assert finding["severity_verified"] == "high"
        assert finding["verifier_pro_argument"] == "strong evidence"
        assert finding["verifier_session_id"] == "sess-v"
        assert finding["validation_mode"] == "v2"

    def test_evidence_only_bumps_up(self):
        finding = _make_finding(evidence_level="root_cause_explained")
        verdict = _make_verdict(evidence_level="crash_reproduced")
        apply_validator_verdict(finding, verdict)
        assert finding.get("evidence_level") == "root_cause_explained"

    def test_evidence_bumps_up_when_higher(self):
        finding = _make_finding(evidence_level="suspicion")
        verdict = _make_verdict(evidence_level="crash_reproduced")
        apply_validator_verdict(finding, verdict)
        assert finding.get("evidence_level") == "crash_reproduced"

    def test_stores_axis_results(self):
        finding = _make_finding()
        verdict = _make_verdict()
        apply_validator_verdict(finding, verdict)
        axes = finding["validator_axes"]
        assert "real" in axes
        assert axes["real"]["passed"] is True
        assert axes["real"]["confidence"] == "high"

    def test_tier_disagreement_detected(self):
        finding = _make_finding(severity="low")
        verdict = _make_verdict(severity_validated="critical")
        apply_validator_verdict(finding, verdict, discoverer_severity="low")
        assert "severity_disagreement" in finding
        assert "delta=3" in finding["severity_disagreement"]

    def test_tier_disagreement_not_set_below_threshold(self):
        finding = _make_finding(severity="high")
        verdict = _make_verdict(severity_validated="medium")
        apply_validator_verdict(finding, verdict, discoverer_severity="high")
        assert "severity_disagreement" not in finding


# --- Patch oracle integration ------------------------------------------------


class TestPatchOracle:
    def test_patch_oracle_passed_bumps_evidence(self):
        finding = _make_finding(evidence_level="crash_reproduced")
        verdict = _make_verdict(
            patch_oracle_attempted=True,
            patch_oracle_passed=True,
        )
        apply_validator_verdict(finding, verdict)
        assert finding.get("evidence_level") == "root_cause_explained"
        assert finding.get("patch_oracle_passed") is True

    def test_patch_oracle_failed_no_downgrade(self):
        finding = _make_finding(evidence_level="root_cause_explained")
        verdict = _make_verdict(
            evidence_level="crash_reproduced",
            patch_oracle_attempted=True,
            patch_oracle_passed=False,
        )
        apply_validator_verdict(finding, verdict)
        assert finding.get("evidence_level") == "root_cause_explained"


# --- Rejected finding archival ------------------------------------------------


class TestRejectedFindings:
    def test_rejected_finding_gets_rejected_axes(self):
        finding = _make_finding()
        verdict = _make_verdict(
            advance=False,
            axes=Axes(
                real=AxisResult(passed=True, confidence="high", rationale="yes"),
                triggerable=AxisResult(passed=False, confidence="low", rationale="dead code"),
                impactful=AxisResult(passed=True, confidence="high", rationale="yes"),
                general=AxisResult(passed=False, confidence="low", rationale="exotic config"),
            ),
        )
        apply_validator_verdict(finding, verdict)
        assert finding["verified"] is False
        assert set(finding["rejected_axes"]) == {"triggerable", "general"}

    def test_rejected_finding_severity_cleared(self):
        schema = _VerdictSchema.model_validate({
            "axes": {
                "real": {"passed": False, "confidence": "high", "rationale": "not real"},
                "triggerable": {"passed": False, "confidence": "low", "rationale": "n/a"},
            },
            "advance": False,
            "severity": "high",
            "evidence_level": "static_corroboration",
        })
        verdict = schema.to_verdict("hunter-abc")
        assert verdict.severity_validated is None


# --- Calibration tests --------------------------------------------------------


class TestCalibration:
    def test_calibration_record_defaults(self):
        r = CalibrationRecord(
            finding_id="x", session_id="s", cwe="CWE-787",
            discoverer_severity="high",
        )
        assert r.validator_severity is None
        assert r.human_severity is None
        assert r.exact_match is None
        assert r.within_one is None

    def test_calibration_store_append_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cal.jsonl"
            store = CalibrationStore(path)
            store.append(CalibrationRecord(
                finding_id="f1", session_id="s1", cwe="CWE-787",
                discoverer_severity="high", validator_severity="high",
            ))
            store.append(CalibrationRecord(
                finding_id="f2", session_id="s1", cwe="CWE-416",
                discoverer_severity="critical", validator_severity="high",
            ))
            records = store.load_all()
            assert len(records) == 2
            assert records[0].finding_id == "f1"

    def test_calibration_record_human_verdict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cal.jsonl"
            store = CalibrationStore(path)
            store.append(CalibrationRecord(
                finding_id="f1", session_id="s1", cwe="CWE-787",
                discoverer_severity="high", validator_severity="high",
            ))
            store.record_human_verdict("f1", "s1", "high")
            records = store.load_all()
            assert records[0].human_severity == "high"
            assert records[0].exact_match is True
            assert records[0].within_one is True

    def test_calibration_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cal.jsonl"
            store = CalibrationStore(path)
            store.append(CalibrationRecord(
                finding_id="f1", session_id="s1", cwe="CWE-787",
                discoverer_severity="high", validator_severity="high",
            ))
            store.append(CalibrationRecord(
                finding_id="f2", session_id="s1", cwe="CWE-416",
                discoverer_severity="critical", validator_severity="medium",
            ))
            store.record_human_verdict("f1", "s1", "high")
            store.record_human_verdict("f2", "s1", "critical")
            stats = store.stats()
            assert stats["total_records"] == 2
            assert stats["human_reviewed"] == 2
            assert stats["exact_match_rate"] == 0.5  # f1 matches, f2 doesn't


# --- avalidate integration test -----------------------------------------------


class TestAvalidate:
    @pytest.mark.asyncio
    async def test_avalidate_parses_response(self):
        mock_llm = AsyncMock()
        verdict_json = json.dumps({
            "axes": {
                "real": {"passed": True, "confidence": "high", "rationale": "yes"},
                "triggerable": {"passed": True, "confidence": "medium", "rationale": "likely"},
                "impactful": {"passed": True, "confidence": "high", "rationale": "yes", "boundary_crossed": "privilege"},
                "general": {"passed": True, "confidence": "high", "rationale": "yes"},
            },
            "advance": True,
            "severity": "high",
            "evidence_level": "crash_reproduced",
            "pro_argument": "strong",
            "counter_argument": "weak",
            "tie_breaker": "crash",
        })
        mock_response = MagicMock()
        mock_response.first_text = verdict_json
        mock_llm.aask_text = AsyncMock(return_value=mock_response)

        val = Validator(mock_llm)
        verdict = await val.avalidate(_make_finding())
        assert verdict.advance is True
        assert verdict.severity_validated == "high"
        assert verdict.axes.impactful.boundary_crossed == "privilege"

    @pytest.mark.asyncio
    async def test_avalidate_llm_error_returns_error_verdict(self):
        mock_llm = AsyncMock()
        mock_llm.aask_text = AsyncMock(side_effect=RuntimeError("API down"))

        val = Validator(mock_llm)
        verdict = await val.avalidate(_make_finding())
        assert verdict.advance is False
        assert "validator error" in verdict.tie_breaker


# --- File context tests -------------------------------------------------------


class TestFileContext:
    def test_build_file_context_with_line_ref(self):
        val = Validator(MagicMock())
        f = _make_finding(line_number=10)
        content = "\n".join(f"line {i}" for i in range(1, 100))
        ctx = val._build_file_context(f, content)
        assert "line 10" in ctx

    def test_build_file_context_fallback_on_empty_refs(self):
        val = Validator(MagicMock())
        f = _make_finding()
        f.pop("line_number", None)
        content = "first line\nsecond line\nthird line"
        ctx = val._build_file_context(f, content)
        assert "first line" in ctx

    def test_build_file_context_empty_content(self):
        val = Validator(MagicMock())
        f = _make_finding()
        ctx = val._build_file_context(f, "")
        assert ctx == ""


# --- Runner integration -------------------------------------------------------


class TestRunnerIntegration:
    def test_validator_mode_v2_default(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner
        r = SourceHuntRunner(repo_url="test", depth="standard")
        assert r.validator_mode == "v2"

    def test_validator_mode_v1_legacy(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner
        r = SourceHuntRunner(
            repo_url="test", depth="standard", validator_mode="v1",
        )
        assert r.validator_mode == "v1"

    def test_calibration_store_created_by_default(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner
        r = SourceHuntRunner(repo_url="test", depth="standard")
        assert r._calibration_store is not None

    def test_calibration_disabled(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner
        r = SourceHuntRunner(
            repo_url="test", depth="standard", enable_calibration=False,
        )
        assert r._calibration_store is None
