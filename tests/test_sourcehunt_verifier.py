"""Unit tests for the sourcehunt verifier.

Critical assertions:
- Independent context — verifier message NEVER contains hunter reasoning
- v0.1 prompt is non-adversarial; v0.2 flag flips to adversarial
- Output schema includes pro_argument / counter_argument / tie_breaker_evidence
  (counter_argument is empty in v0.1)
- evidence_level is set to crash_reproduced or root_cause_explained on success
- apply_verifier_result merges the verdict into the SourceFinding
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from vulnexploit.sourcehunt.verifier import (
    VERIFIER_SYSTEM_PROMPT_V01,
    VERIFIER_SYSTEM_PROMPT_V02,
    Verifier,
    VerifierResult,
    apply_verifier_result,
)


def _mock_llm_returning_json(payload: dict) -> MagicMock:
    mock = MagicMock()
    response = MagicMock()
    response.content = json.dumps(payload)
    mock.invoke.return_value = response
    return mock


def _mock_llm_raw(content: str) -> MagicMock:
    mock = MagicMock()
    response = MagicMock()
    response.content = content
    mock.invoke.return_value = response
    return mock


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "finding_type": "memory_safety",
        "cwe": "CWE-787",
        "severity": "critical",
        "description": "memcpy with unchecked length",
        "code_snippet": "memcpy(frame, input, input_len);",
        "evidence_level": "static_corroboration",
        "discovered_by": "hunter:general",
    }
    base.update(kwargs)
    return base


# --- v0.1 / v0.2 prompt selection -------------------------------------------


class TestVerifierPromptSelection:
    def test_v01_default_non_adversarial(self):
        v = Verifier(MagicMock())
        assert v._system_prompt is VERIFIER_SYSTEM_PROMPT_V01
        assert v.adversarial is False

    def test_v02_flag_flips_to_adversarial(self):
        v = Verifier(MagicMock(), adversarial=True)
        assert v._system_prompt is VERIFIER_SYSTEM_PROMPT_V02
        assert v.adversarial is True

    def test_v01_prompt_is_simpler(self):
        # v0.1 doesn't require steel-manning; v0.2 does
        assert "STEEL-MAN" not in VERIFIER_SYSTEM_PROMPT_V01
        assert "STEEL-MAN" in VERIFIER_SYSTEM_PROMPT_V02

    def test_both_prompts_request_json(self):
        assert "JSON" in VERIFIER_SYSTEM_PROMPT_V01
        assert "JSON" in VERIFIER_SYSTEM_PROMPT_V02


# --- Independent context guarantee ------------------------------------------


class TestAdversarialBudgetGate:
    """v0.4: the verifier only spends adversarial budget on findings with
    evidence_level >= static_corroboration (default threshold)."""

    def test_suspicion_falls_back_to_v01(self):
        """A suspicion-level finding gets the cheap non-adversarial prompt."""
        llm = _mock_llm_returning_json({
            "is_real": False, "severity": "low",
            "evidence_level": "suspicion",
            "pro_argument": "p", "counter_argument": "",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True)   # default threshold = static_corroboration
        v.verify(_make_finding(evidence_level="suspicion"))
        system_msg = llm.invoke.call_args[0][0][0]
        # Below the gate → V01 (no STEEL-MAN wording)
        assert "STEEL-MAN" not in system_msg.content

    def test_static_corroboration_uses_v02(self):
        """Exactly at the threshold → adversarial prompt."""
        llm = _mock_llm_returning_json({
            "is_real": True, "severity": "high",
            "evidence_level": "root_cause_explained",
            "pro_argument": "p", "counter_argument": "c",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True)
        v.verify(_make_finding(evidence_level="static_corroboration"))
        system_msg = llm.invoke.call_args[0][0][0]
        assert "STEEL-MAN" in system_msg.content

    def test_crash_reproduced_uses_v02(self):
        llm = _mock_llm_returning_json({
            "is_real": True, "severity": "critical",
            "evidence_level": "root_cause_explained",
            "pro_argument": "p", "counter_argument": "c",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True)
        v.verify(_make_finding(evidence_level="crash_reproduced"))
        system_msg = llm.invoke.call_args[0][0][0]
        assert "STEEL-MAN" in system_msg.content

    def test_custom_threshold_crash_reproduced(self):
        """A caller can set a stricter threshold — e.g. only spend adversarial
        budget when there's an actual sanitizer crash."""
        llm = _mock_llm_returning_json({
            "is_real": False, "severity": "low",
            "evidence_level": "static_corroboration",
            "pro_argument": "p", "counter_argument": "",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True, adversarial_threshold="crash_reproduced")
        v.verify(_make_finding(evidence_level="static_corroboration"))
        system_msg = llm.invoke.call_args[0][0][0]
        # static_corroboration < crash_reproduced → V01
        assert "STEEL-MAN" not in system_msg.content

    def test_threshold_none_disables_gate(self):
        """adversarial_threshold=None → adversarial runs on every finding."""
        llm = _mock_llm_returning_json({
            "is_real": False, "severity": "low",
            "evidence_level": "suspicion",
            "pro_argument": "p", "counter_argument": "x",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True, adversarial_threshold=None)
        v.verify(_make_finding(evidence_level="suspicion"))
        system_msg = llm.invoke.call_args[0][0][0]
        assert "STEEL-MAN" in system_msg.content

    def test_gate_does_nothing_when_adversarial_off(self):
        """adversarial=False → V01 for every finding regardless of level."""
        llm = _mock_llm_returning_json({
            "is_real": True, "severity": "high",
            "evidence_level": "patch_validated",
            "pro_argument": "p", "counter_argument": "",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=False)
        v.verify(_make_finding(evidence_level="patch_validated"))
        system_msg = llm.invoke.call_args[0][0][0]
        assert "STEEL-MAN" not in system_msg.content

    def test_missing_evidence_level_falls_back_below_gate(self):
        """A finding without an evidence_level field → suspicion → below gate."""
        llm = _mock_llm_returning_json({
            "is_real": False, "severity": "low",
            "evidence_level": "suspicion",
            "pro_argument": "", "counter_argument": "",
            "tie_breaker": "", "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True)
        finding = {"id": "f", "file": "x.c"}   # no evidence_level
        v.verify(finding)
        system_msg = llm.invoke.call_args[0][0][0]
        assert "STEEL-MAN" not in system_msg.content

    def test_mixed_batch_picks_per_finding(self):
        """Running verify() across a mixed batch picks the right prompt per call."""
        llm = MagicMock()
        # Response doesn't matter — we only care about which prompt was used
        resp = MagicMock()
        resp.content = json.dumps({
            "is_real": True, "severity": "high",
            "evidence_level": "crash_reproduced",
            "pro_argument": "p", "counter_argument": "c",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        llm.invoke.return_value = resp

        v = Verifier(llm, adversarial=True)
        findings = [
            _make_finding(id="low", evidence_level="suspicion"),
            _make_finding(id="med", evidence_level="static_corroboration"),
            _make_finding(id="high", evidence_level="crash_reproduced"),
        ]
        for f in findings:
            v.verify(f)

        assert llm.invoke.call_count == 3
        prompts = [call[0][0][0].content for call in llm.invoke.call_args_list]
        assert "STEEL-MAN" not in prompts[0]   # suspicion
        assert "STEEL-MAN" in prompts[1]       # static_corroboration
        assert "STEEL-MAN" in prompts[2]       # crash_reproduced


class TestIndependentContext:
    """The verifier must NOT see hunter reasoning messages — only the finding."""

    def test_user_message_does_not_contain_hunter_reasoning(self):
        llm = _mock_llm_returning_json({
            "is_real": True, "severity": "critical",
            "evidence_level": "root_cause_explained",
            "pro_argument": "yes", "counter_argument": "no",
            "tie_breaker": "x", "duplicate_cve": None,
        })
        v = Verifier(llm)
        finding = _make_finding()
        v.verify(finding, file_content="int main() {}\n")

        # Inspect what was passed to the LLM
        call_args = llm.invoke.call_args[0][0]
        # Should be exactly two messages: SystemMessage + HumanMessage
        assert len(call_args) == 2
        human_msg = call_args[1].content
        # The hunter's reasoning chain must NOT appear
        assert "hunter" not in human_msg.lower() or "discovered_by" in human_msg
        # But the finding metadata IS present
        assert "memcpy with unchecked length" in human_msg
        assert "src/codec_a.c" in human_msg

    def test_user_message_includes_file_content_when_provided(self):
        llm = _mock_llm_returning_json({
            "is_real": True, "severity": "high",
            "evidence_level": "crash_reproduced",
            "pro_argument": "p", "counter_argument": "",
            "tie_breaker": "t", "duplicate_cve": None,
        })
        v = Verifier(llm)
        finding = _make_finding()
        v.verify(finding, file_content="#include <string.h>\nvoid bug() {}\n")
        human_msg = llm.invoke.call_args[0][0][1].content
        assert "<string.h>" in human_msg

    def test_file_content_is_capped(self):
        llm = _mock_llm_returning_json({
            "is_real": False, "severity": None,
            "evidence_level": "suspicion",
            "pro_argument": "", "counter_argument": "",
            "tie_breaker": "", "duplicate_cve": None,
        })
        v = Verifier(llm)
        finding = _make_finding()
        huge = "x" * 50000
        v.verify(finding, file_content=huge)
        human_msg = llm.invoke.call_args[0][0][1].content
        # File content section is capped to 8KB
        assert "x" * 8001 not in human_msg


# --- Response parsing -------------------------------------------------------


class TestResponseParsing:
    def test_basic_json_response(self):
        llm = _mock_llm_returning_json({
            "is_real": True,
            "severity": "high",
            "evidence_level": "crash_reproduced",
            "pro_argument": "memcpy length is unchecked",
            "counter_argument": "",
            "tie_breaker": "ASan crash on input >64",
            "duplicate_cve": None,
        })
        v = Verifier(llm)
        result = v.verify(_make_finding())
        assert isinstance(result, VerifierResult)
        assert result.is_real is True
        assert result.severity_verified == "high"
        assert result.evidence_level == "crash_reproduced"
        assert "memcpy" in result.pro_argument
        assert result.counter_argument == ""

    def test_v02_response_with_counter_argument(self):
        llm = _mock_llm_returning_json({
            "is_real": False,
            "severity": "low",
            "evidence_level": "static_corroboration",
            "pro_argument": "looks like memcpy bug",
            "counter_argument": "but caller validates length",
            "tie_breaker": "validation in callers/main.c:42",
            "duplicate_cve": None,
        })
        v = Verifier(llm, adversarial=True)
        result = v.verify(_make_finding())
        assert result.is_real is False
        assert result.severity_verified is None  # not_real → None
        assert "validates length" in result.counter_argument
        assert "validation in callers/main.c:42" in result.tie_breaker

    def test_invalid_severity_clamped(self):
        llm = _mock_llm_returning_json({
            "is_real": True,
            "severity": "apocalyptic",  # not a valid level
            "evidence_level": "crash_reproduced",
            "pro_argument": "x", "counter_argument": "", "tie_breaker": "",
            "duplicate_cve": None,
        })
        v = Verifier(llm)
        result = v.verify(_make_finding())
        # Verifier coerces invalid severity to None (caller decides what to do)
        assert result.severity_verified is None

    def test_invalid_evidence_level_falls_back_to_suspicion(self):
        llm = _mock_llm_returning_json({
            "is_real": True,
            "severity": "high",
            "evidence_level": "made_up_level",
            "pro_argument": "x", "counter_argument": "", "tie_breaker": "",
            "duplicate_cve": None,
        })
        v = Verifier(llm)
        result = v.verify(_make_finding())
        assert result.evidence_level == "suspicion"

    def test_no_json_in_response(self):
        llm = _mock_llm_raw("I'm just a chatty model with no JSON")
        v = Verifier(llm)
        result = v.verify(_make_finding())
        assert result.is_real is False
        assert "no JSON" in result.tie_breaker

    def test_invalid_json_in_response(self):
        llm = _mock_llm_raw("{ not valid json }")
        v = Verifier(llm)
        result = v.verify(_make_finding())
        assert result.is_real is False

    def test_llm_exception_returns_error_result(self):
        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        v = Verifier(llm)
        result = v.verify(_make_finding())
        assert result.is_real is False
        assert "rate limited" in result.tie_breaker


# --- apply_verifier_result --------------------------------------------------


class TestPatchOracle:
    """v0.3: the patch oracle is a truth test — write a fix, re-run the PoC."""

    def test_llm_only_high_confidence_passes(self):
        llm = _mock_llm_returning_json({
            "diff": "-memcpy(buf, input, len);\n+memcpy(buf, input, min(len, sizeof(buf)));",
            "fix_description": "cap memcpy length at buffer size",
            "confidence": "high",
        })
        v = Verifier(llm)
        passed, diff, notes = v.run_patch_oracle(
            _make_finding(),
            file_content="int f() { memcpy(buf, input, len); }",
            sandbox=None,
            rerun_poc=None,
        )
        assert passed is True
        assert "memcpy" in diff
        assert "confidence=high" in notes

    def test_llm_only_medium_confidence_does_not_pass(self):
        llm = _mock_llm_returning_json({
            "diff": "# maybe add a guard",
            "fix_description": "not sure",
            "confidence": "medium",
        })
        v = Verifier(llm)
        passed, diff, notes = v.run_patch_oracle(
            _make_finding(),
            file_content="x",
        )
        assert passed is False

    def test_no_json_returns_false(self):
        llm = _mock_llm_raw("I can't write a fix for this")
        v = Verifier(llm)
        passed, diff, notes = v.run_patch_oracle(_make_finding(), file_content="")
        assert passed is False
        assert diff == ""

    def test_llm_exception_returns_false(self):
        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        v = Verifier(llm)
        passed, diff, notes = v.run_patch_oracle(_make_finding(), file_content="")
        assert passed is False
        assert "rate limited" in notes

    def test_sandbox_path_crash_survives(self):
        """When rerun_poc says 'still crashes', the oracle returns False."""
        llm = _mock_llm_returning_json({
            "diff": "# patch",
            "fix_description": "attempted fix",
            "confidence": "high",
        })
        v = Verifier(llm)
        fake_sandbox = MagicMock()
        fake_sandbox.write_file = MagicMock()
        passed, diff, notes = v.run_patch_oracle(
            _make_finding(),
            file_content="x",
            sandbox=fake_sandbox,
            rerun_poc=lambda sb, f: True,   # still crashes
        )
        assert passed is False
        assert "crash survived" in notes

    def test_sandbox_path_crash_gone(self):
        """When rerun_poc says 'crash gone', the oracle returns True."""
        llm = _mock_llm_returning_json({
            "diff": "# patch",
            "fix_description": "correct fix",
            "confidence": "medium",   # even medium confidence passes if crash is gone
        })
        v = Verifier(llm)
        fake_sandbox = MagicMock()
        fake_sandbox.write_file = MagicMock()
        passed, diff, notes = v.run_patch_oracle(
            _make_finding(),
            file_content="x",
            sandbox=fake_sandbox,
            rerun_poc=lambda sb, f: False,  # crash gone
        )
        assert passed is True
        assert "eliminated crash" in notes


class TestApplyPatchOracleResult:
    """apply_verifier_result should record patch oracle outcome and bump evidence."""

    def test_passed_oracle_bumps_evidence_level(self):
        finding = _make_finding(evidence_level="static_corroboration")
        result = VerifierResult(
            finding_id="x", is_real=True, severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
            patch_oracle_attempted=True,
            patch_oracle_passed=True,
            patch_oracle_diff="# fix",
            patch_oracle_notes="eliminated",
        )
        apply_verifier_result(finding, result)
        assert finding["patch_oracle_passed"] is True
        # A passed patch oracle is causal validation → root_cause_explained
        assert finding["evidence_level"] == "root_cause_explained"

    def test_failed_oracle_does_not_downgrade(self):
        finding = _make_finding(evidence_level="crash_reproduced")
        result = VerifierResult(
            finding_id="x", is_real=True, severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
            patch_oracle_attempted=True,
            patch_oracle_passed=False,
            patch_oracle_diff="# failed",
            patch_oracle_notes="crash survived",
        )
        apply_verifier_result(finding, result)
        assert finding["patch_oracle_passed"] is False
        # Evidence level stays at crash_reproduced (not downgraded)
        assert finding["evidence_level"] == "crash_reproduced"

    def test_oracle_not_attempted_leaves_field_none(self):
        finding = _make_finding()
        result = VerifierResult(
            finding_id="x", is_real=True, severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
            # patch_oracle_attempted=False (default)
        )
        apply_verifier_result(finding, result)
        # finding["patch_oracle_passed"] should NOT be set
        assert finding.get("patch_oracle_passed") is None


class TestApplyVerifierResult:
    def test_merges_basic_fields(self):
        finding = _make_finding(evidence_level="static_corroboration")
        result = VerifierResult(
            finding_id="hunter-abc",
            is_real=True,
            severity_verified="critical",
            evidence_level="root_cause_explained",
            pro_argument="strong case",
            counter_argument="weak counter",
            tie_breaker="conclusive",
            duplicate_cve=None,
        )
        merged = apply_verifier_result(finding, result, session_id="verifier-1")
        assert merged["verified"] is True
        assert merged["severity_verified"] == "critical"
        assert merged["verifier_pro_argument"] == "strong case"
        assert merged["verifier_counter_argument"] == "weak counter"
        assert merged["verifier_tie_breaker"] == "conclusive"
        assert merged["verifier_session_id"] == "verifier-1"

    def test_evidence_level_only_bumps_up(self):
        # If finding already has root_cause_explained and verifier returns
        # crash_reproduced (lower), keep root_cause_explained
        finding = _make_finding(evidence_level="root_cause_explained")
        result = VerifierResult(
            finding_id="x", is_real=True, severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        # Did not regress
        assert finding["evidence_level"] == "root_cause_explained"

    def test_evidence_level_bumps_when_verifier_stronger(self):
        finding = _make_finding(evidence_level="static_corroboration")
        result = VerifierResult(
            finding_id="x", is_real=True, severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        assert finding["evidence_level"] == "crash_reproduced"

    def test_not_real_clears_severity_verified(self):
        finding = _make_finding()
        result = VerifierResult(
            finding_id="x", is_real=False, severity_verified=None,
            evidence_level="suspicion",
            pro_argument="", counter_argument="", tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        assert finding["verified"] is False
        assert finding["severity_verified"] is None
