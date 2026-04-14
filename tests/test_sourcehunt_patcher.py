"""Tests for the v0.3 Auto-Patch mode."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from vulnexploit.sourcehunt.patcher import (
    AutoPatcher,
    PatchAttempt,
    apply_patch_attempt,
)


def _mock_llm(payload: dict) -> MagicMock:
    llm = MagicMock()
    response = MagicMock()
    response.content = json.dumps(payload)
    llm.invoke.return_value = response
    return llm


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "f1",
        "file": "src/codec.c",
        "line_number": 47,
        "cwe": "CWE-787",
        "severity": "critical",
        "verified": True,
        "evidence_level": "root_cause_explained",
        "description": "memcpy overflow",
        "code_snippet": "memcpy(buf, input, len);",
        "crash_evidence": "ASan: heap-buffer-overflow",
    }
    base.update(kwargs)
    return base


# --- Eligibility gate ------------------------------------------------------


class TestEligibility:
    def test_eligible_critical_with_root_cause(self):
        patcher = AutoPatcher(MagicMock())
        assert patcher.is_eligible(_make_finding())

    def test_eligible_high_with_root_cause(self):
        patcher = AutoPatcher(MagicMock())
        assert patcher.is_eligible(_make_finding(severity="high"))

    def test_unverified_not_eligible(self):
        patcher = AutoPatcher(MagicMock())
        assert not patcher.is_eligible(_make_finding(verified=False))

    def test_medium_not_eligible(self):
        patcher = AutoPatcher(MagicMock())
        assert not patcher.is_eligible(_make_finding(severity="medium"))

    def test_crash_reproduced_not_enough(self):
        patcher = AutoPatcher(MagicMock())
        assert not patcher.is_eligible(_make_finding(evidence_level="crash_reproduced"))

    def test_exploit_demonstrated_eligible(self):
        patcher = AutoPatcher(MagicMock())
        assert patcher.is_eligible(_make_finding(evidence_level="exploit_demonstrated"))


# --- LLM path --------------------------------------------------------------


class TestAttemptLLMPath:
    def test_basic_llm_response_parsed(self):
        llm = _mock_llm({
            "diff": "-memcpy(buf, input, len);\n+memcpy(buf, input, min(len, sizeof(buf)));",
            "commit_message": "cap memcpy length at buffer size",
            "explanation": "avoids heap overflow when len > sizeof(buf)",
            "confidence": "high",
        })
        patcher = AutoPatcher(llm)
        attempt = patcher.attempt(_make_finding(), file_content="int f() {}")
        assert attempt.attempted is True
        assert attempt.validated is False   # no sandbox → not validated
        assert "min(len" in attempt.diff
        assert attempt.commit_message == "cap memcpy length at buffer size"
        assert attempt.confidence == "high"
        assert "llm-only" in attempt.notes

    def test_invalid_json_returns_unvalidated(self):
        llm = MagicMock()
        resp = MagicMock()
        resp.content = "I cannot help with this"
        llm.invoke.return_value = resp
        patcher = AutoPatcher(llm)
        attempt = patcher.attempt(_make_finding())
        assert attempt.attempted is True
        assert attempt.validated is False
        assert "no JSON" in attempt.notes

    def test_llm_exception_returns_error_attempt(self):
        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        patcher = AutoPatcher(llm)
        attempt = patcher.attempt(_make_finding())
        assert attempt.attempted is True
        assert attempt.validated is False
        assert "rate limited" in attempt.notes

    def test_ineligible_not_attempted(self):
        llm = MagicMock()
        patcher = AutoPatcher(llm)
        attempt = patcher.attempt(_make_finding(verified=False))
        assert attempt.attempted is False
        assert "Skipped" in attempt.notes
        # LLM was not called
        assert llm.invoke.call_count == 0


# --- Sandbox validation path -----------------------------------------------


class TestAttemptSandboxPath:
    def test_validated_when_crash_gone(self):
        llm = _mock_llm({
            "diff": "# fix",
            "commit_message": "fix",
            "explanation": "ok",
            "confidence": "high",
        })
        patcher = AutoPatcher(llm)
        fake_sandbox = MagicMock()
        fake_sandbox.write_file = MagicMock()
        attempt = patcher.attempt(
            _make_finding(),
            file_content="",
            sandbox=fake_sandbox,
            rerun_poc=lambda sb, f: False,   # crash gone
        )
        assert attempt.validated is True
        assert "validated" in attempt.notes

    def test_rejected_when_crash_survives(self):
        llm = _mock_llm({
            "diff": "# bad fix",
            "commit_message": "fix",
            "explanation": "ok",
            "confidence": "high",
        })
        patcher = AutoPatcher(llm)
        fake_sandbox = MagicMock()
        fake_sandbox.write_file = MagicMock()
        attempt = patcher.attempt(
            _make_finding(),
            file_content="",
            sandbox=fake_sandbox,
            rerun_poc=lambda sb, f: True,   # crash still happens
        )
        assert attempt.validated is False
        assert "rejected" in attempt.notes
        assert "crash reproduces" in attempt.notes

    def test_validation_error(self):
        llm = _mock_llm({
            "diff": "# fix",
            "commit_message": "fix",
            "explanation": "ok",
            "confidence": "high",
        })
        patcher = AutoPatcher(llm)
        fake_sandbox = MagicMock()
        fake_sandbox.write_file = MagicMock()

        def boom(sb, f):
            raise RuntimeError("sandbox exploded")

        attempt = patcher.attempt(
            _make_finding(),
            file_content="",
            sandbox=fake_sandbox,
            rerun_poc=boom,
        )
        assert attempt.validated is False
        assert "validation error" in attempt.notes


# --- apply_patch_attempt ---------------------------------------------------


class TestApplyPatchAttempt:
    def test_validated_patch_bumps_evidence_to_gold(self):
        finding = _make_finding(evidence_level="exploit_demonstrated")
        attempt = PatchAttempt(
            finding_id="x", attempted=True, validated=True,
            diff="# fix", commit_message="fix", explanation="",
            confidence="high", notes="",
        )
        apply_patch_attempt(finding, attempt)
        assert finding["auto_patch"] == "# fix"
        assert finding["auto_patch_validated"] is True
        assert finding["evidence_level"] == "patch_validated"

    def test_unvalidated_patch_records_but_does_not_bump(self):
        finding = _make_finding(evidence_level="root_cause_explained")
        attempt = PatchAttempt(
            finding_id="x", attempted=True, validated=False,
            diff="# attempted", commit_message="attempt", explanation="",
            confidence="medium", notes="llm-only",
        )
        apply_patch_attempt(finding, attempt)
        assert finding["auto_patch"] == "# attempted"
        assert finding["auto_patch_validated"] is False
        assert finding["evidence_level"] == "root_cause_explained"   # unchanged

    def test_ineligible_attempt_leaves_fields_none(self):
        finding = _make_finding()
        attempt = PatchAttempt(
            finding_id="x", attempted=False, validated=False,
            diff="", commit_message="", explanation="",
            confidence="low", notes="skipped",
        )
        apply_patch_attempt(finding, attempt)
        assert finding.get("auto_patch") is None
        assert finding.get("auto_patch_validated") is None
