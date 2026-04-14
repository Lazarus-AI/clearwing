"""Tests for the R4 unified Finding type.

The core contract: round-trip conversion from any legacy shape → Finding →
back to the same shape preserves every field that shape cares about.
"""
from __future__ import annotations

import pytest

from clearwing.findings import (
    Finding,
    from_analysis_finding,
    from_cicd_dict,
    from_source_dict,
    to_cicd_dict,
    to_source_dict,
)
from clearwing.findings.types import _coerce_severity


# --- Finding dataclass ------------------------------------------------------


class TestFindingDataclass:
    def test_default_construction(self):
        f = Finding()
        assert f.id == ""
        assert f.severity == "info"
        assert f.evidence_level == "suspicion"
        assert f.verified is False
        assert f.extra == {}

    def test_effective_severity_uses_verified_when_set(self):
        f = Finding(severity="high", severity_verified="critical")
        assert f.effective_severity == "critical"

    def test_effective_severity_falls_back_to_severity(self):
        f = Finding(severity="medium")
        assert f.effective_severity == "medium"

    def test_is_source_finding(self):
        assert Finding(file="src/foo.c").is_source_finding
        assert not Finding(target="10.0.0.1").is_source_finding

    def test_is_network_finding(self):
        assert Finding(target="10.0.0.1").is_network_finding
        # A finding with both file and target is a source finding
        assert not Finding(target="10.0.0.1", file="src/foo.c").is_network_finding

    def test_is_strong_evidence(self):
        assert not Finding(evidence_level="suspicion").is_strong_evidence
        assert not Finding(evidence_level="static_corroboration").is_strong_evidence
        assert Finding(evidence_level="crash_reproduced").is_strong_evidence
        assert Finding(evidence_level="patch_validated").is_strong_evidence

    def test_is_validated_patch(self):
        assert Finding(auto_patch="x", auto_patch_validated=True).is_validated_patch
        assert not Finding(auto_patch="x", auto_patch_validated=False).is_validated_patch
        assert not Finding().is_validated_patch


# --- Severity coercion ------------------------------------------------------


class TestCoerceSeverity:
    def test_canonical_values(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert _coerce_severity(sev) == sev

    def test_uppercase(self):
        assert _coerce_severity("HIGH") == "high"

    def test_semgrep_error_maps_to_high(self):
        assert _coerce_severity("error") == "high"

    def test_semgrep_warning_maps_to_medium(self):
        assert _coerce_severity("warning") == "medium"

    def test_note_maps_to_low(self):
        assert _coerce_severity("note") == "low"

    def test_empty_maps_to_info(self):
        assert _coerce_severity("") == "info"
        assert _coerce_severity(None) == "info"

    def test_unknown_maps_to_info(self):
        assert _coerce_severity("apocalyptic") == "info"


# --- from_source_dict / to_source_dict round-trip --------------------------


class TestSourceDictRoundtrip:
    def _full_source_dict(self) -> dict:
        return {
            "id": "hunter-abc",
            "file": "src/codec.c",
            "line_number": 47,
            "end_line": None,
            "finding_type": "memory_safety",
            "cwe": "CWE-787",
            "severity": "critical",
            "confidence": "high",
            "description": "memcpy overflow",
            "code_snippet": "memcpy(buf, input, user_len);",
            "crash_evidence": "ASan: heap-buffer-overflow",
            "poc": "AAAA",
            "evidence_level": "crash_reproduced",
            "discovered_by": "hunter:memory_safety",
            "related_finding_id": None,
            "related_cve": None,
            "seeded_from_crash": False,
            "verified": True,
            "severity_verified": "critical",
            "verifier_pro_argument": "strong",
            "verifier_counter_argument": "weak",
            "verifier_tie_breaker": "evidence A",
            "patch_oracle_passed": None,
            "auto_patch": None,
            "auto_patch_validated": None,
            "exploit": None,
            "exploit_success": None,
            "hunter_session_id": "sess-1",
            "verifier_session_id": "verif-1",
        }

    def test_roundtrip_preserves_all_fields(self):
        d = self._full_source_dict()
        f = from_source_dict(d)
        assert f.id == "hunter-abc"
        assert f.file == "src/codec.c"
        assert f.severity == "critical"
        assert f.evidence_level == "crash_reproduced"
        assert f.verified is True

        back = to_source_dict(f)
        for key in d:
            assert back[key] == d[key], f"field {key!r} did not round-trip"

    def test_extra_keys_preserved_in_extra_field(self):
        d = self._full_source_dict()
        d["custom_v04_field"] = "preserved"
        f = from_source_dict(d)
        assert f.extra["custom_v04_field"] == "preserved"
        back = to_source_dict(f)
        assert back["custom_v04_field"] == "preserved"

    def test_empty_string_optional_fields_become_none(self):
        d = {
            "id": "x",
            "file": "",               # empty → None after normalization
            "crash_evidence": "",     # empty → None
            "severity_verified": "",  # empty → None
        }
        f = from_source_dict(d)
        assert f.file is None
        assert f.crash_evidence is None
        assert f.severity_verified is None

    def test_minimal_source_dict(self):
        """A bare-minimum dict still produces a valid Finding."""
        f = from_source_dict({"id": "x", "severity": "low"})
        assert f.id == "x"
        assert f.severity == "low"
        # Defaults fill in
        assert f.evidence_level == "suspicion"
        assert f.verified is False


# --- from_cicd_dict / to_cicd_dict round-trip ------------------------------


class TestCicdDictRoundtrip:
    def test_basic_cicd_finding(self):
        d = {
            "description": "Open port 22",
            "severity": "low",
            "cve": None,
            "details": "SSH banner: OpenSSH 8.2",
        }
        f = from_cicd_dict(d, target="10.0.0.1")
        assert f.description == "Open port 22"
        assert f.severity == "low"
        assert f.target == "10.0.0.1"
        assert f.discovered_by == "network_scanner"
        # Network findings start at static_corroboration (a scanner hit)
        assert f.evidence_level == "static_corroboration"

    def test_cicd_with_cve(self):
        d = {
            "description": "Apache mod_rewrite RCE",
            "severity": "critical",
            "cve": "CVE-2021-44790",
            "details": "CVSS 9.8",
        }
        f = from_cicd_dict(d, target="app.example.com")
        assert f.cve == "CVE-2021-44790"
        assert f.cwe == "CVE-2021-44790"   # CWE falls back to CVE for CICD
        assert f.severity == "critical"

    def test_cicd_to_dict_roundtrip(self):
        d = {
            "description": "Dirlisting enabled",
            "severity": "medium",
            "cve": None,
            "details": "",
        }
        f = from_cicd_dict(d, target="web.example.com")
        back = to_cicd_dict(f)
        assert back["description"] == "Dirlisting enabled"
        assert back["severity"] == "medium"
        assert back["details"] == ""

    def test_to_cicd_uses_verified_severity(self):
        f = Finding(severity="low", severity_verified="critical", description="x")
        d = to_cicd_dict(f)
        assert d["severity"] == "critical"

    def test_to_cicd_includes_file_and_line_when_present(self):
        """Source-hunt findings cast to CICD shape should preserve file info
        so the file-aware SARIF generator works on them."""
        f = Finding(
            id="f",
            description="memcpy overflow",
            severity="critical",
            file="src/codec.c",
            line_number=47,
            cwe="CWE-787",
        )
        d = to_cicd_dict(f)
        assert d["file"] == "src/codec.c"
        assert d["line_number"] == 47


# --- from_analysis_finding -------------------------------------------------


class TestFromAnalysisFinding:
    def test_from_dataclass_instance(self):
        """The SourceAnalyzer dataclass should convert cleanly."""
        from clearwing.analysis.source_analyzer import Finding as AnalysisFinding
        af = AnalysisFinding(
            file_path="app.py",
            line_number=23,
            finding_type="sql_injection",
            severity="critical",
            description="f-string SQL",
            code_snippet="cursor.execute(f\"...\")",
            cwe="CWE-89",
            confidence="high",
        )
        f = from_analysis_finding(af)
        assert f.file == "app.py"
        assert f.line_number == 23
        assert f.severity == "critical"
        assert f.cwe == "CWE-89"
        assert f.confidence == "high"
        assert f.discovered_by == "source_analyzer"
        assert f.evidence_level == "static_corroboration"
        assert f.id.startswith("static-")

    def test_from_dict(self):
        d = {
            "file_path": "x.py",
            "line_number": 5,
            "finding_type": "xss",
            "severity": "medium",
            "description": "innerHTML",
            "code_snippet": "el.innerHTML = x",
            "cwe": "CWE-79",
            "confidence": "medium",
        }
        f = from_analysis_finding(d)
        assert f.file == "x.py"
        assert f.severity == "medium"
        assert f.cwe == "CWE-79"

    def test_invalid_type_raises(self):
        with pytest.raises(TypeError, match="unsupported"):
            from_analysis_finding("not a finding")


# --- Cross-shape conversions -----------------------------------------------


class TestCrossShapeConversions:
    """Exercise the 'one Finding, many consumers' claim."""

    def test_cicd_finding_as_finding_is_not_source(self):
        d = {"description": "open port", "severity": "low", "cve": None, "details": ""}
        f = from_cicd_dict(d, target="10.0.0.1")
        assert f.is_network_finding
        assert not f.is_source_finding

    def test_source_finding_as_finding_is_source(self):
        d = {
            "id": "x", "file": "a.c", "line_number": 10,
            "severity": "high", "description": "bug",
        }
        f = from_source_dict(d)
        assert f.is_source_finding
        assert not f.is_network_finding

    def test_finding_can_be_passed_to_both_report_pipelines(self):
        """A unified Finding roundtrips through BOTH shapes without losing info."""
        f = Finding(
            id="x", file="src/codec.c", line_number=47,
            severity="critical", description="bug",
            cwe="CWE-787",
            evidence_level="root_cause_explained",
            verified=True,
        )
        source_dict = to_source_dict(f)
        cicd_dict = to_cicd_dict(f)
        # Source dict has all the source-hunt fields
        assert source_dict["file"] == "src/codec.c"
        assert source_dict["evidence_level"] == "root_cause_explained"
        assert source_dict["verified"] is True
        # CICD dict has the legacy fields plus file/line for SARIF
        assert cicd_dict["description"] == "bug"
        assert cicd_dict["file"] == "src/codec.c"
        assert cicd_dict["line_number"] == 47
