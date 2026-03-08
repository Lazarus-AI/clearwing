from __future__ import annotations

"""Tests for the CVSS v3.1 scoring and finding deduplication modules."""

import pytest

from vulnexploit.scoring import CVSSVector, CVSSCalculator, VULN_PRESETS, Finding, FindingDeduplicator


# ---------------------------------------------------------------------------
# CVSSVector tests
# ---------------------------------------------------------------------------

class TestCVSSVector:
    def test_to_string_format(self):
        v = CVSSVector()
        result = v.to_string()
        assert result.startswith("CVSS:3.1/")
        assert "AV:N" in result
        assert "AC:L" in result
        assert "PR:N" in result
        assert "UI:N" in result
        assert "S:U" in result
        assert "C:H" in result
        assert "I:H" in result
        assert "A:H" in result

    def test_to_string_full(self):
        v = CVSSVector(
            attack_vector="A",
            attack_complexity="H",
            privileges_required="L",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="N",
            availability="H",
        )
        expected = "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H"
        assert v.to_string() == expected

    def test_from_string_round_trip(self):
        original = CVSSVector(
            attack_vector="L",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        )
        vector_str = original.to_string()
        parsed = CVSSVector.from_string(vector_str)
        assert parsed == original
        assert parsed.to_string() == vector_str

    def test_from_string_parses_v30_prefix(self):
        vs = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v = CVSSVector.from_string(vs)
        assert v.attack_vector == "N"
        assert v.scope == "U"
        assert v.confidentiality == "H"


# ---------------------------------------------------------------------------
# CVSSCalculator tests
# ---------------------------------------------------------------------------

class TestCVSSCalculator:
    @pytest.fixture
    def calc(self):
        return CVSSCalculator()

    def test_rce_network_score_is_10(self, calc):
        """RCE network (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) should be 10.0."""
        vector = CVSSVector(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H",
        )
        assert calc.calculate(vector) == 10.0

    def test_xss_reflected_score(self, calc):
        """XSS reflected should score around 6.1."""
        vector = VULN_PRESETS["xss_reflected"]
        score = calc.calculate(vector)
        assert score == 6.1

    def test_info_disclosure_score(self, calc):
        """info_disclosure should score around 5.3."""
        vector = VULN_PRESETS["info_disclosure"]
        score = calc.calculate(vector)
        assert score == 5.3

    def test_zero_impact_returns_zero(self, calc):
        """C:N/I:N/A:N should yield 0.0."""
        vector = CVSSVector(
            confidentiality="N", integrity="N", availability="N",
        )
        assert calc.calculate(vector) == 0.0

    # --- severity_rating boundaries ---

    def test_severity_none(self, calc):
        assert calc.severity_rating(0.0) == "none"

    def test_severity_low_lower_bound(self, calc):
        assert calc.severity_rating(0.1) == "low"

    def test_severity_low_upper_bound(self, calc):
        assert calc.severity_rating(3.9) == "low"

    def test_severity_medium_lower_bound(self, calc):
        assert calc.severity_rating(4.0) == "medium"

    def test_severity_medium_upper_bound(self, calc):
        assert calc.severity_rating(6.9) == "medium"

    def test_severity_high_lower_bound(self, calc):
        assert calc.severity_rating(7.0) == "high"

    def test_severity_high_upper_bound(self, calc):
        assert calc.severity_rating(8.9) == "high"

    def test_severity_critical_lower_bound(self, calc):
        assert calc.severity_rating(9.0) == "critical"

    def test_severity_critical_upper_bound(self, calc):
        assert calc.severity_rating(10.0) == "critical"

    # --- score_from_string ---

    def test_score_from_string_returns_tuple(self, calc):
        result = calc.score_from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert isinstance(result, tuple)
        assert len(result) == 2
        score, severity = result
        assert score == 10.0
        assert severity == "critical"


# ---------------------------------------------------------------------------
# VULN_PRESETS tests
# ---------------------------------------------------------------------------

class TestVulnPresets:
    def test_expected_keys(self):
        expected_keys = {
            "rce_network", "rce_authenticated", "sqli", "xss_reflected",
            "xss_stored", "ssrf", "path_traversal", "info_disclosure", "dos",
        }
        assert expected_keys == set(VULN_PRESETS.keys())

    def test_rce_network_preset_scores_10(self):
        calc = CVSSCalculator()
        assert calc.calculate(VULN_PRESETS["rce_network"]) == 10.0


# ---------------------------------------------------------------------------
# Finding dataclass tests
# ---------------------------------------------------------------------------

class TestFinding:
    def test_defaults(self):
        f = Finding(id="F-1", title="Test", description="desc", severity="high")
        assert f.cvss_score == 0.0
        assert f.cvss_vector == ""
        assert f.cve == ""
        assert f.target == ""
        assert f.port == 0
        assert f.service == ""
        assert f.evidence == ""
        assert f.remediation == ""
        assert f.duplicate_of is None
        assert f.confidence == 1.0


# ---------------------------------------------------------------------------
# FindingDeduplicator tests
# ---------------------------------------------------------------------------

class TestFindingDeduplicator:
    @pytest.fixture
    def dedup(self):
        return FindingDeduplicator()

    def test_empty_findings(self, dedup):
        assert dedup.deduplicate([]) == []

    def test_removes_exact_cve_duplicates(self, dedup):
        f1 = Finding(id="1", title="SQL Injection", description="d", severity="high",
                     cve="CVE-2023-1234", target="10.0.0.1", port=80)
        f2 = Finding(id="2", title="SQLi variant", description="d", severity="high",
                     cve="CVE-2023-1234", target="10.0.0.2", port=443)
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0].id == "1"
        assert f2.duplicate_of == "1"

    def test_removes_signature_duplicates(self, dedup):
        f1 = Finding(id="1", title="SQL Injection", description="d", severity="high",
                     target="10.0.0.1", port=80)
        f2 = Finding(id="2", title="SQL Injection", description="d2", severity="high",
                     target="10.0.0.1", port=80)
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0].id == "1"
        assert f2.duplicate_of == "1"

    def test_removes_similar_titles_fuzzy(self, dedup):
        f1 = Finding(id="1", title="SQL Injection vulnerability in login",
                     description="d", severity="high", target="10.0.0.1", port=80)
        f2 = Finding(id="2", title="SQL Injection vulnerability in login page",
                     description="d2", severity="high", target="10.0.0.1", port=80)
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 1
        assert f2.duplicate_of == "1"

    def test_keeps_different_findings(self, dedup):
        f1 = Finding(id="1", title="SQL Injection", description="d", severity="high",
                     target="10.0.0.1", port=80)
        f2 = Finding(id="2", title="Cross-Site Scripting", description="d", severity="medium",
                     target="10.0.0.1", port=443)
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 2

    def test_sorts_by_severity(self, dedup):
        findings = [
            Finding(id="1", title="Info leak", description="d", severity="info",
                    target="a", port=1),
            Finding(id="2", title="RCE", description="d", severity="critical",
                    target="b", port=2),
            Finding(id="3", title="SQLi", description="d", severity="high",
                    target="c", port=3),
            Finding(id="4", title="XSS", description="d", severity="medium",
                    target="d", port=4),
            Finding(id="5", title="Weak cipher", description="d", severity="low",
                    target="e", port=5),
        ]
        result = dedup.deduplicate(findings)
        severities = [f.severity for f in result]
        assert severities == ["critical", "high", "medium", "low", "info"]

    def test_merge_findings_combines_and_deduplicates(self, dedup):
        group1 = [
            Finding(id="1", title="SQL Injection", description="d", severity="high",
                    cve="CVE-2023-1234", target="10.0.0.1", port=80),
        ]
        group2 = [
            Finding(id="2", title="SQLi variant", description="d", severity="high",
                    cve="CVE-2023-1234", target="10.0.0.2", port=443),
            Finding(id="3", title="XSS", description="d", severity="medium",
                    target="10.0.0.1", port=80),
        ]
        result = dedup.merge_findings([group1, group2])
        assert len(result) == 2
        ids = {f.id for f in result}
        assert "1" in ids
        assert "3" in ids

    def test_is_similar_false_for_different_targets(self, dedup):
        a = Finding(id="1", title="SQL Injection vulnerability",
                    description="d", severity="high", target="10.0.0.1", port=80)
        b = Finding(id="2", title="SQL Injection vulnerability",
                    description="d", severity="high", target="10.0.0.2", port=80)
        assert dedup._is_similar(a, b) is False

    def test_is_similar_false_for_different_ports(self, dedup):
        a = Finding(id="1", title="SQL Injection vulnerability",
                    description="d", severity="high", target="10.0.0.1", port=80)
        b = Finding(id="2", title="SQL Injection vulnerability",
                    description="d", severity="high", target="10.0.0.1", port=443)
        assert dedup._is_similar(a, b) is False
