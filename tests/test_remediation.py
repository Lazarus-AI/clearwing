"""Tests for the Remediation Generator module."""

from __future__ import annotations

import pytest

from vulnexploit.remediation import RemediationAdvice, RemediationGenerator, REMEDIATION_DB


# --- RemediationAdvice dataclass ---


class TestRemediationAdvice:
    def test_defaults(self):
        advice = RemediationAdvice(
            vulnerability="Test Vuln",
            severity="low",
            title="Test Title",
            description="Test description.",
            recommendation="Fix it.",
        )
        assert advice.code_fix == ""
        assert advice.config_fix == ""
        assert advice.references == []
        assert advice.effort == "medium"
        assert advice.priority == 0


# --- REMEDIATION_DB ---


class TestRemediationDB:
    EXPECTED_KEYS = [
        "sql_injection",
        "xss",
        "ssrf",
        "path_traversal",
        "command_injection",
        "weak_credentials",
        "outdated_software",
        "missing_headers",
        "open_redirect",
        "xxe",
    ]

    def test_has_expected_keys(self):
        for key in self.EXPECTED_KEYS:
            assert key in REMEDIATION_DB, f"Missing key: {key}"

    def test_entries_have_non_empty_fields(self):
        for key, advice in REMEDIATION_DB.items():
            assert advice.title, f"{key} has empty title"
            assert advice.description, f"{key} has empty description"
            assert advice.recommendation, f"{key} has empty recommendation"

    def test_severity_values_are_valid(self):
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for key, advice in REMEDIATION_DB.items():
            assert advice.severity in valid_severities, (
                f"{key} has invalid severity: {advice.severity}"
            )

    def test_effort_values_are_valid(self):
        valid_efforts = {"low", "medium", "high"}
        for key, advice in REMEDIATION_DB.items():
            assert advice.effort in valid_efforts, (
                f"{key} has invalid effort: {advice.effort}"
            )


# --- RemediationGenerator ---


@pytest.fixture
def generator():
    return RemediationGenerator()


class TestGetAdvice:
    def test_exact_match(self, generator):
        advice = generator.get_advice("sql_injection")
        assert advice is not None
        assert advice.vulnerability == "SQL Injection"

    def test_case_insensitive(self, generator):
        advice = generator.get_advice("SQL_Injection")
        assert advice is not None
        assert advice.vulnerability == "SQL Injection"

    def test_case_insensitive_with_spaces(self, generator):
        advice = generator.get_advice("SQL Injection")
        assert advice is not None
        assert advice.vulnerability == "SQL Injection"

    def test_case_insensitive_with_hyphens(self, generator):
        advice = generator.get_advice("command-injection")
        assert advice is not None
        assert advice.vulnerability == "Command Injection"

    def test_unknown_returns_none(self, generator):
        advice = generator.get_advice("unknown_vulnerability_type")
        assert advice is None


class TestGetAdviceForCve:
    def test_sql_injection_description(self, generator):
        advice = generator.get_advice_for_cve(
            "CVE-2023-1234", "SQL injection in login form"
        )
        assert advice is not None
        assert "SQL Injection" in advice.vulnerability

    def test_xss_description(self, generator):
        advice = generator.get_advice_for_cve(
            "CVE-2023-5678", "Cross-site scripting in search field"
        )
        assert advice is not None
        assert "XSS" in advice.vulnerability

    def test_unknown_returns_none(self, generator):
        advice = generator.get_advice_for_cve(
            "CVE-2023-9999", "Some completely unknown vulnerability"
        )
        assert advice is None

    def test_attaches_cve_id(self, generator):
        advice = generator.get_advice_for_cve(
            "CVE-2023-1234", "SQL injection vulnerability"
        )
        assert advice is not None
        assert "CVE-2023-1234" in advice.vulnerability

    def test_attaches_nvd_reference(self, generator):
        advice = generator.get_advice_for_cve(
            "CVE-2023-1234", "SQL injection vulnerability"
        )
        assert advice is not None
        assert "https://nvd.nist.gov/vuln/detail/CVE-2023-1234" in advice.references


class TestGenerateReport:
    def test_sorts_by_priority(self, generator):
        findings = [
            {"description": "Missing security headers detected"},
            {"description": "SQL injection in login form"},
            {"description": "XSS in search field"},
        ]
        report = generator.generate_report(findings)
        assert len(report) == 3
        # SQL injection (priority=10) should come first
        assert report[0].title == "Use parameterized queries"
        # XSS (priority=9) second
        assert report[1].title == "Encode output and validate input"
        # Missing headers (priority=5) last
        assert report[2].title == "Add security headers"

    def test_deduplicates(self, generator):
        findings = [
            {"description": "SQL injection in login form"},
            {"description": "SQL injection in search form"},
            {"description": "Another sqli issue found"},
        ]
        report = generator.generate_report(findings)
        assert len(report) == 1
        assert report[0].title == "Use parameterized queries"

    def test_with_cve(self, generator):
        findings = [
            {"cve": "CVE-2023-1234", "description": "SQL injection"},
        ]
        report = generator.generate_report(findings)
        assert len(report) == 1
        assert "CVE-2023-1234" in report[0].vulnerability

    def test_empty_findings(self, generator):
        report = generator.generate_report([])
        assert report == []


class TestFormatMarkdown:
    def test_returns_valid_markdown(self, generator):
        findings = [
            {"description": "SQL injection in login form"},
            {"description": "XSS in search field"},
        ]
        report = generator.generate_report(findings)
        md = generator.format_markdown(report)

        assert md.startswith("# Remediation Report")
        assert "## 1." in md
        assert "## 2." in md
        assert "**Severity:**" in md
        assert "**Vulnerability:**" in md
        assert "**Recommendation:**" in md
        assert "```" in md

    def test_empty_list_returns_message(self, generator):
        md = generator.format_markdown([])
        assert md == "No remediation advice available for the given findings."

    def test_includes_code_fix(self, generator):
        advice = [REMEDIATION_DB["sql_injection"]]
        md = generator.format_markdown(advice)
        assert "**Suggested Code Fix:**" in md
        assert "parameterized" in md.lower() or "cursor.execute" in md

    def test_includes_config_fix(self, generator):
        advice = [REMEDIATION_DB["missing_headers"]]
        md = generator.format_markdown(advice)
        assert "**Suggested Configuration:**" in md

    def test_includes_references(self, generator):
        advice = [REMEDIATION_DB["sql_injection"]]
        md = generator.format_markdown(advice)
        assert "**References:**" in md
        assert "https://cheatsheetseries.owasp.org" in md


class TestAddCustom:
    def test_adds_new_entry(self, generator):
        custom = RemediationAdvice(
            vulnerability="Custom Vuln",
            severity="low",
            title="Custom Fix",
            description="A custom vulnerability.",
            recommendation="Apply custom fix.",
            effort="high",
            priority=3,
        )
        generator.add_custom("custom_vuln", custom)
        result = generator.get_advice("custom_vuln")
        assert result is not None
        assert result.title == "Custom Fix"
        assert result.effort == "high"


class TestListKnownTypes:
    def test_returns_sorted_list(self, generator):
        types = generator.list_known_types()
        assert types == sorted(types)
        assert "sql_injection" in types
        assert "xss" in types
        assert "ssrf" in types
        assert len(types) == len(REMEDIATION_DB)
