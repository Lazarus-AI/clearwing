import json

import pytest

from clearwing.core.engine import ScanResult, ScanState
from clearwing.reporting import ReportGenerator
from clearwing.reporting.report_generator import _format_service_label


class TestReportGenerator:
    """Tests for ReportGenerator module."""

    @pytest.fixture
    def generator(self):
        return ReportGenerator()

    @pytest.fixture
    def sample_result(self):
        """Create a sample ScanResult for testing."""
        result = ScanResult(target="192.168.1.1")
        result.open_ports = [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "SSH"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "HTTP"},
        ]
        result.services = [
            {"port": 22, "service": "SSH", "version": "8.0", "banner": "SSH-2.0-OpenSSH_8.0"},
            {"port": 80, "service": "HTTP", "version": "2.4.41", "banner": "Apache/2.4.41"},
        ]
        result.vulnerabilities = [
            {
                "cve": "CVE-2017-0144",
                "description": "EternalBlue",
                "cvss": 9.3,
                "port": 445,
                "service": "SMB",
            }
        ]
        result.exploits = [
            {
                "cve": "CVE-2017-0144",
                "exploit_name": "EternalBlue",
                "success": True,
                "message": "Exploit successful",
            }
        ]
        result.os_info = "Linux"
        result.state = ScanState.COMPLETED
        return result

    def test_text_report(self, generator, sample_result):
        """Test text report generation."""
        report = generator.generate(sample_result, "text")
        assert isinstance(report, str)
        assert "CLEARWING SCAN REPORT" in report
        assert "192.168.1.1" in report
        assert "SSH" in report

    def test_json_report(self, generator, sample_result):
        """Test JSON report generation."""
        report = generator.generate(sample_result, "json")
        data = json.loads(report)
        assert data["target"] == "192.168.1.1"
        assert len(data["open_ports"]) == 2
        assert len(data["vulnerabilities"]) == 1

    def test_html_report(self, generator, sample_result):
        """Test HTML report generation."""
        report = generator.generate(sample_result, "html")
        assert isinstance(report, str)
        assert "<html>" in report
        assert "<table>" in report
        assert "192.168.1.1" in report

    def test_markdown_report(self, generator, sample_result):
        """Test Markdown report generation."""
        report = generator.generate(sample_result, "markdown")
        assert isinstance(report, str)
        assert "# Clearwing Scan Report" in report
        assert "| Port | Protocol | Service | State |" in report

    def test_save_report(self, generator, sample_result, tmp_path):
        """Test saving report to file."""
        filepath = tmp_path / "report.txt"
        generator.save(sample_result, str(filepath))
        assert filepath.exists()
        content = filepath.read_text()
        assert "CLEARWING SCAN REPORT" in content

    def test_auto_format_detection(self, generator, sample_result, tmp_path):
        """Test automatic format detection from file extension."""
        # Test JSON
        json_path = tmp_path / "report.json"
        generator.save(sample_result, str(json_path))
        data = json.loads(json_path.read_text())
        assert "target" in data

        # Test HTML
        html_path = tmp_path / "report.html"
        generator.save(sample_result, str(html_path))
        content = html_path.read_text()
        assert "<html>" in content


class TestFormatServiceLabel:
    """Regression tests for the `_format_service_label` helper that
    cleaned up `HTTP vNone` / `HTTP vVercel` ugliness in text reports
    (see PR #20).
    """

    def test_version_none_returns_service_alone(self):
        """`version=None` should drop the version segment entirely, not
        render `HTTP vNone`."""
        assert _format_service_label("HTTP", None) == "HTTP"

    @pytest.mark.parametrize("blank", ["", "   ", "none", "None", "NONE", "Unknown", "unknown"])
    def test_blank_or_placeholder_version_returns_service_alone(self, blank):
        """Empty, whitespace, or the common placeholder strings ('none',
        'Unknown', any case) should be treated as 'no version known' and
        produce just the service name."""
        assert _format_service_label("HTTP", blank) == "HTTP"

    def test_numeric_version_gets_v_prefix(self):
        """Version strings that start with a digit are real versions and
        should be rendered as `service v<version>`."""
        assert _format_service_label("SSH", "1.2.3") == "SSH v1.2.3"

    def test_non_numeric_version_parenthesised(self):
        """Non-numeric server/banner labels (e.g. `Vercel` captured from a
        `Server:` header) should be parenthesised so they don't masquerade
        as a version number."""
        assert _format_service_label("HTTP", "Vercel") == "HTTP (Vercel)"

    def test_version_with_trailing_distro_tag(self):
        """Versions like Apache's `2.4.41 (Ubuntu)` start with a digit and
        should keep the `v` prefix even though they contain non-version
        characters after the numeric portion."""
        assert _format_service_label("HTTP", "2.4.41 (Ubuntu)") == "HTTP v2.4.41 (Ubuntu)"
