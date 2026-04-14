import json

import pytest

from clearwing.core.engine import ScanResult, ScanState
from clearwing.reporting import ReportGenerator


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
