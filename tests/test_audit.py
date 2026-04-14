"""Tests for the Audit Logger and Session Metrics modules."""

import json
from pathlib import Path

import pytest

from vulnexploit.safety.audit import AuditLogger, SessionMetrics
from vulnexploit.safety.audit.logger import AuditEntry


@pytest.fixture
def logger(tmp_path, monkeypatch):
    """Create an AuditLogger with a temp base directory."""
    monkeypatch.setattr(AuditLogger, "BASE_DIR", tmp_path)
    return AuditLogger("test-session-001")


# --- AuditLogger ---

class TestAuditLogger:
    def test_init_creates_directory(self, logger):
        assert logger.log_dir.exists()
        assert logger.log_dir.name == "test-session-001"

    def test_log_basic_entry(self, logger):
        entry = logger.log("custom_event", details={"key": "value"})
        assert entry.event_type == "custom_event"
        assert entry.session_id == "test-session-001"
        assert entry.details["key"] == "value"
        assert entry.timestamp  # non-empty
        assert logger.entry_count == 1

    def test_log_tool_call(self, logger):
        entry = logger.log_tool_call(
            tool_name="scan_ports",
            args={"target": "10.0.0.1"},
            result="Port 80 open",
            duration_ms=1500,
        )
        assert entry.event_type == "tool_call"
        assert entry.tool_name == "scan_ports"
        assert entry.tool_args == {"target": "10.0.0.1"}
        assert entry.tool_result == "Port 80 open"
        assert entry.duration_ms == 1500

    def test_log_llm_call(self, logger):
        entry = logger.log_llm_call(
            model="claude-sonnet-4-6",
            input_tokens=1000,
            output_tokens=200,
            cost_usd=0.006,
        )
        assert entry.event_type == "llm_call"
        assert entry.details["model"] == "claude-sonnet-4-6"
        assert entry.details["input_tokens"] == 1000

    def test_log_command(self, logger):
        entry = logger.log_command(
            command="nmap -sV 10.0.0.1",
            exit_code=0,
            output="Nmap scan report...",
        )
        assert entry.event_type == "command"
        assert entry.details["command"] == "nmap -sV 10.0.0.1"

    def test_log_finding(self, logger):
        entry = logger.log_finding(
            description="Path traversal in Apache",
            severity="high",
            cve="CVE-2021-41773",
        )
        assert entry.event_type == "finding"
        assert entry.severity == "high"
        assert entry.details["cve"] == "CVE-2021-41773"

    def test_log_approval(self, logger):
        entry = logger.log_approval(
            prompt="Execute exploit?",
            approved=True,
        )
        assert entry.event_type == "approval"
        assert entry.details["approved"] is True

    def test_log_error(self, logger):
        entry = logger.log_error("Connection refused", port=80)
        assert entry.event_type == "error"
        assert entry.severity == "error"
        assert entry.details["error"] == "Connection refused"

    def test_entries_written_to_file(self, logger):
        logger.log_tool_call("scan_ports", {"target": "10.0.0.1"}, "result")
        logger.log_tool_call("detect_services", {"target": "10.0.0.1"}, "result2")

        audit_file = logger.log_dir / "audit.jsonl"
        assert audit_file.exists()
        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 2

        parsed = json.loads(lines[0])
        assert parsed["tool_name"] == "scan_ports"

    def test_command_log_separate_file(self, logger):
        logger.log_command("nmap 10.0.0.1", 0, "output")
        cmd_file = logger.log_dir / "commands.jsonl"
        assert cmd_file.exists()
        lines = cmd_file.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_finding_log_separate_file(self, logger):
        logger.log_finding("XSS found", severity="medium")
        findings_file = logger.log_dir / "findings.jsonl"
        assert findings_file.exists()

    def test_agent_log_separate_file(self, logger):
        logger.log("tool_call", agent="recon", tool_name="scan_ports")
        agents_file = logger.log_dir / "agents.jsonl"
        assert agents_file.exists()

    def test_main_agent_not_in_agents_log(self, logger):
        logger.log("tool_call", agent="main", tool_name="scan_ports")
        agents_file = logger.log_dir / "agents.jsonl"
        assert not agents_file.exists()

    def test_read_log(self, logger):
        logger.log_tool_call("scan_ports", {}, "result1")
        logger.log_tool_call("detect_services", {}, "result2")

        entries = logger.read_log("audit.jsonl")
        assert len(entries) == 2
        assert entries[0].tool_name == "scan_ports"
        assert entries[1].tool_name == "detect_services"

    def test_read_empty_log(self, logger):
        entries = logger.read_log("nonexistent.jsonl")
        assert entries == []

    def test_get_findings(self, logger):
        logger.log_finding("vuln1", severity="high")
        logger.log_finding("vuln2", severity="low")
        findings = logger.get_findings()
        assert len(findings) == 2

    def test_get_commands(self, logger):
        logger.log_command("nmap", 0, "output")
        commands = logger.get_commands()
        assert len(commands) == 1

    def test_tool_result_truncation(self, logger):
        long_result = "x" * 5000
        entry = logger.log_tool_call("test", {}, long_result)
        assert len(entry.tool_result) == 2000

    def test_entry_count(self, logger):
        assert logger.entry_count == 0
        logger.log("event1")
        logger.log("event2")
        logger.log("event3")
        assert logger.entry_count == 3


# --- SessionMetrics ---

class TestSessionMetrics:
    def _make_entries(self):
        """Create a list of AuditEntry objects for testing."""
        return [
            AuditEntry(
                timestamp="2025-01-01T10:00:00+00:00",
                session_id="test",
                event_type="llm_call",
                details={"model": "claude-sonnet-4-6", "input_tokens": 1000,
                         "output_tokens": 200, "cost_usd": 0.006},
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:05+00:00",
                session_id="test",
                event_type="tool_call",
                agent="recon",
                tool_name="scan_ports",
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:10+00:00",
                session_id="test",
                event_type="tool_call",
                agent="main",
                tool_name="scan_ports",
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:15+00:00",
                session_id="test",
                event_type="command",
                details={"command": "nmap", "exit_code": 0, "output": "..."},
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:20+00:00",
                session_id="test",
                event_type="finding",
                severity="critical",
                details={"description": "RCE", "cve": "CVE-2021-1234"},
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:25+00:00",
                session_id="test",
                event_type="finding",
                severity="low",
                details={"description": "Info disclosure"},
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:30+00:00",
                session_id="test",
                event_type="approval",
                details={"prompt": "Run exploit?", "approved": True},
            ),
            AuditEntry(
                timestamp="2025-01-01T10:00:35+00:00",
                session_id="test",
                event_type="approval",
                details={"prompt": "Delete file?", "approved": False},
            ),
        ]

    def test_from_audit_entries(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)

        assert metrics.session_id == "test"
        assert metrics.total_llm_calls == 1
        assert metrics.total_tool_calls == 2
        assert metrics.total_commands == 1
        assert metrics.total_findings == 2
        assert metrics.total_approvals == 2
        assert metrics.approvals_granted == 1
        assert metrics.approvals_denied == 1

    def test_token_and_cost_aggregation(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)

        assert metrics.total_input_tokens == 1000
        assert metrics.total_output_tokens == 200
        assert metrics.total_cost_usd == pytest.approx(0.006)

    def test_findings_by_severity(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)

        assert metrics.findings_critical == 1
        assert metrics.findings_low == 1
        assert metrics.findings_high == 0

    def test_agent_tool_calls(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)

        assert metrics.agent_tool_calls.get("recon") == 1
        assert metrics.agent_tool_calls.get("main") == 1

    def test_tool_call_counts(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)

        assert metrics.tool_call_counts.get("scan_ports") == 2

    def test_duration(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)

        assert metrics.total_duration_seconds == 35.0

    def test_summary(self):
        entries = self._make_entries()
        metrics = SessionMetrics.from_audit_entries("test", entries)
        summary = metrics.summary()

        assert "test" in summary
        assert "LLM calls: 1" in summary
        assert "Tool calls: 2" in summary
        assert "Findings: 2" in summary

    def test_empty_entries(self):
        metrics = SessionMetrics.from_audit_entries("empty", [])
        assert metrics.total_llm_calls == 0
        assert metrics.total_tool_calls == 0
        assert metrics.total_duration_seconds == 0.0
