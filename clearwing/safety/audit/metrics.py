"""Session metrics aggregation from audit logs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SessionMetrics:
    """Aggregated metrics for a penetration testing session."""

    session_id: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    total_duration_seconds: float = 0.0

    # Counts
    total_tool_calls: int = 0
    total_llm_calls: int = 0
    total_commands: int = 0
    total_findings: int = 0
    total_approvals: int = 0
    approvals_granted: int = 0
    approvals_denied: int = 0

    # Cost
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0

    # Findings by severity
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0

    # Per-agent breakdown
    agent_tool_calls: dict = field(default_factory=dict)
    tool_call_counts: dict = field(default_factory=dict)

    @classmethod
    def from_audit_entries(cls, session_id: str, entries: list) -> SessionMetrics:
        """Build metrics from a list of AuditEntry objects."""
        metrics = cls(session_id=session_id)

        for entry in entries:
            ts = entry.timestamp
            if metrics.start_time is None:
                try:
                    metrics.start_time = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    pass

            try:
                metrics.end_time = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                pass

            if entry.event_type == "tool_call":
                metrics.total_tool_calls += 1
                agent = entry.agent or "main"
                metrics.agent_tool_calls[agent] = metrics.agent_tool_calls.get(agent, 0) + 1
                tool = entry.tool_name or "unknown"
                metrics.tool_call_counts[tool] = metrics.tool_call_counts.get(tool, 0) + 1

            elif entry.event_type == "llm_call":
                metrics.total_llm_calls += 1
                details = entry.details or {}
                metrics.total_input_tokens += details.get("input_tokens", 0)
                metrics.total_output_tokens += details.get("output_tokens", 0)
                metrics.total_cost_usd += details.get("cost_usd", 0.0)

            elif entry.event_type == "command":
                metrics.total_commands += 1

            elif entry.event_type == "finding":
                metrics.total_findings += 1
                sev = (entry.severity or "info").lower()
                if sev == "critical":
                    metrics.findings_critical += 1
                elif sev == "high":
                    metrics.findings_high += 1
                elif sev == "medium":
                    metrics.findings_medium += 1
                elif sev == "low":
                    metrics.findings_low += 1
                else:
                    metrics.findings_info += 1

            elif entry.event_type == "approval":
                metrics.total_approvals += 1
                details = entry.details or {}
                if details.get("approved"):
                    metrics.approvals_granted += 1
                else:
                    metrics.approvals_denied += 1

        if metrics.start_time and metrics.end_time:
            metrics.total_duration_seconds = (metrics.end_time - metrics.start_time).total_seconds()

        return metrics

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Session: {self.session_id}",
            f"Duration: {self.total_duration_seconds:.0f}s",
            f"LLM calls: {self.total_llm_calls} ({self.total_input_tokens + self.total_output_tokens:,} tokens, ${self.total_cost_usd:.4f})",
            f"Tool calls: {self.total_tool_calls}",
            f"Commands: {self.total_commands}",
            f"Findings: {self.total_findings} "
            f"(C:{self.findings_critical} H:{self.findings_high} M:{self.findings_medium} "
            f"L:{self.findings_low} I:{self.findings_info})",
            f"Approvals: {self.approvals_granted} granted, {self.approvals_denied} denied",
        ]
        return "\n".join(lines)
