"""Append-only audit logger for penetration testing sessions."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: str
    session_id: str
    event_type: str  # tool_call, llm_call, approval, error, finding, command
    agent: str = "main"  # main, recon, exploit, reporter, planner
    tool_name: str | None = None
    tool_args: dict | None = None
    tool_result: str | None = None
    duration_ms: int | None = None
    severity: str | None = None  # for findings: critical, high, medium, low, info
    details: dict = field(default_factory=dict)


class AuditLogger:
    """Append-only, concurrent-safe audit logger.

    Writes structured JSON log entries to:
    ~/.clearwing/audit/{session_id}/audit.jsonl

    Also maintains separate logs for:
    - commands.jsonl — every shell command executed
    - findings.jsonl — vulnerabilities and exploits
    - agents.jsonl — per-agent activity
    """

    BASE_DIR: Path = Path("~/.clearwing/audit").expanduser()

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._dir = self.BASE_DIR / session_id
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._entry_count = 0

    # ------------------------------------------------------------------
    # Core logging
    # ------------------------------------------------------------------

    def log(self, event_type: str, agent: str = "main", **kwargs) -> AuditEntry:
        """Create and persist an audit entry."""
        entry = AuditEntry(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            session_id=self.session_id,
            event_type=event_type,
            agent=agent,
            **kwargs,
        )
        self._append("audit.jsonl", entry)

        # Route to specialized logs
        if event_type == "command":
            self._append("commands.jsonl", entry)
        elif event_type == "finding":
            self._append("findings.jsonl", entry)
        if agent != "main":
            self._append("agents.jsonl", entry)

        self._entry_count += 1
        return entry

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def log_tool_call(
        self, tool_name: str, args: dict, result: str, duration_ms: int = 0, agent: str = "main"
    ) -> AuditEntry:
        """Log a tool invocation."""
        return self.log(
            "tool_call",
            agent=agent,
            tool_name=tool_name,
            tool_args=args,
            tool_result=result[:2000],  # Truncate large results
            duration_ms=duration_ms,
        )

    def log_llm_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        agent: str = "main",
    ) -> AuditEntry:
        """Log an LLM API call."""
        return self.log(
            "llm_call",
            agent=agent,
            details={
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_usd,
            },
        )

    def log_command(
        self, command: str, exit_code: int, output: str, agent: str = "main"
    ) -> AuditEntry:
        """Log a shell command execution."""
        return self.log(
            "command",
            agent=agent,
            details={
                "command": command,
                "exit_code": exit_code,
                "output": output[:2000],
            },
        )

    def log_finding(
        self,
        description: str,
        severity: str = "info",
        cve: str = "",
        agent: str = "main",
        **details,
    ) -> AuditEntry:
        """Log a vulnerability or finding."""
        return self.log(
            "finding",
            agent=agent,
            severity=severity,
            details={"description": description, "cve": cve, **details},
        )

    def log_approval(self, prompt: str, approved: bool, agent: str = "main") -> AuditEntry:
        """Log a human approval decision."""
        return self.log(
            "approval",
            agent=agent,
            details={"prompt": prompt, "approved": approved},
        )

    def log_error(self, error: str, agent: str = "main", **details) -> AuditEntry:
        """Log an error."""
        return self.log(
            "error",
            agent=agent,
            severity="error",
            details={"error": error, **details},
        )

    # ------------------------------------------------------------------
    # Reading logs
    # ------------------------------------------------------------------

    def read_log(self, filename: str = "audit.jsonl") -> list[AuditEntry]:
        """Read all entries from a log file."""
        path = self._dir / filename
        if not path.exists():
            return []
        entries = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    raw = json.loads(line)
                    entries.append(AuditEntry(**raw))
        return entries

    def get_findings(self) -> list[AuditEntry]:
        """Get all findings."""
        return self.read_log("findings.jsonl")

    def get_commands(self) -> list[AuditEntry]:
        """Get all executed commands."""
        return self.read_log("commands.jsonl")

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def log_dir(self) -> Path:
        return self._dir

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _append(self, filename: str, entry: AuditEntry):
        """Thread-safe append to a JSONL file."""
        path = self._dir / filename
        data = asdict(entry)
        line = json.dumps(data, default=str) + "\n"
        with self._lock:
            with path.open("a", encoding="utf-8") as f:
                f.write(line)
