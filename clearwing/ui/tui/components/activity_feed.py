"""Scrollable activity feed widget for Clearwing TUI."""

from __future__ import annotations

from rich.panel import Panel
from rich.text import Text
from textual.widgets import RichLog

from .tool_renderers import render_tool_result


class ActivityFeed(RichLog):
    """Scrollable agent activity feed with color-coded messages."""

    def __init__(self, **kwargs):
        super().__init__(auto_scroll=True, wrap=True, **kwargs)

    def add_message(self, content: str, msg_type: str = "info") -> None:
        """Add a message with color based on type."""
        color_map = {
            "info": "blue",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "flag": "magenta",
        }
        color = color_map.get(msg_type, "white")
        self.write(Text(content, style=color))

    def add_tool_start(self, tool_name: str, data: dict) -> None:
        """Add a tool-start indicator to the feed."""
        if tool_name == "read_source_file" and isinstance(data, dict):
            file = data.get("file", "?")
            start = data.get("start_line", 1)
            end = data.get("end_line", -1)
            range_str = f":{start}-{end}" if end != -1 else f":{start}"
            hunter = data.get("hunter_target", "")
            prefix = f"[{hunter}] " if hunter else ""
            self.write(Text(f"  {prefix}reading {file}{range_str}", style="dim cyan"))
        else:
            self.write(Text(f">>> Running: {tool_name}", style="dim cyan"))

    def add_tool_result(self, tool_name: str, data: dict) -> None:
        """Add a rendered tool result to the feed."""
        rendered = render_tool_result(tool_name, data)
        self.write(rendered)

    def add_validation(self, payload: dict) -> None:
        """Add a compact 4-axis validation summary."""
        fid = payload.get("finding_id", "?")
        axes = payload.get("axes", {})
        parts = [f"{ax}:{'pass' if v else 'fail'}" for ax, v in axes.items()]
        axes_str = " ".join(parts) if parts else "no axes"
        outcome = "advanced" if payload.get("advance") else "rejected"
        sev = payload.get("severity") or "n/a"
        self.write(Text(
            f"[VALIDATOR] {fid}: {axes_str} \u2192 {outcome} (severity={sev})",
            style="bold cyan" if payload.get("advance") else "dim yellow",
        ))

    def add_finding(self, finding: dict) -> None:
        """Add a finding banner to the feed."""
        severity = finding.get("severity", "info")
        sev_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim white",
        }.get(severity, "white")
        file = finding.get("file", "?")
        line = finding.get("line_number", "?")
        desc = (finding.get("description") or "")[:120]
        panel = Panel(
            Text(f"{file}:{line}\n{desc}", style=sev_style),
            title=f"FINDING [{severity.upper()}]",
            border_style=sev_style,
        )
        self.write(panel)

    def add_flag(self, flag: str, context: str) -> None:
        """Add a prominent flag-found banner to the feed."""
        panel = Panel(
            Text(f"{flag}", style="bold magenta"),
            title="FLAG FOUND",
            border_style="magenta",
            subtitle=context[:50] if context else None,
        )
        self.write(panel)
