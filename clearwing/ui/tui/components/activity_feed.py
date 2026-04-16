"""Scrollable activity feed widget for Clearwing TUI."""

from __future__ import annotations

from rich.panel import Panel
from rich.text import Text
from textual.widgets import RichLog

from .tool_renderers import render_tool_result


class ActivityFeed(RichLog):
    """Scrollable agent activity feed with color-coded messages."""

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
        self.write(Text(f">>> Running: {tool_name}", style="dim cyan"))

    def add_tool_result(self, tool_name: str, data: dict) -> None:
        """Add a rendered tool result to the feed."""
        rendered = render_tool_result(tool_name, data)
        self.write(rendered)

    def add_flag(self, flag: str, context: str) -> None:
        """Add a prominent flag-found banner to the feed."""
        panel = Panel(
            Text(f"{flag}", style="bold magenta"),
            title="FLAG FOUND",
            border_style="magenta",
            subtitle=context[:50] if context else None,
        )
        self.write(panel)
