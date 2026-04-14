"""User input bar widget for Clearwing TUI."""

from __future__ import annotations

from textual.widgets import Input


class InputBar(Input):
    """User input bar at the bottom of the TUI."""

    DEFAULT_CSS = """
    InputBar {
        dock: bottom;
        height: 3;
        border: solid $primary;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(placeholder="Type a message or command...", **kwargs)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if text:
            self.app.submit_input(text)
            self.value = ""
