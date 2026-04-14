"""Help screen modal for Clearwing TUI."""

from __future__ import annotations

from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static


HELP_TEXT = """\
[bold cyan]Clearwing TUI — Help[/bold cyan]

[bold]Keybindings[/bold]
  [yellow]Ctrl+P[/yellow]    Pause / Resume the agent
  [yellow]Ctrl+Q[/yellow]    Quit the application
  [yellow]F1[/yellow]        Show this help screen
  [yellow]Escape[/yellow]    Close this dialog

[bold]Input Commands[/bold]
  Type any message in the input bar to send instructions
  to the running agent.

  Special commands (prefix with /):
    [green]/status[/green]     Show current agent status
    [green]/cost[/green]       Show token usage and cost summary
    [green]/pause[/green]      Pause the agent
    [green]/resume[/green]     Resume the agent
    [green]/quit[/green]       Quit the application

[bold]Activity Feed[/bold]
  The main area displays agent activity in real time:
    [blue]Blue[/blue]        Informational messages
    [green]Green[/green]      Success / completion messages
    [yellow]Yellow[/yellow]     Warnings and approval requests
    [red]Red[/red]        Errors
    [magenta]Magenta[/magenta]    Captured flags

[dim]Press Escape to close this dialog.[/dim]
"""


class HelpScreen(ModalScreen):
    """Modal screen that displays keybindings and usage information."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        padding: 1 2;
        background: $surface;
    }
    """

    def compose(self):
        with Vertical(id="help-dialog"):
            yield Static(HELP_TEXT)
