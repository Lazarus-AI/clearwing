"""Sessions subcommand."""

from rich.table import Table

from ...data.memory import SessionStore


def add_parser(subparsers):
    parser = subparsers.add_parser("sessions", help="List past interactive sessions")
    parser.add_argument("--target", help="Filter sessions by target")
    return parser


def handle(cli, args):
    """Show past interactive sessions."""
    store = SessionStore()
    sessions = store.list_sessions(target=getattr(args, "target", None))

    if not sessions:
        cli.console.print("[yellow]No sessions found.[/yellow]")
        return

    table = Table(title="Interactive Sessions")
    table.add_column("Session ID", style="cyan")
    table.add_column("Target", style="magenta")
    table.add_column("Model", style="blue")
    table.add_column("Status", style="green")
    table.add_column("Started", style="yellow")
    table.add_column("Cost", style="red")
    table.add_column("Flags", style="bold magenta")

    for s in sessions:
        table.add_row(
            s.session_id,
            s.target or "N/A",
            s.model,
            s.status,
            s.start_time.strftime("%Y-%m-%d %H:%M") if s.start_time else "?",
            f"${s.cost_usd:.4f}",
            str(len(s.flags_found)),
        )

    cli.console.print(table)
