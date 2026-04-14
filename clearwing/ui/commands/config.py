"""Config subcommand."""

from rich.panel import Panel


def add_parser(subparsers):
    parser = subparsers.add_parser("config", help="Show or edit configuration")
    parser.add_argument(
        "--set", nargs=2, metavar=("KEY", "VALUE"), help="Set a configuration value"
    )
    parser.add_argument("--save", help="Save configuration to file")
    return parser


def handle(cli, args):
    """Show or edit configuration."""
    if args.set:
        key, value = args.set
        keys = key.split(".")
        cli.config.set(*keys, value=value)
        cli.console.print(f"[green]Set {key} = {value}[/green]")

    if args.save:
        cli.config.save(args.save)
        cli.console.print(f"[green]Configuration saved to {args.save}[/green]")

    cli.console.print(Panel(str(cli.config.config), title="Current Configuration"))
