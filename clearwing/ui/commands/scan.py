"""Scan subcommand."""

import asyncio
from typing import Any

from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn


def add_parser(subparsers):
    parser = subparsers.add_parser("scan", help="Scan a target for vulnerabilities")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 22,80,443 or 1-1024)")
    parser.add_argument(
        "-t", "--threads", type=int, default=100, help="Number of concurrent threads"
    )
    parser.add_argument("-s", "--stealth", action="store_true", help="Stealth mode")
    parser.add_argument("-e", "--exploit", action="store_true", help="Attempt exploitation")
    parser.add_argument("-o", "--output", help="Output file for report")
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "html", "markdown"],
        default="text",
        help="Report format",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return parser


def handle(cli, args):
    """Run a scan."""
    from ...core import ScanConfig

    cli.console.print(Panel.fit(f"[bold blue]Scanning target: {args.target}[/bold blue]"))

    # Parse ports
    ports = None
    if args.ports:
        ports = _parse_ports(args.ports)

    scan_config = ScanConfig(
        target=args.target,
        ports=ports,
        threads=args.threads,
        stealth_mode=args.stealth,
        exploit=args.exploit,
        verbose=args.verbose,
    )

    cli.engine.register_callback(
        "on_port_found",
        lambda target, port: cli.console.print(
            f"[green]+[/green] Port {port['port']}/{port['protocol']} open - {port['service']}"
        ),
    )
    cli.engine.register_callback(
        "on_vulnerability_found",
        lambda target, vuln: cli.console.print(
            f"[yellow]![/yellow] {vuln.get('cve')} - {vuln.get('description', 'N/A')}"
        ),
    )
    cli.engine.register_callback("on_scan_complete", lambda result: _on_scan_complete(cli, result))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=cli.console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=None)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(cli.engine.scan(args.target, scan_config))
        finally:
            loop.close()

        progress.update(task, completed=True)

    report = cli.engine.get_report(args.format)
    cli.console.print(report)

    if args.output:
        cli.engine.save_results(args.output)
        cli.console.print(f"[green]Report saved to {args.output}[/green]")


def _parse_ports(ports_str: str) -> list:
    ports = []
    for part in ports_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


def _on_scan_complete(cli, result: Any) -> None:
    cli.console.print("\n[bold green]Scan completed![/bold green]")
    cli.console.print(f"  Open Ports: {len(result.open_ports)}")
    cli.console.print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
    cli.console.print(
        f"  Successful Exploits: {sum(1 for e in result.exploits if e.get('success'))}"
    )
