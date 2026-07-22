"""Operate (autonomous operator agent) subcommand."""

import logging
import os
import sys

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "operate", help="Run autonomous Operator agent with a set of goals or a mission plan"
    )
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    parser.add_argument(
        "--goal", action="append", dest="goals", help="Goal for the operator (can be repeated)"
    )
    parser.add_argument(
        "--mission", default="IronRainDemo", help="Mission plan to load (default: IronRainDemo)"
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-6", help="LLM model name (default: claude-sonnet-4-6)"
    )
    parser.add_argument(
        "--operator-model",
        default="",
        help="Separate model for the operator LLM (defaults to --model)",
    )
    parser.add_argument(
        "--max-turns", type=int, default=100, help="Maximum inner-agent turns (default: 100)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        metavar="MINUTES",
        help="Timeout in minutes (default: 60)",
    )
    parser.add_argument(
        "--cost-limit",
        type=float,
        metavar="DOLLARS",
        help="Stop when estimated cost exceeds this amount (USD)",
    )
    parser.add_argument(
        "--auto-approve-exploits",
        action="store_true",
        help="Auto-approve exploit actions (default: require escalation)",
    )
    parser.add_argument("--base-url", metavar="URL", help="OpenAI-compatible API base URL")
    parser.add_argument("--api-key", metavar="KEY", help="API key for the endpoint")
    parser.add_argument(
        "--lhost", metavar="IP",
        help="Listener host — address the target can reach to call back (e.g. host.docker.internal, 192.168.1.x)",
    )
    parser.add_argument(
        "--lport", type=int, default=9999, metavar="PORT",
        help="Listener port for callback verification (default: 9999)",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v = INFO, -vv = DEBUG)",
    )
    return parser


# ─── ATT&CK Chain Table Builder ──────────────────────────────────────────────

_STATUS_ICONS = {
    "pending": "[dim]○[/dim]",
    "active": "[bold yellow]●[/bold yellow]",
    "completed": "[bold green]✓[/bold green]",
}


def _build_chain_table(attack_chain) -> Table:
    """Build a Rich Table showing ATT&CK technique progression."""
    table = Table(
        title="[bold]MITRE ATT&CK Kill Chain[/bold]",
        show_header=True,
        header_style="bold",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("", width=3, justify="center")
    table.add_column("Technique", style="cyan", min_width=10)
    table.add_column("Tactic", style="dim")
    table.add_column("Name", min_width=20)
    table.add_column("Evidence", style="green", max_width=50)

    for tech in attack_chain.techniques:
        icon = _STATUS_ICONS.get(tech.status, "?")
        name_style = {
            "pending": "dim",
            "active": "bold yellow",
            "completed": "bold green",
        }.get(tech.status, "")
        table.add_row(
            icon,
            tech.technique_id,
            tech.tactic,
            Text(tech.name, style=name_style),
            tech.evidence[:50] if tech.evidence else "",
        )
    return table


# ─── Pre-flight Connectivity Checks ──────────────────────────────────────────


def _preflight_checks(target: str, lhost: str, lport: int) -> list[str]:
    """Run connectivity checks and return status lines for display."""
    import shutil
    import socket
    import subprocess

    results = []

    # 1. Can we reach the target port?
    host, _, port_str = target.rpartition(":")
    if not host:
        host, port_str = target, "80"
    try:
        port = int(port_str)
    except ValueError:
        port = 80

    try:
        sock = socket.create_connection((host, port), timeout=3)
        sock.close()
        results.append(f"[green]✓[/green] Target {host}:{port} — reachable")
    except (OSError, socket.timeout):
        results.append(f"[red]✗[/red] Target {host}:{port} — UNREACHABLE")

    # 2. Is Docker available + can we find a target container?
    docker = shutil.which("docker")
    if not docker:
        results.append("[yellow]![/yellow] Docker CLI not found — skipping container checks")
        return results

    # Find containers with the target port mapped
    try:
        ps_out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=5,
        )
        target_container = None
        for line in ps_out.stdout.strip().splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2 and f":{port}->" in parts[1]:
                target_container = parts[0]
                break

        if not target_container:
            results.append(f"[yellow]![/yellow] No container found mapping port {port}")
            return results

        results.append(f"[green]✓[/green] Target container: {target_container}")
    except (subprocess.TimeoutExpired, OSError):
        results.append("[yellow]![/yellow] Docker ps failed")
        return results

    # 3. Does host.docker.internal resolve inside the target container?
    try:
        import shlex

        resolve = subprocess.run(
            ["docker", "exec", target_container, "sh", "-c",
             f"getent hosts {shlex.quote(lhost)} 2>/dev/null || grep {shlex.quote(lhost)} /etc/hosts"],
            capture_output=True, text=True, timeout=5,
        )
        if resolve.returncode == 0 and resolve.stdout.strip():
            ip = resolve.stdout.strip().split()[0]
            results.append(f"[green]✓[/green] {lhost} resolves → {ip}")
        else:
            results.append(f"[red]✗[/red] {lhost} does NOT resolve inside container")
    except (subprocess.TimeoutExpired, OSError):
        results.append(f"[yellow]![/yellow] Could not check {lhost} resolution")

    # 4. Does the container have curl?
    try:
        curl_check = subprocess.run(
            ["docker", "exec", target_container, "which", "curl"],
            capture_output=True, text=True, timeout=5,
        )
        if curl_check.returncode == 0:
            results.append("[green]✓[/green] curl available in target container")
        else:
            results.append("[red]✗[/red] curl NOT found in target — RCE callback will fail")
    except (subprocess.TimeoutExpired, OSError):
        results.append("[yellow]![/yellow] Could not verify curl in container")

    # 5. Can container reach lhost:lport? (only if listener is already up)
    try:
        reach = subprocess.run(
            ["docker", "exec", target_container, "curl", "-s", "-o", "/dev/null",
             "-w", "%{http_code}", "--connect-timeout", "2",
             f"http://{lhost}:{lport}/"],
            capture_output=True, text=True, timeout=8,
        )
        code = reach.stdout.strip()
        if code and code != "000":
            results.append(f"[green]✓[/green] Container → {lhost}:{lport} — HTTP {code}")
        else:
            results.append(f"[yellow]![/yellow] Container → {lhost}:{lport} — no listener yet (will start during run)")
    except (subprocess.TimeoutExpired, OSError):
        results.append(f"[yellow]![/yellow] Could not test container → {lhost}:{lport}")

    return results


# ─── Handle Command ──────────────────────────────────────────────────────────


def handle(cli, args):
    """Run the autonomous Operator agent."""
    # Wire up logging: -v = INFO, -vv = DEBUG, env override still works
    if args.verbose >= 2:
        log_level = "DEBUG"
    elif args.verbose == 1:
        log_level = "INFO"
    else:
        log_level = os.environ.get("CLEARWING_LOG_LEVEL", "WARNING").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.WARNING),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    from ...agent.attack_chain import AttackTechnique
    from ...agent.operator import OperatorAgent, OperatorConfig

    goals = args.goals or []
    if not goals and args.mission == "IronRainDemo":
        goals = [
            "Execute the 'IronRainDemo' mission protocol.",
            "Perform full recon on the target.",
            "Identify and adapt a PoC for any discovered critical vulnerabilities.",
            "Establish a beachhead and pivot into the internal network.",
            "Generate a final Mission After Action Report (AAR).",
        ]

    def on_message(role: str, content: str) -> None:
        style = {"agent": "cyan", "operator": "green", "approval": "yellow"}.get(role, "white")
        label = role.capitalize()
        display_content = content[:2000] + ("..." if len(content) > 2000 else "")
        cli.console.print(
            Panel(
                display_content,
                title=f"[bold {style}]{label}[/bold {style}]",
                border_style=style,
            )
        )

    def on_technique(tech: AttackTechnique) -> None:
        """Reprint the ATT&CK table whenever a technique advances."""
        cli.console.print(_build_chain_table(operator.attack_chain))

    def on_escalate(question: str) -> str:
        cli.console.print(
            Panel(
                question,
                title="[bold yellow]Operator Escalation[/bold yellow]",
                border_style="yellow",
            )
        )
        try:
            return Prompt.ask("[bold yellow]Your answer[/bold yellow]")
        except (EOFError, KeyboardInterrupt):
            return ""

    config = OperatorConfig(
        goals=goals,
        target=args.target,
        model=args.model,
        operator_model=args.operator_model or "",
        base_url=getattr(args, "base_url", None),
        api_key=getattr(args, "api_key", None),
        max_turns=args.max_turns,
        timeout_minutes=args.timeout,
        cost_limit=args.cost_limit or 0.0,
        auto_approve_exploits=args.auto_approve_exploits,
        lhost=args.lhost or "host.docker.internal",
        lport=args.lport,
        on_message=on_message,
        on_escalate=on_escalate,
        on_technique=on_technique,
    )

    # ─── Pre-flight checks ────────────────────────────────────────────────
    preflight = _preflight_checks(args.target, args.lhost or "host.docker.internal", args.lport)

    # Print header + initial chain state
    preflight_lines = "\n".join(f"  {line}" for line in preflight)
    cli.console.print(
        Panel.fit(
            "[bold cyan]Clearwing Operator Agent[/bold cyan]\n"
            f"Target: {args.target}\n"
            f"Mission: {args.mission}\n"
            f"Model: {args.model}\n"
            f"LHOST: {args.lhost or 'host.docker.internal'}:{args.lport}\n"
            f"Goals:\n" + "\n".join(f"  {i + 1}. {g}" for i, g in enumerate(goals))
            + f"\n\n[bold]Pre-flight:[/bold]\n{preflight_lines}"
        )
    )

    if args.mission and not args.goals:
        goals.insert(0, f"LOAD_SKILL: {args.mission}")

    operator = OperatorAgent(config)

    # Show initial chain (all pending)
    cli.console.print(_build_chain_table(operator.attack_chain))

    try:
        result = operator.run()
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Operator interrupted.[/yellow]")
        sys.exit(1)

    # ─── Final report ─────────────────────────────────────────────────────
    cli.console.print()
    cli.console.print(_build_chain_table(operator.attack_chain))

    status_style = {
        "completed": "green",
        "escalated": "yellow",
        "timeout": "red",
        "error": "red",
        "cost_limit": "yellow",
    }.get(result.status, "white")
    cli.console.print(f"\n[bold {status_style}]Status: {result.status}[/bold {status_style}]")
    cli.console.print(f"Turns: {result.turns}")
    cli.console.print(f"Cost: ${result.cost_usd:.4f}")
    cli.console.print(f"Duration: {result.duration_seconds:.0f}s")

    if result.findings:
        cli.console.print(f"\n[bold]Findings ({len(result.findings)}):[/bold]")
        for f in result.findings:
            sev = f.get("severity", "info")
            sev_style = {"critical": "red", "high": "red", "medium": "yellow"}.get(sev, "white")
            cli.console.print(
                f"  [{sev_style}][{sev.upper()}][/{sev_style}] {f.get('description', 'N/A')}"
            )

    if result.flags_found:
        cli.console.print(
            f"\n[bold magenta]Flags found ({len(result.flags_found)}):[/bold magenta]"
        )
        for f in result.flags_found:
            cli.console.print(f"  [magenta]{f.get('flag', '?')}[/magenta]")

    if result.escalation_question:
        cli.console.print(f"\n[yellow]Escalation: {result.escalation_question}[/yellow]")

    if result.error:
        cli.console.print(f"\n[red]Error: {result.error}[/red]")

    has_critical = any(f.get("severity") in ("critical", "high") for f in result.findings)
    sys.exit(2 if has_critical else (1 if result.status != "completed" else 0))
