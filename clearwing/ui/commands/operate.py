"""Operate (autonomous operator agent) subcommand."""

import argparse
import asyncio
import sys
from typing import Any

from rich.panel import Panel
from rich.prompt import Prompt


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "operate", help="Run autonomous Operator agent with a set of goals or a mission plan"
    )
    parser.add_argument("--target", help="Target IP address or hostname")
    parser.add_argument("--machine-fd", type=int, help=argparse.SUPPRESS)
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
    parser.set_defaults(_command_parser=parser)
    return parser


def handle(cli, args):
    """Run the autonomous Operator agent."""
    if args.machine_fd is not None:
        raise SystemExit(_handle_machine(args.machine_fd))
    if not args.target:
        args._command_parser.error("the following arguments are required: --target")

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
        on_message=on_message,
        on_escalate=on_escalate,
    )

    cli.console.print(
        Panel.fit(
            "[bold cyan]Clearwing Operator Agent[/bold cyan]\n"
            f"Target: {args.target}\n"
            f"Mission: {args.mission}\n"
            f"Model: {args.model}\n"
            f"Goals:\n" + "\n".join(f"  {i + 1}. {g}" for i, g in enumerate(goals))
        )
    )

    if args.mission:
        goals.insert(0, f"LOAD_SKILL: {args.mission}")

    operator = OperatorAgent(config)
    try:
        result = operator.run()
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Operator interrupted.[/yellow]")
        sys.exit(1)

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


def _handle_machine(descriptor: int) -> int:
    from ...agent.operator import OperatorAgent, OperatorConfig
    from ...providers import ProviderManager, install_runtime_routing
    from ..machine import MachineChannel

    channel = MachineChannel(descriptor, "operate")
    try:
        request, routing = channel.read_start()
        parsed = _machine_request(request)
        install_runtime_routing(routing)
        provider_manager = ProviderManager.from_config(routing)

        def on_message(role: str, content: str) -> None:
            channel.emit("progress", {"role": str(role), "content": str(content)})

        result = asyncio.run(
            OperatorAgent(
                OperatorConfig(
                    goals=parsed["goals"],
                    target=parsed["target"],
                    provider_manager=provider_manager,
                    max_turns=parsed["max_turns"],
                    timeout_minutes=parsed["timeout_minutes"],
                    cost_limit=parsed["cost_limit"],
                    auto_approve_scans=parsed["auto_approve_scans"],
                    auto_approve_exploits=parsed["auto_approve_exploits"],
                    on_message=on_message,
                )
            ).arun()
        )
        channel.result(result)
        return 0 if result.status == "completed" else 1
    except BaseException as exc:  # noqa: BLE001
        channel.error(exc)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    finally:
        channel.close()


def _machine_request(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "target",
        "goals",
        "max_turns",
        "timeout_minutes",
        "cost_limit",
        "auto_approve_scans",
        "auto_approve_exploits",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown request field(s): {', '.join(unknown)}")
    target = _bounded_text(value.get("target"), "target", 2048)
    goals_value = value.get("goals")
    if not isinstance(goals_value, list) or not 1 <= len(goals_value) <= 64:
        raise ValueError("goals must contain between 1 and 64 strings")
    goals = [
        _bounded_text(goal, f"goals[{index}]", 4096)
        for index, goal in enumerate(goals_value)
    ]
    return {
        "target": target,
        "goals": goals,
        "max_turns": _bounded_integer(value.get("max_turns", 100), "max_turns", 1, 1000),
        "timeout_minutes": _bounded_integer(
            value.get("timeout_minutes", 60), "timeout_minutes", 1, 1440
        ),
        "cost_limit": _bounded_number(value.get("cost_limit", 0.0), "cost_limit", 0, 10000),
        "auto_approve_scans": _boolean(
            value.get("auto_approve_scans", True), "auto_approve_scans"
        ),
        "auto_approve_exploits": _boolean(
            value.get("auto_approve_exploits", False), "auto_approve_exploits"
        ),
    }


def _bounded_text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ValueError(f"{name} must be at most {maximum} characters")
    return normalized


def _bounded_integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")
    return result


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value
