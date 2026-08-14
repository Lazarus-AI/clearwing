"""Operator workflow for installing and evaluating the CyberPi harness."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from rich.table import Table


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "cyberpi",
        help="Install, diagnose, smoke-test, and benchmark the CyberPi harness",
    )
    actions = parser.add_subparsers(dest="cyberpi_action")

    install = actions.add_parser("install", help="Install the pinned Pi runtime")
    install.add_argument("--force", action="store_true", help="Reinstall an existing runtime")

    doctor = actions.add_parser("doctor", help="Check Node, Pi, and Docker prerequisites")
    doctor.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    smoke = actions.add_parser(
        "smoke", help="Run one bounded CyberPi/provider integration check (uses inference)"
    )
    _provider_arguments(smoke)
    smoke.add_argument(
        "--output-dir", default=None, help="Directory for the result and JSONL trajectory"
    )
    smoke.add_argument(
        "--max-turns", type=_positive_int, default=3, help="Maximum model turns (default: 3)"
    )
    smoke.add_argument(
        "--max-output-tokens",
        type=_positive_int,
        default=4096,
        help="Maximum output tokens per turn (default: 4096)",
    )

    benchmark = actions.add_parser(
        "benchmark", help="Compare native and CyberPi on paired positive/negative fixtures"
    )
    _provider_arguments(benchmark)
    benchmark.add_argument(
        "--output-dir", default=None, help="Directory for JSON, Markdown, and trajectories"
    )
    benchmark.add_argument(
        "--suite",
        default="micro",
        help="Benchmark suite: micro, tuning-cves, held-out-cves, or a suite JSON path",
    )
    benchmark.add_argument(
        "--repository-cache",
        default=None,
        help="Private cache for pinned CVE repository snapshots",
    )
    benchmark.add_argument(
        "--runs", type=_positive_int, default=1, help="Replicates per fixture (default: 1)"
    )
    benchmark.add_argument(
        "--max-turns", type=_positive_int, default=4, help="Maximum model turns (default: 4)"
    )
    benchmark.add_argument(
        "--max-output-tokens",
        type=_positive_int,
        default=4096,
        help="Maximum output tokens per turn (default: 4096)",
    )
    return parser


def handle(cli, args) -> None:
    action = getattr(args, "cyberpi_action", None)
    handlers = {
        "install": _handle_install,
        "doctor": _handle_doctor,
        "smoke": _handle_smoke,
        "benchmark": _handle_benchmark,
    }
    if action not in handlers:
        cli.console.print("[yellow]Usage: clearwing cyberpi <install|doctor|smoke|benchmark>[/yellow]")
        return
    handlers[action](cli, args)


def _handle_install(cli, args) -> None:
    from clearwing.sourcehunt.cyberpi_runtime import CyberPiRuntime, CyberPiRuntimeError

    runtime = CyberPiRuntime()
    cli.console.print(f"Installing pinned CyberPi runtime in [cyan]{runtime.runtime_dir}[/cyan]")
    try:
        destination = runtime.install(force=args.force)
    except CyberPiRuntimeError as exc:
        cli.console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    cli.console.print(f"[green]CyberPi is installed:[/green] {destination}")
    cli.console.print("Next: [bold]clearwing cyberpi doctor[/bold]")


def _handle_doctor(cli, args) -> None:
    from clearwing.sourcehunt.cyberpi_runtime import CyberPiRuntime

    status = CyberPiRuntime().inspect(include_docker=True)
    if args.json:
        sys.stdout.write(json.dumps(status.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        table = Table(title="CyberPi preflight", show_header=True, header_style="bold")
        table.add_column("Status", width=6)
        table.add_column("Check")
        table.add_column("Detail")
        glyphs = {"ok": "[green]OK[/green]", "warn": "[yellow]WARN[/yellow]", "error": "[red]ERR[/red]"}
        for check in status.checks:
            detail = check.detail + (f"\n[dim]{check.remedy}[/dim]" if check.remedy else "")
            table.add_row(glyphs[check.status], check.name, detail)
        cli.console.print(table)
        if status.ready:
            cli.console.print("[green]CyberPi is ready.[/green]")
        else:
            cli.console.print("[red]CyberPi needs attention; use the remedies above.[/red]")
    sys.exit(0 if status.ready else 1)


def _handle_smoke(cli, args) -> None:
    from clearwing.bench.cyberpi import BUILTIN_FIXTURES, CyberPiBenchmark

    llm, endpoint, output_dir = _evaluation_context(cli, args)
    cli.console.print(f"CyberPi smoke test: [cyan]{endpoint.describe()}[/cyan]")
    report = asyncio.run(
        CyberPiBenchmark(
            llm,
            output_dir=output_dir,
            max_turns=args.max_turns,
            max_output_tokens=args.max_output_tokens,
        ).arun(
            engines=("cyberpi",), fixtures=(BUILTIN_FIXTURES[0],)
        )
    )
    json_path, markdown_path = report.write(output_dir)
    observation = report.observations[0]
    if observation.error:
        cli.console.print(f"[red]CyberPi/provider integration failed:[/red] {observation.error}")
        cli.console.print(f"Result: {json_path}")
        sys.exit(1)
    cli.console.print("[green]CyberPi/provider integration succeeded.[/green]")
    behavior = "found the known fixture vulnerability" if observation.passed else "completed but missed the fixture vulnerability"
    cli.console.print(f"Behavior check: {behavior}")
    cli.console.print(f"Tokens: {observation.tokens_used}; trajectory: {observation.trajectory}")
    cli.console.print(f"Reports: {json_path}, {markdown_path}")


def _handle_benchmark(cli, args) -> None:
    llm, endpoint, output_dir = _evaluation_context(cli, args)
    cli.console.print(
        f"CyberPi paired benchmark: [cyan]{endpoint.describe()}[/cyan], "
        f"suite={args.suite}, runs={args.runs}"
    )
    report: Any
    if args.suite == "micro":
        from clearwing.bench.cyberpi import CyberPiBenchmark

        report = asyncio.run(
            CyberPiBenchmark(
                llm,
                output_dir=output_dir,
                max_turns=args.max_turns,
                max_output_tokens=args.max_output_tokens,
            ).arun(replicates=args.runs)
        )
    else:
        from clearwing.bench.cyberpi_cves import (
            CyberPiCVEBenchmark,
            CyberPiCVESuite,
            CyberPiSuiteError,
        )

        try:
            suite = CyberPiCVESuite.load(args.suite)
            report = asyncio.run(
                CyberPiCVEBenchmark(
                    llm,
                    suite,
                    output_dir=output_dir,
                    repository_cache=args.repository_cache,
                    max_turns=args.max_turns,
                    max_output_tokens=args.max_output_tokens,
                ).arun(replicates=args.runs)
            )
        except CyberPiSuiteError as exc:
            cli.console.print(f"[red]Error: {exc}[/red]")
            sys.exit(1)
    json_path, markdown_path = report.write(output_dir)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Engine")
    if args.suite == "micro":
        table.add_column("Passed", justify="right")
        table.add_column("Tokens", justify="right")
        table.add_column("Reported cost*", justify="right")
        table.add_column("Errors", justify="right")
        for engine, values in report.metrics().items():
            table.add_row(
                engine,
                f"{values['passed']}/{values['cases']}",
                str(values["tokens"]),
                f"${float(values['cost_usd']):.4f}",
                str(values["errors"]),
            )
    else:
        table.add_column("Recall", justify="right")
        table.add_column("Fixed FPR", justify="right")
        table.add_column("CWE", justify="right")
        table.add_column("Evidence", justify="right")
        table.add_column("Mean tokens", justify="right")
        table.add_column("Errors", justify="right")
        for engine, values in report.metrics().items():
            table.add_row(
                engine,
                f"{float(values['vulnerable_recall']):.0%}",
                f"{float(values['fixed_false_positive_rate']):.0%}",
                f"{float(values['cwe_accuracy']):.0%}",
                f"{float(values['evidence_quality']):.0%}",
                f"{float(values['tokens_mean']):.0f}",
                str(values["errors"]),
            )
    cli.console.print(table)
    cli.console.print(
        "[dim]* Native uses Clearwing's estimate; CyberPi uses the provider/model report. "
        "Compare tokens unless endpoint pricing is configured.[/dim]"
    )
    cli.console.print(f"Reports: {json_path}, {markdown_path}")
    if not report.successful:
        sys.exit(1)


def _evaluation_context(cli, args):
    from clearwing.core.config import default_results_dir
    from clearwing.providers import ProviderManager, resolve_llm_endpoint
    from clearwing.sourcehunt.cyberpi_runtime import CyberPiRuntime, CyberPiRuntimeError

    try:
        runtime = CyberPiRuntime()
        runtime.require_ready(include_docker=False)
    except CyberPiRuntimeError as exc:
        cli.console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    endpoint = resolve_llm_endpoint(
        cli_model=args.model,
        cli_base_url=args.base_url,
        cli_api_key=args.api_key,
        config_provider=cli.config.get_provider_section() or None,
    )
    if not endpoint.api_key:
        cli.console.print(
            "[red]Error: no API credential is configured. Run `clearwing setup` or set "
            "CLEARWING_API_KEY.[/red]"
        )
        sys.exit(1)
    llm = ProviderManager.for_endpoint(endpoint).get_native_client("hunter")
    output_dir = (
        Path(args.output_dir).expanduser()
        if args.output_dir
        else Path(default_results_dir("bench")).expanduser() / "cyberpi"
    )
    return llm, endpoint, output_dir


def _provider_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", default=None, help="Exact provider model identifier")
    parser.add_argument("--base-url", default=None, help="Provider API base URL")
    parser.add_argument("--api-key", default=None, help="Provider API key (prefer configuration/env)")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


__all__ = ["add_parser", "handle"]
