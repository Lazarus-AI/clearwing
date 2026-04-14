"""Parallel scanning subcommand."""

import sys


def add_parser(subparsers):
    parser = subparsers.add_parser("parallel", help="Scan multiple targets in parallel")
    parser.add_argument(
        "--targets", required=True, help="Comma-separated list of target IPs or hostnames"
    )
    parser.add_argument(
        "--max-parallel", type=int, default=3, help="Maximum number of parallel scans (default: 3)"
    )
    parser.add_argument(
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan depth (default: standard)",
    )
    parser.add_argument(
        "--cost-limit",
        type=float,
        metavar="DOLLARS",
        help="Total cost limit across all targets (USD)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="MINUTES",
        help="Per-target timeout in minutes (default: 30)",
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-6", help="LLM model name (default: claude-sonnet-4-6)"
    )
    parser.add_argument("--base-url", metavar="URL", help="OpenAI-compatible API base URL")
    parser.add_argument("--api-key", metavar="KEY", help="API key for the endpoint")
    return parser


def handle(cli, args):
    """Run parallel scans against multiple targets."""
    from ...runners.parallel import ParallelExecutor, ParallelScanConfig

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets:
        cli.console.print("[red]Error: No targets specified.[/red]")
        sys.exit(1)

    def on_complete(result):
        status_style = "green" if result.status == "completed" else "red"
        cli.console.print(
            f"[{status_style}]{result.target}: {result.status} "
            f"({len(result.findings)} findings, ${result.cost_usd:.4f}, "
            f"{result.duration_seconds:.0f}s)[/{status_style}]"
        )

    config = ParallelScanConfig(
        targets=targets,
        max_parallel=args.max_parallel,
        model=args.model,
        depth=args.depth,
        timeout_minutes=args.timeout,
        total_cost_limit=args.cost_limit or 0.0,
        on_target_complete=on_complete,
        base_url=getattr(args, "base_url", None),
        api_key=getattr(args, "api_key", None),
    )

    cli.console.print(
        f"[bold blue]Parallel scan: {len(targets)} targets, "
        f"max_parallel={args.max_parallel}, depth={args.depth}[/bold blue]"
    )

    executor = ParallelExecutor(config)
    try:
        results = executor.run()
    except KeyboardInterrupt:
        executor.cancel()
        results = list(executor._results.values())
        cli.console.print("\n[yellow]Scan cancelled by user.[/yellow]")

    cli.console.print(f"\n{executor.get_summary()}")

    has_error = any(r.status == "error" for r in results)
    sys.exit(1 if has_error else 0)
