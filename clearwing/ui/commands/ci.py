"""CI/CD subcommand."""

import sys


def add_parser(subparsers):
    parser = subparsers.add_parser('ci', help='Run non-interactive CI/CD scan')
    parser.add_argument('--target', required=True, help='Target URL or IP address')
    parser.add_argument('--depth', choices=['quick', 'standard', 'deep'],
                        default='quick', help='Scan depth (default: quick)')
    parser.add_argument('--output', choices=['json', 'sarif'],
                        default='json', help='Output format (default: json)')
    parser.add_argument('--output-path', metavar='FILE',
                        help='Write results to file')
    parser.add_argument('--cost-limit', type=float, metavar='DOLLARS',
                        help='Stop when estimated cost exceeds this amount (USD)')
    parser.add_argument('--timeout', type=int, default=30, metavar='MINUTES',
                        help='Timeout in minutes (default: 30)')
    parser.add_argument('--model', default='claude-sonnet-4-6',
                        help='LLM model name (default: claude-sonnet-4-6)')
    parser.add_argument('--base-url', metavar='URL',
                        help='OpenAI-compatible API base URL')
    parser.add_argument('--api-key', metavar='KEY',
                        help='API key for the endpoint')
    return parser


def handle(cli, args):
    """Run a non-interactive CI/CD scan."""
    from ...runners.cicd import CICDRunner

    runner = CICDRunner(
        target=args.target,
        depth=args.depth,
        model=args.model,
        output_format=args.output,
        output_path=args.output_path,
        cost_limit=args.cost_limit,
        timeout_minutes=args.timeout,
        base_url=getattr(args, 'base_url', None),
        api_key=getattr(args, 'api_key', None),
    )

    cli.console.print(
        f"[bold blue]CI/CD scan: target={args.target} depth={args.depth} "
        f"format={args.output}[/bold blue]"
    )

    try:
        result = runner.run()
    except ValueError as exc:
        cli.console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)

    cli.console.print(f"\n[bold]Scan complete[/bold]")
    cli.console.print(f"  Duration: {result.duration_seconds:.1f}s")
    cli.console.print(f"  Findings: {len(result.findings)}")
    cli.console.print(f"  Cost: ${result.cost_usd:.4f}")
    cli.console.print(f"  Tokens: {result.tokens_used}")

    if result.output_path:
        cli.console.print(f"  Output: {result.output_path}")

    for finding in result.findings:
        sev = finding.get("severity", "info").upper()
        desc = finding.get("description", "")
        cli.console.print(f"  [{sev}] {desc}")

    sys.exit(result.exit_code)
