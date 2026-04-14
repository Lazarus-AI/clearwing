"""Sourcehunt CLI subcommand — runs the Overwing source-code vulnerability pipeline."""

import sys


def add_parser(subparsers):
    parser = subparsers.add_parser(
        'sourcehunt',
        help='Source-code vulnerability hunting (Overwing pipeline)',
    )
    parser.add_argument('repo', help='Git URL or local path to a repository')
    parser.add_argument('--branch', default='main',
                        help='Git branch to clone (default: main)')
    parser.add_argument('--local-path', metavar='PATH',
                        help='Use this local path instead of cloning')
    parser.add_argument('--depth', choices=['quick', 'standard', 'deep'],
                        default='standard',
                        help='Hunt depth (default: standard)')
    parser.add_argument('--budget', type=float, default=5.0, metavar='USD',
                        help='Max dollars to spend (default: 5.0)')
    parser.add_argument('--max-parallel', type=int, default=8,
                        help='Max concurrent hunters (default: 8)')
    parser.add_argument('--tier-split', default='70/25/5',
                        help='Budget split A/B/C as percentages '
                             '(default: 70/25/5; e.g. 60/30/10 for more propagation audits)')
    parser.add_argument('--skip-tier-c', action='store_true',
                        help='Disable Tier C propagation audits (faster, '
                             'misses root-cause-in-boring-files bugs)')
    parser.add_argument('--no-verify', action='store_true',
                        help='Skip the independent-context verifier pass')
    parser.add_argument('--no-adversarial', action='store_true',
                        help='Disable adversarial verifier (use the simpler v0.1 prompt)')
    parser.add_argument('--adversarial-threshold', default='static_corroboration',
                        choices=['suspicion', 'static_corroboration', 'crash_reproduced',
                                 'root_cause_explained', 'always'],
                        help='Minimum evidence level to spend adversarial-verifier '
                             'budget on. "always" disables the gate; default is '
                             'static_corroboration.')
    parser.add_argument('--no-exploit', action='store_true',
                        help='Skip the exploit-triage pass')
    parser.add_argument('--no-variant-loop', action='store_true',
                        help='Skip the variant hunter loop (v0.3 compounding)')
    parser.add_argument('--no-mechanism-memory', action='store_true',
                        help='Skip cross-run mechanism memory (v0.3)')
    parser.add_argument('--no-patch-oracle', action='store_true',
                        help='Skip the patch-oracle truth test (v0.3)')
    parser.add_argument('--auto-patch', action='store_true',
                        help='Enable auto-patch mode (v0.3 — opt-in)')
    parser.add_argument('--auto-pr', action='store_true',
                        help='Open draft PRs for validated auto-patches via gh CLI')
    parser.add_argument('--export-disclosures', action='store_true',
                        help='Write MITRE + HackerOne disclosure templates for '
                             'verified findings (evidence_level >= root_cause_explained)')
    parser.add_argument('--reporter-name', default='(your name)',
                        help='Reporter name for disclosure templates')
    parser.add_argument('--reporter-affiliation', default='(your affiliation)',
                        help='Reporter affiliation for disclosure templates')
    parser.add_argument('--reporter-email', default='(your email)',
                        help='Reporter contact email for disclosure templates')
    parser.add_argument('--watch', action='store_true',
                        help='Watch mode: poll git for new commits and re-scan the blast radius')
    parser.add_argument('--poll-interval', type=int, default=300,
                        help='Watch mode poll interval in seconds (default: 300)')
    parser.add_argument('--max-watch-iterations', type=int, default=0,
                        help='Watch mode max iterations (0 = infinite)')
    parser.add_argument('--github-checks', action='store_true',
                        help='Watch mode: post findings as GitHub check runs '
                             'via the `gh` CLI. Requires gh to be installed '
                             'and authenticated (gh auth login).')
    parser.add_argument('--github-check-name', default='Overwing Sourcehunt',
                        help='Name of the check run (default: Overwing Sourcehunt)')
    parser.add_argument('--webhook', action='store_true',
                        help='Webhook mode: start an HTTP server that receives '
                             'GitHub push events and runs sourcehunt on each commit. '
                             'Complements --watch (poll-based).')
    parser.add_argument('--webhook-port', type=int, default=8787,
                        help='Webhook listen port (default: 8787)')
    parser.add_argument('--webhook-host', default='0.0.0.0',
                        help='Webhook listen host (default: 0.0.0.0)')
    parser.add_argument('--webhook-secret', default=None,
                        help='HMAC-SHA256 shared secret. Falls back to '
                             'GITHUB_WEBHOOK_SECRET env var.')
    parser.add_argument('--webhook-allowed-repo', action='append', default=[],
                        metavar='OWNER/REPO',
                        help='Only accept pushes from this repo (repeatable). '
                             'Empty = allow all repos that pass HMAC verification.')
    parser.add_argument('--webhook-allowed-branch', action='append', default=[],
                        metavar='BRANCH',
                        help='Only scan pushes to this branch (repeatable). '
                             'Empty = allow all branches.')
    parser.add_argument('--retro-hunt', metavar='CVE_ID',
                        help='Retro-hunt mode: given a CVE ID + --patch-source, '
                             'generate a Semgrep rule from the fix and find variants')
    parser.add_argument('--patch-source', metavar='PATH_OR_SHA',
                        help='Patch source for --retro-hunt (local diff file or git SHA)')
    parser.add_argument('--patch-repo', metavar='REPO',
                        help='Repository to resolve --patch-source git SHAs from '
                             '(defaults to the retro-hunt target repo)')
    parser.add_argument('--model', default=None,
                        help='Override all role models with one model name')
    parser.add_argument('--output-dir', default='./sourcehunt-results',
                        help='Output directory (default: ./sourcehunt-results)')
    parser.add_argument('--format', nargs='+',
                        choices=['sarif', 'markdown', 'json', 'all'],
                        default=['all'],
                        help='Output formats to write (default: all)')
    return parser


def handle(cli, args):
    """Run the sourcehunt pipeline."""
    from ...sourcehunt.pool import TierBudget
    from ...sourcehunt.runner import SourceHuntRunner

    # Parse tier-split
    try:
        a, b, c = (int(x) / 100.0 for x in args.tier_split.split('/'))
    except ValueError:
        cli.console.print(
            f"[red]Error: --tier-split must be three integers like '70/25/5', got '{args.tier_split}'[/red]"
        )
        sys.exit(1)

    if args.skip_tier_c:
        # Redistribute Tier C allocation into A
        a += c
        c = 0.0

    try:
        tier_budget = TierBudget(
            tier_a_fraction=a,
            tier_b_fraction=b,
            tier_c_fraction=c,
        )
    except ValueError as e:
        cli.console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    formats = args.format
    if 'all' in formats:
        formats = ['sarif', 'markdown', 'json']

    # Retro-hunt mode dispatches to the RetroHunter
    if args.retro_hunt:
        from ...sourcehunt.retro_hunt import RetroHunter
        if not args.patch_source:
            cli.console.print(
                "[red]Error: --retro-hunt requires --patch-source[/red]"
            )
            sys.exit(1)
        # Build an LLM for rule generation
        import os
        llm = None
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                from langchain_anthropic import ChatAnthropic
                llm = ChatAnthropic(model="claude-sonnet-4-6")
            except Exception as e:
                cli.console.print(f"[red]Could not build LLM: {e}[/red]")
                sys.exit(1)
        if llm is None:
            cli.console.print(
                "[red]Error: retro-hunt requires an LLM. Set ANTHROPIC_API_KEY.[/red]"
            )
            sys.exit(1)

        cli.console.print(
            f"[bold blue]Retro-hunting {args.retro_hunt} in {args.repo}[/bold blue]"
        )
        hunter = RetroHunter(llm=llm)
        result = hunter.hunt(
            cve_id=args.retro_hunt,
            patch_source=args.patch_source,
            target_repo_path=args.local_path or args.repo,
            repo_path_for_git_source=args.patch_repo or args.local_path or args.repo,
        )
        cli.console.print(f"\n[bold]Retro-hunt complete[/bold]")
        cli.console.print(f"  CVE: {result.cve_id}")
        cli.console.print(f"  Rule: {result.rule_description}")
        cli.console.print(f"  Findings: {len(result.findings)}")
        if result.notes:
            cli.console.print(f"  Notes: {result.notes}")
        for f in result.findings[:5]:
            cli.console.print(
                f"  [{f['severity'].upper()}] {f['file']}:{f['line_number']} "
                f"— {f['description'][:80]}"
            )
        sys.exit(0)

    # Webhook mode: start an HTTP server that runs sourcehunt on each commit
    if args.webhook:
        from ...sourcehunt.commit_monitor import CommitMonitor, CommitMonitorConfig
        from ...sourcehunt.webhook_server import (
            WebhookConfig,
            commit_monitor_on_push_factory,
            serve_forever,
        )
        import os as _os

        local_path = args.local_path or args.repo
        if not os.path.isdir(local_path):
            cli.console.print(
                f"[red]Error: webhook mode requires a local git clone path, got '{local_path}'[/red]"
            )
            sys.exit(1)

        secret = args.webhook_secret or _os.environ.get("GITHUB_WEBHOOK_SECRET", "")
        if not secret:
            cli.console.print(
                "[red]Error: webhook mode requires a shared secret "
                "(--webhook-secret or GITHUB_WEBHOOK_SECRET env)[/red]"
            )
            sys.exit(1)

        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=os.path.abspath(local_path),
            branch=args.branch,
            depth=args.depth,
            budget_usd=args.budget,
            output_dir=args.output_dir,
            enable_github_checks=args.github_checks,
            github_check_name=args.github_check_name,
        ))
        cli.console.print(
            f"[bold blue]Webhook server: {args.webhook_host}:{args.webhook_port} "
            f"(depth={args.depth}, budget=${args.budget})[/bold blue]"
        )
        if args.webhook_allowed_repo:
            cli.console.print(f"  allowed repos: {', '.join(args.webhook_allowed_repo)}")
        if args.webhook_allowed_branch:
            cli.console.print(f"  allowed branches: {', '.join(args.webhook_allowed_branch)}")
        serve_forever(WebhookConfig(
            host=args.webhook_host,
            port=args.webhook_port,
            secret=secret,
            allowed_repos=args.webhook_allowed_repo,
            allowed_branches=args.webhook_allowed_branch,
            on_push=commit_monitor_on_push_factory(monitor),
        ))
        sys.exit(0)

    # Watch mode dispatches to the CommitMonitor instead of a one-shot runner
    if args.watch:
        from ...sourcehunt.commit_monitor import CommitMonitor, CommitMonitorConfig
        import os
        local_path = args.local_path or args.repo
        if not os.path.isdir(local_path):
            cli.console.print(
                f"[red]Error: watch mode requires a local git clone path, got '{local_path}'[/red]"
            )
            sys.exit(1)
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=os.path.abspath(local_path),
            branch=args.branch,
            poll_interval_seconds=args.poll_interval,
            max_iterations=args.max_watch_iterations,
            output_dir=args.output_dir,
            depth=args.depth,
            budget_usd=args.budget,
            enable_github_checks=args.github_checks,
            github_check_name=args.github_check_name,
        ))
        cli.console.print(
            f"[bold blue]Watching {local_path} every {args.poll_interval}s "
            f"(depth={args.depth})[/bold blue]"
        )
        try:
            results = monitor.run()
        except KeyboardInterrupt:
            cli.console.print("\n[yellow]Watch cancelled by user[/yellow]")
            sys.exit(0)
        cli.console.print(f"[bold]Watch complete. Processed {len(results)} commits.[/bold]")
        sys.exit(0)

    runner = SourceHuntRunner(
        repo_url=args.repo,
        branch=args.branch,
        local_path=args.local_path,
        depth=args.depth,
        budget_usd=args.budget,
        max_parallel=args.max_parallel,
        tier_budget=tier_budget,
        output_dir=args.output_dir,
        output_formats=formats,
        no_verify=args.no_verify,
        no_exploit=args.no_exploit,
        adversarial_verifier=not args.no_adversarial,
        adversarial_threshold=(
            None if args.adversarial_threshold == "always"
            else args.adversarial_threshold
        ),
        enable_variant_loop=not args.no_variant_loop,
        enable_mechanism_memory=not args.no_mechanism_memory,
        enable_patch_oracle=not args.no_patch_oracle,
        enable_auto_patch=args.auto_patch,
        auto_pr=args.auto_pr,
        export_disclosures=args.export_disclosures,
        disclosure_reporter_name=args.reporter_name,
        disclosure_reporter_affiliation=args.reporter_affiliation,
        disclosure_reporter_email=args.reporter_email,
        model_override=args.model,
    )

    cli.console.print(
        f"[bold blue]Sourcehunt: {args.repo} depth={args.depth} budget=${args.budget:.2f}[/bold blue]"
    )

    try:
        result = runner.run()
    except (ValueError, RuntimeError) as exc:
        cli.console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)

    # Summary
    cli.console.print(f"\n[bold]Sourcehunt complete[/bold]")
    cli.console.print(f"  Session: {result.session_id}")
    cli.console.print(f"  Duration: {result.duration_seconds:.1f}s")
    cli.console.print(f"  Files ranked: {result.files_ranked}")
    cli.console.print(f"  Files hunted: {result.files_hunted}")
    cli.console.print(f"  Findings: {len(result.findings)} ({len(result.verified_findings)} verified)")
    cli.console.print(f"  Critical: {result.critical_count}, High: {result.high_count}")
    cli.console.print(f"  Spend: ${result.cost_usd:.4f}")
    spt = result.spent_per_tier
    cli.console.print(
        f"    A=${spt.get('A', 0):.4f}  B=${spt.get('B', 0):.4f}  C=${spt.get('C', 0):.4f}"
    )

    if result.output_paths:
        cli.console.print(f"  Outputs:")
        for fmt, path in result.output_paths.items():
            cli.console.print(f"    {fmt}: {path}")

    # Top findings
    if result.findings:
        cli.console.print(f"\n[bold]Top findings:[/bold]")
        for f in result.findings[:5]:
            sev = (f.get("severity_verified") or f.get("severity", "info")).upper()
            file = f.get("file", "?")
            line = f.get("line_number", "?")
            desc = f.get("description", "")[:80]
            cli.console.print(f"  [{sev}] {file}:{line} — {desc}")

    sys.exit(result.exit_code)
