"""Sourcehunt CLI subcommand — runs the Clearwing source-code vulnerability pipeline."""

import logging
import os
import sys


def _format_budget(budget: float) -> str:
    if budget <= 0:
        return "unlimited"
    return f"${budget:.2f}"


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "sourcehunt",
        help="Source-code vulnerability hunting (source-hunt pipeline)",
    )
    parser.add_argument("repo", help="Git URL or local path to a repository")
    parser.add_argument("--branch", default="main", help="Git branch to clone (default: main)")
    parser.add_argument(
        "--local-path", metavar="PATH", help="Use this local path instead of cloning"
    )
    parser.add_argument(
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Hunt depth (default: standard)",
    )
    parser.add_argument(
        "--agent-mode",
        choices=["auto", "constrained", "deep"],
        default="auto",
        dest="agent_mode",
        help="Agent mode: 'auto' derives from --depth, 'constrained' forces legacy "
        "9-tool hunter, 'deep' forces full-shell agent (default: auto)",
    )
    parser.add_argument(
        "--prompt-mode",
        choices=["unconstrained", "specialist"],
        default="unconstrained",
        dest="prompt_mode",
        help="Prompt mode: 'unconstrained' uses a simple discovery prompt "
        "(default), 'specialist' uses legacy prescriptive checklists",
    )
    parser.add_argument(
        "--campaign-hint",
        default=None,
        dest="campaign_hint",
        metavar="OBJECTIVE",
        help="Campaign objective hint, e.g. 'bugs reachable from unauthenticated remote input'",
    )
    parser.add_argument(
        "--exploit",
        action="store_true",
        default=False,
        dest="exploit_mode",
        help="Instruct hunters to write exploits for found vulnerabilities",
    )
    parser.add_argument(
        "--starting-band",
        choices=["fast", "standard", "deep"],
        default=None,
        dest="starting_band",
        help="Override starting band for all runs (default: auto from --depth)",
    )
    parser.add_argument(
        "--redundancy",
        type=int,
        default=None,
        metavar="N",
        help="Override redundancy count for high-ranked files (default: auto from priority)",
    )
    parser.add_argument(
        "--shard-entry-points",
        action="store_true",
        default=False,
        dest="shard_entry_points",
        help="Shard agents by function-level entry point for high-ranked files "
        "(auto-enabled at --depth deep)",
    )
    parser.add_argument(
        "--min-shard-rank",
        type=int,
        default=4,
        dest="min_shard_rank",
        metavar="N",
        help="Minimum file rank for entry-point sharding (default: 4)",
    )
    parser.add_argument(
        "--subsystem-hunt",
        action="store_true",
        default=False,
        dest="subsystem_hunt",
        help="Enable cross-subsystem hunting after per-file hunts. "
        "Auto-identifies subsystems from ranked files.",
    )
    parser.add_argument(
        "--subsystem",
        action="append",
        default=[],
        metavar="PATH",
        dest="subsystem_paths",
        help="Manually specify a subsystem directory to hunt (repeatable). "
        "Implies --subsystem-hunt. Example: --subsystem net/ipv4/",
    )
    parser.add_argument(
        "--no-per-file-hunt",
        action="store_true",
        default=False,
        dest="no_per_file_hunt",
        help="Skip per-file hunting; only run subsystem hunts.",
    )
    parser.add_argument(
        "--seed-corpus",
        default=None,
        dest="seed_corpus",
        metavar="PATH",
        help="Path to a local seed corpus directory",
    )
    parser.add_argument(
        "--seed-cves",
        action="store_true",
        default=False,
        dest="seed_cves",
        help="Auto-extract CVE history from git log as seed context",
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=0.0,
        metavar="USD",
        help="Max dollars to spend (default: unlimited; 0 = unlimited)",
    )
    parser.add_argument(
        "--max-parallel", type=int, default=8, help="Max concurrent hunters (default: 8)"
    )
    parser.add_argument(
        "--tier-split",
        default="70/25/5",
        help="Budget split A/B/C as percentages "
        "(default: 70/25/5; e.g. 60/30/10 for more propagation audits)",
    )
    parser.add_argument(
        "--skip-tier-c",
        action="store_true",
        help="Disable Tier C propagation audits (faster, misses root-cause-in-boring-files bugs)",
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Skip the independent-context verifier pass"
    )
    parser.add_argument(
        "--no-adversarial",
        action="store_true",
        help="Disable adversarial verifier (use the simpler v0.1 prompt)",
    )
    parser.add_argument(
        "--adversarial-threshold",
        default="static_corroboration",
        choices=[
            "suspicion",
            "static_corroboration",
            "crash_reproduced",
            "root_cause_explained",
            "always",
        ],
        help="Minimum evidence level to spend adversarial-verifier "
        'budget on. "always" disables the gate; default is '
        "static_corroboration.",
    )
    parser.add_argument(
        "--validator-mode",
        choices=["v1", "v2"],
        default="v2",
        dest="validator_mode",
        help="Validation mode: v1 (legacy verifier) or v2 (4-axis validator, default).",
    )
    parser.add_argument(
        "--calibrate",
        metavar="SESSION_ID",
        default=None,
        help="Interactively assign human severity ratings for calibration tracking.",
    )
    parser.add_argument("--no-exploit", action="store_true", help="Skip the exploit-triage pass")
    parser.add_argument(
        "--exploit-budget",
        choices=["standard", "deep", "campaign"],
        default=None,
        dest="exploit_budget",
        help="Exploit development budget band (default: auto from --depth). "
             "standard=$25/1hr, deep=$200/4hr, campaign=$2000/12hr.",
    )
    parser.add_argument(
        "--elaborate",
        metavar="FINDING_ID",
        default=None,
        help="Launch interactive HITL session to elaborate a finding from a previous run.",
    )
    parser.add_argument(
        "--elaborate-auto",
        action="store_true",
        default=False,
        dest="elaborate_auto",
        help="Run autonomous elaboration agent (no human guidance).",
    )
    parser.add_argument(
        "--elaborate-top",
        type=int,
        default=None,
        dest="elaborate_top",
        metavar="N",
        help="Elaborate on the top N findings by severity/primitive quality.",
    )
    parser.add_argument(
        "--elaborate-cap",
        default=None,
        dest="elaborate_cap",
        metavar="PERCENT_OR_INT",
        help="Cap elaboration at N%% of verified findings or absolute count (default: 10%%).",
    )
    parser.add_argument(
        "--elaborate-session",
        default=None,
        dest="elaborate_session",
        metavar="SESSION_ID",
        help="Session ID to load findings from (for --elaborate modes).",
    )
    parser.add_argument(
        "--elaborate-pipeline",
        action="store_true",
        default=False,
        dest="elaborate_pipeline",
        help="Enable Stage 1.5 elaboration in the pipeline (autonomous, top 10%%).",
    )
    parser.add_argument(
        "--no-variant-loop",
        action="store_true",
        help="Skip the variant hunter loop (v0.3 compounding)",
    )
    parser.add_argument(
        "--no-mechanism-memory", action="store_true", help="Skip cross-run mechanism memory (v0.3)"
    )
    parser.add_argument(
        "--no-patch-oracle", action="store_true", help="Skip the patch-oracle truth test (v0.3)"
    )
    parser.add_argument(
        "--no-stability-check",
        action="store_true",
        help="Skip the PoC stability verification (Stage 2.5)",
    )
    parser.add_argument(
        "--no-findings-pool",
        action="store_true",
        help="Disable the shared findings pool (dedup + cross-agent queries)",
    )
    parser.add_argument(
        "--gvisor", action="store_true",
        help="Use gVisor runtime for container isolation",
    )
    parser.add_argument(
        "--encrypt-artifacts", action="store_true",
        help="Enable encrypted artifact storage",
    )
    parser.add_argument(
        "--no-behavior-monitor", action="store_true",
        help="Disable behavioral monitoring",
    )
    parser.add_argument(
        "--auto-patch", action="store_true", help="Enable auto-patch mode (v0.3 — opt-in)"
    )
    parser.add_argument(
        "--auto-pr",
        action="store_true",
        help="Open draft PRs for validated auto-patches via gh CLI",
    )
    parser.add_argument(
        "--export-disclosures",
        action="store_true",
        help="Write MITRE + HackerOne disclosure templates for "
        "verified findings (evidence_level >= root_cause_explained)",
    )
    parser.add_argument(
        "--reporter-name", default="(your name)", help="Reporter name for disclosure templates"
    )
    parser.add_argument(
        "--reporter-affiliation",
        default="(your affiliation)",
        help="Reporter affiliation for disclosure templates",
    )
    parser.add_argument(
        "--reporter-email",
        default="(your email)",
        help="Reporter contact email for disclosure templates",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch mode: poll git for new commits and re-scan the blast radius",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=300,
        help="Watch mode poll interval in seconds (default: 300)",
    )
    parser.add_argument(
        "--max-watch-iterations",
        type=int,
        default=0,
        help="Watch mode max iterations (0 = infinite)",
    )
    parser.add_argument(
        "--github-checks",
        action="store_true",
        help="Watch mode: post findings as GitHub check runs "
        "via the `gh` CLI. Requires gh to be installed "
        "and authenticated (gh auth login).",
    )
    parser.add_argument(
        "--github-check-name",
        default="Clearwing Sourcehunt",
        help="Name of the check run (default: Clearwing Sourcehunt)",
    )
    parser.add_argument(
        "--webhook",
        action="store_true",
        help="Webhook mode: start an HTTP server that receives "
        "GitHub push events and runs sourcehunt on each commit. "
        "Complements --watch (poll-based).",
    )
    parser.add_argument(
        "--webhook-port", type=int, default=8787, help="Webhook listen port (default: 8787)"
    )
    parser.add_argument(
        "--webhook-host", default="0.0.0.0", help="Webhook listen host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--webhook-secret",
        default=None,
        help="HMAC-SHA256 shared secret. Falls back to GITHUB_WEBHOOK_SECRET env var.",
    )
    parser.add_argument(
        "--webhook-allowed-repo",
        action="append",
        default=[],
        metavar="OWNER/REPO",
        help="Only accept pushes from this repo (repeatable). "
        "Empty = allow all repos that pass HMAC verification.",
    )
    parser.add_argument(
        "--webhook-allowed-branch",
        action="append",
        default=[],
        metavar="BRANCH",
        help="Only scan pushes to this branch (repeatable). Empty = allow all branches.",
    )
    parser.add_argument(
        "--retro-hunt",
        metavar="CVE_ID",
        help="Retro-hunt mode: given a CVE ID + --patch-source, "
        "generate a Semgrep rule from the fix and find variants",
    )
    parser.add_argument(
        "--patch-source",
        metavar="PATH_OR_SHA",
        help="Patch source for --retro-hunt (local diff file or git SHA)",
    )
    parser.add_argument(
        "--patch-repo",
        metavar="REPO",
        help="Repository to resolve --patch-source git SHAs from "
        "(defaults to the retro-hunt target repo)",
    )
    parser.add_argument(
        "--nday", action="store_true", default=False,
        help="N-day exploit pipeline mode",
    )
    parser.add_argument(
        "--cve-list", metavar="PATH", default=None,
        help="File with CVE IDs for --nday (one per line: CVE-ID [commit_sha])",
    )
    parser.add_argument(
        "--cve", metavar="CVE_ID", default=None,
        help="Single CVE to exploit in --nday mode",
    )
    parser.add_argument(
        "--patch-commit", metavar="SHA", default=None,
        help="Git SHA of the patch commit for --nday --cve",
    )
    parser.add_argument(
        "--recent-cves", action="store_true", default=False,
        help="Auto-discover recent CVEs from git history for --nday",
    )
    parser.add_argument(
        "--nday-days", type=int, default=90,
        help="Days to look back for --recent-cves (default: 90)",
    )
    parser.add_argument(
        "--nday-budget",
        choices=["standard", "deep", "campaign"],
        default="deep",
        help="Budget band per CVE in --nday mode (default: deep)",
    )
    parser.add_argument(
        "--model", default=None, help="Override all role models with one model name"
    )
    parser.add_argument(
        "--base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible API base URL. Point at OpenRouter, Ollama "
        "(http://localhost:11434/v1), LM Studio (http://localhost:1234/v1), "
        "vLLM, Together, Groq, etc. Overrides ANTHROPIC_API_KEY for this run. "
        "Also settable via the CLEARWING_BASE_URL env var.",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API key for the --base-url endpoint. Also settable via the "
        "CLEARWING_API_KEY env var. Use any placeholder for fully-local "
        "endpoints like Ollama / LM Studio that ignore it.",
    )
    parser.add_argument(
        "--output-dir",
        default="./sourcehunt-results",
        help="Output directory (default: ./sourcehunt-results)",
    )
    parser.add_argument(
        "--format",
        nargs="+",
        choices=["sarif", "markdown", "json", "all"],
        default=["all"],
        help="Output formats to write (default: all)",
    )
    return parser


def handle(cli, args):
    """Run the sourcehunt pipeline."""
    from ...providers import ProviderManager, resolve_llm_endpoint
    from ...sourcehunt.pool import TierBudget
    from ...sourcehunt.runner import SourceHuntRunner

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", force=True)

    # Resolve the LLM endpoint once at the top of the command.
    # CLI > env > ~/.clearwing/config.yaml > ANTHROPIC_API_KEY default.
    endpoint = resolve_llm_endpoint(
        cli_model=args.model,
        cli_base_url=getattr(args, "base_url", None),
        cli_api_key=getattr(args, "api_key", None),
        config_provider=cli.config.get_provider_section() or None,
    )
    cli.console.print(f"[dim]LLM endpoint: {endpoint.describe()}[/dim]")
    provider_manager = ProviderManager.for_endpoint(endpoint)

    # Parse tier-split
    try:
        a, b, c = (int(x) / 100.0 for x in args.tier_split.split("/"))
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
    if "all" in formats:
        formats = ["sarif", "markdown", "json"]

    # Retro-hunt mode dispatches to the RetroHunter
    if args.retro_hunt:
        from ...sourcehunt.retro_hunt import RetroHunter

        if not args.patch_source:
            cli.console.print("[red]Error: --retro-hunt requires --patch-source[/red]")
            sys.exit(1)
        # Build an LLM for rule generation via the same resolved
        # endpoint as the rest of the pipeline.
        try:
            llm = provider_manager.get_llm("default")
        except Exception as e:
            cli.console.print(f"[red]Could not build LLM: {e}[/red]")
            cli.console.print(
                "[red]Set ANTHROPIC_API_KEY, CLEARWING_BASE_URL, "
                "or pass --base-url/--api-key.[/red]"
            )
            sys.exit(1)

        cli.console.print(f"[bold blue]Retro-hunting {args.retro_hunt} in {args.repo}[/bold blue]")
        hunter = RetroHunter(llm=llm)
        result = hunter.hunt(
            cve_id=args.retro_hunt,
            patch_source=args.patch_source,
            target_repo_path=args.local_path or args.repo,
            repo_path_for_git_source=args.patch_repo or args.local_path or args.repo,
        )
        cli.console.print("\n[bold]Retro-hunt complete[/bold]")
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

    # N-day exploit pipeline
    if args.nday:
        import asyncio

        from ...sourcehunt.nday import NdayPipeline
        from ...sourcehunt.nday_filter import NdayCandidate, fetch_recent_cves, parse_cve_list

        candidates: list[NdayCandidate] = []
        if args.cve:
            candidates = [NdayCandidate(
                cve_id=args.cve, patch_source=args.patch_commit or "",
            )]
        elif args.cve_list:
            candidates = parse_cve_list(args.cve_list)
        elif args.recent_cves:
            candidates = fetch_recent_cves(
                args.local_path or args.repo, args.nday_days,
            )
        else:
            cli.console.print(
                "[red]Error: --nday requires --cve, --cve-list, or --recent-cves[/red]"
            )
            sys.exit(1)

        if not candidates:
            cli.console.print("[yellow]No CVE candidates found.[/yellow]")
            sys.exit(0)

        try:
            llm = provider_manager.get_llm("default")
        except Exception as e:
            cli.console.print(f"[red]Could not build LLM: {e}[/red]")
            sys.exit(1)

        cli.console.print(
            f"[bold blue]N-day pipeline: {len(candidates)} CVEs "
            f"(budget={args.nday_budget})[/bold blue]"
        )

        pipeline = NdayPipeline(
            llm=llm,
            repo_path=args.local_path or args.repo,
            budget_band=args.nday_budget,
            project=args.repo,
            output_dir=args.output_dir,
        )
        result = asyncio.run(pipeline.arun(candidates))

        cli.console.print("\n[bold]N-day pipeline complete[/bold]")
        cli.console.print(f"  Total CVEs: {result.total_cves}")
        cli.console.print(f"  Filtered: {result.filtered_cves}")
        cli.console.print(f"  Attempted: {result.attempted}")
        cli.console.print(f"  Exploited: {result.exploited}")
        cli.console.print(f"  Partial: {result.partial}")
        cli.console.print(f"  Failed: {result.failed}")
        cli.console.print(f"  Build failed: {result.build_failed}")
        cli.console.print(f"  Cost: ${result.total_cost_usd:.2f}")
        cli.console.print(f"  Duration: {result.duration_seconds:.1f}s")

        for r in result.results:
            if r.status == "exploited":
                cli.console.print(f"  [green]✓ {r.cve_id} — exploited[/green]")
            elif r.status == "partial":
                cli.console.print(f"  [yellow]~ {r.cve_id} — partial[/yellow]")
            elif r.status == "filtered":
                cli.console.print(f"  [dim]- {r.cve_id} — filtered[/dim]")

        sys.exit(0)

    # Elaborate mode: interactive HITL or autonomous agent
    if args.elaborate or args.elaborate_auto:
        from ...sourcehunt.elaboration import (
            ElaborationAgent,
            find_latest_session,
            load_finding_from_session,
            load_session_findings,
            prioritize_for_elaboration,
        )

        session_id = args.elaborate_session or find_latest_session(
            args.output_dir,
        )
        if not session_id:
            cli.console.print(
                "[red]No session found. Use --elaborate-session SESSION_ID.[/red]"
            )
            sys.exit(1)

        if args.elaborate:
            finding = load_finding_from_session(
                args.output_dir, session_id, args.elaborate,
            )
            if finding is None:
                cli.console.print(
                    f"[red]Finding {args.elaborate} not found in session {session_id}[/red]"
                )
                sys.exit(1)
            _run_elaborate_interactive(
                cli, args, finding, session_id, endpoint, provider_manager,
            )
        else:
            all_findings = load_session_findings(args.output_dir, session_id)
            verified = [f for f in all_findings if f.get("verified")]
            cap = args.elaborate_top or args.elaborate_cap or "10%"
            targets = prioritize_for_elaboration(verified, cap)
            if not targets:
                cli.console.print("[yellow]No findings eligible for elaboration.[/yellow]")
                sys.exit(0)
            _run_elaborate_auto(
                cli, args, targets, session_id, endpoint, provider_manager,
            )
        sys.exit(0)

    # Calibrate mode: assign human severity ratings for calibration tracking
    if args.calibrate:
        from ...sourcehunt.calibration import CalibrationStore
        from ...sourcehunt.elaboration import load_session_findings

        session_id = args.calibrate
        all_findings = load_session_findings(args.output_dir, session_id)
        verified = [f for f in all_findings if f.get("verified")]
        if not verified:
            cli.console.print(
                f"[yellow]No verified findings in session {session_id}[/yellow]"
            )
            sys.exit(0)

        store = CalibrationStore()
        cli.console.print(
            f"[bold blue]Calibrating {len(verified)} verified findings "
            f"from session {session_id}[/bold blue]"
        )
        for f in verified:
            fid = f.get("id", "?")
            sev = (f.get("severity_verified") or f.get("severity") or "?").upper()
            desc = f.get("description", "")[:80]
            cli.console.print(f"\n  [{sev}] {fid}: {desc}")
            human = input("  Human severity (critical/high/medium/low/info, or skip): ").strip().lower()
            if human in ("critical", "high", "medium", "low", "info"):
                store.record_human_verdict(fid, session_id, human)
                cli.console.print(f"  Recorded: {human}")
            else:
                cli.console.print("  Skipped")

        stats = store.stats()
        cli.console.print(f"\n[bold]Calibration stats:[/bold]")
        cli.console.print(f"  Total records: {stats['total_records']}")
        cli.console.print(f"  Human reviewed: {stats['human_reviewed']}")
        cli.console.print(f"  Exact match rate: {stats['exact_match_rate']:.1%}")
        cli.console.print(f"  Within-one rate: {stats['within_one_rate']:.1%}")
        sys.exit(0)

    # Webhook mode: start an HTTP server that runs sourcehunt on each commit
    if args.webhook:
        from ...sourcehunt.commit_monitor import CommitMonitor, CommitMonitorConfig
        from ...sourcehunt.webhook_server import (
            WebhookConfig,
            commit_monitor_on_push_factory,
            serve_forever,
        )

        local_path = args.local_path or args.repo
        if not os.path.isdir(local_path):
            cli.console.print(
                f"[red]Error: webhook mode requires a local git clone path, got '{local_path}'[/red]"
            )
            sys.exit(1)

        secret = args.webhook_secret or os.environ.get("GITHUB_WEBHOOK_SECRET", "")
        if not secret:
            cli.console.print(
                "[red]Error: webhook mode requires a shared secret "
                "(--webhook-secret or GITHUB_WEBHOOK_SECRET env)[/red]"
            )
            sys.exit(1)

        monitor = CommitMonitor(
            CommitMonitorConfig(
                repo_path=os.path.abspath(local_path),
                branch=args.branch,
                depth=args.depth,
                budget_usd=args.budget,
                output_dir=args.output_dir,
                enable_github_checks=args.github_checks,
                github_check_name=args.github_check_name,
            )
        )
        cli.console.print(
            f"[bold blue]Webhook server: {args.webhook_host}:{args.webhook_port} "
            f"(depth={args.depth}, budget={_format_budget(args.budget)})[/bold blue]"
        )
        if args.webhook_allowed_repo:
            cli.console.print(f"  allowed repos: {', '.join(args.webhook_allowed_repo)}")
        if args.webhook_allowed_branch:
            cli.console.print(f"  allowed branches: {', '.join(args.webhook_allowed_branch)}")
        serve_forever(
            WebhookConfig(
                host=args.webhook_host,
                port=args.webhook_port,
                secret=secret,
                allowed_repos=args.webhook_allowed_repo,
                allowed_branches=args.webhook_allowed_branch,
                on_push=commit_monitor_on_push_factory(monitor),
            )
        )
        sys.exit(0)

    # Watch mode dispatches to the CommitMonitor instead of a one-shot runner
    if args.watch:
        from ...sourcehunt.commit_monitor import CommitMonitor, CommitMonitorConfig

        local_path = args.local_path or args.repo
        if not os.path.isdir(local_path):
            cli.console.print(
                f"[red]Error: watch mode requires a local git clone path, got '{local_path}'[/red]"
            )
            sys.exit(1)
        monitor = CommitMonitor(
            CommitMonitorConfig(
                repo_path=os.path.abspath(local_path),
                branch=args.branch,
                poll_interval_seconds=args.poll_interval,
                max_iterations=args.max_watch_iterations,
                output_dir=args.output_dir,
                depth=args.depth,
                budget_usd=args.budget,
                enable_github_checks=args.github_checks,
                github_check_name=args.github_check_name,
            )
        )
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

    if args.no_per_file_hunt and not args.subsystem_hunt and not args.subsystem_paths:
        cli.console.print(
            "[red]Error: --no-per-file-hunt requires --subsystem-hunt or --subsystem[/red]"
        )
        sys.exit(1)

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
        exploit_budget=args.exploit_budget,
        enable_elaboration=args.elaborate_pipeline,
        adversarial_verifier=not args.no_adversarial,
        adversarial_threshold=(
            None if args.adversarial_threshold == "always" else args.adversarial_threshold
        ),
        validator_mode=args.validator_mode,
        enable_variant_loop=not args.no_variant_loop,
        enable_mechanism_memory=not args.no_mechanism_memory,
        enable_patch_oracle=not args.no_patch_oracle,
        enable_stability_verification=not args.no_stability_check,
        enable_auto_patch=args.auto_patch,
        auto_pr=args.auto_pr,
        export_disclosures=args.export_disclosures,
        disclosure_reporter_name=args.reporter_name,
        disclosure_reporter_affiliation=args.reporter_affiliation,
        disclosure_reporter_email=args.reporter_email,
        model_override=args.model,
        provider_manager=provider_manager,
        agent_mode=args.agent_mode,
        prompt_mode=args.prompt_mode,
        campaign_hint=args.campaign_hint,
        exploit_mode=args.exploit_mode,
        starting_band=args.starting_band,
        redundancy_override=args.redundancy,
        shard_entry_points=True if args.shard_entry_points else None,
        min_shard_rank=args.min_shard_rank,
        seed_corpus_sources=(
            (["git_cve"] if args.seed_cves else []) or None
        ),
        enable_findings_pool=not args.no_findings_pool,
        enable_subsystem_hunt=args.subsystem_hunt or bool(args.subsystem_paths),
        subsystem_paths=args.subsystem_paths or None,
        no_per_file_hunt=args.no_per_file_hunt,
        enable_behavior_monitor=not getattr(args, "no_behavior_monitor", False),
        enable_artifact_store=getattr(args, "encrypt_artifacts", False),
        gvisor_runtime="runsc" if getattr(args, "gvisor", False) else None,
    )

    cli.console.print(
        f"[bold blue]Sourcehunt: {args.repo} depth={args.depth} "
        f"budget={_format_budget(args.budget)}[/bold blue]"
    )

    try:
        result = runner.run()
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Sourcehunt cancelled by user[/yellow]")
        sys.exit(130)
    except (ValueError, RuntimeError) as exc:
        cli.console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)

    # Summary
    cli.console.print("\n[bold]Sourcehunt complete[/bold]")
    cli.console.print(f"  Session: {result.session_id}")
    cli.console.print(f"  Duration: {result.duration_seconds:.1f}s")
    cli.console.print(f"  Files ranked: {result.files_ranked}")
    cli.console.print(f"  Files hunted: {result.files_hunted}")
    cli.console.print(
        f"  Findings: {len(result.findings)} ({len(result.verified_findings)} verified)"
    )
    cli.console.print(f"  Critical: {result.critical_count}, High: {result.high_count}")
    cli.console.print(f"  Spend: ${result.cost_usd:.4f}")
    spt = result.spent_per_tier
    cli.console.print(
        f"    A=${spt.get('A', 0):.4f}  B=${spt.get('B', 0):.4f}  C=${spt.get('C', 0):.4f}"
    )

    if result.output_paths:
        cli.console.print("  Outputs:")
        for fmt, path in result.output_paths.items():
            cli.console.print(f"    {fmt}: {path}")

    # Top findings
    if result.findings:
        cli.console.print("\n[bold]Top findings:[/bold]")
        for f in result.findings[:5]:
            sev = (f.get("severity_verified") or f.get("severity", "info")).upper()
            file = f.get("file", "?")
            line = f.get("line_number", "?")
            desc = f.get("description", "")[:80]
            cli.console.print(f"  [{sev}] {file}:{line} — {desc}")

    sys.exit(result.exit_code)


# --- Elaborate helpers -------------------------------------------------------


def _run_elaborate_interactive(cli, args, finding, session_id, endpoint, provider_manager):
    """Launch an interactive HITL elaboration session."""
    import asyncio
    import json

    from rich.prompt import Prompt

    from ...sourcehunt.elaboration import (
        ElaborationAgent,
        _build_elaboration_prompt,
        build_elaboration_tools,
    )

    cli.console.print(f"\n[bold blue]Elaboration session for {finding.get('id', '?')}[/bold blue]")
    cli.console.print(f"  File: {finding.get('file', '?')}:{finding.get('line_number', '?')}")
    cli.console.print(f"  CWE: {finding.get('cwe', 'N/A')}")
    cli.console.print(
        f"  Current impact: "
        f"{finding.get('exploit_impact') or finding.get('impact') or 'unknown'}"
    )
    cli.console.print(
        f"  Primitive: "
        f"{finding.get('exploit_primitive_type') or finding.get('primitive_type') or 'unknown'}"
    )
    cli.console.print("\nType your guidance to upgrade the exploit. Type 'quit' to end.\n")

    try:
        llm = provider_manager.get_llm("default")
    except Exception as e:
        cli.console.print(f"[red]Could not build LLM: {e}[/red]")
        sys.exit(1)

    system_prompt = _build_elaboration_prompt(finding)
    messages: list[dict] = [
        {"role": "user", "content": (
            f"I'm working with you to upgrade the exploit for finding {finding.get('id', '?')}. "
            f"The current impact is {finding.get('exploit_impact') or 'unknown'}. "
            f"Let's start by reviewing what we have."
        )},
    ]

    from ...agent.tools.hunt.sandbox import HunterContext

    ctx = HunterContext(
        repo_path="/workspace",
        file_path=finding.get("file"),
        session_id=f"elaborate-hitl-{session_id}",
        specialist="elaboration",
    )
    tools = build_elaboration_tools(ctx, finding)
    tool_schemas = [{"name": t.name, "description": t.description, "input_schema": t.schema} for t in tools]
    tool_handlers = {t.name: t.handler for t in tools}

    total_cost = 0.0

    async def _chat_turn(user_input: str) -> str:
        nonlocal total_cost
        messages.append({"role": "user", "content": user_input})
        try:
            response = await llm.achat(
                messages=messages,
                system=system_prompt,
                tools=tool_schemas,
            )
        except Exception as e:
            return f"[red]LLM error: {e}[/red]"

        assistant_text = ""
        content_blocks = response.content if hasattr(response, "content") else []
        for block in content_blocks:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    assistant_text += block.get("text", "")
                elif block.get("type") == "tool_use":
                    tool_name = block.get("name", "")
                    tool_input = block.get("input", {})
                    handler = tool_handlers.get(tool_name)
                    if handler:
                        try:
                            tool_result = handler(**tool_input)
                            cli.console.print(f"  [dim]Tool {tool_name}: {tool_result}[/dim]")
                        except Exception as e:
                            cli.console.print(f"  [red]Tool {tool_name} error: {e}[/red]")

        messages.append({"role": "assistant", "content": content_blocks})
        if hasattr(response, "usage"):
            usage = response.usage
            if hasattr(usage, "cost_usd"):
                total_cost += usage.cost_usd

        return assistant_text

    while True:
        try:
            user_input = Prompt.ask("[bold green]You[/bold green]")
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.strip().lower() in ("quit", "exit", "done"):
            break
        if not user_input.strip():
            continue

        result_text = asyncio.run(_chat_turn(user_input))
        if result_text:
            cli.console.print(f"\n[bold blue]Assistant[/bold blue]: {result_text}\n")

        if ctx.elaboration_result is not None:
            break

    if ctx.elaboration_result is not None:
        ctx.elaboration_result.human_guided = True
        ctx.elaboration_result.cost = total_cost
        result = ctx.elaboration_result
        cli.console.print("\n[bold]Elaboration result:[/bold]")
        cli.console.print(f"  Elaborated: {result.elaborated}")
        if result.upgraded_impact:
            cli.console.print(f"  Upgraded impact: {result.upgraded_impact}")
        if result.upgrade_path:
            cli.console.print(f"  Upgrade path: {result.upgrade_path}")
        if result.blocking_mitigations:
            cli.console.print(f"  Blocking: {', '.join(result.blocking_mitigations)}")

        out_dir = os.path.join(args.output_dir, session_id, "elaborations")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{finding.get('id', 'unknown')}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result.__dict__, f, indent=2, default=str)
        cli.console.print(f"  Saved: {out_path}")
    else:
        cli.console.print("\n[yellow]Session ended without recording a result.[/yellow]")

    cli.console.print(f"  Total cost: ${total_cost:.4f}")


def _run_elaborate_auto(cli, args, targets, session_id, endpoint, provider_manager):
    """Run autonomous elaboration on a list of findings."""
    import asyncio
    import json

    from ...sourcehunt.elaboration import ElaborationAgent

    cli.console.print(
        f"\n[bold blue]Autonomous elaboration: {len(targets)} findings[/bold blue]"
    )

    try:
        llm = provider_manager.get_llm("default")
    except Exception as e:
        cli.console.print(f"[red]Could not build LLM: {e}[/red]")
        sys.exit(1)

    agent = ElaborationAgent(
        llm=llm,
        output_dir=args.output_dir,
        project_name=args.repo.split("/")[-1] if args.repo else "target",
    )

    async def _run_all():
        results = []
        for i, finding in enumerate(targets, 1):
            fid = finding.get("id", "?")
            cli.console.print(f"\n[bold]({i}/{len(targets)}) Elaborating {fid}...[/bold]")
            result = await agent.aattempt(finding)
            results.append(result)
            status = "[green]UPGRADED[/green]" if result.elaborated else "[yellow]NOT UPGRADED[/yellow]"
            cli.console.print(f"  Result: {status}")
            if result.upgraded_impact:
                cli.console.print(f"  Upgraded impact: {result.upgraded_impact}")
            if result.upgrade_path:
                cli.console.print(f"  Path: {result.upgrade_path}")
            if result.blocking_mitigations:
                cli.console.print(f"  Blocking: {', '.join(result.blocking_mitigations)}")
        return results

    results = asyncio.run(_run_all())

    out_dir = os.path.join(args.output_dir, session_id, "elaborations")
    os.makedirs(out_dir, exist_ok=True)
    for r in results:
        out_path = os.path.join(out_dir, f"{r.original_finding_id}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(r.__dict__, f, indent=2, default=str)

    upgraded = sum(1 for r in results if r.elaborated)
    total_cost = sum(r.cost for r in results)
    cli.console.print(f"\n[bold]Elaboration complete: {upgraded}/{len(results)} upgraded[/bold]")
    cli.console.print(f"  Total cost: ${total_cost:.4f}")
    cli.console.print(f"  Results saved: {out_dir}")
