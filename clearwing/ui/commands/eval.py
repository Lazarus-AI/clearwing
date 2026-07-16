"""Evaluation CLI — clearwing eval (spec 018).

Subcommands:
    preprocessing   A/B test the preprocessing pipeline
    compare         Compare two eval result files
    sourcehunt-plan Build the complete Phase-0 ablation matrix
    sourcehunt-run  Execute or resume a pinned ablation matrix
    sourcehunt-observe Score completed sourcehunt sessions
    sourcehunt-baseline Aggregate precision, recall, cost, and failures
"""

from __future__ import annotations

import asyncio
import logging
import sys


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "eval",
        help="Evaluation and A/B testing",
    )
    sub = parser.add_subparsers(dest="eval_action")

    pp = sub.add_parser(
        "preprocessing",
        help="A/B test the preprocessing pipeline",
    )
    pp.add_argument(
        "--project",
        required=True,
        help="Git URL or local path to a repository",
    )
    pp.add_argument(
        "--commit",
        default="",
        help="Git commit to check out before evaluation",
    )
    pp.add_argument(
        "--configs",
        default="glasswing_minimal,sourcehunt_full",
        help="Comma-separated config names (default: glasswing_minimal,sourcehunt_full)",
    )
    pp.add_argument("--model", default=None, help="LLM model name")
    pp.add_argument("--base-url", default=None, help="LLM API base URL")
    pp.add_argument("--api-key", default=None, help="LLM API key")
    pp.add_argument(
        "--budget-per-config",
        type=float,
        default=500.0,
        help="USD budget per config per run (default: $500)",
    )
    pp.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Runs per config for statistical significance (default: 1)",
    )
    pp.add_argument(
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Hunt depth (default: standard)",
    )
    pp.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: ./results/eval or ~/.clearwing/results/eval)",
    )
    pp.add_argument(
        "--ground-truth",
        nargs="*",
        default=None,
        help="Known CVE IDs for recall measurement",
    )
    pp.add_argument(
        "--format",
        choices=["table", "json", "markdown"],
        default="table",
        dest="output_format",
        help="Output format (default: table)",
    )

    compare = sub.add_parser(
        "compare",
        help="Compare two eval result files",
    )
    compare.add_argument(
        "results",
        nargs=2,
        metavar="FILE",
        help="Two eval result JSON files to compare",
    )

    sourcehunt_plan = sub.add_parser(
        "sourcehunt-plan",
        help="Build a local/frontier staged sourcehunt ablation plan",
    )
    sourcehunt_plan.add_argument(
        "--ground-truth",
        default="evaluations/sourcehunt_ground_truth.yaml",
        help="Machine-readable sourcehunt ground-truth manifest",
    )
    sourcehunt_plan.add_argument(
        "--flows",
        default="legacy,proof",
        help="Comma-separated flows (default: legacy,proof)",
    )
    sourcehunt_plan.add_argument(
        "--cases",
        default="",
        help="Comma-separated case IDs (default: every manifest case)",
    )
    sourcehunt_plan.add_argument(
        "--levels",
        default="1,2,3,4,5,6,7",
        help="Comma-separated ablation levels",
    )
    sourcehunt_plan.add_argument("--replicates", type=int, default=1)
    sourcehunt_plan.add_argument("--local-model", required=True)
    sourcehunt_plan.add_argument("--frontier-model", required=True)
    sourcehunt_plan.add_argument("--output", required=True)

    sourcehunt_observe = sub.add_parser(
        "sourcehunt-observe",
        help="Score completed sessions against a sourcehunt ablation plan",
    )
    sourcehunt_observe.add_argument("--plan", required=True)
    sourcehunt_observe.add_argument(
        "--ground-truth",
        default="evaluations/sourcehunt_ground_truth.yaml",
    )
    sourcehunt_observe.add_argument(
        "--session",
        action="append",
        required=True,
        metavar="RUN_ID=SESSION_DIR",
        help="Associate one planned run ID with its session directory",
    )
    sourcehunt_observe.add_argument("--output", required=True)

    sourcehunt_run = sub.add_parser(
        "sourcehunt-run",
        help="Execute a planned local/frontier sourcehunt ablation matrix",
    )
    sourcehunt_run.add_argument("--plan", required=True)
    sourcehunt_run.add_argument(
        "--ground-truth",
        default="evaluations/sourcehunt_ground_truth.yaml",
    )
    sourcehunt_run.add_argument(
        "--checkout",
        action="append",
        required=True,
        metavar="CASE_ID=PATH",
        help="Pre-positioned vulnerable checkout; repeat for every case",
    )
    sourcehunt_run.add_argument(
        "--compile-commands",
        action="append",
        default=[],
        metavar="CASE_ID=PATH",
    )
    sourcehunt_run.add_argument(
        "--validation-manifest",
        action="append",
        default=[],
        metavar="CASE_ID=PATH",
    )
    sourcehunt_run.add_argument(
        "--scheduler-calibration",
        default="",
        help="Optional Phase-3 action-utility calibration JSON",
    )
    sourcehunt_run.add_argument(
        "--proof-learning-registry",
        default="",
        help="Optional explicitly promoted Phase-5 mechanism registry",
    )
    sourcehunt_run.add_argument("--output-dir", required=True)
    sourcehunt_run.add_argument("--checkpoint", required=True)
    sourcehunt_run.add_argument(
        "--resume-observations",
        default="",
        help="Optional additional observation file; --checkpoint is resumed automatically",
    )
    sourcehunt_run.add_argument("--budget-per-run", type=float, required=True)
    sourcehunt_run.add_argument("--base-url", default=None)
    sourcehunt_run.add_argument("--api-key", default=None)
    sourcehunt_run.add_argument("--proof-max-actions", type=int, default=200)
    sourcehunt_run.add_argument("--proof-max-model-calls", type=int, default=40)
    sourcehunt_run.add_argument("--proof-max-dynamic-actions", type=int, default=20)

    sourcehunt_baseline = sub.add_parser(
        "sourcehunt-baseline",
        help="Aggregate a complete sourcehunt ablation matrix",
    )
    sourcehunt_baseline.add_argument("--plan", required=True)
    sourcehunt_baseline.add_argument(
        "--observations",
        action="append",
        required=True,
        help="Observation JSON file; may be repeated",
    )
    sourcehunt_baseline.add_argument("--output", required=True)
    sourcehunt_baseline.add_argument("--markdown-output", default="")
    sourcehunt_baseline.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Emit a visibly incomplete report instead of failing",
    )
    sourcehunt_calibrate = sub.add_parser(
        "sourcehunt-calibrate",
        help="Compile Phase-3 scheduler utility from proof evaluation sessions",
    )
    sourcehunt_calibrate.add_argument(
        "--observations",
        action="append",
        required=True,
        help="Observation JSON file; may be repeated",
    )
    sourcehunt_calibrate.add_argument("--output", required=True)
    sourcehunt_counterfactual = sub.add_parser(
        "sourcehunt-counterfactual",
        help="Evaluate a complete vulnerable/counterfactual proof-session matrix",
    )
    sourcehunt_counterfactual.add_argument("--manifest", required=True)
    sourcehunt_counterfactual.add_argument(
        "--session",
        action="append",
        required=True,
        metavar="NAME=SESSION_DIR",
    )
    sourcehunt_counterfactual.add_argument("--output", required=True)
    sourcehunt_promote = sub.add_parser(
        "sourcehunt-promote",
        help="Promote eligible exploratory retrospectives into a proof registry",
    )
    sourcehunt_promote.add_argument(
        "--retrospectives",
        action="append",
        required=True,
        help="Retrospective bundle JSON; may be repeated",
    )
    sourcehunt_promote.add_argument("--output", required=True)
    sourcehunt_learning_coverage = sub.add_parser(
        "sourcehunt-learning-coverage",
        help="Compare local-model coverage before and after a promoted registry",
    )
    sourcehunt_learning_coverage.add_argument("--registry", required=True)
    sourcehunt_learning_coverage.add_argument(
        "--before-session",
        action="append",
        required=True,
    )
    sourcehunt_learning_coverage.add_argument(
        "--after-session",
        action="append",
        required=True,
    )
    sourcehunt_learning_coverage.add_argument("--output", required=True)
    compare.add_argument(
        "--format",
        choices=["table", "json", "markdown"],
        default="table",
        dest="output_format",
        help="Output format (default: table)",
    )

    return parser


def handle(cli, args):
    """Dispatch to the appropriate eval subcommand."""
    action = getattr(args, "eval_action", None)
    if not action:
        cli.console.print(
            "[yellow]Usage: clearwing eval <preprocessing|compare|sourcehunt-plan|"
            "sourcehunt-run|sourcehunt-observe|sourcehunt-baseline|"
            "sourcehunt-calibrate|sourcehunt-counterfactual|sourcehunt-promote|"
            "sourcehunt-learning-coverage>[/yellow]",
        )
        return

    handlers = {
        "preprocessing": _handle_preprocessing,
        "compare": _handle_compare,
        "sourcehunt-plan": _handle_sourcehunt_plan,
        "sourcehunt-observe": _handle_sourcehunt_observe,
        "sourcehunt-run": _handle_sourcehunt_run,
        "sourcehunt-baseline": _handle_sourcehunt_baseline,
        "sourcehunt-calibrate": _handle_sourcehunt_calibrate,
        "sourcehunt-counterfactual": _handle_sourcehunt_counterfactual,
        "sourcehunt-promote": _handle_sourcehunt_promote,
        "sourcehunt-learning-coverage": _handle_sourcehunt_learning_coverage,
    }
    handler = handlers.get(action)
    if handler:
        handler(cli, args)
    else:
        cli.console.print(f"[red]Unknown action: {action}[/red]")


def _handle_preprocessing(cli, args):
    from ...core.config import default_results_dir
    from ...eval.metrics import format_eval_comparison
    from ...eval.preprocessing import PreprocessingEval
    from ...providers import ProviderManager, resolve_llm_endpoint

    if args.output_dir is None:
        args.output_dir = default_results_dir("eval")

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        force=True,
    )

    endpoint = resolve_llm_endpoint(
        cli_model=args.model,
        cli_base_url=args.base_url,
        cli_api_key=args.api_key,
        config_provider=cli.config.get_provider_section() or None,
    )
    cli.console.print(f"[dim]LLM endpoint: {endpoint.describe()}[/dim]")
    provider_manager = ProviderManager.for_endpoint(endpoint)

    config_names = [c.strip() for c in args.configs.split(",") if c.strip()]
    model_name = args.model or endpoint.model or "unknown"

    cli.console.print(
        f"[bold]Preprocessing Evaluation:[/bold] "
        f"configs={','.join(config_names)}, "
        f"budget=${args.budget_per_config:.0f}/config, "
        f"runs={args.runs}",
    )

    evaluator = PreprocessingEval(
        provider_manager=provider_manager,
        project=args.project,
        commit=args.commit,
        configs=config_names,
        model_name=model_name,
        budget_per_config=args.budget_per_config,
        runs=args.runs,
        depth=args.depth,
        output_dir=args.output_dir,
        ground_truth_cves=args.ground_truth,
    )

    result = asyncio.run(evaluator.arun())

    cli.console.print("")
    output = format_eval_comparison(result, fmt=args.output_format)
    cli.console.print(output)


def _handle_compare(cli, args):
    from ...eval.metrics import (
        format_eval_comparison,
        load_eval_result,
    )

    try:
        a = load_eval_result(args.results[0])
        b = load_eval_result(args.results[1])
    except Exception as e:
        cli.console.print(f"[red]Error loading results: {e}[/red]")
        sys.exit(1)

    cli.console.print(
        format_eval_comparison(a, fmt=args.output_format),
    )
    cli.console.print("")
    cli.console.print(
        format_eval_comparison(b, fmt=args.output_format),
    )


def _handle_sourcehunt_plan(cli, args):
    from ...eval.sourcehunt import (
        AblationArm,
        AblationLevel,
        GroundTruthManifest,
        build_ablation_plan,
    )

    try:
        manifest = GroundTruthManifest.load(args.ground_truth)
        if args.cases:
            case_ids = [item.strip() for item in args.cases.split(",") if item.strip()]
            manifest = GroundTruthManifest(cases=[manifest.case(case_id) for case_id in case_ids])
        flows = [item.strip() for item in args.flows.split(",") if item.strip()]
        invalid_flows = sorted(set(flows) - {"legacy", "proof"})
        if invalid_flows:
            raise ValueError(f"Unknown flow(s): {', '.join(invalid_flows)}")
        levels = [
            AblationLevel(int(item.strip())) for item in args.levels.split(",") if item.strip()
        ]
        arms = [
            AblationArm(
                flow=flow,
                model_tier=tier,
                model=(args.local_model if tier == "local" else args.frontier_model),
            )
            for flow in flows
            for tier in ("local", "frontier")
        ]
        plan = build_ablation_plan(
            manifest,
            arms,
            levels=levels,
            replicates=args.replicates,
            ground_truth_path=args.ground_truth,
        )
        target = plan.write(args.output)
    except Exception as exc:
        cli.console.print(f"[red]Unable to build sourcehunt plan: {exc}[/red]")
        sys.exit(1)
    cli.console.print(f"[green]Wrote {len(plan.runs)} sourcehunt runs to {target}[/green]")


def _handle_sourcehunt_observe(cli, args):
    from ...eval.sourcehunt import (
        AblationPlan,
        GroundTruthManifest,
        inspect_ablation_session,
        write_observations,
    )

    try:
        plan = AblationPlan.load(args.plan)
        manifest = GroundTruthManifest.load(args.ground_truth)
        specs = {run.id: run for run in plan.runs}
        observations = []
        for assignment in args.session:
            run_id, separator, session_dir = assignment.partition("=")
            if not separator or not run_id or not session_dir:
                raise ValueError(f"Invalid --session {assignment!r}; expected RUN_ID=SESSION_DIR")
            spec = specs.get(run_id)
            if spec is None:
                raise ValueError(f"Run ID is not present in the plan: {run_id}")
            observations.append(
                inspect_ablation_session(
                    spec,
                    manifest.case(spec.case_id),
                    session_dir,
                )
            )
        target = write_observations(observations, args.output)
    except Exception as exc:
        cli.console.print(f"[red]Unable to score sourcehunt sessions: {exc}[/red]")
        sys.exit(1)
    cli.console.print(f"[green]Wrote {len(observations)} observations to {target}[/green]")


def _handle_sourcehunt_run(cli, args):  # noqa: C901
    from pathlib import Path

    from ...eval.sourcehunt import (
        AblationPlan,
        GroundTruthManifest,
        execute_sourcehunt_run,
        load_observations,
        run_ablation_campaign,
    )
    from ...providers import ProviderManager, resolve_llm_endpoint

    def assignments(values, label):
        result = {}
        for value in values:
            key, separator, path = value.partition("=")
            if not separator or not key or not path:
                raise ValueError(f"Invalid {label} assignment: {value!r}")
            if key in result:
                raise ValueError(f"Duplicate {label} assignment for {key}")
            result[key] = path
        return result

    async def execute_campaign():
        plan = AblationPlan.load(args.plan)
        manifest = GroundTruthManifest.load(args.ground_truth)
        checkouts = assignments(args.checkout, "checkout")
        compile_commands = assignments(args.compile_commands, "compile-commands")
        validation_manifests = assignments(
            args.validation_manifest,
            "validation-manifest",
        )
        planned_case_ids = {run.case_id for run in plan.runs}
        missing = sorted(planned_case_ids - set(checkouts))
        if missing:
            raise ValueError("Missing checkout(s): " + ", ".join(missing))
        for label, mapping in (
            ("checkout", checkouts),
            ("compile-commands", compile_commands),
            ("validation-manifest", validation_manifests),
        ):
            unknown = sorted(set(mapping) - planned_case_ids)
            if unknown:
                raise ValueError(f"Unknown {label} case(s): " + ", ".join(unknown))
        missing_compile_commands = sorted(
            case_id
            for case_id in planned_case_ids
            if manifest.case(case_id).language.lower() in {"c", "cpp", "c++"}
            and case_id not in compile_commands
        )
        if missing_compile_commands:
            raise ValueError(
                "Missing compile-commands for C/C++ case(s): " + ", ".join(missing_compile_commands)
            )
        resume_paths: list[str] = []
        checkpoint = Path(args.checkpoint).expanduser()
        if checkpoint.is_file():
            resume_paths.append(str(checkpoint))
        if args.resume_observations:
            explicit = Path(args.resume_observations).expanduser()
            if explicit.resolve() != checkpoint.resolve():
                resume_paths.append(str(explicit))
        existing = load_observations(resume_paths)
        providers = {}

        async def executor(spec, case):
            provider = providers.get(spec.model)
            if provider is None:
                endpoint = resolve_llm_endpoint(
                    cli_model=spec.model,
                    cli_base_url=args.base_url,
                    cli_api_key=args.api_key,
                    config_provider=cli.config.get_provider_section() or None,
                )
                provider = ProviderManager.for_endpoint(endpoint)
                providers[spec.model] = provider
            return await execute_sourcehunt_run(
                spec,
                case,
                checkout=checkouts[spec.case_id],
                output_dir=args.output_dir,
                provider_manager=provider,
                budget_usd=args.budget_per_run,
                compile_commands=compile_commands.get(spec.case_id),
                validation_manifest=validation_manifests.get(spec.case_id),
                scheduler_calibration=(args.scheduler_calibration or None),
                learning_registry=(args.proof_learning_registry or None),
                proof_max_actions=args.proof_max_actions,
                proof_max_model_calls=args.proof_max_model_calls,
                proof_max_dynamic_actions=args.proof_max_dynamic_actions,
            )

        return await run_ablation_campaign(
            plan,
            manifest,
            executor,
            checkpoint_path=args.checkpoint,
            existing=existing,
        )

    try:
        observations = asyncio.run(execute_campaign())
    except Exception as exc:
        cli.console.print(f"[red]Sourcehunt ablation campaign failed: {exc}[/red]")
        sys.exit(1)
    cli.console.print(
        f"[green]Completed {len(observations)} planned runs; checkpoint: {args.checkpoint}[/green]"
    )


def _handle_sourcehunt_baseline(cli, args):
    from pathlib import Path

    from ...eval.sourcehunt import (
        AblationPlan,
        aggregate_baseline,
        load_observations,
    )

    try:
        plan = AblationPlan.load(args.plan)
        observations = load_observations(args.observations)
        report = aggregate_baseline(
            plan,
            observations,
            require_complete=not args.allow_incomplete,
        )
        target = report.write(args.output)
        markdown_target = Path(args.markdown_output or str(Path(args.output).with_suffix(".md")))
        markdown_target.parent.mkdir(parents=True, exist_ok=True)
        markdown_target.write_text(report.markdown(), encoding="utf-8")
    except Exception as exc:
        cli.console.print(f"[red]Unable to aggregate sourcehunt baseline: {exc}[/red]")
        sys.exit(1)
    cli.console.print(f"[green]Wrote baseline to {target} and {markdown_target}[/green]")


def _handle_sourcehunt_calibrate(cli, args):
    from ...eval.sourcehunt import load_observations
    from ...sourcehunt.proof import SchedulerCalibrationCompiler

    try:
        observations = load_observations(args.observations)
        session_dirs = sorted(
            {observation.session_dir for observation in observations if observation.flow == "proof"}
        )
        if not session_dirs:
            raise ValueError("No proof-flow sessions were present in the observations")
        calibration = SchedulerCalibrationCompiler().compile(session_dirs)
        target = calibration.write(args.output)
    except Exception as exc:
        cli.console.print(f"[red]Unable to calibrate sourcehunt scheduler: {exc}[/red]")
        sys.exit(1)
    cli.console.print(
        f"[green]Wrote {len(calibration.profiles)} scheduler profiles to {target}[/green]"
    )


def _handle_sourcehunt_counterfactual(cli, args):
    from ...eval import CounterfactualManifest, evaluate_counterfactual_sessions

    try:
        sessions: dict[str, str] = {}
        for assignment in args.session:
            name, separator, session_dir = assignment.partition("=")
            if not separator or not name or not session_dir:
                raise ValueError(f"Invalid --session {assignment!r}; expected NAME=SESSION_DIR")
            if name in sessions:
                raise ValueError(f"Duplicate counterfactual session: {name}")
            sessions[name] = session_dir
        manifest = CounterfactualManifest.load(args.manifest)
        report = evaluate_counterfactual_sessions(manifest, sessions)
        target = report.write(args.output)
    except Exception as exc:
        cli.console.print(f"[red]Unable to evaluate counterfactual suite: {exc}[/red]")
        sys.exit(1)
    color = "green" if not report.score.failures else "yellow"
    cli.console.print(
        f"[{color}]Counterfactual consistency {report.score.passed}/"
        f"{report.score.total}; wrote {target}[/{color}]"
    )


def _handle_sourcehunt_promote(cli, args):
    from pathlib import Path

    from ...sourcehunt.proof import LearningRegistry, RetrospectiveBundle

    try:
        bundles = [RetrospectiveBundle.load(path) for path in args.retrospectives]
        output = Path(args.output).expanduser()
        existing = LearningRegistry.load(output) if output.is_file() else None
        registry = LearningRegistry.promote(bundles, existing=existing)
        target = registry.write(output)
    except Exception as exc:
        cli.console.print(f"[red]Unable to promote sourcehunt learning: {exc}[/red]")
        sys.exit(1)
    cli.console.print(
        f"[green]Wrote {len(registry.mechanisms)} promoted mechanisms to {target}[/green]"
    )


def _handle_sourcehunt_learning_coverage(cli, args):
    from ...sourcehunt.proof import LearningCoverageCompiler, LearningRegistry

    try:
        registry = LearningRegistry.load(args.registry)
        report = LearningCoverageCompiler().compare(
            registry,
            args.before_session,
            args.after_session,
        )
        target = report.write(args.output)
    except Exception as exc:
        cli.console.print(f"[red]Unable to compare sourcehunt learning coverage: {exc}[/red]")
        sys.exit(1)
    color = "green" if report.improved else "yellow"
    cli.console.print(
        f"[{color}]Structured rediscovery delta {report.structured_rediscovery_delta:+d}; "
        "local-only resolved obligation delta "
        f"{report.local_only_resolved_obligation_delta:+d}; "
        f"local-only delta {report.local_only_completion_rate_delta:+.3f}; "
        f"wrote {target}[/{color}]"
    )
