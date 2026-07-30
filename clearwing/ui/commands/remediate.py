"""Standalone remediation lifecycle CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.table import Table


def _add_provider_args(parser) -> None:
    parser.add_argument("--model", default=None, help="LLM model override")
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible endpoint")
    parser.add_argument("--api-key", default=None, help="LLM API key override")


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "remediate",
        help="Policy-gated remediation and adversarial fix validation",
    )
    sub = parser.add_subparsers(dest="remediate_action")

    run = sub.add_parser("run", help="Generate, review, and optionally apply fixes")
    run.add_argument("--repo", required=True, help="Local Git repository root")
    run.add_argument("--findings", required=True, help="Sourcehunt findings.json")
    run.add_argument(
        "--mode",
        choices=["report-only", "apply"],
        default="report-only",
        help="Generate only or transactionally modify the checkout (default: report-only)",
    )
    run.add_argument("--output-dir", default=None, help="External DTO/checkpoint directory")
    run.add_argument("--policy", default=None, help="Remediation policy YAML")
    run.add_argument("--resume", action="store_true", help="Resume matching checkpoints")
    run.add_argument("--top", type=int, default=None, help="Only process the top N findings")
    run.add_argument(
        "--finding-id",
        action="append",
        default=None,
        help="Only process this finding ID; repeatable",
    )
    run.add_argument(
        "--sandbox-validate",
        action="store_true",
        help="Recompile and replay each PoC in a fresh no-network sandbox",
    )
    run.add_argument("--gvisor", action="store_true", help="Use runsc for sandbox replay")
    _add_provider_args(run)

    validate = sub.add_parser("validate", help="Re-run the panel over stored DTOs")
    validate.add_argument("--repo", required=True, help="Local Git repository root")
    validate.add_argument("--output-dir", required=True, help="DTO/checkpoint directory")
    validate.add_argument("--policy", default=None, help="Remediation policy YAML")
    validate.add_argument("--finding-id", action="append", default=None)
    validate.add_argument("--sandbox-validate", action="store_true")
    validate.add_argument("--gvisor", action="store_true")
    _add_provider_args(validate)

    status = sub.add_parser("status", help="Summarize a remediation workspace")
    status.add_argument("--output-dir", required=True, help="DTO/checkpoint directory")

    init = sub.add_parser("policy-init", help="Write a documented default policy")
    init.add_argument("path", help="Destination YAML path")
    init.add_argument("--force", action="store_true", help="Replace an existing file")
    return parser


def handle(cli, args) -> None:
    action = getattr(args, "remediate_action", None)
    if action == "run":
        asyncio.run(_handle_run(cli, args))
    elif action == "validate":
        asyncio.run(_handle_validate(cli, args))
    elif action == "status":
        _handle_status(cli, args)
    elif action == "policy-init":
        _handle_policy_init(cli, args)
    else:
        cli.console.print(
            "[yellow]Usage: clearwing remediate <run|validate|status|policy-init>[/yellow]"
        )


def _provider_manager(cli, args):
    from clearwing.providers import ProviderManager, resolve_llm_endpoint

    providers_cfg = cli.config.get_providers_config()
    override = bool(args.model or args.base_url or args.api_key)
    if providers_cfg.get("providers") and not override:
        return ProviderManager.from_config(providers_cfg)
    endpoint = resolve_llm_endpoint(
        cli_model=args.model,
        cli_base_url=args.base_url,
        cli_api_key=args.api_key,
        config_provider=cli.config.get_provider_section() or None,
    )
    return ProviderManager.for_endpoint(endpoint)


def _panel(manager, policy):
    from clearwing.remediation.panel import RemediationValidationPanel

    clients = {
        "security_architect": manager.get_native_client("remediation_architect"),
        "penetration_tester": manager.get_native_client("remediation_adversary"),
        "regression_reviewer": manager.get_native_client("remediation_regression"),
    }
    return RemediationValidationPanel(
        clients,  # type: ignore[arg-type]
        threshold=policy.validation_threshold,
        require_dynamic_validation=policy.require_dynamic_validation,
    )


async def _handle_run(cli, args) -> None:
    from clearwing.core.config import default_results_dir
    from clearwing.remediation.policy import RemediationPolicy
    from clearwing.remediation.store import RemediationStore
    from clearwing.remediation.workflow import RemediationWorkflow, load_findings

    repo = Path(args.repo).expanduser().resolve()
    output = (
        Path(args.output_dir).expanduser()
        if args.output_dir
        else (Path(default_results_dir("remediation")) / repo.name)
    )
    policy = RemediationPolicy.load(args.policy)
    manager = _provider_manager(cli, args)
    store = RemediationStore(output)
    dynamic = _dynamic_validator(args, repo)
    try:
        workflow = RemediationWorkflow(
            repo=repo,
            store=store,
            remediator_llm=manager.get_native_client("remediator"),
            validation_panel=_panel(manager, policy),
            policy=policy,
            mode=args.mode,
            dynamic_validator=dynamic,
        )
        results = await workflow.run(
            load_findings(args.findings),
            resume=args.resume,
            top=args.top,
            finding_ids=set(args.finding_id or []),
        )
        _print_results(cli, results, output)
    finally:
        if dynamic is not None:
            dynamic.close()
        store.close()


async def _handle_validate(cli, args) -> None:
    from clearwing.remediation.policy import RemediationPolicy
    from clearwing.remediation.store import RemediationStore
    from clearwing.remediation.workflow import RemediationWorkflow

    policy = RemediationPolicy.load(args.policy)
    manager = _provider_manager(cli, args)
    store = RemediationStore(args.output_dir)
    dynamic = _dynamic_validator(args, Path(args.repo).expanduser().resolve())
    try:
        workflow = RemediationWorkflow(
            repo=args.repo,
            store=store,
            remediator_llm=manager.get_native_client("remediator"),
            validation_panel=_panel(manager, policy),
            policy=policy,
            mode="report-only",
            dynamic_validator=dynamic,
        )
        selected = set(args.finding_id or [])
        results = []
        for dto in store.load_all():
            if selected and dto.finding.id not in selected:
                continue
            if dto.proposed_fix is None:
                continue
            results.append(await workflow.validate_existing(dto))
        _print_results(cli, results, Path(args.output_dir))
    finally:
        if dynamic is not None:
            dynamic.close()
        store.close()


def _handle_status(cli, args) -> None:
    from clearwing.remediation.store import RemediationStore

    store = RemediationStore(args.output_dir)
    try:
        counts = store.status_counts()
    finally:
        store.close()
    table = Table(title="Remediation Status")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for status, count in sorted(counts.items()):
        table.add_row(status, str(count))
    cli.console.print(table if counts else "[yellow]No remediation DTOs found.[/yellow]")


def _handle_policy_init(cli, args) -> None:
    from clearwing.remediation.policy import default_policy_document

    target = Path(args.path).expanduser()
    if target.exists() and not args.force:
        cli.console.print(f"[red]Refusing to overwrite {target}; pass --force[/red]")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(default_policy_document(), encoding="utf-8")
    cli.console.print(f"[green]Wrote remediation policy to {target}[/green]")


def _dynamic_validator(args, repo: Path):
    if not args.sandbox_validate:
        return None
    from clearwing.remediation.dynamic import SandboxPatchValidator

    return SandboxPatchValidator(repo, runtime="runsc" if args.gvisor else None)


def _print_results(cli, results, output: Path) -> None:
    table = Table(title="Remediation Results")
    table.add_column("Finding")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Validation")
    for dto in results:
        validation = dto.validation.status if dto.validation else "—"
        table.add_row(dto.finding.id, dto.mode, dto.status, validation)
    cli.console.print(table)
    cli.console.print(f"[dim]Workspace: {output.expanduser().resolve()}[/dim]")
