"""`clearwing asm` — attack-surface management.

Sub-actions:
  asm scan    <scope|domain>   discover the surface, record the delta, report
  asm monitor <scope|domain>   run discovery continuously (or once with --once)
  asm sweep   <scope>          port/service/vuln scan every known host
  asm report  <scope>          (re)render the aggregate report from the store
  asm list    [scope]          list scopes, or the assets in one

Discovery is passive-first and host-safe; it never exploits and never triggers
approval-gated actions automatically.
"""

from __future__ import annotations

import sys
from typing import Any

from clearwing.asm.assets import AssetStore
from clearwing.asm.scope import Scope, ScopeError


def add_parser(subparsers):
    parser = subparsers.add_parser("asm", help="Attack-surface management (discovery + monitoring)")
    sub = parser.add_subparsers(dest="asm_action")

    p_scan = sub.add_parser("scan", help="Discover the attack surface for a scope or domain")
    p_scan.add_argument("target", help="A configured asm scope name or a root domain")
    p_scan.add_argument("--mode", default="recon", help="Workflow mode (recon, stealth, web-assessment, external-sweep)")
    p_scan.add_argument("--no-scan", action="store_true", help="Do not port/service/vuln-scan new hosts")
    p_scan.add_argument("--screenshot", action="store_true", help="Screenshot live web hosts into a gallery")
    p_scan.add_argument("--notify", action="store_true", help="Send configured notifications for new assets")
    p_scan.add_argument("-o", "--output-dir", help="Report output directory")

    p_mon = sub.add_parser("monitor", help="Continuously monitor a scope for new assets")
    p_mon.add_argument("target", help="A configured asm scope name or a root domain")
    p_mon.add_argument("--mode", default="recon", help="Workflow mode")
    p_mon.add_argument("--interval", type=float, help="Seconds between cycles (default: config)")
    p_mon.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    p_mon.add_argument("--no-scan", action="store_true", help="Do not scan new hosts")

    p_sweep = sub.add_parser("sweep", help="Scan every known host in a scope")
    p_sweep.add_argument("target", help="A configured asm scope name or a root domain")
    p_sweep.add_argument("--max-parallel", type=int, default=10, help="Concurrent host scans")
    p_sweep.add_argument("-o", "--output-dir", help="Report output directory")

    p_report = sub.add_parser("report", help="Render the aggregate report for a scope")
    p_report.add_argument("target", help="A configured asm scope name or a root domain")
    p_report.add_argument("-o", "--output-dir", help="Report output directory")

    p_list = sub.add_parser("list", help="List known scopes, or assets in one scope")
    p_list.add_argument("target", nargs="?", help="Scope to list assets for (omit to list scopes)")

    parser.set_defaults(_command_parser=parser)
    return parser


def handle(cli, args):
    action = getattr(args, "asm_action", None)
    if action is None:
        args._command_parser.print_help()
        return
    asm_cfg = cli.config.get("asm") or {}
    try:
        if action == "scan":
            _handle_scan(cli, args, asm_cfg)
        elif action == "monitor":
            _handle_monitor(cli, args, asm_cfg)
        elif action == "sweep":
            _handle_sweep(cli, args, asm_cfg)
        elif action == "report":
            _handle_report(cli, args, asm_cfg)
        elif action == "list":
            _handle_list(cli, args)
    except ScopeError as exc:
        cli.console.print(f"[red]Scope error:[/red] {exc}")
        sys.exit(2)


# -- scan --------------------------------------------------------------------


def _handle_scan(cli, args, asm_cfg: dict[str, Any]) -> None:
    from clearwing.asm import discovery
    from clearwing.asm.modes import get_mode
    from clearwing.core.event_payloads import AssetDiscoveredPayload
    from clearwing.core.events import EventBus

    scope = Scope.resolve(args.target, asm_cfg)
    mode = get_mode(args.mode)
    cli.console.print(f"[bold blue]ASM scan[/bold blue] scope=[cyan]{scope.name}[/cyan] mode=[cyan]{mode.name}[/cyan]")

    notifier = _maybe_notifier(cli, args, asm_cfg)
    store = AssetStore()
    try:
        result = discovery.run_discovery(scope, mode.discovery)
        new_assets = store.record_observations(scope.name, result.assets)

        kg = _load_kg()
        if kg is not None:
            discovery.project_to_graph(kg, new_assets)
            _save_kg(kg)

        bus = EventBus()
        for asset in new_assets:
            bus.emit_asset_discovered(
                AssetDiscoveredPayload(scope.name, asset.asset_type, asset.value, asset.source, asset.parent_id)
            )

        cli.console.print(f"[green]+[/green] {len(new_assets)} new assets; {sum(store.stats(scope.name).values())} total")
        for atype, n in sorted(store.stats(scope.name).items()):
            cli.console.print(f"    {atype}: {n}")

        findings: list[dict] = []
        if (mode.scan_new_assets or mode.sweep) and not args.no_scan:
            findings = _sweep(cli, store, scope.name, asm_cfg)
        if mode.screenshot or args.screenshot:
            _screenshot(cli, store, scope.name)

        paths = _write_report(store, scope.name, args, findings)
        for fmt, path in paths.items():
            cli.console.print(f"[green]Report ({fmt}):[/green] {path}")
    finally:
        store.close()
        if notifier is not None:
            notifier.unsubscribe()


# -- monitor -----------------------------------------------------------------


def _handle_monitor(cli, args, asm_cfg: dict[str, Any]) -> None:
    from clearwing.asm.modes import get_mode
    from clearwing.asm.monitor import AsmMonitor, AsmMonitorConfig

    scope = Scope.resolve(args.target, asm_cfg)
    mode = get_mode(args.mode)
    interval = args.interval if args.interval is not None else float(asm_cfg.get("poll_interval_seconds", 86400))
    cli.console.print(
        f"[bold blue]ASM monitor[/bold blue] scope=[cyan]{scope.name}[/cyan] "
        f"interval={interval:.0f}s {'(single cycle)' if args.once else '(Ctrl-C to stop)'}"
    )

    notifier = _maybe_notifier(cli, args, asm_cfg, force=True)
    kg = _load_kg()
    config = AsmMonitorConfig(
        scope=scope,
        poll_interval_seconds=interval,
        max_iterations=1 if args.once else 0,
        scan_new_assets=not args.no_scan and asm_cfg.get("scan_new_assets", True),
        threat_intel=asm_cfg.get("threat_intel", True),
        discovery_options=mode.discovery,
        knowledge_graph=kg,
        on_cycle=lambda new: cli.console.print(f"[green]cycle:[/green] {len(new)} new assets"),
    )
    monitor = AsmMonitor(config)
    try:
        monitor.run()
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Monitor stopped.[/yellow]")
        monitor.cancel()
    finally:
        if kg is not None:
            _save_kg(kg)
        if notifier is not None:
            notifier.unsubscribe()


# -- sweep / report / list ---------------------------------------------------


def _handle_sweep(cli, args, asm_cfg: dict[str, Any]) -> None:
    scope = Scope.resolve(args.target, asm_cfg)
    store = AssetStore()
    try:
        findings = _sweep(cli, store, scope.name, asm_cfg, max_parallel=args.max_parallel)
        paths = _write_report(store, scope.name, args, findings)
        for fmt, path in paths.items():
            cli.console.print(f"[green]Report ({fmt}):[/green] {path}")
    finally:
        store.close()


def _handle_report(cli, args, asm_cfg: dict[str, Any]) -> None:
    scope = Scope.resolve(args.target, asm_cfg)
    store = AssetStore()
    try:
        paths = _write_report(store, scope.name, args, [])
        for fmt, path in paths.items():
            cli.console.print(f"[green]Report ({fmt}):[/green] {path}")
    finally:
        store.close()


def _handle_list(cli, args) -> None:
    store = AssetStore()
    try:
        if not args.target:
            scopes = store.scopes()
            if not scopes:
                cli.console.print("[yellow]No scopes yet. Run `clearwing asm scan <domain>`.[/yellow]")
            for name in scopes:
                total = sum(store.stats(name).values())
                cli.console.print(f"  [cyan]{name}[/cyan] — {total} assets")
        else:
            for atype, n in sorted(store.stats(args.target).items()):
                cli.console.print(f"[bold]{atype}[/bold] ({n})")
                for asset in store.known_assets(args.target, atype):
                    cli.console.print(f"    {asset.value}")
    finally:
        store.close()


# -- helpers -----------------------------------------------------------------


def _sweep(cli, store, scope_name, asm_cfg, max_parallel: int = 10) -> list[dict]:
    from clearwing.asm.sweep import sweep_scope

    cli.console.print("[cyan]Sweeping known hosts...[/cyan]")
    try:
        result = sweep_scope(
            store, scope_name, max_parallel=max_parallel, threat_intel=asm_cfg.get("threat_intel", True)
        )
    except Exception as exc:  # scanning is best-effort
        cli.console.print(f"[yellow]Sweep skipped:[/yellow] {exc}")
        return []
    cli.console.print(f"[green]+[/green] scanned {len(result.hosts_scanned)} hosts, {len(result.findings)} findings")
    return result.findings


def _screenshot(cli, store, scope_name) -> None:
    try:
        from clearwing.agent.tools.recon.discovery_tools import screenshot_surface
    except ImportError:
        return
    urls = [a.value for a in store.known_assets(scope_name, "host")]
    if not urls:
        return
    result = screenshot_surface.func(urls)
    cli.console.print(f"[green]Gallery:[/green] {result.get('gallery')}")


def _write_report(store, scope_name, args, findings) -> dict[str, str]:
    from clearwing.asm.report import write_report

    return write_report(
        store, scope_name, out_dir=getattr(args, "output_dir", None), findings=findings, since=0.0
    )


def _maybe_notifier(cli, args, asm_cfg, force: bool = False):
    if not (force or getattr(args, "notify", False)):
        return None
    from clearwing.asm.notify import Notifier

    notifier = Notifier.from_config(asm_cfg)
    if notifier.enabled:
        notifier.subscribe()
        return notifier
    if getattr(args, "notify", False):
        cli.console.print("[yellow]--notify set but no webhook configured (asm.slack_webhook_url / env).[/yellow]")
    return None


def _load_kg():
    try:
        from clearwing.core.config import clearwing_home
        from clearwing.data.knowledge import KnowledgeGraph

        return KnowledgeGraph(persist_path=str(clearwing_home() / "knowledge_graph.json"))
    except Exception:
        return None


def _save_kg(kg) -> None:
    try:
        kg.save()
    except Exception:
        pass
