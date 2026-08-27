"""`clearwing models` — show and preview the resolved model roles.

Roles are the vendor-neutral capability layer (see docs/model-roles.md):
each role (`utility`, `researcher`, `frontier`, …) resolves to a concrete
model from whatever provider you configured, via that provider's tier
ladder. This command prints that resolution so you can see — on one
screen — which model and reasoning budget every role lands on, which task
strings each role serves, and why.

Three things it answers:

  clearwing models                     what my current config resolves to
  clearwing models --provider deepseek what a provider WOULD give me
  clearwing models --task hunter       which model one call site uses

It also flags the two things that silently bite: a provider whose API key
env var is unset, and a reasoning budget that will be dropped because the
model family rejects the parameter.
"""

from __future__ import annotations

import json
import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clearwing.llm.native import effective_reasoning_effort
from clearwing.providers.binding import capabilities_for, validate_inference
from clearwing.providers.catalog import (
    PROVIDER_PRESETS,
    ProviderPreset,
    preset_by_key,
)
from clearwing.providers.roles import (
    ROLES,
    TASK_ROLES,
    RoleAssignment,
    recommend_roles,
    role_for_task,
)

# --- CLI plumbing --------------------------------------------------------


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "models",
        help="Show which model each role resolves to (and preview providers)",
        description=(
            "Resolve the six model roles to concrete models for the current "
            "config, or preview what a provider's tier ladder would give. "
            "Flags unset API keys and reasoning budgets that will be dropped."
        ),
    )
    parser.add_argument(
        "--provider",
        action="append",
        metavar="KEY",
        help=(
            "Preview roles for this provider preset instead of the current "
            "config. Repeatable: the second provider takes the reviewer role "
            "(e.g. --provider deepseek --provider anthropic)."
        ),
    )
    parser.add_argument(
        "--task",
        metavar="TASK",
        help="Explain which role/model a single task string resolves to.",
    )
    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List provider preset keys and their tier ladders, then exit.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the rich table.",
    )
    return parser


def handle(cli, args) -> None:
    console: Console = cli.console

    if args.list_providers:
        _print_providers(console, as_json=args.json)
        return

    if args.provider:
        presets = _presets_from_keys(console, args.provider)
        if presets is None:
            return
        assignments = recommend_roles(presets)
        mode = "preview"
        source = "--provider " + " ".join(p.key for p in presets)
    else:
        assignments, presets, mode, source = _current_assignments(cli)

    if args.task:
        _print_task(console, args.task, assignments, as_json=args.json)
        return

    routes_cfg = {}
    if not args.provider:
        raw = getattr(cli.config, "config", {}) or {}
        mr = raw.get("model_roles")
        if isinstance(mr, dict):
            routes_cfg = mr.get("routes") or {}

    if args.json:
        _print_json(console, assignments, presets, mode, source, routes_cfg)
    else:
        _print_table(console, assignments, presets, mode, source)
        _print_routes(console, routes_cfg)


# --- Resolution ----------------------------------------------------------


def _current_assignments(
    cli,
) -> tuple[dict[str, RoleAssignment], list[ProviderPreset], str, str]:
    """Resolve roles for the operator's current config.

    Returns (assignments, presets, mode, source). ``mode`` is:
      - ``active``: a ``model_roles:`` block is configured — these
        assignments are exactly what runs.
      - ``recommendation``: no role config; the current setup runs a single
        endpoint for every task, so this is what roles *would* give.
    """
    raw = getattr(cli.config, "config", {}) or {}
    roles_cfg = raw.get("model_roles")
    if isinstance(roles_cfg, dict):
        # Resolve through the SAME path the manager uses, so the display can
        # never disagree with what actually runs (named models, roles:
        # bindings, overrides, validation).
        from clearwing.providers.manager import ProviderManager

        assignments, presets_by_key, _problems = ProviderManager.resolve_role_assignments(
            roles_cfg
        )
        presets = list(presets_by_key.values())
        return assignments, presets, "active", "config model_roles:"

    # No role config: infer the closest provider preset from the resolved
    # endpoint so the recommendation reflects the backend actually in use.
    from clearwing.providers import resolve_llm_endpoint

    endpoint = resolve_llm_endpoint(config_provider=cli.config.get_provider_section())
    preset = _preset_for_endpoint(endpoint)
    return (
        recommend_roles([preset]),
        [preset],
        "recommendation",
        f"inferred from current endpoint ({endpoint.describe()})",
    )


def _presets_from_keys(console: Console, keys: list[str]) -> list[ProviderPreset] | None:
    presets: list[ProviderPreset] = []
    for k in keys:
        p = preset_by_key(k)
        if p is None:
            known = ", ".join(sorted(pp.key for pp in PROVIDER_PRESETS))
            console.print(f"[red]Unknown provider preset: {k!r}[/red]")
            console.print(f"[dim]Known keys: {known}[/dim]")
            return None
        presets.append(p)
    return presets


def _preset_for_endpoint(endpoint) -> ProviderPreset:
    """Best-effort map a resolved endpoint back to a catalog preset."""
    if endpoint.base_url:
        host = endpoint.base_url.rstrip("/")
        for p in PROVIDER_PRESETS:
            if p.default_base_url and p.default_base_url.rstrip("/") == host:
                return p
    # Anthropic-direct (or anything we couldn't match): the Anthropic ladder.
    return preset_by_key("anthropic")


# --- Checks --------------------------------------------------------------


def _key_missing(preset: ProviderPreset | None) -> bool:
    """True when this provider needs an API key env var that isn't set."""
    if preset is None or preset.is_local or preset.auth_flow:
        return False
    var = preset.api_key_env_var
    return bool(var) and not os.environ.get(var)


def _reasoning_note(model: str, reasoning: str) -> str | None:
    """Describe a reasoning budget that won't survive to the wire, else None."""
    effective = effective_reasoning_effort(model, reasoning)
    if reasoning not in ("none", "auto", None) and effective is None:
        return f"{reasoning} → omitted (model family rejects reasoning_effort)"
    return None


def _tasks_by_role() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {name: [] for name in ROLES}
    for task, role in TASK_ROLES.items():
        out.setdefault(role, []).append(task)
    for tasks in out.values():
        tasks.sort()
    return out


# --- Output --------------------------------------------------------------


def _mode_banner(mode: str, source: str) -> Panel:
    if mode == "active":
        body = f"[green]active[/green] — these assignments run.  [dim]source: {source}[/dim]"
        style = "green"
    elif mode == "preview":
        body = f"[cyan]preview[/cyan] — not yet configured.  [dim]{source}[/dim]"
        style = "cyan"
    else:
        body = (
            "[yellow]recommendation[/yellow] — no [bold]model_roles:[/bold] block is "
            "configured, so every task currently runs one endpoint.\n"
            f"[dim]{source}[/dim]\n"
            "Add a [bold]model_roles:[/bold] block to activate per-role selection "
            "(see docs/model-roles.md)."
        )
        style = "yellow"
    return Panel(body, title="Model roles", border_style=style)


def _print_table(
    console: Console,
    assignments: dict[str, RoleAssignment],
    presets: list[ProviderPreset],
    mode: str,
    source: str,
) -> None:
    console.print()
    console.print(_mode_banner(mode, source))
    console.print()

    tasks_by_role = _tasks_by_role()
    presets_by_key = {p.key: p for p in presets}

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Role", style="bold")
    table.add_column("Model")
    table.add_column("Reasoning")
    table.add_column("Output", justify="right")
    table.add_column("Serves tasks", overflow="fold")

    warnings: list[str] = []
    for name in ROLES:
        a = assignments[name]
        preset = presets_by_key.get(a.provider) or preset_by_key(a.provider)

        reasoning_cell = a.reasoning or "[dim]auto[/dim]"
        note = _reasoning_note(a.model, a.reasoning)
        if note:
            reasoning_cell = f"[yellow]{a.reasoning}[/yellow]"
            warnings.append(f"{name}: {note}")

        model_cell = f"{a.provider}[dim]/[/dim]{a.model}"
        if _key_missing(preset):
            model_cell += "  [red](key unset)[/red]"
            warnings.append(f"{name}: {preset.api_key_env_var} is not set for {a.provider}")
        if a.constraints.get("independent_model_family") and not a.constraints.get(
            "independent_satisfied"
        ):
            model_cell += "  [yellow](not independent)[/yellow]"
            warnings.append(
                f"{name}: independent review requested but reviewer shares the "
                f"primary's model family (or only one provider is configured)"
            )
        if a.constraints.get("fallback_used"):
            model_cell += "  [yellow](failover)[/yellow]"
            warnings.append(
                f"{name}: primary binding unavailable — failed over to {a.model}"
            )
        if a.constraints.get("available") is False:
            model_cell += "  [red](unavailable)[/red]"
            warnings.append(f"{name}: no binding in the fallback chain is available")

        # Load-time validation against the model's (built-in) capabilities.
        for problem in validate_inference(name, a.model, a.inference, capabilities_for(a.model)):
            warnings.append(problem)

        out = a.inference.max_output_tokens
        out_cell = f"{out:,}" if out else "[dim]—[/dim]"

        tasks = tasks_by_role.get(name, [])
        tasks_cell = ", ".join(tasks) if tasks else "[dim]—[/dim]"

        table.add_row(name, model_cell, reasoning_cell, out_cell, tasks_cell)

    console.print(table)

    if warnings:
        console.print()
        wpanel = "\n".join(f"[yellow]•[/yellow] {w}" for w in dict.fromkeys(warnings))
        console.print(Panel(wpanel, title="Warnings", border_style="yellow"))

    console.print()
    console.print(
        "[dim]Override a role in ~/.clearwing/config.yaml:[/dim]\n"
        "[dim]  model_roles:\n"
        "    providers: \\[anthropic]\n"
        "    overrides:\n"
        "      frontier: {model: claude-opus-4-7, reasoning: max}[/dim]"
    )


def _print_routes(console: Console, routes_cfg: dict) -> None:
    """Compact table of task-route agent limits + per-route overrides."""
    if not routes_cfg:
        return
    table = Table(
        title="Task routes",
        title_style="bold",
        show_header=True,
        header_style="bold",
        box=None,
        padding=(0, 1),
    )
    table.add_column("Route", style="bold")
    table.add_column("Role")
    table.add_column("max_steps", justify="right")
    table.add_column("max_tool_calls", justify="right")
    table.add_column("Inference override")
    for name, rc in routes_cfg.items():
        if not isinstance(rc, dict):
            continue
        role = rc.get("role") or role_for_task(name).name
        agent = rc.get("agent") or {}
        steps = str(agent.get("max_steps", "—"))
        calls = str(agent.get("max_tool_calls", "—"))
        inf = rc.get("inference") or {}
        inf_cell = ", ".join(f"{k}={v}" for k, v in inf.items()) if inf else "[dim]—[/dim]"
        table.add_row(name, role, steps, calls, inf_cell)
    console.print()
    console.print(table)


def _print_task(
    console: Console,
    task: str,
    assignments: dict[str, RoleAssignment],
    *,
    as_json: bool,
) -> None:
    role = role_for_task(task)
    a = assignments[role.name]
    effective = effective_reasoning_effort(a.model, a.reasoning)
    if as_json:
        console.print_json(
            data={
                "task": task,
                "role": role.name,
                "provider": a.provider,
                "model": a.model,
                "reasoning": a.reasoning,
                "effective_reasoning": effective,
                "max_output_tokens": a.inference.max_output_tokens,
                "temperature": a.inference.temperature,
            }
        )
        return
    known = task in TASK_ROLES
    hint = "" if known else "  [dim](unmapped task → researcher role)[/dim]"
    console.print(
        f"\n[bold]{task}[/bold]{hint} → role [bold]{role.name}[/bold] → "
        f"{a.provider}[dim]/[/dim]{a.model}  [dim](reasoning: {a.reasoning}"
        + (f", effective: {effective}" if effective != a.reasoning else "")
        + ")[/dim]\n"
    )


def _print_providers(console: Console, *, as_json: bool) -> None:
    if as_json:
        console.print_json(
            data=[
                {
                    "key": p.key,
                    "default_model": p.default_model,
                    "tiers": dict(p.tier_models),
                    "is_local": p.is_local,
                    "api_key_env_var": p.api_key_env_var,
                }
                for p in PROVIDER_PRESETS
            ]
        )
        return
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Provider", style="bold")
    table.add_column("small")
    table.add_column("mid")
    table.add_column("large")
    for p in PROVIDER_PRESETS:
        table.add_row(
            p.key,
            p.model_for_tier("small"),
            p.model_for_tier("mid"),
            p.model_for_tier("large"),
        )
    console.print()
    console.print(table)
    console.print("\n[dim]A blank ladder falls back to the provider's default model.[/dim]")


def _print_json(
    console: Console,
    assignments: dict[str, RoleAssignment],
    presets: list[ProviderPreset],
    mode: str,
    source: str,
    routes_cfg: dict | None = None,
) -> None:
    tasks_by_role = _tasks_by_role()
    payload = {
        "mode": mode,
        "source": source,
        "providers": [p.key for p in presets],
        "routes": routes_cfg or {},
        "roles": [
            {
                "role": name,
                "provider": assignments[name].provider,
                "model": assignments[name].model,
                "reasoning": assignments[name].reasoning,
                "effective_reasoning": effective_reasoning_effort(
                    assignments[name].model, assignments[name].reasoning
                ),
                "max_output_tokens": assignments[name].inference.max_output_tokens,
                "temperature": assignments[name].inference.temperature,
                "constraints": assignments[name].constraints,
                "reason": assignments[name].reason,
                "tasks": tasks_by_role.get(name, []),
                "validation": validate_inference(
                    name,
                    assignments[name].model,
                    assignments[name].inference,
                    capabilities_for(assignments[name].model),
                ),
            }
            for name in ROLES
        ],
    }
    console.file.write(json.dumps(payload, indent=2))
    console.file.write("\n")
