"""Live rich panel showing recent LLM calls + running token totals.

Gated behind CLEARWING_LLM_LOG (same flag as the per-call INFO logging in
``clearwing.llm.native``). When enabled, ``llm_activity_panel`` pins a small
panel to the bottom of the terminal that repaints from the ring buffer in
``native.recent_call_stats`` while a synchronous run (e.g. ``runner.run()``)
blocks the main thread. Log lines scroll above it via a RichHandler on the
same console.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from rich.console import Console, Group
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from clearwing.llm import native
from clearwing.observability.telemetry import CostTracker


def _fmt_tokens(n: int | None) -> str:
    """Compact token count: 1840 -> '1.8k', 48210 -> '48.2k'."""
    if not n:
        return "0"
    if n < 1000:
        return str(n)
    return f"{n / 1000:.1f}k"


def _fmt_ms(ms: int) -> str:
    return f"{ms / 1000:.1f}s" if ms >= 1000 else f"{ms}ms"


def _fmt_usd(cost: float) -> str:
    return f"${cost:.4f}" if cost < 0.01 else f"${cost:.2f}"


def _cost_usd(counts: dict, model: str | None) -> float:
    """USD estimate for a token dict (cumulative totals or a single call).

    Delegates to CostTracker.estimate_cost so cached input tokens bill at the
    cheaper cached rate. Edit the pricing table in observability/telemetry.py.
    Token values may be None (failed calls) and are coerced to 0.
    """
    if not model:
        return 0.0
    return CostTracker.estimate_cost(
        counts["input_tokens"] or 0,
        counts["output_tokens"] or 0,
        model,
        counts.get("cached_tokens") or 0,
    )


def _build_panel(budget_usd: float | None = None) -> Panel:
    stats = native.recent_call_stats()
    totals = stats["totals"]
    recent = stats["recent"]

    model = recent[-1]["model"] if recent else None
    spent = _cost_usd(totals, model)

    header = Text.assemble(
        ("calls ", "dim"),
        (f"{totals['calls']}", "bold"),
        ("  ·  in ", "dim"),
        (_fmt_tokens(totals["input_tokens"]), "bold cyan"),
        ("  ·  out ", "dim"),
        (_fmt_tokens(totals["output_tokens"]), "bold green"),
        ("  ·  ", "dim"),
        (_fmt_usd(spent), "bold yellow"),
    )
    if budget_usd is not None:
        pct = min(spent / budget_usd, 1.0)
        header.append(f" / {_fmt_usd(budget_usd)}", style="dim")
        header.append(f"  ({pct:.0%})", style="bold yellow")
    if totals["failures"]:
        header.append("  ·  ")
        header.append(f"{totals['failures']} failed", style="bold red")

    renderables: list = [header]

    if budget_usd is not None:
        progress = Progress(BarColumn(bar_width=40))
        task: TaskID = progress.add_task("", total=budget_usd, completed=spent)
        progress.update(task, completed=spent)
        renderables.append(progress)

    table = Table(box=None, show_header=True, header_style="dim", pad_edge=False, padding=(0, 2))
    table.add_column("model")
    table.add_column("at", justify="right")
    table.add_column("time", justify="right")
    table.add_column("in", justify="right")
    table.add_column("out", justify="right")
    table.add_column("$", justify="right")
    table.add_column("tc", justify="right")
    table.add_column("", justify="right")

    if not recent:
        table.add_row("[dim]waiting for first call…[/dim]", "", "", "", "", "", "", "")
    for call in recent:
        cost = _fmt_usd(_cost_usd(call, call["model"])) if call["ok"] else ""
        table.add_row(
            call["model"],
            call.get("ts", ""),
            _fmt_ms(call["elapsed_ms"]),
            _fmt_tokens(call["input_tokens"]),
            _fmt_tokens(call["output_tokens"]),
            cost,
            str(call["tool_calls"]),
            "[green]ok[/green]" if call["ok"] else "[red]err[/red]",
        )

    renderables.append(Rule(style="dim"))
    renderables.append(table)

    return Panel(
        Group(*renderables),
        title="LLM activity",
        title_align="left",
        border_style="cyan",
    )


class _ActivityRenderable:
    """Re-renders on every Live refresh so the panel reflects live totals."""

    def __init__(self, budget_usd: float | None = None) -> None:
        self.budget_usd = budget_usd

    def __rich__(self) -> Panel:
        return _build_panel(self.budget_usd)


@contextmanager
def llm_activity_panel(
    console: Console | None = None,
    refresh_hz: float = 4.0,
    live: bool = False,
    budget_usd: float | None = None,
) -> Iterator[None]:
    """Pin a live LLM-activity panel while the wrapped block runs.

    No-op unless CLEARWING_LLM_LOG is set or *live* is True. Routes root
    logging through a RichHandler on *console* for the duration so INFO lines
    scroll cleanly above the pinned panel, then restores the prior handlers on
    exit.
    """
    if not live and not native.call_logging_enabled():
        yield
        return

    console = console or Console(stderr=True)

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    root.handlers = [
        RichHandler(console=console, show_path=False, show_time=False, markup=False)
    ]
    root.setLevel(logging.INFO)

    live_display = Live(
        _ActivityRenderable(budget_usd),
        console=console,
        refresh_per_second=refresh_hz,
        transient=False,
    )
    try:
        with live_display:
            yield
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)
