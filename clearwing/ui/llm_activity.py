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
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

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

# Ring buffer of recent read_file / read_source_file events (populated by EventBus)
_recent_reads: deque[dict] = deque(maxlen=8)
# Ring buffer of recent hunter status messages (model narration)
_recent_status: deque[dict] = deque(maxlen=6)
# Ring buffer of recent trace steps
_recent_traces: deque[dict] = deque(maxlen=6)
# Ring buffer of recent execute commands
_recent_execs: deque[dict] = deque(maxlen=6)


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


def _append_trace_and_status(renderables: list[Any]) -> None:
    """Append structured hunter trace and narration rows to the panel."""

    if _recent_traces:
        renderables.append(Rule(style="dim"))
        for trace in _recent_traces:
            hunter = trace.get("hunter_target", "?")
            file = trace.get("file", "?")
            line = trace.get("line", "?")
            function = trace.get("function") or "?"
            note = (trace.get("note") or "")[:80]
            step_number = trace.get("step_number", "?")
            renderables.append(
                Text.assemble(
                    (f"[{hunter}] ", "dim cyan"),
                    (f"trace#{step_number} ", "bold magenta"),
                    (f"{file}:{line} ", ""),
                    (f"({function}) ", "dim"),
                    (note, "italic"),
                )
            )

    if _recent_status:
        renderables.append(Rule(style="dim"))
        for status in _recent_status:
            hunter = status.get("hunter_target", "?")
            text = status.get("text", "")
            # Truncate to first newline or 120 chars.
            first_line = text.split("\n", 1)[0][:120]
            if first_line:
                renderables.append(
                    Text.assemble(
                        (f"[{hunter}] ", "dim cyan"),
                        (first_line, ""),
                    )
                )


def _build_panel(
    budget_usd: float | None = None,
    spend_ledger: Any = None,
) -> Panel:
    stats = native.recent_call_stats()
    totals = stats["totals"]
    recent = stats["recent"]

    model = recent[-1]["model"] if recent else None
    if spend_ledger is not None:
        ledger_snapshot = spend_ledger.snapshot()
        totals = {
            **totals,
            "calls": ledger_snapshot["call_count"],
            "input_tokens": ledger_snapshot["input_tokens"],
            "cached_tokens": ledger_snapshot["cached_input_tokens"],
            "output_tokens": ledger_snapshot["output_tokens"],
        }
        spent = float(ledger_snapshot["total_spent"])
    else:
        spent = _cost_usd(totals, model)

    cached = totals.get("cached_tokens") or 0
    total_in = totals["input_tokens"] or 0
    cache_pct = (cached / total_in * 100) if total_in > 0 else 0

    header = Text.assemble(
        ("calls ", "dim"),
        (f"{totals['calls']}", "bold"),
        ("  ·  in ", "dim"),
        (_fmt_tokens(total_in), "bold cyan"),
        ("  ·  cached ", "dim"),
        (_fmt_tokens(cached), "bold magenta"),
        (f" ({cache_pct:.0f}%)", "dim magenta"),
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
    table.add_column("cache", justify="right")
    table.add_column("out", justify="right")
    table.add_column("$", justify="right")
    table.add_column("tc", justify="right")
    table.add_column("", justify="right")

    if not recent:
        table.add_row("[dim]waiting for first call…[/dim]", "", "", "", "", "", "", "", "")
    for call in recent:
        cost = _fmt_usd(_cost_usd(call, call["model"])) if call["ok"] else ""
        call_cached = call.get("cached_tokens") or 0
        call_in = call.get("input_tokens") or 0
        cache_str = _fmt_tokens(call_cached) if call_cached else ""
        if call_cached and call_in:
            cache_str += f" ({call_cached * 100 // call_in}%)"
        table.add_row(
            call["model"],
            call.get("ts", ""),
            _fmt_ms(call["elapsed_ms"]),
            _fmt_tokens(call["input_tokens"]),
            cache_str,
            _fmt_tokens(call["output_tokens"]),
            cost,
            str(call["tool_calls"]),
            "[green]ok[/green]" if call["ok"] else "[red]err[/red]",
        )

    renderables.append(Rule(style="dim"))
    renderables.append(table)

    if _recent_reads:
        renderables.append(Rule(style="dim"))
        reads_table = Table(
            box=None, show_header=True, header_style="dim", pad_edge=False, padding=(0, 2),
        )
        reads_table.add_column("hunter")
        reads_table.add_column("sandbox")
        reads_table.add_column("file")
        reads_table.add_column("lines", justify="right")
        for rd in _recent_reads:
            hunter = rd.get("hunter_target", "?")
            sandbox = rd.get("sandbox_id") or ""
            file = rd.get("file", "?")
            start = rd.get("start_line", 1)
            end = rd.get("end_line", -1)
            lines = f"{start}-{end}" if end != -1 else f"{start}+"
            reads_table.add_row(
                f"[dim]{hunter}[/dim]",
                f"[dim yellow]{sandbox}[/dim yellow]",
                file,
                lines,
            )
        renderables.append(reads_table)

    if _recent_execs:
        renderables.append(Rule(style="dim"))
        for ex in _recent_execs:
            hunter = ex.get("hunter_target", "?")
            sandbox = ex.get("sandbox_id") or "?"
            cmd = (ex.get("command") or "")[:100]
            renderables.append(
                Text.assemble(
                    (f"[{hunter}] ", "dim cyan"),
                    (f"{sandbox} ", "dim yellow"),
                    (f"$ {cmd}", "bold"),
                )
            )

    _append_trace_and_status(renderables)

    return Panel(
        Group(*renderables),
        title="LLM activity",
        title_align="left",
        border_style="cyan",
    )


class _ActivityRenderable:
    """Re-renders on every Live refresh so the panel reflects live totals."""

    def __init__(self, budget_usd: float | None = None, spend_ledger: Any = None) -> None:
        self.budget_usd = budget_usd
        self.spend_ledger = spend_ledger

    def __rich__(self) -> Panel:
        return _build_panel(self.budget_usd, self.spend_ledger)


@contextmanager
def llm_activity_panel(
    console: Console | None = None,
    refresh_hz: float = 4.0,
    live: bool = False,
    budget_usd: float | None = None,
    spend_ledger: Any = None,
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

    from clearwing.core.events import EventBus, EventType

    bus = EventBus()

    def _on_read(data):
        if not isinstance(data, dict):
            return
        if data.get("tool_name") in ("read_source_file", "read_file"):
            _recent_reads.append(data)
        elif data.get("tool_name") == "execute":
            _recent_execs.append(data)
        else:
            tool = data.get("tool_name") or data.get("tool", "?")
            hunter = data.get("hunter_target") or data.get("args", {}).get("hunter_target", "")
            logging.getLogger("clearwing.sourcehunt.live").info(
                "[%s] tool: %s", hunter or "agent", tool,
            )

    def _on_status(data):
        if isinstance(data, dict) and data.get("text"):
            _recent_status.append(data)

    def _on_trace(data):
        if isinstance(data, dict):
            _recent_traces.append(data)

    bus.subscribe(EventType.TOOL_START, _on_read)
    bus.subscribe(EventType.HUNTER_STATUS, _on_status)
    bus.subscribe(EventType.TRACE_STEP, _on_trace)

    console = console or Console(stderr=True)

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    root.handlers = [
        RichHandler(console=console, show_path=False, show_time=False, markup=False)
    ]
    root.setLevel(logging.INFO)

    live_display = Live(
        _ActivityRenderable(budget_usd, spend_ledger),
        console=console,
        refresh_per_second=refresh_hz,
        transient=False,
    )
    try:
        with live_display:
            yield
    finally:
        bus.unsubscribe(EventType.TOOL_START, _on_read)
        bus.unsubscribe(EventType.HUNTER_STATUS, _on_status)
        bus.unsubscribe(EventType.TRACE_STEP, _on_trace)
        _recent_reads.clear()
        _recent_status.clear()
        _recent_traces.clear()
        _recent_execs.clear()
        root.handlers = saved_handlers
        root.setLevel(saved_level)
