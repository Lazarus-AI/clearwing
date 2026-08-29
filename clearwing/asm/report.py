"""Per-scope aggregate attack-surface report.

Renders the current inventory, the delta since a given time, and any findings
(threat-intel-prioritized) into markdown / json under
``results/asm/<scope>/``. Findings reuse the canonical shapes; the asset graph
can additionally be visualized via
:meth:`clearwing.reporting.report_generator.ReportGenerator.generate_attack_graph`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from clearwing.asm.assets import ASSET_TYPES, AssetStore


def build_report(
    store: AssetStore,
    scope: str,
    *,
    since: float | None = None,
    findings: list[dict] | None = None,
) -> dict[str, Any]:
    """Assemble the report data structure for *scope*."""
    by_type: dict[str, list[str]] = {}
    for asset_type in ASSET_TYPES:
        values = [a.value for a in store.known_assets(scope, asset_type)]
        if values:
            by_type[asset_type] = values
    delta = [
        {"type": a.asset_type, "value": a.value, "source": a.source}
        for a in (store.deltas_since(scope, since) if since is not None else [])
    ]
    return {
        "scope": scope,
        "generated_at": time.time(),
        "stats": store.stats(scope),
        "assets": by_type,
        "new_since_last": delta,
        "findings": findings or [],
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, default=str)


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = [f"# Attack surface — {report['scope']}", ""]
    stats = report.get("stats", {})
    total = sum(stats.values())
    lines.append(f"**{total} assets** — " + ", ".join(f"{n} {t}" for t, n in sorted(stats.items())))
    lines.append("")

    delta = report.get("new_since_last", [])
    if delta:
        lines.append(f"## New since last run ({len(delta)})")
        for item in delta[:200]:
            lines.append(f"- `{item['value']}` ({item['type']}, via {item['source']})")
        lines.append("")

    findings = report.get("findings", [])
    if findings:
        lines.append(f"## Findings ({len(findings)}) — prioritized")
        for f in findings[:100]:
            flags = []
            if f.get("known_exploited"):
                flags.append("**KEV**")
            if f.get("epss") is not None:
                flags.append(f"EPSS {f['epss']:.2f}")
            tag = (" — " + ", ".join(flags)) if flags else ""
            ident = f.get("cve") or f.get("cwe") or f.get("finding_type", "?")
            lines.append(
                f"- [{f.get('severity', 'info')}] `{ident}` on "
                f"{f.get('target', f.get('service', '?'))}{tag}"
            )
        lines.append("")

    for asset_type, values in report.get("assets", {}).items():
        lines.append(f"## {asset_type} ({len(values)})")
        for value in values[:500]:
            lines.append(f"- `{value}`")
        lines.append("")
    return "\n".join(lines)


def write_report(
    store: AssetStore,
    scope: str,
    *,
    out_dir: str | Path | None = None,
    formats: tuple[str, ...] = ("markdown", "json"),
    since: float | None = None,
    findings: list[dict] | None = None,
) -> dict[str, str]:
    """Build and write the report; return {format: path}."""
    from clearwing.core.config import default_results_dir

    base = Path(out_dir) if out_dir is not None else Path(default_results_dir("asm")) / scope
    base.mkdir(parents=True, exist_ok=True)
    report = build_report(store, scope, since=since, findings=findings)
    paths: dict[str, str] = {}
    if "json" in formats:
        p = base / "asm-report.json"
        p.write_text(render_json(report), encoding="utf-8")
        paths["json"] = str(p)
    if "markdown" in formats:
        p = base / "asm-report.md"
        p.write_text(render_markdown(report), encoding="utf-8")
        paths["markdown"] = str(p)
    return paths


__all__ = ["build_report", "render_json", "render_markdown", "write_report"]
