"""Tool-specific Rich renderers for the ActivityFeed."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def render_tool_result(tool_name: str, data: dict):
    """Render tool results with tool-specific formatting."""
    renderer = RENDERERS.get(tool_name, _default_renderer)
    return renderer(data)


def _port_scan_renderer(data: dict):
    result = data.get("result", data)
    if isinstance(result, list):
        table = Table(title="Port Scan Results", show_lines=False)
        table.add_column("Port", style="cyan")
        table.add_column("Protocol", style="blue")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        for port in result:
            if isinstance(port, dict):
                table.add_row(
                    str(port.get("port", "")),
                    port.get("protocol", "tcp"),
                    port.get("state", "open"),
                    port.get("service", "unknown"),
                )
        return table
    return _default_renderer(data)


def _vuln_scan_renderer(data: dict):
    result = data.get("result", data)
    if isinstance(result, list):
        table = Table(title="Vulnerabilities", show_lines=False)
        table.add_column("CVE", style="red")
        table.add_column("CVSS", style="yellow")
        table.add_column("Description")
        for v in result:
            if isinstance(v, dict):
                table.add_row(
                    v.get("cve", "N/A"),
                    str(v.get("cvss", "?")),
                    v.get("description", "")[:60],
                )
        return table
    return _default_renderer(data)


def _kali_renderer(data: dict):
    result = data.get("result", data)
    cmd = data.get("command", "")
    output = result.get("output", str(result)) if isinstance(result, dict) else str(result)
    return Panel(
        Text(output, style="green"),
        title=f"Kali: {cmd[:40]}" if cmd else "Kali Output",
        border_style="green",
    )


def _default_renderer(data: dict):
    result = data.get("result", data)
    text = str(result)
    if len(text) > 500:
        text = text[:500] + "..."
    return Text(f"  Result: {text}", style="dim")


RENDERERS = {
    "scan_ports": _port_scan_renderer,
    "detect_services": _default_renderer,
    "scan_vulnerabilities": _vuln_scan_renderer,
    "kali_execute": _kali_renderer,
    "exploit_vulnerability": _default_renderer,
}
