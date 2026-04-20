import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader


class ReportGenerator:
    """Report generation module supporting multiple formats."""

    def __init__(self):
        self.templates = {
            "text": self._generate_text,
            "json": self._generate_json,
            "html": self._generate_html,
            "markdown": self._generate_markdown,
        }
        template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)  # noqa: S701

    def generate_attack_graph(self, graph_data: dict) -> str:
        """
        Generate an interactive D3.js attack graph HTML report.

        Args:
            graph_data: Serialized NetworkX graph data (node_link_data format)

        Returns:
            HTML string
        """
        template = self.jinja_env.get_template("attack_graph.html")
        return template.render(graph_data=json.dumps(graph_data))

    def generate(self, scan_result: Any, format: str = "text") -> str:
        """
        Generate a report from scan results.

        Args:
            scan_result: ScanResult object from CoreEngine
            format: Output format ('text', 'json', 'html', 'markdown')

        Returns:
            Formatted report string
        """
        generator = self.templates.get(format, self._generate_text)
        return generator(scan_result)

    def save(self, scan_result: Any, filepath: str, format: str = None) -> None:
        """
        Save report to a file.

        Args:
            scan_result: ScanResult object from CoreEngine
            filepath: Path to save the report
            format: Output format (auto-detected from extension if not provided)
        """
        if format is None:
            ext = Path(filepath).suffix.lower()
            format_map = {".txt": "text", ".json": "json", ".html": "html", ".md": "markdown"}
            format = format_map.get(ext, "text")

        report = self.generate(scan_result, format)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(report)

    def _generate_text(self, scan_result: Any) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("CLEARWING SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {scan_result.target}")
        lines.append(f"Scan Start: {scan_result.start_time}")
        lines.append(f"Scan End: {scan_result.end_time or 'In Progress'}")
        lines.append(f"OS Detected: {scan_result.os_info or 'Unknown'}")
        lines.append(f"State: {scan_result.state.value}")
        lines.append("")

        lines.append("-" * 70)
        lines.append("OPEN PORTS")
        lines.append("-" * 70)
        if scan_result.open_ports:
            for port in scan_result.open_ports:
                lines.append(
                    f"  Port {port['port']}/{port['protocol']}: {port['service']} ({port['state']})"
                )
        else:
            lines.append("  No open ports found")
        lines.append("")

        lines.append("-" * 70)
        lines.append("SERVICES")
        lines.append("-" * 70)
        if scan_result.services:
            for service in scan_result.services:
                lines.append(
                    f"  Port {service['port']}: "
                    f"{_format_service_label(service['service'], service.get('version'))}"
                )
                if service.get("banner"):
                    lines.append(f"    Banner: {service['banner'][:100]}...")
        else:
            lines.append("  No services detected")
        lines.append("")

        lines.append("-" * 70)
        lines.append("VULNERABILITIES")
        lines.append("-" * 70)
        if scan_result.vulnerabilities:
            for vuln in scan_result.vulnerabilities:
                lines.append(f"  [{vuln.get('cve', 'N/A')}] {vuln.get('description', 'N/A')}")
                lines.append(
                    f"    Service: {vuln.get('service', 'N/A')} (Port {vuln.get('port', 'N/A')})"
                )
                lines.append(f"    CVSS Score: {vuln.get('cvss', 'N/A')}")
        else:
            lines.append("  No vulnerabilities found")
        lines.append("")

        lines.append("-" * 70)
        lines.append("EXPLOITS")
        lines.append("-" * 70)
        if scan_result.exploits:
            for exploit in scan_result.exploits:
                status = "SUCCESS" if exploit.get("success") else "FAILED"
                lines.append(
                    f"  [{status}] {exploit.get('exploit_name', 'N/A')} ({exploit.get('cve', 'N/A')})"
                )
                lines.append(f"    Message: {exploit.get('message', exploit.get('error', 'N/A'))}")
        else:
            lines.append("  No exploits attempted")
        lines.append("")

        if scan_result.errors:
            lines.append("-" * 70)
            lines.append("ERRORS")
            lines.append("-" * 70)
            for error in scan_result.errors:
                lines.append(f"  - {error}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _generate_json(self, scan_result: Any) -> str:
        """Generate JSON report."""
        data = {
            "target": scan_result.target,
            "scan_start": scan_result.start_time.isoformat(),
            "scan_end": scan_result.end_time.isoformat() if scan_result.end_time else None,
            "os_info": scan_result.os_info,
            "state": scan_result.state.value,
            "open_ports": scan_result.open_ports,
            "services": scan_result.services,
            "vulnerabilities": scan_result.vulnerabilities,
            "exploits": scan_result.exploits,
            "errors": scan_result.errors,
        }
        return json.dumps(data, indent=2)

    def _generate_html(self, scan_result: Any) -> str:
        """Generate HTML report."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Clearwing Report - {scan_result.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 1px solid #ccc; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <h1>Clearwing Scan Report</h1>
    <p><strong>Target:</strong> {scan_result.target}</p>
    <p><strong>Scan Time:</strong> {scan_result.start_time} - {scan_result.end_time or "In Progress"}</p>
    <p><strong>OS Detected:</strong> {scan_result.os_info or "Unknown"}</p>
    
    <h2>Open Ports</h2>
    <table>
        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>State</th></tr>
"""
        for port in scan_result.open_ports:
            html += f"        <tr><td>{port['port']}</td><td>{port['protocol']}</td><td>{port['service']}</td><td>{port['state']}</td></tr>\n"

        html += """
    </table>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>CVE</th><th>Description</th><th>Service</th><th>CVSS</th></tr>
"""
        for vuln in scan_result.vulnerabilities:
            html += f"        <tr><td>{vuln.get('cve', 'N/A')}</td><td>{vuln.get('description', 'N/A')}</td><td>{vuln.get('service', 'N/A')}</td><td>{vuln.get('cvss', 'N/A')}</td></tr>\n"

        html += """
    </table>
    
    <h2>Exploits</h2>
    <table>
        <tr><th>Exploit</th><th>CVE</th><th>Status</th><th>Message</th></tr>
"""
        for exploit in scan_result.exploits:
            status_class = "success" if exploit.get("success") else "error"
            html += f"        <tr><td>{exploit.get('exploit_name', 'N/A')}</td><td>{exploit.get('cve', 'N/A')}</td><td class='{status_class}'>{exploit.get('success', False)}</td><td>{exploit.get('message', exploit.get('error', 'N/A'))}</td></tr>\n"

        html += """
    </table>
</body>
</html>
"""
        return html

    def _generate_markdown(self, scan_result: Any) -> str:
        """Generate Markdown report."""
        md = f"""# Clearwing Scan Report

**Target:** {scan_result.target}
**Scan Time:** {scan_result.start_time} - {scan_result.end_time or "In Progress"}
**OS Detected:** {scan_result.os_info or "Unknown"}

## Open Ports

| Port | Protocol | Service | State |
|------|----------|---------|-------|
"""
        for port in scan_result.open_ports:
            md += f"| {port['port']} | {port['protocol']} | {port['service']} | {port['state']} |\n"

        md += "\n## Vulnerabilities\n\n"
        md += "| CVE | Description | Service | CVSS |\n"
        md += "|-----|-------------|---------|------|\n"

        for vuln in scan_result.vulnerabilities:
            md += f"| {vuln.get('cve', 'N/A')} | {vuln.get('description', 'N/A')} | {vuln.get('service', 'N/A')} | {vuln.get('cvss', 'N/A')} |\n"

        md += "\n## Exploits\n\n"
        md += "| Exploit | CVE | Success | Message |\n"
        md += "|---------|-----|---------|----------|\n"

        for exploit in scan_result.exploits:
            md += f"| {exploit.get('exploit_name', 'N/A')} | {exploit.get('cve', 'N/A')} | {exploit.get('success', False)} | {exploit.get('message', exploit.get('error', 'N/A'))} |\n"

        return md


def _format_service_label(service: str, version: Any) -> str:
    """Render `service` + `version` for the human-readable scan report.

    The previous `f"{service} v{version}"` produced ugly output like
    `HTTP vNone` (when version was missing) and `HTTP vVercel` (when the
    version-pattern regex captured a server name from a `Server:` header
    instead of a real version string). Disambiguate:

      - missing/blank version       -> just the service name
      - looks like a version (1.x)  -> `service v<version>`
      - anything else (server name) -> `service (<version>)`
    """
    if version is None:
        return service
    label = str(version).strip()
    if not label or label.lower() in ("none", "unknown"):
        return service
    if label[0].isdigit():
        return f"{service} v{label}"
    return f"{service} ({label})"
