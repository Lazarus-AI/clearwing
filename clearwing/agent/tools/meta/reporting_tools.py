from clearwing.agent.tooling import tool
from clearwing.core.engine import ScanResult
from clearwing.data.database import Database
from clearwing.reporting import ReportGenerator


@tool
def generate_report(format: str, scan_data: dict) -> str:
    """Generate a report from scan data collected by the agent.

    Args:
        format: Report format - 'text', 'json', 'html', or 'markdown'.
        scan_data: Dict with keys: target, open_ports, services, vulnerabilities,
                   exploits, os_info.

    Returns:
        Formatted report string.
    """
    result = ScanResult(target=scan_data.get("target", "unknown"))
    result.open_ports = scan_data.get("open_ports", [])
    result.services = scan_data.get("services", [])
    result.vulnerabilities = scan_data.get("vulnerabilities", [])
    result.exploits = scan_data.get("exploits", [])
    result.os_info = scan_data.get("os_info")

    generator = ReportGenerator()
    return generator.generate(result, format)


@tool
def save_report(filepath: str, format: str, scan_data: dict) -> str:
    """Save a report to a file.

    Args:
        filepath: Path to save the report file.
        format: Report format - 'text', 'json', 'html', or 'markdown'.
        scan_data: Dict with keys: target, open_ports, services, vulnerabilities,
                   exploits, os_info.

    Returns:
        Confirmation message with file path.
    """
    result = ScanResult(target=scan_data.get("target", "unknown"))
    result.open_ports = scan_data.get("open_ports", [])
    result.services = scan_data.get("services", [])
    result.vulnerabilities = scan_data.get("vulnerabilities", [])
    result.exploits = scan_data.get("exploits", [])
    result.os_info = scan_data.get("os_info")

    generator = ReportGenerator()
    generator.save(result, filepath, format)
    return f"Report saved to {filepath}"


@tool
def query_scan_history(target: str | None = None) -> list[dict]:
    """Query scan history from the database.

    Args:
        target: Optional target IP to filter. Returns all targets if not provided.

    Returns:
        List of scan history records.
    """
    db = Database()
    if target:
        return db.get_target_history(target)
    return db.get_all_targets()


@tool
def search_cves(pattern: str) -> list[dict]:
    """Search for CVEs in the scan database by pattern.

    Args:
        pattern: SQL LIKE pattern for CVE IDs (e.g. 'CVE-2017%').

    Returns:
        List of matching vulnerability records.
    """
    db = Database()
    return db.search_vulnerabilities(pattern)
