import ipaddress
import re
from typing import Any


def validate_ip(ip: str) -> bool:
    """
    Validate an IP address.

    Args:
        ip: IP address string

    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def cidr_to_ips(cidr: str) -> list[str]:
    """
    Convert CIDR notation to list of IP addresses.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        List of IP addresses in the network
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def format_output(data: dict[str, Any], format: str = "text") -> str:
    """
    Format data for output.

    Args:
        data: Dictionary of data to format
        format: Output format ('text', 'json', 'table')

    Returns:
        Formatted string
    """
    if format == "json":
        import json

        return json.dumps(data, indent=2)

    elif format == "table":
        # Simple table formatting
        lines = []
        for key, value in data.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    else:  # text
        lines = []
        for key, value in data.items():
            lines.append(f"{key.replace('_', ' ').title()}: {value}")
        return "\n".join(lines)


def parse_port_range(port_spec: str) -> list[int]:
    """
    Parse port specification into list of ports.

    Args:
        port_spec: Port specification (e.g., '22,80,443' or '1-1024')

    Returns:
        List of port numbers
    """
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


def get_service_name(port: int) -> str:
    """
    Get common service name for a port.

    Args:
        port: Port number

    Returns:
        Service name or 'Unknown'
    """
    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP-Proxy",
    }
    return service_map.get(port, "Unknown")


def calculate_cvss_severity(score: float) -> str:
    """
    Calculate severity level from CVSS score.

    Args:
        score: CVSS score (0.0-10.0)

    Returns:
        Severity level string
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "NONE"


def truncate_string(s: str, max_length: int = 50) -> str:
    """
    Truncate string to maximum length with ellipsis.

    Args:
        s: String to truncate
        max_length: Maximum length

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - 3] + "..."


def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input by removing potentially dangerous characters.

    Args:
        input_str: Input string to sanitize

    Returns:
        Sanitized string
    """
    # Remove or escape special characters
    sanitized = re.sub(r"[;&|`$(){}[\]<>]", "", input_str)
    return sanitized.strip()
