from langchain_core.tools import tool


@tool
def validate_target(ip_or_cidr: str) -> dict:
    """Validate an IP address or CIDR range and expand CIDR to individual IPs.

    Args:
        ip_or_cidr: IP address (e.g. '192.168.1.1') or CIDR (e.g. '192.168.1.0/24').

    Returns:
        Dict with keys: valid (bool), is_cidr (bool), ips (list of IP strings).
    """
    from clearwing.core.helpers import validate_ip, cidr_to_ips

    if "/" in ip_or_cidr:
        ips = cidr_to_ips(ip_or_cidr)
        return {"valid": len(ips) > 0, "is_cidr": True, "ips": ips}

    valid = validate_ip(ip_or_cidr)
    return {"valid": valid, "is_cidr": False, "ips": [ip_or_cidr] if valid else []}


@tool
def calculate_severity(cvss_score: float) -> str:
    """Calculate severity level from a CVSS score.

    Args:
        cvss_score: CVSS score between 0.0 and 10.0.

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, LOW, or NONE.
    """
    from clearwing.core.helpers import calculate_cvss_severity

    return calculate_cvss_severity(cvss_score)
