import clearwing.scanning as scanning
from clearwing.agent.tooling import tool


@tool
async def scan_ports(
    target: str,
    ports: list[int] | None = None,
    scan_type: str = "syn",
    threads: int = 100,
) -> list[dict]:
    """Scan a target for open ports.

    Args:
        target: Target IP address.
        ports: List of ports to scan. Defaults to common ports if not provided.
        scan_type: Type of scan - 'syn' or 'connect'.
        threads: Number of concurrent threads.

    Returns:
        List of open port info dicts with keys: port, protocol, state, service.
    """
    scanner = scanning.PortScanner()
    return await scanner.scan(target, ports or [], scan_type, threads)


@tool
async def detect_services(target: str, open_ports: list[dict]) -> list[dict]:
    """Detect services running on open ports via banner grabbing.

    Args:
        target: Target IP address.
        open_ports: List of open port dicts from scan_ports (must have 'port' key).

    Returns:
        List of service info dicts with keys: port, service, banner, version, protocol.
    """
    scanner = scanning.ServiceScanner()
    return await scanner.detect(target, open_ports)


@tool
async def scan_vulnerabilities(target: str, services: list[dict]) -> list[dict]:
    """Scan detected services for known vulnerabilities using local DB and NVD.

    Args:
        target: Target IP address.
        services: List of service dicts from detect_services.

    Returns:
        List of vulnerability dicts with keys: cve, description, cvss, port, service.
    """
    scanner = scanning.VulnerabilityScanner()
    try:
        return await scanner.scan(target, services)
    finally:
        await scanner.close()


@tool
async def detect_os(target: str) -> str:
    """Detect the operating system of the target using TTL and TCP fingerprinting.

    Args:
        target: Target IP address.

    Returns:
        Detected OS string (e.g. 'Linux/Unix', 'Windows') or 'Unknown'.
    """
    scanner = scanning.OSScanner()
    return await scanner.detect(target)


@tool
async def record_finding(
    description: str,
    port: int | None = None,
    service: str = "",
    version: str = "",
    severity: str = "info",
    cve: str = "",
    cvss: float = 0.0,
    url: str = "",
    request: str = "",
    response: str = "",
    evidence: str = "",
) -> dict:
    """Record a structured security finding for the run's final report.

    Use this to register a finding you identified from ANY source — Kali/nmap
    output via ``kali_execute``, manual analysis, or source review — that the
    automated ``scan_vulnerabilities`` tool did not capture. Kali/manual output is
    free text and never reaches the structured findings list on its own, so an
    Operator that relies on the Kali path must call this once per distinct finding
    (e.g. one per vulnerable service) before concluding, or the run reports zero
    findings despite a successful scan.

    Always attach the concrete detection evidence: the exact ``url`` you hit, the
    ``request`` you sent and the ``response`` you got back (for web/HTTP findings),
    or the raw tool output in ``evidence`` (for nmap/Kali). Without it the report
    and any DefectDojo export show a bare CVE with no proof of how it was found.

    Args:
        description: Human-readable description of the finding (required).
        port: Affected TCP/UDP port, if applicable.
        service: Affected service name (e.g. 'vsftpd', 'mysql').
        version: Detected service version, if known.
        severity: One of info, low, medium, high, critical (default: info).
        cve: Related CVE id, if known (e.g. 'CVE-2011-2523').
        cvss: CVSS base score, if known.
        url: The exact URL/endpoint where the issue was detected (web findings).
        request: The raw HTTP request (or command) that triggered detection.
        response: The raw HTTP response (or tool output) that proves the issue.
        evidence: Any other raw evidence (e.g. nmap/Kali output) when the
            request/response pair does not apply.

    Returns:
        The normalized finding dict that was recorded.
    """
    sev = str(severity).strip().lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "info"
    finding: dict = {
        "description": str(description).strip(),
        "severity": sev,
        "service": str(service).strip(),
        "version": str(version).strip(),
        "cve": str(cve).strip(),
        "cvss": float(cvss) if cvss else 0.0,
    }
    if port is not None:
        try:
            finding["port"] = int(port)
        except (TypeError, ValueError):
            finding["port"] = port
    # Detection evidence — carried through to the report and the DefectDojo
    # export so a finding is not a bare CVE without proof of how it was found.
    for key, value in (
        ("url", url),
        ("request", request),
        ("response", response),
        ("evidence", evidence),
    ):
        text_value = str(value).strip()
        if text_value:
            finding[key] = text_value
    return finding
