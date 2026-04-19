from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from ..data.database import Database
from ..exploitation.exploiters import MetasploitBridge, RCEExploiter
from ..reporting import ReportGenerator
from ..scanning import OSScanner, PortScanner, ServiceScanner, VulnerabilityScanner
from .config import Config, ScanConfig
from .logger import setup_logger
from .module_loader import ModuleLoader


class ScanState(Enum):
    """Enumeration of possible scan states."""

    IDLE = "idle"
    PORT_SCANNING = "port_scanning"
    SERVICE_SCANNING = "service_scanning"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITING = "exploiting"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class ScanResult:
    """Container for scan results."""

    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    exploits: list[dict[str, Any]] = field(default_factory=list)
    os_info: str | None = None
    state: ScanState = ScanState.IDLE
    errors: list[str] = field(default_factory=list)


class CoreEngine:
    """Core engine for orchestrating the scanning and exploitation workflow."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.logger = setup_logger()
        self.module_loader = ModuleLoader()
        self.scan_result = ScanResult(target="")
        self.callbacks: dict[str, list[Callable]] = {
            "on_port_found": [],
            "on_service_detected": [],
            "on_vulnerability_found": [],
            "on_exploit_success": [],
            "on_scan_complete": [],
        }

    def register_callback(self, event: str, callback: Callable) -> None:
        """Register a callback for a specific event."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)

    def _trigger_callback(self, event: str, *args: Any, **kwargs: Any) -> None:
        """Trigger all callbacks for a specific event."""
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Callback error for {event}: {e}")

    async def scan(self, target: str, config: ScanConfig | None = None) -> ScanResult:
        """Perform a complete scan on the target."""
        self.scan_result = ScanResult(target=target)
        self.scan_result.state = ScanState.PORT_SCANNING

        config = config or ScanConfig(target=target)

        try:
            # Port Scanning
            self.logger.info(f"Starting port scan on {target}")
            await self._port_scan(target, config)

            # Service Scanning
            if config.service_detection and self.scan_result.open_ports:
                self.scan_result.state = ScanState.SERVICE_SCANNING
                self.logger.info("Starting service detection")
                await self._service_scan(target, config)

            # OS Detection
            if config.os_detection:
                self.logger.info("Detecting operating system")
                await self._os_detect(target, config)

            # Vulnerability Scanning
            if config.vulnerability_scan and self.scan_result.services:
                self.scan_result.state = ScanState.VULNERABILITY_SCANNING
                self.logger.info("Starting vulnerability scan")
                await self._vulnerability_scan(target, config)

            # Exploitation
            if config.exploit and self.scan_result.vulnerabilities:
                self.scan_result.state = ScanState.EXPLOITING
                self.logger.info("Starting exploitation")
                await self._exploit(target, config)

            self.scan_result.state = ScanState.COMPLETED
            self.scan_result.end_time = datetime.now()
            self._trigger_callback("on_scan_complete", self.scan_result)

        except Exception as e:
            self.scan_result.state = ScanState.ERROR
            self.scan_result.errors.append(str(e))
            self.logger.error(f"Scan error: {e}")

        return self.scan_result

    async def _port_scan(self, target: str, config: ScanConfig) -> None:
        """Perform port scanning."""
        scanner = PortScanner()
        ports = await scanner.scan(target, config.ports, config.scan_type, config.threads)
        self.scan_result.open_ports = ports
        for port in ports:
            self._trigger_callback("on_port_found", target, port)

    async def _service_scan(self, target: str, config: ScanConfig) -> None:
        """Perform service detection."""
        scanner = ServiceScanner()
        services = await scanner.detect(target, self.scan_result.open_ports)
        self.scan_result.services = services
        for service in services:
            self._trigger_callback("on_service_detected", target, service)

    async def _os_detect(self, target: str, config: ScanConfig) -> None:
        """Detect the operating system."""
        scanner = OSScanner()
        os_info = await scanner.detect(target)
        self.scan_result.os_info = os_info

    async def _vulnerability_scan(self, target: str, config: ScanConfig) -> None:
        """Perform vulnerability scanning."""
        scanner = VulnerabilityScanner()
        try:
            vulnerabilities = await scanner.scan(target, self.scan_result.services)
            self.scan_result.vulnerabilities = vulnerabilities
            for vuln in vulnerabilities:
                self._trigger_callback("on_vulnerability_found", target, vuln)
        finally:
            await scanner.close()

    async def _exploit(self, target: str, config: ScanConfig) -> None:
        """Perform exploitation."""
        rce_exploiter = RCEExploiter()
        MetasploitBridge(
            self.config.get("exploitation", "metasploit_host"),
            self.config.get("exploitation", "metasploit_port"),
            self.config.get("exploitation", "metasploit_password"),
        )

        for vuln in self.scan_result.vulnerabilities:
            exploit_result = await rce_exploiter.exploit(target, vuln)
            if exploit_result["success"]:
                self.scan_result.exploits.append(exploit_result)
                self._trigger_callback("on_exploit_success", target, exploit_result)

    def get_report(self, format: str = "text") -> str:
        """Generate a report from the scan results."""
        generator = ReportGenerator()
        return generator.generate(self.scan_result, format)

    def save_results(self, filepath: str) -> None:
        """Save scan results to database."""
        db = Database(self.config.get("database", "path"))
        db.save_scan_result(self.scan_result)
