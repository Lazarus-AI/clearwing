import asyncio
import re
from typing import Any


class ServiceScanner:
    """Service detection and banner grabbing module."""

    # Service-specific probes
    PROBES = {
        "HTTP": b"GET / HTTP/1.0\r\n\r\n",
        "HTTPS": b"GET / HTTP/1.0\r\n\r\n",
        "SMTP": b"EHLO test\r\n",
        "FTP": b"USER anonymous\r\n",
        "SSH": b"SSH-2.0-OpenSSH_7.0\r\n",
        "POP3": b"CAPA\r\n",
        "IMAP": b"a CAPABILITY\r\n",
        "TELNET": b"\r\n",
        "DNS": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    }

    # Service version patterns
    VERSION_PATTERNS = {
        "HTTP": [
            r"Server: ([^\r\n]+)",
            r"X-Powered-By: ([^\r\n]+)",
            r"Apache/([^\s]+)",
            r"nginx/([^\s]+)",
        ],
        "SSH": [r"SSH-([^\s]+)"],
        "FTP": [r"220 ([^\r\n]+)"],
        "SMTP": [r"220 ([^\r\n]+)"],
        "POP3": [r"\+OK ([^\r\n]+)"],
        "IMAP": [r"\* OK ([^\r\n]+)"],
    }

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def detect(self, target: str, open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Detect services running on open ports.

        Args:
            target: Target IP address
            open_ports: List of open port dictionaries from port scanner

        Returns:
            List of dictionaries containing service information
        """
        services = []

        async def detect_service(port_info: dict[str, Any]) -> dict[str, Any]:
            port = port_info["port"]
            service_name = port_info.get("service", "Unknown")

            banner = await self._grab_banner(target, port, service_name)
            version = await self._detect_version(banner, service_name)

            service_info = {
                "port": port,
                "service": service_name,
                "banner": banner,
                "version": version,
                "protocol": "tcp",
            }
            services.append(service_info)
            return service_info

        tasks = [detect_service(port) for port in open_ports]
        await asyncio.gather(*tasks)

        return services

    async def _grab_banner(self, target: str, port: int, service: str) -> str:
        """Grab service banner from open port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self.timeout
            )

            # Send appropriate probe based on service
            probe = self.PROBES.get(service, b"\r\n")
            writer.write(probe)

            # Read response
            response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)

            writer.close()
            await writer.wait_closed()

            return response.decode("utf-8", errors="ignore")

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return ""

    async def _detect_version(self, banner: str, service: str) -> str | None:
        """Detect service version from banner."""
        if not banner:
            return None

        patterns = self.VERSION_PATTERNS.get(service, [])
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def detect_sync(self, target: str, open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Synchronous version of detect."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.detect(target, open_ports))
        finally:
            loop.close()
