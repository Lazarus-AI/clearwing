import asyncio
import logging
from typing import Any

from scapy.all import IP, TCP, sr1

logger = logging.getLogger(__name__)


COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5900,
    8080,
    8443,
    2222,
    2323,
    2525,
    3333,
    4444,
    5555,
    6666,
    7777,
    8888,
    9999,
    10000,
    12345,
    20000,
    30000,
    40000,
    50000,
]

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class PortScanner:
    """Port scanning module with multiple scan techniques."""

    def __init__(self):
        self.timeout = 1

    async def scan(
        self, target: str, ports: list[int] = None, scan_type: str = "syn", threads: int = 100
    ) -> list[dict[str, Any]]:
        """
        Scan target for open ports.

        Args:
            target: Target IP address
            ports: List of ports to scan (defaults to COMMON_PORTS)
            scan_type: Type of scan ('syn', 'connect', 'fin', 'ack', 'xmas', 'null')
            threads: Number of concurrent threads

        Returns:
            List of dictionaries containing port information
        """
        ports = ports or COMMON_PORTS
        open_ports = []

        # Create semaphore for limiting concurrent connections
        semaphore = asyncio.Semaphore(threads)

        async def scan_port(port: int) -> dict[str, Any]:
            async with semaphore:
                try:
                    if scan_type == "syn":
                        result = await self._syn_scan(target, port)
                    elif scan_type == "connect":
                        result = await self._connect_scan(target, port)
                    else:
                        result = await self._syn_scan(target, port)

                    if result:
                        open_ports.append(
                            {
                                "port": port,
                                "protocol": "tcp",
                                "state": "open",
                                "service": SERVICE_NAMES.get(port, "Unknown"),
                            }
                        )
                except Exception:
                    logger.debug("Port scan failed for %s:%d", target, port, exc_info=True)
            return None

        # Run all scans concurrently
        tasks = [scan_port(port) for port in ports]
        await asyncio.gather(*tasks)

        return sorted(open_ports, key=lambda x: x["port"])

    async def _syn_scan(self, target: str, port: int) -> bool:
        """Perform SYN scan on a single port."""
        try:
            ip = IP(dst=target)
            tcp = TCP(dport=port, flags="S")
            pkt = ip / tcp
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda: sr1(pkt, timeout=self.timeout, verbose=0)
            )
            if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                # Send RST to close the connection
                rst_pkt = ip / TCP(dport=port, flags="R")
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: sr1(rst_pkt, timeout=1, verbose=0)
                )
                return True
        except Exception:
            logger.debug("SYN scan failed for %s:%d", target, port, exc_info=True)
        return False

    async def _connect_scan(self, target: str, port: int) -> bool:
        """Perform TCP connect scan on a single port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    def scan_sync(
        self, target: str, ports: list[int] = None, scan_type: str = "syn"
    ) -> list[dict[str, Any]]:
        """Synchronous version of scan for backward compatibility."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.scan(target, ports, scan_type))
        finally:
            loop.close()
