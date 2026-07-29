from __future__ import annotations

import asyncio
import logging
from typing import Any

import libpnet_pyo3

logger = logging.getLogger(__name__)


class OSScanner:
    """Operating system detection module."""

    # TTL values for common OS
    TTL_SIGNATURES = {64: "Linux/Unix", 128: "Windows", 255: "Cisco IOS", 60: "FreeBSD", 256: "AIX"}

    # TCP window sizes for OS fingerprinting
    WINDOW_SIGNATURES = {
        65535: "Linux",
        8192: "Windows",
        16384: "Windows",
        32767: "Windows",
        5840: "Solaris",
        65228: "FreeBSD",
    }

    def __init__(self, timeout: int = 2):
        self.timeout = timeout

    async def detect(self, target: str) -> str:
        """
        Detect the operating system of the target.

        Args:
            target: Target IP address

        Returns:
            Detected OS name or 'Unknown'
        """
        os_info = await self._passive_detect(target)
        if os_info != "Unknown":
            return os_info

        os_info = await self._active_detect(target)
        return os_info

    async def _passive_detect(self, target: str) -> str:
        """Passive OS detection based on TTL and window size."""
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: libpnet_pyo3.tcp_sr1(
                    dst=target, dport=80, flags="S", timeout=self.timeout
                ),
            )

            if resp is None:
                return "Unknown"

            ttl = resp.ttl
            window = resp.window

            # Determine OS based on TTL
            os_name = self._guess_os_by_ttl(ttl)

            # Refine based on window size
            if os_name == "Unknown" and window in self.WINDOW_SIGNATURES:
                os_name = self.WINDOW_SIGNATURES[window]

            return os_name

        except Exception:
            logger.debug("Passive OS detection failed for %s", target, exc_info=True)
            return "Unknown"

    async def _active_detect(self, target: str) -> str:
        """Active OS detection using multiple probes."""
        probes = [
            (80, "S"),  # SYN to port 80
            (443, "S"),  # SYN to port 443
            (22, "S"),  # SYN to port 22
            (25, "S"),  # SYN to port 25
        ]

        results = []
        for port, flags in probes:
            try:
                resp = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda p=port, f=flags: libpnet_pyo3.tcp_sr1(
                        dst=target, dport=p, flags=f, timeout=self.timeout
                    ),
                )

                if resp is not None:
                    results.append(
                        {"ttl": resp.ttl, "window": resp.window, "flags": resp.flags}
                    )
            except Exception:
                logger.debug("OS probe failed for %s:%d", target, port, exc_info=True)
                continue

        if not results:
            return "Unknown"

        # Analyze results
        return self._analyze_probes(results)

    def _guess_os_by_ttl(self, ttl: int) -> str:
        """Guess OS based on TTL value."""
        # Account for network hops (assume max 5 hops)
        if ttl >= 60 and ttl <= 64:
            return "Linux/Unix"
        elif ttl >= 120 and ttl <= 128:
            return "Windows"
        elif ttl >= 250 and ttl <= 255:
            return "Network Device"
        elif ttl >= 55 and ttl <= 60:
            return "FreeBSD"
        return "Unknown"

    def _analyze_probes(self, results: list[dict[str, Any]]) -> str:
        """Analyze probe results to determine OS."""
        ttl_counts = {}
        window_counts = {}

        for result in results:
            ttl = result["ttl"]
            window = result["window"]

            ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1
            window_counts[window] = window_counts.get(window, 0) + 1

        # Find most common TTL
        most_common_ttl = max(ttl_counts, key=ttl_counts.get)
        os_guess = self._guess_os_by_ttl(most_common_ttl)

        return os_guess

    def detect_sync(self, target: str) -> str:
        """Synchronous version of detect."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.detect(target))
        finally:
            loop.close()
