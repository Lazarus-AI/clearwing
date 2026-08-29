"""Mass parallel scanning across a discovered surface.

Once discovery has populated the :class:`AssetStore`, a sweep fans the existing
port/service/vuln scanners across every known host in a scope concurrently
(bounded), aggregates the findings, and prioritizes them with threat intel.
This is the "scan the whole surface, not one host" capability, reusing
Clearwing's deep scanners rather than reimplementing detection.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from clearwing.asm.assets import AssetStore

logger = logging.getLogger(__name__)


@dataclass
class SweepResult:
    scope: str
    hosts_scanned: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


async def _default_scan_async(target: str) -> list[dict]:
    from clearwing.agent.tools.scan.scanner_tools import (
        detect_services,
        scan_ports,
        scan_vulnerabilities,
    )

    ports = await scan_ports(target)
    services = await detect_services(target, ports)
    vulns = await scan_vulnerabilities(target, services)
    for vuln in vulns:
        vuln.setdefault("target", target)
    return vulns


async def sweep_scope_async(
    store: AssetStore,
    scope: str,
    *,
    max_parallel: int = 10,
    threat_intel: bool = True,
    scan_async: Callable[[str], Awaitable[list[dict]]] | None = None,
) -> SweepResult:
    """Scan every known host/ip in *scope* concurrently. Best-effort per host."""
    scanner = scan_async or _default_scan_async
    hosts = sorted(
        {a.value for a in store.known_assets(scope, "ip")}
        | {a.value for a in store.known_assets(scope, "host")}
    )
    semaphore = asyncio.Semaphore(max(1, max_parallel))

    async def _one(host: str) -> list[dict]:
        async with semaphore:
            try:
                return await scanner(host)
            except Exception:
                logger.debug("sweep scan of %s failed", host, exc_info=True)
                return []

    per_host = await asyncio.gather(*(_one(h) for h in hosts))
    findings = [f for group in per_host for f in group]

    if findings and threat_intel:
        try:
            from clearwing.asm.threatintel import ThreatIntel

            findings = ThreatIntel().enrich(findings)
        except Exception:
            logger.debug("threat-intel enrichment failed", exc_info=True)

    return SweepResult(scope=scope, hosts_scanned=hosts, findings=findings)


def sweep_scope(store: AssetStore, scope: str, **kwargs) -> SweepResult:
    """Synchronous wrapper around :func:`sweep_scope_async`."""
    return asyncio.run(sweep_scope_async(store, scope, **kwargs))


__all__ = ["SweepResult", "sweep_scope", "sweep_scope_async"]
