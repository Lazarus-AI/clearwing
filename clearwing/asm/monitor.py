"""Continuous attack-surface monitor.

Modeled on :class:`clearwing.sourcehunt.commit_monitor.CommitMonitor`: a
poll-interval loop (`max_iterations=0` runs forever; cancel is responsive
because sleeps happen in 1-second chunks). Each cycle:

1. runs discovery over the scope,
2. records observations in the :class:`AssetStore` and keeps only the *new*
   assets (the delta),
3. for every new asset: emits `ASSET_DISCOVERED`, mirrors it into the knowledge
   graph, and — when enabled — drives Clearwing's *existing* deep tools on new
   hosts (port/service/vuln scan, optionally KEV/EPSS-prioritized).

It never exploits and never triggers approval-gated actions automatically; it
discovers and scans, then hands any findings to the normal pipeline. Discovery
and scanning are injectable so tests run without a network.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from clearwing.asm.assets import Asset, AssetStore
from clearwing.asm.discovery import DiscoveryOptions, project_to_graph, run_discovery
from clearwing.asm.scope import Scope
from clearwing.core.event_payloads import AssetDiscoveredPayload
from clearwing.core.events import EventBus

logger = logging.getLogger(__name__)


@dataclass
class AsmMonitorConfig:
    scope: Scope
    poll_interval_seconds: float = 86400.0
    max_iterations: int = 0  # 0 = run forever
    scan_new_assets: bool = True
    threat_intel: bool = True
    discovery_options: DiscoveryOptions = field(default_factory=DiscoveryOptions)
    store: AssetStore | None = None
    knowledge_graph: object | None = None
    # Injection seams (default to the real implementations):
    discover_fn: Callable[[Scope, DiscoveryOptions], list[Asset]] | None = None
    scan_fn: Callable[[Asset], list[dict]] | None = None
    on_cycle: Callable[[list[Asset]], None] | None = None


class AsmMonitor:
    """Run one or many discovery cycles over a scope, acting only on new assets."""

    def __init__(self, config: AsmMonitorConfig):
        self.config = config
        self._store = config.store or AssetStore()
        self._owns_store = config.store is None
        self._cancelled = False
        self.iterations = 0

    # -- lifecycle ------------------------------------------------------

    def run(self) -> None:
        """Loop cycles until cancelled or `max_iterations` is reached."""
        try:
            while not self._cancelled:
                self.iterations += 1
                new_assets = self.cycle()
                logger.info(
                    "ASM cycle %d for scope %s: %d new assets",
                    self.iterations,
                    self.config.scope.name,
                    len(new_assets),
                )
                if self.config.max_iterations and self.iterations >= self.config.max_iterations:
                    break
                if not self._cancelled:
                    self._sleep(self.config.poll_interval_seconds)
        finally:
            if self._owns_store:
                self._store.close()

    def cancel(self) -> None:
        self._cancelled = True

    # -- one cycle ------------------------------------------------------

    def cycle(self) -> list[Asset]:
        """Discover → record delta → notify/scan new assets. Returns the delta."""
        scope = self.config.scope
        discovered = self._discover(scope)
        new_assets = self._store.record_observations(scope.name, discovered)

        if self.config.knowledge_graph is not None and new_assets:
            project_to_graph(self.config.knowledge_graph, new_assets)

        bus = EventBus()
        for asset in new_assets:
            bus.emit_asset_discovered(
                AssetDiscoveredPayload(
                    scope=scope.name,
                    asset_type=asset.asset_type,
                    value=asset.value,
                    source=asset.source,
                    parent=asset.parent_id,
                )
            )

        if self.config.scan_new_assets:
            for asset in new_assets:
                if asset.asset_type in ("ip", "host"):
                    self._scan(asset)

        if self.config.on_cycle is not None:
            self.config.on_cycle(new_assets)
        return new_assets

    # -- injectable steps ----------------------------------------------

    def _discover(self, scope: Scope) -> list[Asset]:
        if self.config.discover_fn is not None:
            return self.config.discover_fn(scope, self.config.discovery_options)
        return run_discovery(scope, self.config.discovery_options).assets

    def _scan(self, asset: Asset) -> list[dict]:
        try:
            findings = (
                self.config.scan_fn(asset)
                if self.config.scan_fn is not None
                else _default_scan(asset.value)
            )
        except Exception:
            logger.debug("Deep scan of %s failed", asset.value, exc_info=True)
            return []
        if findings and self.config.threat_intel:
            try:
                from clearwing.asm.threatintel import ThreatIntel

                findings = ThreatIntel().enrich(findings)
            except Exception:
                logger.debug("threat-intel enrichment failed", exc_info=True)
        return findings

    # -- interruptible sleep -------------------------------------------

    def _sleep(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while not self._cancelled and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


def _default_scan(target: str) -> list[dict]:
    """Run the existing port/service/vuln scanners on a host (best-effort)."""
    import asyncio

    from clearwing.agent.tools.scan.scanner_tools import (
        detect_services,
        scan_ports,
        scan_vulnerabilities,
    )

    async def _run() -> list[dict]:
        ports = await scan_ports(target)
        services = await detect_services(target, ports)
        return await scan_vulnerabilities(target, services)

    return asyncio.run(_run())


__all__ = ["AsmMonitor", "AsmMonitorConfig"]
