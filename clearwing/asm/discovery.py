"""Orchestrate the discovery tools into a normalized set of scoped assets.

`run_discovery(scope)` fans the passive/active discovery helpers over a scope's
root domains and returns a flat list of :class:`~clearwing.asm.assets.Asset`
objects with parent links wired (domain → subdomain → ip, domain → url,
subdomain → technology). The helpers are called via the module so tests can
monkeypatch a single seam.

`project_to_graph` mirrors the same assets into the knowledge graph so they are
queryable (`query_knowledge_graph`) and visualizable (attack-graph HTML). The
:class:`AssetStore` remains authoritative for the temporal delta.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from clearwing.agent.tools.recon import discovery_tools as dt
from clearwing.asm.assets import Asset
from clearwing.asm.scope import Scope

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryOptions:
    passive: bool = True  # crt.sh + wayback + optional github
    resolve: bool = True  # DNS-resolve discovered names
    probe: bool = True  # HTTP liveness + tech fingerprint
    wayback: bool = True  # historical URL mining
    max_probe: int = 200  # cap live probes per run


@dataclass
class DiscoveryResult:
    scope: str
    assets: list[Asset] = field(default_factory=list)


def run_discovery(scope: Scope, options: DiscoveryOptions | None = None) -> DiscoveryResult:
    """Discover the current attack surface for *scope*. Never raises on a source
    failure — a dead source just contributes nothing."""
    opts = options or DiscoveryOptions()
    assets: list[Asset] = []
    names_seen: list[str] = []

    for domain in scope.domains:
        domain_assets, resolvable = _discover_domain(scope, domain, opts)
        assets.extend(domain_assets)
        names_seen.extend(resolvable)

    if opts.probe:
        for host in list(dict.fromkeys(names_seen))[: opts.max_probe]:
            assets.extend(_probe_host(scope, host))

    return DiscoveryResult(scope=scope.name, assets=assets)


def _discover_domain(
    scope: Scope, domain: str, opts: DiscoveryOptions
) -> tuple[list[Asset], list[str]]:
    """Discover one root domain: subdomains, URLs, resolved IPs."""
    assets: list[Asset] = [Asset(scope.name, "domain", domain, source="scope")]
    names: set[str] = {domain}
    domain_id = _id(scope, "domain", domain)

    if opts.passive:
        found = set(_safe(dt.crtsh_subdomains, domain, default=[]))
        found |= set(_safe(dt.github_subdomains, domain, default=[]))
        for name in sorted(found):
            if name != domain and scope.in_scope(name):
                names.add(name)
                assets.append(
                    Asset(scope.name, "subdomain", name, parent_id=domain_id, source="crt.sh")
                )

    if opts.wayback:
        for url in _safe(dt.wayback_urls, domain, default=[])[:5000]:
            assets.append(Asset(scope.name, "url", url, parent_id=domain_id, source="wayback"))

    resolvable: list[str] = []
    if opts.resolve:
        for name in sorted(names):
            ips = _safe(dt.resolve_name, name, default=[])
            if ips:
                resolvable.append(name)
            parent = _id(scope, _name_type(name, domain), name)
            for ip in ips:
                assets.append(Asset(scope.name, "ip", ip, parent_id=parent, source="dns"))

    return assets, resolvable


def _probe_host(scope: Scope, host: str) -> list[Asset]:
    """HTTP(S) liveness + tech fingerprint for one host (https preferred)."""
    parent = _id(scope, _host_type_for(host, scope), host)
    for scheme in ("https", "http"):
        result = _safe(dt.probe_url, f"{scheme}://{host}", default={})
        if not result.get("live"):
            continue
        assets = [
            Asset(scope.name, "host", result["url"], parent_id=parent, source="probe",
                  metadata={"status": result.get("status"), "server": result.get("server", "")})
        ]
        assets.extend(
            Asset(scope.name, "technology", tech, parent_id=parent, source="probe")
            for tech in result.get("technologies", [])
        )
        return assets
    return []


def project_to_graph(kg, assets: list[Asset]) -> None:
    """Mirror discovered assets into the knowledge graph (best-effort)."""
    parents = {a.id: a for a in assets}
    for asset in assets:
        try:
            if asset.asset_type == "domain":
                kg.add_domain(asset.value)
            elif asset.asset_type == "subdomain":
                root = _parent_value(asset, parents)
                kg.add_subdomain(root or asset.value, asset.value)
            elif asset.asset_type == "ip":
                name = _parent_value(asset, parents) or asset.value
                kg.add_host_resolution(name, asset.value)
            elif asset.asset_type == "url":
                host = _parent_value(asset, parents) or asset.value
                kg.add_url(host, asset.value)
            elif asset.asset_type == "technology":
                host = _parent_value(asset, parents) or ""
                if host:
                    kg.add_technology(host, asset.value)
        except Exception:
            logger.debug("Could not project asset %s into graph", asset.value, exc_info=True)


# --- helpers ----------------------------------------------------------------


def _id(scope: Scope, asset_type: str, value: str) -> str:
    return Asset.compute_id(scope.name, asset_type, value)


def _name_type(name: str, domain: str) -> str:
    return "domain" if name == domain else "subdomain"


def _host_type_for(host: str, scope: Scope) -> str:
    return "domain" if host in scope.domains else "subdomain"


def _parent_value(asset: Asset, parents: dict[str, Asset]) -> str | None:
    parent = parents.get(asset.parent_id or "")
    return parent.value if parent else None


def _safe(fn, *args, default=None):
    try:
        return fn(*args)
    except Exception:
        logger.debug("discovery source %s failed", getattr(fn, "__name__", fn), exc_info=True)
        return default


__all__ = ["DiscoveryOptions", "DiscoveryResult", "run_discovery", "project_to_graph"]
