"""Attack-Surface Management (ASM) — discovery, continuity, and engagement.

Clearwing is deep on a known target. This subsystem adds the front half of an
engagement: discovering what's out there (subdomains, hosts, ports, services,
URLs, technologies), tracking what changed over time, and feeding new assets
into Clearwing's existing deep scanning / verification pipeline.

Layout:
    assets.py       — Asset + AssetStore (scope-keyed SQLite, delta detection)
    scope.py        — Scope engagement model
    discovery.py    — passive/active discovery orchestration
    monitor.py      — continuous ASM poll loop + deep-tool integration
    notify.py       — outbound Slack/webhook notifier
    threatintel.py  — CISA KEV / EPSS enrichment
    sweep.py        — mass parallel scanning across the surface
    modes.py        — named workflow playbooks
    report.py       — per-scope aggregate reporting
"""

from __future__ import annotations

from clearwing.asm.assets import ASSET_TYPES, Asset, AssetStore
from clearwing.asm.scope import Scope

__all__ = ["ASSET_TYPES", "Asset", "AssetStore", "Scope"]
