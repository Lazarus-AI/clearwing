"""Named workflow playbooks for ASM runs.

Sn1per's value partly came from curated named "modes" (recon, web, stealth,
nuke...) that compose many steps behind one word. These are Clearwing's
equivalent — presets that toggle the discovery/scan/sweep/screenshot steps of an
`asm scan`. They compose the existing engine; they add no new detection.
"""

from __future__ import annotations

from dataclasses import dataclass

from clearwing.asm.discovery import DiscoveryOptions


@dataclass(frozen=True)
class AsmMode:
    name: str
    description: str
    discovery: DiscoveryOptions
    scan_new_assets: bool = False
    sweep: bool = False
    screenshot: bool = False


MODES: dict[str, AsmMode] = {
    "recon": AsmMode(
        name="recon",
        description="Passive discovery only — subdomains, URLs, DNS. No probing.",
        discovery=DiscoveryOptions(passive=True, resolve=True, probe=False, wayback=True),
    ),
    "stealth": AsmMode(
        name="stealth",
        description="Passive-only, no DNS resolution or probing (leaves no trace on the target).",
        discovery=DiscoveryOptions(passive=True, resolve=False, probe=False, wayback=True),
    ),
    "web-assessment": AsmMode(
        name="web-assessment",
        description="Discover + probe live web hosts + screenshot gallery for triage.",
        discovery=DiscoveryOptions(passive=True, resolve=True, probe=True, wayback=True),
        screenshot=True,
    ),
    "external-sweep": AsmMode(
        name="external-sweep",
        description="Full discovery, then port/service/vuln scan across every host.",
        discovery=DiscoveryOptions(passive=True, resolve=True, probe=True, wayback=True),
        scan_new_assets=True,
        sweep=True,
    ),
}

DEFAULT_MODE = "recon"


def get_mode(name: str | None) -> AsmMode:
    """Return the named mode, defaulting to `recon`. Raises on an unknown name."""
    key = (name or DEFAULT_MODE).strip().lower()
    if key not in MODES:
        raise ValueError(f"Unknown asm mode {name!r}; choose from: {', '.join(sorted(MODES))}")
    return MODES[key]


__all__ = ["AsmMode", "MODES", "DEFAULT_MODE", "get_mode"]
