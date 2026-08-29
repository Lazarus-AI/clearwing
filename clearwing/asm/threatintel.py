"""Threat-intel enrichment for prioritization (CISA KEV + FIRST EPSS).

Clearwing already finds CVEs via `scan_vulnerabilities`. This layer answers
"which of these actually matter right now" from two free public feeds:

- **CISA KEV** — the Known Exploited Vulnerabilities catalog (a CVE here is
  being exploited in the wild).
- **EPSS** — FIRST's Exploit Prediction Scoring System (0..1 probability of
  exploitation in the next 30 days).

Enriched findings sort KEV-first, then by EPSS, then by CVSS/severity — so the
monitor, sweep, and reports lead with what's dangerous. The KEV catalog is
cached under ``~/.clearwing/asm/`` with a TTL; `_http_get_json` is the single
monkeypatchable seam.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss?cve="
_KEV_TTL = 24 * 3600
_TIMEOUT = 20


def _http_get_json(url: str, *, timeout: int = _TIMEOUT) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": "clearwing-asm/0.5"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read(16_000_000).decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        logger.debug("threat-intel fetch failed for %s: %s", url, exc)
        return None


def _cache_path() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "asm" / "kev-cache.json"


class ThreatIntel:
    """Lazily-loaded KEV set + EPSS lookups, with a small on-disk KEV cache."""

    def __init__(self, cache_path: Path | None = None):
        self._cache_path = cache_path or _cache_path()
        self._kev: set[str] | None = None
        self._epss: dict[str, float] = {}

    def _load_kev(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        cached = self._read_cache()
        if cached is not None:
            self._kev = cached
            return cached
        data = _http_get_json(_KEV_URL)
        kev: set[str] = set()
        if isinstance(data, dict):
            for vuln in data.get("vulnerabilities", []):
                cve = str(vuln.get("cveID", "")).upper()
                if cve:
                    kev.add(cve)
        self._kev = kev
        if kev:
            self._write_cache(kev)
        return kev

    def is_known_exploited(self, cve: str) -> bool:
        return cve.upper() in self._load_kev()

    def epss_score(self, cve: str) -> float | None:
        cve = cve.upper()
        if cve in self._epss:
            return self._epss[cve]
        data = _http_get_json(_EPSS_URL + cve)
        score: float | None = None
        if isinstance(data, dict):
            for row in data.get("data", []):
                if str(row.get("cve", "")).upper() == cve:
                    try:
                        score = float(row.get("epss"))
                    except (TypeError, ValueError):
                        score = None
        if score is not None:
            self._epss[cve] = score
        return score

    def enrich(self, findings: list[dict]) -> list[dict]:
        """Annotate CVE findings with KEV/EPSS and return them priority-sorted."""
        for finding in findings:
            cve = str(finding.get("cve") or finding.get("cwe") or "")
            if cve.upper().startswith("CVE-"):
                finding["known_exploited"] = self.is_known_exploited(cve)
                finding["epss"] = self.epss_score(cve)
            else:
                finding.setdefault("known_exploited", False)
                finding.setdefault("epss", None)
        return sorted(findings, key=_priority_key, reverse=True)

    # -- cache ----------------------------------------------------------

    def _read_cache(self) -> set[str] | None:
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict) or time.time() - raw.get("fetched_at", 0) > _KEV_TTL:
            return None
        cves = raw.get("cves")
        return set(cves) if isinstance(cves, list) else None

    def _write_cache(self, kev: set[str]) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(
                json.dumps({"fetched_at": time.time(), "cves": sorted(kev)}),
                encoding="utf-8",
            )
        except OSError:
            logger.debug("Could not write KEV cache", exc_info=True)


def _priority_key(finding: dict) -> tuple:
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return (
        1 if finding.get("known_exploited") else 0,
        finding.get("epss") or 0.0,
        float(finding.get("cvss") or 0.0),
        severity_rank.get(str(finding.get("severity", "info")).lower(), 0),
    )


__all__ = ["ThreatIntel"]
