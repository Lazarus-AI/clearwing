"""Tests for threat-intel enrichment and prioritization."""

from __future__ import annotations

import json
import time

import pytest

from clearwing.asm import threatintel
from clearwing.asm.threatintel import ThreatIntel


@pytest.fixture
def ti(tmp_path, monkeypatch):
    intel = ThreatIntel(cache_path=tmp_path / "kev.json")
    intel._kev = {"CVE-2021-44228"}
    intel._epss = {"CVE-2021-44228": 0.97, "CVE-2019-0001": 0.02}
    return intel


def test_enrich_sorts_kev_first_then_epss(ti):
    findings = [
        {"cve": "CVE-2019-0001", "severity": "high", "cvss": 7.5},
        {"cve": "CVE-2021-44228", "severity": "critical", "cvss": 10.0},
        {"cwe": "CWE-79", "severity": "medium"},
    ]
    ordered = ti.enrich(findings)
    assert [f.get("cve") or f.get("cwe") for f in ordered] == [
        "CVE-2021-44228",
        "CVE-2019-0001",
        "CWE-79",
    ]
    assert ordered[0]["known_exploited"] is True and ordered[0]["epss"] == 0.97
    assert ordered[2]["known_exploited"] is False


def test_kev_lookup_case_insensitive(ti):
    assert ti.is_known_exploited("cve-2021-44228") is True
    assert ti.is_known_exploited("CVE-0000-0000") is False


def test_kev_cache_round_trip(tmp_path, monkeypatch):
    calls = {"n": 0}

    def fake_json(url, timeout=20):
        calls["n"] += 1
        return {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}

    monkeypatch.setattr(threatintel, "_http_get_json", fake_json)
    cache = tmp_path / "kev.json"
    first = ThreatIntel(cache_path=cache)
    assert first.is_known_exploited("CVE-2021-44228") is True
    assert calls["n"] == 1
    # a fresh instance reads the on-disk cache instead of fetching again
    second = ThreatIntel(cache_path=cache)
    assert second.is_known_exploited("CVE-2021-44228") is True
    assert calls["n"] == 1


def test_stale_cache_is_ignored(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"fetched_at": time.time() - 10**7, "cves": ["CVE-1"]}))
    intel = ThreatIntel(cache_path=cache)
    assert intel._read_cache() is None
