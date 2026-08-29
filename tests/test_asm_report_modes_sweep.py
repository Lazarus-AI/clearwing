"""Tests for ASM reporting, modes, and the mass sweep."""

from __future__ import annotations

import json

import pytest

from clearwing.asm import report as report_mod
from clearwing.asm import sweep as sweep_mod
from clearwing.asm.assets import Asset, AssetStore
from clearwing.asm.modes import DEFAULT_MODE, MODES, get_mode


@pytest.fixture
def store(tmp_path):
    s = AssetStore(tmp_path / "assets.db")
    s.record_observations(
        "acme",
        [
            Asset("acme", "domain", "acme.com"),
            Asset("acme", "subdomain", "api.acme.com"),
            Asset("acme", "ip", "1.2.3.4"),
            Asset("acme", "host", "https://api.acme.com"),
        ],
    )
    yield s
    s.close()


# --- report -----------------------------------------------------------------


def test_build_report_groups_assets_and_findings(store):
    findings = [{"cve": "CVE-1", "severity": "high", "known_exploited": True, "target": "1.2.3.4"}]
    data = report_mod.build_report(store, "acme", since=0.0, findings=findings)
    assert data["stats"] == {"domain": 1, "subdomain": 1, "ip": 1, "host": 1}
    assert "api.acme.com" in data["assets"]["subdomain"]
    assert len(data["new_since_last"]) == 4  # since=0 → all count as delta
    assert data["findings"] == findings


def test_render_markdown_and_json(store):
    data = report_mod.build_report(store, "acme", since=0.0, findings=[
        {"cve": "CVE-1", "severity": "critical", "known_exploited": True, "epss": 0.9, "target": "1.2.3.4"}
    ])
    md = report_mod.render_markdown(data)
    assert "# Attack surface — acme" in md and "**KEV**" in md and "api.acme.com" in md
    assert json.loads(report_mod.render_json(data))["scope"] == "acme"


def test_write_report_creates_files(store, tmp_path):
    paths = report_mod.write_report(store, "acme", out_dir=tmp_path / "out")
    assert set(paths) == {"markdown", "json"}
    for path in paths.values():
        assert (tmp_path / "out").exists()
        assert path.endswith((".md", ".json"))


# --- modes ------------------------------------------------------------------


def test_modes_registry():
    assert set(MODES) == {"recon", "stealth", "web-assessment", "external-sweep"}
    assert get_mode(None).name == DEFAULT_MODE
    assert get_mode("STEALTH").discovery.probe is False
    assert get_mode("external-sweep").sweep is True


def test_unknown_mode_raises():
    with pytest.raises(ValueError, match="Unknown asm mode"):
        get_mode("nuke")


# --- sweep ------------------------------------------------------------------


def test_sweep_scans_every_known_host(store):
    scanned: list[str] = []

    async def fake_scan(host):
        scanned.append(host)
        return [{"cve": "CVE-1", "severity": "high"}] if host == "1.2.3.4" else []

    result = sweep_mod.sweep_scope(store, "acme", threat_intel=False, scan_async=fake_scan)
    assert sorted(scanned) == ["1.2.3.4", "https://api.acme.com"]
    assert len(result.findings) == 1
    assert result.hosts_scanned == ["1.2.3.4", "https://api.acme.com"]


def test_sweep_tolerates_a_failing_host(store):
    async def fake_scan(host):
        if host == "1.2.3.4":
            raise RuntimeError("scan blew up")
        return [{"cve": "CVE-2", "severity": "low"}]

    result = sweep_mod.sweep_scope(store, "acme", threat_intel=False, scan_async=fake_scan)
    assert [f["cve"] for f in result.findings] == ["CVE-2"]
