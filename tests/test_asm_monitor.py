"""Tests for the continuous ASM monitor."""

from __future__ import annotations

import pytest

from clearwing.asm.assets import Asset, AssetStore
from clearwing.asm.monitor import AsmMonitor, AsmMonitorConfig
from clearwing.asm.scope import Scope
from clearwing.core.events import EventBus, EventType


@pytest.fixture
def store(tmp_path):
    s = AssetStore(tmp_path / "assets.db")
    yield s
    s.close()


@pytest.fixture
def captured_events():
    events: list = []
    handler = events.append
    EventBus().subscribe(EventType.ASSET_DISCOVERED, handler)
    yield events
    EventBus().unsubscribe(EventType.ASSET_DISCOVERED, handler)


def _cfg(store, **kw):
    return AsmMonitorConfig(scope=Scope.from_domain("acme.com", name="acme"), store=store, **kw)


def test_cycle_emits_only_for_new_assets(store, captured_events):
    cycles = iter(
        [
            [Asset("acme", "subdomain", "a.acme.com"), Asset("acme", "subdomain", "b.acme.com")],
            [Asset("acme", "subdomain", "a.acme.com"), Asset("acme", "subdomain", "c.acme.com")],
        ]
    )
    monitor = AsmMonitor(
        _cfg(store, max_iterations=2, poll_interval_seconds=0, scan_new_assets=False,
             discover_fn=lambda s, o: next(cycles))
    )
    monitor.run()
    assert monitor.iterations == 2
    # a.acme.com is only announced once, across both cycles
    assert sorted(p.value for p in captured_events) == ["a.acme.com", "b.acme.com", "c.acme.com"]


def test_scan_runs_only_on_new_ip_and_host_assets(store):
    scanned: list[str] = []
    assets = [
        Asset("acme", "subdomain", "a.acme.com"),
        Asset("acme", "ip", "1.2.3.4"),
        Asset("acme", "host", "https://a.acme.com"),
    ]
    monitor = AsmMonitor(
        _cfg(store, max_iterations=1, poll_interval_seconds=0, scan_new_assets=True,
             threat_intel=False, discover_fn=lambda s, o: assets,
             scan_fn=lambda a: scanned.append(a.value) or [])
    )
    monitor.run()
    assert sorted(scanned) == ["1.2.3.4", "https://a.acme.com"]  # not the subdomain


def test_scan_disabled(store):
    scanned: list[str] = []
    monitor = AsmMonitor(
        _cfg(store, max_iterations=1, poll_interval_seconds=0, scan_new_assets=False,
             discover_fn=lambda s, o: [Asset("acme", "ip", "1.2.3.4")],
             scan_fn=lambda a: scanned.append(a.value) or [])
    )
    monitor.run()
    assert scanned == []


def test_cancel_stops_an_infinite_monitor(store):
    calls = {"n": 0}

    def discover(scope, opts):
        calls["n"] += 1
        monitor.cancel()  # cancel from inside the first cycle
        return [Asset("acme", "subdomain", f"h{calls['n']}.acme.com")]

    monitor = AsmMonitor(
        _cfg(store, max_iterations=0, poll_interval_seconds=999, scan_new_assets=False,
             discover_fn=discover)
    )
    monitor.run()
    assert calls["n"] == 1  # cancelled before a second cycle / long sleep


def test_on_cycle_callback(store):
    seen: list[int] = []
    monitor = AsmMonitor(
        _cfg(store, max_iterations=1, poll_interval_seconds=0, scan_new_assets=False,
             discover_fn=lambda s, o: [Asset("acme", "subdomain", "a.acme.com")],
             on_cycle=lambda new: seen.append(len(new)))
    )
    monitor.run()
    assert seen == [1]
