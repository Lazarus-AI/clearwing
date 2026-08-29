"""Tests for the outbound ASM notifier."""

from __future__ import annotations

import pytest

from clearwing.asm.notify import Notifier
from clearwing.core.event_payloads import AssetDiscoveredPayload
from clearwing.core.events import EventBus, EventType


@pytest.fixture
def posts(monkeypatch):
    sent: list[tuple[str, dict]] = []
    monkeypatch.setattr(Notifier, "_post", lambda self, url, payload: sent.append((url, payload)))
    return sent


def test_disabled_notifier_subscribes_to_nothing(posts):
    n = Notifier()  # no urls
    assert n.enabled is False
    n.subscribe()
    EventBus().emit_asset_discovered(AssetDiscoveredPayload("acme", "subdomain", "a.acme.com", "crt.sh", None))
    assert posts == []


def test_notifies_on_new_asset_and_finding(posts):
    n = Notifier(slack_url="http://sink/slack")
    with n:
        EventBus().emit_asset_discovered(
            AssetDiscoveredPayload("acme", "subdomain", "api.acme.com", "crt.sh", None)
        )
        EventBus().emit(EventType.FINDING_RECORDED, {"severity": "high", "finding_type": "sqli", "file": "x.py"})
    assert len(posts) == 2
    assert "api.acme.com" in posts[0][1]["text"]
    assert "sqli" in posts[1][1]["text"]


def test_unsubscribe_stops_notifications(posts):
    n = Notifier(webhook_url="http://sink/hook")
    n.subscribe()
    n.unsubscribe()
    EventBus().emit_asset_discovered(AssetDiscoveredPayload("acme", "subdomain", "a.acme.com", "crt.sh", None))
    assert posts == []


def test_from_config_prefers_env(monkeypatch):
    monkeypatch.setenv("CLEARWING_SLACK_WEBHOOK", "http://env/slack")
    n = Notifier.from_config({"slack_webhook_env": "CLEARWING_SLACK_WEBHOOK", "slack_webhook_url": "http://literal"})
    assert n.slack_url == "http://env/slack"


def test_a_failing_post_never_raises():
    # the real _post swallows transport errors; sending to a bad url must not throw
    Notifier(slack_url="http://127.0.0.1:1/definitely-not-listening").notify("hi")
