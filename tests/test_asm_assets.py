"""Tests for the ASM asset store and scope model."""

from __future__ import annotations

import pytest

from clearwing.asm.assets import ASSET_TYPES, Asset, AssetStore
from clearwing.asm.scope import Scope, ScopeError


@pytest.fixture
def store(tmp_path):
    s = AssetStore(tmp_path / "assets.db")
    yield s
    s.close()


def _sub(scope, value, **kw):
    return Asset(scope=scope, asset_type="subdomain", value=value, **kw)


def test_record_returns_only_new_assets(store):
    first = store.record_observations("acme", [_sub("acme", "a.acme.com"), _sub("acme", "b.acme.com")])
    assert sorted(a.value for a in first) == ["a.acme.com", "b.acme.com"]

    # re-observing a known asset plus one new one returns only the new one
    delta = store.record_observations("acme", [_sub("acme", "a.acme.com"), _sub("acme", "c.acme.com")])
    assert [a.value for a in delta] == ["c.acme.com"]


def test_delta_is_empty_on_a_stable_surface(store):
    assets = [_sub("acme", "a.acme.com"), _sub("acme", "b.acme.com")]
    store.record_observations("acme", assets)
    assert store.record_observations("acme", assets) == []


def test_scopes_are_isolated(store):
    store.record_observations("acme", [_sub("acme", "a.acme.com")])
    # the same value under a different scope is a different (new) asset
    delta = store.record_observations("other", [_sub("other", "a.acme.com")])
    assert [a.value for a in delta] == ["a.acme.com"]
    assert store.scopes() == ["acme", "other"]


def test_first_seen_is_stable_last_seen_advances(store):
    (a,) = store.record_observations("acme", [_sub("acme", "a.acme.com")])
    first_seen = a.first_seen
    # a second observation must not move first_seen but must refresh last_seen
    store.record_observations("acme", [_sub("acme", "a.acme.com")])
    known = store.known_assets("acme", "subdomain")[0]
    assert known.first_seen == first_seen
    assert known.last_seen >= first_seen


def test_is_new(store):
    asset = _sub("acme", "a.acme.com")
    assert store.is_new("acme", asset) is True
    store.record_observations("acme", [asset])
    assert store.is_new("acme", asset) is False


def test_stats_and_known_assets_filter(store):
    store.record_observations(
        "acme",
        [
            _sub("acme", "a.acme.com"),
            Asset("acme", "ip", "1.2.3.4"),
            Asset("acme", "host", "https://a.acme.com"),
        ],
    )
    assert store.stats("acme") == {"subdomain": 1, "ip": 1, "host": 1}
    assert [a.value for a in store.known_assets("acme", "ip")] == ["1.2.3.4"]


def test_unknown_asset_type_is_skipped(store):
    delta = store.record_observations("acme", [Asset("acme", "bogus", "x")])
    assert delta == []
    assert store.stats("acme") == {}


def test_deterministic_id_and_value_redaction(tmp_path):
    a = Asset("acme", "subdomain", "a.acme.com")
    b = Asset("acme", "subdomain", "a.acme.com")
    assert a.id == b.id and a.id.startswith("asset-")
    assert Asset("acme", "ip", "1.1.1.1").id != a.id


def test_deltas_since(store):
    import time

    store.record_observations("acme", [_sub("acme", "old.acme.com")])
    boundary = time.time()
    time.sleep(0.01)
    store.record_observations("acme", [_sub("acme", "new.acme.com")])
    recent = store.deltas_since("acme", boundary)
    assert [a.value for a in recent] == ["new.acme.com"]


def test_asset_types_constant_covers_the_hierarchy():
    assert {"domain", "subdomain", "host", "ip", "port", "service", "url", "technology"} == set(ASSET_TYPES)


# --- Scope ------------------------------------------------------------------


def test_scope_from_domain_and_in_scope():
    s = Scope.from_domain("Example.com")
    assert s.name == "example_com"
    assert s.in_scope("api.example.com") and s.in_scope("example.com")
    assert not s.in_scope("example.com.evil.com")
    assert not s.in_scope("notexample.com")


def test_scope_exclusions():
    s = Scope(name="acme", domains=["acme.com"], exclusions=["legacy.acme.com"])
    assert s.in_scope("api.acme.com")
    assert not s.in_scope("legacy.acme.com")
    assert not s.in_scope("db.legacy.acme.com")


def test_scope_rejects_bad_name_and_domain():
    with pytest.raises(ScopeError):
        Scope(name="bad name")
    with pytest.raises(ScopeError):
        Scope(name="ok", domains=["not a domain"])


def test_scope_resolve_prefers_configured_scope():
    section = {"scopes": {"acme": {"domains": ["acme.com", "acme.io"]}}}
    resolved = Scope.resolve("acme", section)
    assert resolved.name == "acme" and "acme.io" in resolved.domains
    # a bare domain with no matching scope becomes an ad-hoc scope
    assert Scope.resolve("example.com", section).domains == ["example.com"]
    with pytest.raises(ScopeError):
        Scope.resolve("not-a-scope-or-domain", section)
