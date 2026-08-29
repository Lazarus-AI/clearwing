"""Tests for external discovery tools and the ASM discovery orchestrator."""

from __future__ import annotations

from collections import Counter

import pytest

import clearwing.agent.tools.recon.discovery_tools as dt
from clearwing.asm import discovery
from clearwing.asm.scope import Scope
from clearwing.data.knowledge import KnowledgeGraph


@pytest.fixture(autouse=True)
def _mock_http(monkeypatch):
    """Mock every outbound source so tests never touch the network."""

    def fake_json(url, timeout=20):
        if "crt.sh" in url:
            return [
                {"name_value": "api.example.com\n*.example.com"},
                {"name_value": "www.example.com"},
                {"name_value": "evil.com"},  # out of scope — must be dropped
            ]
        if "web.archive.org" in url:
            return [["original"], ["https://example.com/login"], ["https://example.com/login"]]
        return None

    monkeypatch.setattr(dt, "_http_get_json", fake_json)
    monkeypatch.setattr(dt, "github_subdomains", lambda d, env_var="GITHUB_API_KEY": [])
    monkeypatch.setattr(dt, "resolve_name", lambda n: ["93.184.216.34"] if "example.com" in n else [])
    monkeypatch.setattr(
        dt,
        "probe_url",
        lambda u, timeout=10: {
            "url": u,
            "live": u.startswith("https"),
            "status": 200,
            "server": "nginx",
            "technologies": ["nginx", "WordPress"],
        },
    )


def test_crtsh_parses_and_strips_wildcards():
    subs = dt.crtsh_subdomains("example.com")
    assert "api.example.com" in subs and "example.com" in subs
    assert "*.example.com" not in subs
    assert "evil.com" not in subs  # not a subdomain of example.com


def test_wayback_dedupes_and_skips_header():
    assert dt.wayback_urls("example.com") == ["https://example.com/login"]


def test_fingerprint_from_headers_and_body():
    techs = dt._fingerprint({"x-powered-by": "PHP/8.1", "server": "nginx/1.18"}, "<div>wp-content</div>")
    assert set(techs) == {"PHP", "nginx", "WordPress"}


def test_discover_subdomains_tool_shape():
    out = dt.discover_subdomains.func("example.com")
    assert out["count"] == len(out["subdomains"]) and "crt.sh" in out["sources"]


def test_run_discovery_builds_the_hierarchy_and_respects_scope():
    scope = Scope.from_domain("example.com", name="acme")
    result = discovery.run_discovery(scope)
    counts = Counter(a.asset_type for a in result.assets)
    assert counts["domain"] == 1
    assert {a.value for a in result.assets if a.asset_type == "subdomain"} == {
        "api.example.com",
        "www.example.com",
    }
    assert "evil.com" not in {a.value for a in result.assets}
    assert counts["ip"] >= 1 and counts["host"] >= 1
    assert "WordPress" in {a.value for a in result.assets if a.asset_type == "technology"}


def test_discovery_options_gate_steps():
    scope = Scope.from_domain("example.com", name="acme")
    passive_only = discovery.run_discovery(
        scope, discovery.DiscoveryOptions(passive=True, resolve=False, probe=False, wayback=False)
    )
    types = {a.asset_type for a in passive_only.assets}
    assert "subdomain" in types
    assert "ip" not in types and "host" not in types and "url" not in types


def test_project_to_graph_mirrors_assets():
    scope = Scope.from_domain("example.com", name="acme")
    result = discovery.run_discovery(scope)
    kg = KnowledgeGraph()
    discovery.project_to_graph(kg, result.assets)
    subs = {e.id for e in kg.get_entities_by_type("subdomain")}
    assert "api.example.com" in subs
    assert kg.get_entity("example.com") is not None
    neighbors = {getattr(n, "id", n) for n in kg.get_neighbors("example.com", "HAS_SUBDOMAIN")}
    assert "api.example.com" in neighbors


def test_discovery_never_raises_when_a_source_fails(monkeypatch):
    monkeypatch.setattr(dt, "crtsh_subdomains", lambda d: (_ for _ in ()).throw(RuntimeError("boom")))
    scope = Scope.from_domain("example.com", name="acme")
    # a failing source contributes nothing but does not crash the run
    result = discovery.run_discovery(scope)
    assert any(a.asset_type == "domain" for a in result.assets)
