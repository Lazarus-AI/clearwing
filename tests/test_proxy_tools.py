"""Tests for proxy tools module."""

import json
from pathlib import Path

import pytest

from clearwing.agent.tools.recon.proxy_tools import (
    ProxyHistory,
    _proxy_history,
    get_proxy_tools,
    proxy_clear_history,
    proxy_get_history,
    proxy_get_request,
)


@pytest.fixture(autouse=True)
def clear_proxy():
    """Clear proxy history before each test."""
    _proxy_history.clear()
    yield
    _proxy_history.clear()


# --- ProxyHistory ---


class TestProxyHistory:
    def test_add_entry(self):
        history = ProxyHistory()
        entry = history.add(
            method="GET",
            url="http://example.com",
            status_code=200,
            response_body="OK",
        )
        assert entry.id == 1
        assert entry.method == "GET"
        assert entry.url == "http://example.com"
        assert entry.status_code == 200

    def test_sequential_ids(self):
        history = ProxyHistory()
        e1 = history.add("GET", "http://a.com")
        e2 = history.add("POST", "http://b.com")
        assert e1.id == 1
        assert e2.id == 2

    def test_get_by_id(self):
        history = ProxyHistory()
        history.add("GET", "http://a.com")
        history.add("POST", "http://b.com")
        entry = history.get(2)
        assert entry.method == "POST"

    def test_get_nonexistent(self):
        history = ProxyHistory()
        assert history.get(999) is None

    def test_get_all_no_filter(self):
        history = ProxyHistory()
        history.add("GET", "http://a.com", status_code=200)
        history.add("POST", "http://b.com", status_code=201)
        results = history.get_all()
        assert len(results) == 2

    def test_get_all_filter_method(self):
        history = ProxyHistory()
        history.add("GET", "http://a.com")
        history.add("POST", "http://b.com")
        history.add("GET", "http://c.com")
        results = history.get_all(method="GET")
        assert len(results) == 2

    def test_get_all_filter_url(self):
        history = ProxyHistory()
        history.add("GET", "http://a.com/api/v1")
        history.add("GET", "http://b.com/login")
        results = history.get_all(url_contains="api")
        assert len(results) == 1

    def test_get_all_filter_status(self):
        history = ProxyHistory()
        history.add("GET", "http://a.com", status_code=200)
        history.add("GET", "http://b.com", status_code=404)
        results = history.get_all(status_code=404)
        assert len(results) == 1

    def test_get_all_limit(self):
        history = ProxyHistory()
        for i in range(10):
            history.add("GET", f"http://example.com/{i}")
        results = history.get_all(limit=3)
        assert len(results) == 3

    def test_clear(self):
        history = ProxyHistory()
        history.add("GET", "http://a.com")
        history.add("GET", "http://b.com")
        assert history.count == 2
        history.clear()
        assert history.count == 0

    def test_export(self, tmp_path):
        history = ProxyHistory()
        history.add("GET", "http://a.com", status_code=200)
        history.add("POST", "http://b.com", status_code=201)

        export_path = str(tmp_path / "export.json")
        history.export(export_path)

        data = json.loads(Path(export_path).read_text())
        assert len(data) == 2
        assert data[0]["method"] == "GET"

    def test_response_body_truncation(self):
        history = ProxyHistory()
        long_body = "x" * 20000
        entry = history.add("GET", "http://a.com", response_body=long_body)
        assert len(entry.response_body) == 10000

    def test_count_property(self):
        history = ProxyHistory()
        assert history.count == 0
        history.add("GET", "http://a.com")
        assert history.count == 1


# --- Proxy tool functions ---


class TestProxyTools:
    def test_get_proxy_tools_count(self):
        tools = get_proxy_tools()
        assert len(tools) == 6

    def test_tool_names(self):
        tools = get_proxy_tools()
        names = [t.name for t in tools]
        expected = [
            "proxy_request",
            "proxy_get_history",
            "proxy_get_request",
            "proxy_replay",
            "proxy_clear_history",
            "proxy_export_history",
        ]
        assert names == expected

    def test_proxy_get_history_empty(self):
        result = proxy_get_history.invoke({})
        assert result == []

    def test_proxy_get_request_not_found(self):
        result = proxy_get_request.invoke({"request_id": 999})
        assert "error" in result

    def test_proxy_clear_history_empty(self):
        result = proxy_clear_history.invoke({})
        assert result["cleared"] == 0
