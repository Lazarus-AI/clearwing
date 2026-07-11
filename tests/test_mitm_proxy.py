"""Tests for MITM Proxy (unit tests, no real browser)."""

from __future__ import annotations

from dataclasses import asdict
from unittest.mock import patch

import pytest

import clearwing.agent.tools.recon.mitm_proxy as mitm_mod
from clearwing.agent.tools.recon.mitm_proxy import (
    InterceptRule,
    _inject_rules,
    _intercept_rules,
    _intercepted_tabs,
    _is_text_content,
    _lock,
    _matches_inject,
    _matches_rule,
    _mitm_request_ids,
    _route_handlers,
    get_mitm_tools,
    mitm_get_decrypted_traffic,
    mitm_inject_response,
    mitm_set_intercept_rule,
    mitm_start,
    mitm_stop,
)
from clearwing.agent.tools.recon.proxy_tools import _proxy_history


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset all module-level state between tests."""
    with _lock:
        _intercept_rules.clear()
        mitm_mod._next_rule_id = 1
        _intercepted_tabs.clear()
        _mitm_request_ids.clear()
        _inject_rules.clear()
        _route_handlers.clear()

    _proxy_history.clear()

    yield

    with _lock:
        _intercept_rules.clear()
        mitm_mod._next_rule_id = 1
        _intercepted_tabs.clear()
        _mitm_request_ids.clear()
        _inject_rules.clear()
        _route_handlers.clear()

    _proxy_history.clear()


# --- InterceptRule ---


class TestInterceptRule:
    def test_fields(self):
        rule = InterceptRule(id=1, url_pattern="*/api/*", methods=["POST"], log_request_body=True, log_response_body=True, enabled=True)
        assert rule.id == 1
        assert rule.url_pattern == "*/api/*"
        assert rule.methods == ["POST"]

    def test_defaults(self):
        rule = InterceptRule(id=1, url_pattern="*")
        assert rule.methods == []
        assert rule.log_request_body is True
        assert rule.log_response_body is True
        assert rule.enabled is True

    def test_asdict(self):
        rule = InterceptRule(id=1, url_pattern="*")
        d = asdict(rule)
        assert d["id"] == 1
        assert d["url_pattern"] == "*"


# --- _is_text_content ---


class TestIsTextContent:
    @pytest.mark.parametrize("ct", [
        "text/html",
        "text/plain",
        "text/css",
        "application/json",
        "application/json; charset=utf-8",
        "application/xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
    ])
    def test_text_types(self, ct):
        assert _is_text_content(ct) is True

    @pytest.mark.parametrize("ct", [
        "image/png",
        "image/jpeg",
        "application/octet-stream",
        "application/pdf",
        "audio/mpeg",
    ])
    def test_binary_types(self, ct):
        assert _is_text_content(ct) is False

    def test_none(self):
        assert _is_text_content(None) is False

    def test_empty_string(self):
        assert _is_text_content("") is False


# --- _matches_rule ---


class TestMatchesRule:
    def test_empty_rules_returns_none(self):
        assert _matches_rule("https://example.com/api/auth", "POST") is None

    def test_matches_wildcard(self):
        _intercept_rules[1] = InterceptRule(id=1, url_pattern="*")
        assert _matches_rule("https://example.com/anything", "GET") is not None

    def test_matches_path_pattern(self):
        _intercept_rules[1] = InterceptRule(id=1, url_pattern="*/api/v1/auth*")
        assert _matches_rule("https://example.com/api/v1/auth/init", "POST") is not None

    def test_no_match(self):
        _intercept_rules[1] = InterceptRule(id=1, url_pattern="*/api/v2/*")
        assert _matches_rule("https://example.com/api/v1/auth", "POST") is None

    def test_method_filter_match(self):
        _intercept_rules[1] = InterceptRule(id=1, url_pattern="*", methods=["POST"])
        assert _matches_rule("https://example.com/api", "POST") is not None

    def test_method_filter_no_match(self):
        _intercept_rules[1] = InterceptRule(id=1, url_pattern="*", methods=["POST"])
        assert _matches_rule("https://example.com/api", "GET") is None

    def test_disabled_rule_skipped(self):
        _intercept_rules[1] = InterceptRule(id=1, url_pattern="*", enabled=False)
        assert _matches_rule("https://example.com/api", "GET") is None


# --- _matches_inject ---


class TestMatchesInject:
    def test_no_inject_rules(self):
        assert _matches_inject("https://example.com/api") is None

    def test_matches_pattern(self):
        _inject_rules["*/api/auth*"] = {"status": 401, "headers": {}, "body": "denied"}
        result = _matches_inject("https://example.com/api/auth/init")
        assert result is not None
        assert result["status"] == 401

    def test_no_match(self):
        _inject_rules["*/api/v2/*"] = {"status": 200, "headers": {}, "body": "ok"}
        assert _matches_inject("https://example.com/api/v1/auth") is None


# --- mitm_set_intercept_rule ---


class TestMitmSetInterceptRule:
    def test_creates_rule(self):
        result = mitm_set_intercept_rule.invoke({"url_pattern": "*/api/*"})
        assert result["status"] == "rule_added"
        assert result["rule"]["url_pattern"] == "*/api/*"
        assert result["rule"]["id"] == 1

    def test_parses_methods(self):
        result = mitm_set_intercept_rule.invoke({"url_pattern": "*", "methods": "POST,PUT"})
        assert result["rule"]["methods"] == ["POST", "PUT"]

    def test_empty_methods_means_all(self):
        result = mitm_set_intercept_rule.invoke({"url_pattern": "*"})
        assert result["rule"]["methods"] == []

    def test_increments_id(self):
        mitm_set_intercept_rule.invoke({"url_pattern": "*"})
        result = mitm_set_intercept_rule.invoke({"url_pattern": "*/api/*"})
        assert result["rule"]["id"] == 2


# --- mitm_get_decrypted_traffic ---


class TestMitmGetDecryptedTraffic:
    def test_empty_when_no_mitm_traffic(self):
        _proxy_history.add(method="GET", url="https://example.com", status_code=200, duration_ms=50)
        result = mitm_get_decrypted_traffic.invoke({})
        assert result["count"] == 0

    def test_filters_to_mitm_ids(self):
        entry = _proxy_history.add(method="POST", url="https://example.com/auth", status_code=200, duration_ms=100)
        _mitm_request_ids.append(entry.id)
        _proxy_history.add(method="GET", url="https://example.com/other", status_code=200, duration_ms=50)

        result = mitm_get_decrypted_traffic.invoke({})
        assert result["count"] == 1
        assert result["entries"][0]["url"] == "https://example.com/auth"

    def test_url_contains_filter(self):
        e1 = _proxy_history.add(method="POST", url="https://example.com/auth", status_code=200, duration_ms=100)
        e2 = _proxy_history.add(method="GET", url="https://example.com/static/style.css", status_code=200, duration_ms=10)
        _mitm_request_ids.extend([e1.id, e2.id])

        result = mitm_get_decrypted_traffic.invoke({"url_contains": "auth"})
        assert result["count"] == 1

    def test_method_filter(self):
        e1 = _proxy_history.add(method="POST", url="https://example.com/auth", status_code=200, duration_ms=100)
        e2 = _proxy_history.add(method="GET", url="https://example.com/auth", status_code=200, duration_ms=50)
        _mitm_request_ids.extend([e1.id, e2.id])

        result = mitm_get_decrypted_traffic.invoke({"method": "POST"})
        assert result["count"] == 1


# --- mitm_start / mitm_stop errors ---


class TestMitmStartErrors:
    def test_error_already_intercepting(self):
        _intercepted_tabs.add("default")
        result = mitm_start.invoke({"tab_name": "default"})
        assert "error" in result
        assert "already" in result["error"].lower()


class TestMitmStopErrors:
    def test_error_not_intercepting(self):
        result = mitm_stop.invoke({"tab_name": "default"})
        assert "error" in result
        assert "not being intercepted" in result["error"].lower()


# --- mitm_inject_response ---


class TestMitmInjectResponse:
    def test_inject_sets_rule(self):
        with patch("clearwing.agent.tools.recon.mitm_proxy.interrupt"):
            result = mitm_inject_response.invoke({
                "url_pattern": "*/api/auth*",
                "status": 401,
                "body": '{"error": "denied"}',
            })
        assert result["status"] == "inject_rule_set"
        assert "*/api/auth*" in _inject_rules
        assert _inject_rules["*/api/auth*"]["status"] == 401

    def test_inject_remove(self):
        _inject_rules["*/api/*"] = {"status": 200, "headers": {}, "body": "ok"}
        with patch("clearwing.agent.tools.recon.mitm_proxy.interrupt"):
            result = mitm_inject_response.invoke({"url_pattern": "*/api/*", "remove": True})
        assert result["status"] == "removed"
        assert "*/api/*" not in _inject_rules

    def test_inject_remove_nonexistent(self):
        with patch("clearwing.agent.tools.recon.mitm_proxy.interrupt"):
            result = mitm_inject_response.invoke({"url_pattern": "*/missing/*", "remove": True})
        assert result["status"] == "not_found"

    def test_inject_calls_interrupt(self):
        with patch("clearwing.agent.tools.recon.mitm_proxy.interrupt") as mock_interrupt:
            mitm_inject_response.invoke({"url_pattern": "*", "body": "injected"})
            mock_interrupt.assert_called_once()


# --- Tool metadata ---


class TestGetMitmTools:
    def test_returns_list(self):
        tools = get_mitm_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_mitm_tools()
        assert len(tools) == 5

    def test_tool_names(self):
        tools = get_mitm_tools()
        names = [t.name for t in tools]
        assert names == [
            "mitm_start",
            "mitm_stop",
            "mitm_set_intercept_rule",
            "mitm_get_decrypted_traffic",
            "mitm_inject_response",
        ]
