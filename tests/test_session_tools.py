"""Tests for session and token replay tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

import clearwing.agent.tools.recon.session_tools as sess_mod
from clearwing.agent.tools.recon.session_tools import (
    extract_session_tokens,
    get_session_tools,
    replay_with_mutations,
    test_session_fixation,
)


@dataclass
class FakeProxyEntry:
    id: int = 1
    url: str = ""
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)


@dataclass
class FakeProxyHistory:
    entries: list = field(default_factory=list)


class TestExtractSessionTokens:
    def _patch_history(self, fake):
        return patch("clearwing.agent.tools.recon.proxy_tools._proxy_history", fake)

    def test_empty_history(self):
        fake = FakeProxyHistory()
        with self._patch_history(fake):
            result = extract_session_tokens.invoke({})
        assert result["total_tokens"] == 0

    def test_finds_bearer_token(self):
        entry = FakeProxyEntry(
            id=1,
            url="http://example.com/api/test",
            request_headers={"Authorization": "Bearer abc123"},
        )
        fake = FakeProxyHistory(entries=[entry])
        with self._patch_history(fake):
            result = extract_session_tokens.invoke({})
        assert len(result["bearer_tokens"]) == 1
        assert result["bearer_tokens"][0]["type"] == "bearer"

    def test_finds_cookies(self):
        entry = FakeProxyEntry(
            id=1,
            url="http://example.com/",
            request_headers={"Cookie": "session_id=abc; theme=dark"},
        )
        fake = FakeProxyHistory(entries=[entry])
        with self._patch_history(fake):
            result = extract_session_tokens.invoke({})
        assert len(result["session_cookies"]) == 2

    def test_url_filter(self):
        entries = [
            FakeProxyEntry(id=1, url="http://example.com/api/auth", request_headers={"Authorization": "Bearer abc"}),
            FakeProxyEntry(id=2, url="http://example.com/static/js", request_headers={"Authorization": "Bearer def"}),
        ]
        fake = FakeProxyHistory(entries=entries)
        with self._patch_history(fake):
            result = extract_session_tokens.invoke({"url_filter": "/api/"})
        assert len(result["bearer_tokens"]) == 1


class TestReplayWithMutations:
    def test_declined(self):
        with patch.object(sess_mod, "interrupt", return_value=False):
            result = replay_with_mutations.invoke({
                "target_url": "http://example.com/api/test",
                "token": "abc123",
            })
        assert "error" in result

    def test_mutations_tested(self):
        def mock_request(url, method="GET", body=None, headers=None, cookies="", timeout=30):
            headers = headers or {}
            auth = headers.get("Authorization", "")
            if auth == "Bearer AbC123":
                return (200, {}, '{"ok": true}', 10.0)
            return (401, {}, '{"error": "unauthorized"}', 5.0)

        with (
            patch.object(sess_mod, "interrupt", return_value=True),
            patch.object(sess_mod, "_http_request", mock_request),
        ):
            result = replay_with_mutations.invoke({
                "target_url": "http://example.com/api",
                "token": "AbC123",
            })
        assert result["baseline_status"] == 200
        assert result["mutations_tested"] >= 10
        assert any(r["mutation"] == "original" and r["status"] == 200 for r in result["results"])

    def test_weak_validation_detected(self):
        def mock_request(url, method="GET", body=None, headers=None, cookies="", timeout=30):
            return (200, {}, '{"ok": true}', 10.0)

        with (
            patch.object(sess_mod, "interrupt", return_value=True),
            patch.object(sess_mod, "_http_request", mock_request),
        ):
            result = replay_with_mutations.invoke({
                "target_url": "http://example.com/api",
                "token": "abc123",
            })
        assert any("WARNING" in f for f in result["findings"])


class TestSessionFixation:
    def test_declined(self):
        with patch.object(sess_mod, "interrupt", return_value=False):
            result = test_session_fixation.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_no_cookies(self):
        def mock_request(url, method="GET", body=None, headers=None, cookies="", timeout=30):
            return (200, {}, "<html></html>", 10.0)

        with (
            patch.object(sess_mod, "interrupt", return_value=True),
            patch.object(sess_mod, "_http_request", mock_request),
        ):
            result = test_session_fixation.invoke({"target": "http://example.com"})
        assert result["fixation_risk"] is False

    def test_fixation_detected(self):
        call_count = [0]

        def mock_request(url, method="GET", body=None, headers=None, cookies="", timeout=30):
            call_count[0] += 1
            if call_count[0] == 1:
                return (200, {"Set-Cookie": "session_id=abc123; HttpOnly"}, "<html></html>", 10.0)
            return (200, {}, '{"status": "ok"}', 10.0)

        with (
            patch.object(sess_mod, "interrupt", return_value=True),
            patch.object(sess_mod, "_http_request", mock_request),
        ):
            result = test_session_fixation.invoke({"target": "http://example.com"})
        assert result["fixation_risk"] is True
        assert "session_id" in result["session_like_unchanged"]


class TestGetSessionTools:
    def test_returns_list(self):
        assert isinstance(get_session_tools(), list)

    def test_tool_count(self):
        assert len(get_session_tools()) == 3

    def test_tool_names(self):
        names = [t.name for t in get_session_tools()]
        assert names == ["extract_session_tokens", "replay_with_mutations", "test_session_fixation"]
