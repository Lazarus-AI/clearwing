"""Tests for Confidential Computing endpoint discovery tools."""

from __future__ import annotations

import json
from unittest.mock import patch

import clearwing.agent.tools.recon.cc_tools as cc_mod
from clearwing.agent.tools.recon.cc_tools import (
    cc_discover_schema,
    cc_fuzz_fields,
    get_cc_tools,
)


class TestCcDiscoverSchema:
    def test_declined(self):
        with patch.object(cc_mod, "interrupt", return_value=False):
            result = cc_discover_schema.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_connection_failure(self):
        def mock_post(url, body, headers=None, timeout=30):
            return (0, {}, "Connection refused", 0.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_discover_schema.invoke({"target": "http://example.com"})
        assert result["iterations"] == 1
        assert result["schema_complete"] is False

    def test_endpoint_not_found(self):
        def mock_post(url, body, headers=None, timeout=30):
            return (404, {}, '{"error": "not found"}', 5.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_discover_schema.invoke({"target": "http://example.com"})
        assert result["final_status"] == 404
        assert result["schema_complete"] is False

    def test_discovers_fields(self):
        call_count = [0]

        def mock_post(url, body, headers=None, timeout=30):
            call_count[0] += 1
            payload = json.loads(body)
            if "attestation" not in payload:
                return (422, {}, 'missing field `attestation`', 5.0)
            if "session_id" not in payload:
                return (422, {}, 'missing field `session_id`', 5.0)
            return (200, {}, '{"session": "created"}', 10.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_discover_schema.invoke({"target": "http://example.com"})
        assert result["schema_complete"] is True
        assert "attestation" in result["discovered_fields"]
        assert "session_id" in result["discovered_fields"]

    def test_stops_when_no_new_fields(self):
        def mock_post(url, body, headers=None, timeout=30):
            return (422, {}, '{"error": "something went wrong"}', 5.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_discover_schema.invoke({
                "target": "http://example.com",
                "max_iterations": 5,
            })
        assert result["schema_complete"] is False
        assert result["iterations"] <= 5

    def test_initial_fields(self):
        def mock_post(url, body, headers=None, timeout=30):
            payload = json.loads(body)
            if "known_field" in payload and "new_field" not in payload:
                return (422, {}, 'missing field `new_field`', 5.0)
            if "new_field" in payload:
                return (200, {}, '{}', 5.0)
            return (422, {}, 'missing field `known_field`', 5.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_discover_schema.invoke({
                "target": "http://example.com",
                "initial_fields": {"known_field": "value"},
            })
        assert "new_field" in result["discovered_fields"]


class TestCcFuzzFields:
    def test_declined(self):
        with patch.object(cc_mod, "interrupt", return_value=False):
            result = cc_fuzz_fields.invoke({
                "target": "http://example.com",
                "base_payload": {"field1": "value1"},
            })
        assert "error" in result

    def test_no_fields(self):
        result = cc_fuzz_fields.invoke({
            "target": "http://example.com",
            "base_payload": {},
        })
        assert "error" in result

    def test_no_interesting_findings(self):
        def mock_post(url, body, headers=None, timeout=30):
            return (422, {}, '{"error": "invalid"}', 5.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_fuzz_fields.invoke({
                "target": "http://example.com",
                "base_payload": {"field1": "value1"},
                "fields_to_fuzz": ["field1"],
            })
        assert len(result["interesting_findings"]) == 0

    def test_accepts_fuzz_value(self):
        def mock_post(url, body, headers=None, timeout=30):
            payload = json.loads(body)
            if payload.get("field1") is None:
                return (200, {}, '{"ok": true}', 5.0)
            return (422, {}, '{"error": "invalid"}', 5.0)

        with (
            patch.object(cc_mod, "interrupt", return_value=True),
            patch.object(cc_mod, "_http_post_raw", mock_post),
        ):
            result = cc_fuzz_fields.invoke({
                "target": "http://example.com",
                "base_payload": {"field1": "value1"},
                "fields_to_fuzz": ["field1"],
            })
        assert len(result["interesting_findings"]) > 0
        assert any(f["severity"] == "HIGH" for f in result["interesting_findings"])


class TestGetCcTools:
    def test_returns_list(self):
        assert isinstance(get_cc_tools(), list)

    def test_tool_count(self):
        assert len(get_cc_tools()) == 2

    def test_tool_names(self):
        names = [t.name for t in get_cc_tools()]
        assert names == ["cc_discover_schema", "cc_fuzz_fields"]
