"""Tests for Mycelium pairing protocol tools."""

from __future__ import annotations

import json
from unittest.mock import patch

import clearwing.agent.tools.crypto.mycelium_tools as myc_mod
from clearwing.agent.tools.crypto.mycelium_tools import (
    get_mycelium_tools,
    mycelium_create_channel,
    mycelium_fuzz_auth,
    mycelium_probe_channel,
    mycelium_test_race,
)


class TestMyceliumCreateChannel:
    def test_declined(self):
        with patch.object(myc_mod, "interrupt", return_value=False):
            result = mycelium_create_channel.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_connection_failure(self):
        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            return (0, {}, "Connection refused", 0.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_create_channel.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_successful_creation(self):
        resp = json.dumps({
            "channelUuid": "test-uuid-1234",
            "channelSeed": "seed-abc",
            "initiatorAuth": "auth-xyz",
        })

        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            return (200, {}, resp, 50.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_create_channel.invoke({"target": "http://example.com"})
        assert result["channel_uuid"] == "test-uuid-1234"
        assert result["channel_seed"] == "seed-abc"
        assert result["initiator_auth"] == "auth-xyz"

    def test_channel_type_v(self):
        resp = json.dumps({"channelUuid": "v-uuid", "channelSeed": "s", "initiatorAuth": "a"})

        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            assert "/mycelium/v" in url
            return (200, {}, resp, 10.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_create_channel.invoke({
                "target": "http://example.com",
                "channel_type": "v",
            })
        assert result["channel_type"] == "v"


class TestMyceliumProbeChannel:
    def test_declined(self):
        with patch.object(myc_mod, "interrupt", return_value=False):
            result = mycelium_probe_channel.invoke({
                "target": "http://example.com",
                "channel_uuid": "test",
            })
        assert "error" in result

    def test_read_segment(self):
        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            return (200, {"Content-Type": "application/octet-stream"}, "segment-data", 15.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_probe_channel.invoke({
                "target": "http://example.com",
                "channel_uuid": "test-uuid",
                "segment": 1,
                "auth_value": "my-auth",
            })
        assert result["status"] == 200
        assert result["auth_provided"] is True

    def test_write_segment(self):
        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            assert method == "PUT"
            return (201, {}, "", 20.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_probe_channel.invoke({
                "target": "http://example.com",
                "channel_uuid": "test-uuid",
                "segment": 2,
                "method": "PUT",
                "body": '{"test": true}',
            })
        assert result["method"] == "PUT"


class TestMyceliumFuzzAuth:
    def test_declined(self):
        with patch.object(myc_mod, "interrupt", return_value=False):
            result = mycelium_fuzz_auth.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_all_rejected(self):
        call_count = [0]

        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            call_count[0] += 1
            if method == "POST" and call_count[0] == 1:
                return (200, {}, json.dumps({
                    "channelUuid": "fuzz-uuid",
                    "channelSeed": "fuzz-seed",
                    "initiatorAuth": "fuzz-auth",
                }), 10.0)
            return (403, {}, '{"error": "forbidden"}', 5.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_fuzz_auth.invoke({"target": "http://example.com"})
        assert len(result["bypasses"]) == 0
        assert "properly rejected" in result["summary"]

    def test_bypass_detected(self):
        call_count = [0]

        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            call_count[0] += 1
            if method == "POST" and call_count[0] == 1:
                return (200, {}, json.dumps({
                    "channelUuid": "fuzz-uuid",
                    "channelSeed": "fuzz-seed",
                    "initiatorAuth": "fuzz-auth",
                }), 10.0)
            headers = headers or {}
            if not any(h in headers for h in ("ChannelAuth", "ChannelJoinAuth", "Authorization")):
                return (200, {}, '{"data": "leaked"}', 5.0)
            return (403, {}, '{"error": "forbidden"}', 5.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_fuzz_auth.invoke({"target": "http://example.com"})
        assert len(result["bypasses"]) > 0


class TestMyceliumTestRace:
    def test_declined(self):
        with patch.object(myc_mod, "interrupt", return_value=False):
            result = mycelium_test_race.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_all_rejected(self):
        call_count = [0]

        def mock_request(url, method="GET", body=None, headers=None, timeout=30):
            call_count[0] += 1
            if method == "POST" and "/mycelium/u" in url and call_count[0] <= 2:
                return (200, {}, json.dumps({
                    "channelUuid": "race-uuid",
                    "channelSeed": "race-seed",
                    "initiatorAuth": "race-auth",
                }), 10.0)
            if "ChannelAuth" in (headers or {}):
                return (201, {}, "", 5.0)
            return (403, {}, '{"error": "forbidden"}', 5.0)

        with (
            patch.object(myc_mod, "interrupt", return_value=True),
            patch.object(myc_mod, "_http_request", mock_request),
        ):
            result = mycelium_test_race.invoke({
                "target": "http://example.com",
                "concurrent_joins": 3,
            })
        assert result["successful_writes"] == 0
        assert "No race condition" in result["findings"][0]


class TestGetMyceliumTools:
    def test_returns_list(self):
        tools = get_mycelium_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        assert len(get_mycelium_tools()) == 4

    def test_tool_names(self):
        names = [t.name for t in get_mycelium_tools()]
        assert names == [
            "mycelium_create_channel",
            "mycelium_probe_channel",
            "mycelium_fuzz_auth",
            "mycelium_test_race",
        ]
