"""Unit tests for SRP protocol testing tools (no network)."""

from __future__ import annotations

import pytest

from clearwing.agent.tools.crypto.srp_tools import (
    get_srp_tools,
    srp_extract_verifier_info,
    srp_fuzz_parameters,
    srp_handshake,
    srp_timing_attack,
)


class TestGetSRPTools:
    def test_returns_list(self):
        tools = get_srp_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_srp_tools()
        assert len(tools) == 4

    def test_tool_names(self):
        tools = get_srp_tools()
        names = [t.name for t in tools]
        expected = [
            "srp_handshake",
            "srp_fuzz_parameters",
            "srp_extract_verifier_info",
            "srp_timing_attack",
        ]
        assert names == expected


class TestSRPHandshakeUnreachable:
    def test_connection_failure(self):
        result = srp_handshake.invoke({
            "target": "http://127.0.0.1:1",
            "username": "test@example.com",
        })
        assert result["success"] is False
        assert "error" in result or "Connection" in str(result)


class TestSRPExtractUnreachable:
    def test_connection_failure(self):
        result = srp_extract_verifier_info.invoke({
            "target": "http://127.0.0.1:1",
            "username": "test@example.com",
        })
        assert result.get("success") is False or "error" in str(result)


class TestSRPFuzzNoInterrupt:
    def test_returns_error_when_declined(self):
        from unittest.mock import patch

        with patch("clearwing.agent.tools.crypto.srp_tools.interrupt", return_value=False):
            result = srp_fuzz_parameters.invoke({
                "target": "http://127.0.0.1:1",
                "username": "test@example.com",
            })
            assert result["success"] is False
            assert "declined" in result["error"].lower()


class TestSRPTimingNoInterrupt:
    def test_returns_error_when_declined(self):
        from unittest.mock import patch

        with patch("clearwing.agent.tools.crypto.srp_tools.interrupt", return_value=False):
            result = srp_timing_attack.invoke({
                "target": "http://127.0.0.1:1",
                "username": "test@example.com",
            })
            assert result["success"] is False
            assert "declined" in result["error"].lower()


class TestSRPTimingValidation:
    def test_rejects_too_few_samples(self):
        from unittest.mock import patch

        with patch("clearwing.agent.tools.crypto.srp_tools.interrupt", return_value=True):
            result = srp_timing_attack.invoke({
                "target": "http://127.0.0.1:1",
                "username": "test@example.com",
                "samples": 2,
            })
            assert result["success"] is False
            assert "samples" in result["error"].lower()

    def test_rejects_unknown_test_type(self):
        from unittest.mock import patch

        with patch("clearwing.agent.tools.crypto.srp_tools.interrupt", return_value=True):
            result = srp_timing_attack.invoke({
                "target": "http://127.0.0.1:1",
                "username": "test@example.com",
                "test_type": "invalid",
            })
            assert result["success"] is False


class TestSRPFuzzUnknownVectors:
    def test_rejects_unknown_category(self):
        from unittest.mock import patch

        with patch("clearwing.agent.tools.crypto.srp_tools.interrupt", return_value=True):
            result = srp_fuzz_parameters.invoke({
                "target": "http://127.0.0.1:1",
                "username": "test@example.com",
                "test_vectors": "nonexistent",
            })
            assert result["success"] is False


class TestSRPHandshakeUnknownGroup:
    def test_rejects_invalid_group(self):
        result = srp_handshake.invoke({
            "target": "http://127.0.0.1:1",
            "username": "test@example.com",
            "group_bits": 512,
        })
        assert result["success"] is False
        assert "group" in result["error"].lower()
