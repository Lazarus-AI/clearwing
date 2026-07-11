"""Tests for recovery code analysis tools."""

from __future__ import annotations

from unittest.mock import patch

import clearwing.agent.tools.crypto.recovery_tools as rec_mod
from clearwing.agent.tools.crypto.recovery_tools import (
    analyze_recovery_entropy,
    generate_recovery_codes,
    get_recovery_tools,
    test_recovery_acceptance,
)


class TestGenerateRecoveryCodes:
    def test_default_count(self):
        result = generate_recovery_codes.invoke({})
        assert len(result["codes"]) == 10

    def test_custom_count(self):
        result = generate_recovery_codes.invoke({"count": 3})
        assert len(result["codes"]) == 3

    def test_max_count_capped(self):
        result = generate_recovery_codes.invoke({"count": 200})
        assert len(result["codes"]) == 100

    def test_code_format(self):
        result = generate_recovery_codes.invoke({"count": 1})
        code = result["codes"][0]
        assert code.startswith("1PRK-")
        parts = code.split("-")
        assert parts[0] == "1PRK"
        assert len(parts) == 10  # prefix + 9 segments

    def test_codes_unique(self):
        result = generate_recovery_codes.invoke({"count": 20})
        assert len(set(result["codes"])) == 20

    def test_format_info(self):
        result = generate_recovery_codes.invoke({})
        fmt = result["format"]
        assert fmt["prefix"] == "1PRK"
        assert fmt["charset_size"] == 33
        assert fmt["total_entropy_bits"] > 200


class TestTestRecoveryAcceptance:
    def test_declined(self):
        with patch.object(rec_mod, "interrupt", return_value=False):
            result = test_recovery_acceptance.invoke({"target": "http://example.com"})
        assert "error" in result

    def test_all_404(self):
        def mock_post(url, payload, headers=None, timeout=30):
            return (404, '{"error": "not found"}', 5.0)

        with (
            patch.object(rec_mod, "interrupt", return_value=True),
            patch.object(rec_mod, "_http_post", mock_post),
        ):
            result = test_recovery_acceptance.invoke({
                "target": "http://example.com",
                "count": 2,
            })
        assert result["accepted_count"] == 0
        assert all(v == "not_found" for v in result["endpoint_summary"].values())

    def test_connection_error(self):
        def mock_post(url, payload, headers=None, timeout=30):
            return (0, "Connection refused", 0.0)

        with (
            patch.object(rec_mod, "interrupt", return_value=True),
            patch.object(rec_mod, "_http_post", mock_post),
        ):
            result = test_recovery_acceptance.invoke({
                "target": "http://example.com",
                "count": 1,
            })
        assert result["accepted_count"] == 0

    def test_code_accepted(self):
        def mock_post(url, payload, headers=None, timeout=30):
            if "recover" in url:
                return (200, '{"success": true}', 10.0)
            return (404, "", 5.0)

        with (
            patch.object(rec_mod, "interrupt", return_value=True),
            patch.object(rec_mod, "_http_post", mock_post),
        ):
            result = test_recovery_acceptance.invoke({
                "target": "http://example.com",
                "count": 2,
            })
        assert result["accepted_count"] > 0
        assert any("CRITICAL" in f for f in result["findings"])


class TestAnalyzeRecoveryEntropy:
    def test_default_entropy(self):
        result = analyze_recovery_entropy.invoke({})
        assert result["total_entropy_bits"] > 200
        assert "impossible" in result["assessment"].lower() or "infeasible" in result["assessment"].lower()

    def test_custom_charset(self):
        result = analyze_recovery_entropy.invoke({"charset_size": 10, "random_chars": 20})
        expected = 20 * 3.321928  # log2(10) ≈ 3.32
        assert abs(result["total_entropy_bits"] - expected) < 1

    def test_brute_force_estimates(self):
        result = analyze_recovery_entropy.invoke({})
        estimates = result["brute_force_estimates"]
        assert "online_10_per_sec" in estimates
        assert "offline_1B_per_sec" in estimates

    def test_lockout_note(self):
        result = analyze_recovery_entropy.invoke({"lockout_after": 10})
        assert result["lockout_after"] == 10
        assert "locks after 10" in result["lockout_note"]

    def test_weak_entropy_warning(self):
        result = analyze_recovery_entropy.invoke({"charset_size": 10, "random_chars": 8})
        assert "WARNING" in result["assessment"]


class TestGetRecoveryTools:
    def test_returns_list(self):
        assert isinstance(get_recovery_tools(), list)

    def test_tool_count(self):
        assert len(get_recovery_tools()) == 3

    def test_tool_names(self):
        names = [t.name for t in get_recovery_tools()]
        assert names == [
            "generate_recovery_codes",
            "test_recovery_acceptance",
            "analyze_recovery_entropy",
        ]
