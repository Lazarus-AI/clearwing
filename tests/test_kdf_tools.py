"""Tests for KDF Analysis Tools (unit tests, no real network)."""

from __future__ import annotations

from unittest.mock import patch

import clearwing.agent.tools.crypto.kdf_tools as kdf_mod
from clearwing.agent.tools.crypto.kdf_tools import (
    _format_duration,
    _normalize_algorithm,
    analyze_kdf_parameters,
    benchmark_kdf_cracking,
    get_kdf_tools,
    kdf_oracle_test,
    test_2skd_implementation,
)

# --- Helper tests ---


class TestNormalizeAlgorithm:
    def test_canonical(self):
        assert _normalize_algorithm("PBKDF2-HMAC-SHA256", "sha256") == "PBKDF2-HMAC-SHA256"

    def test_bare_pbkdf2(self):
        assert _normalize_algorithm("PBKDF2", "sha256") == "PBKDF2-HMAC-SHA256"

    def test_lowercase(self):
        assert _normalize_algorithm("pbkdf2-sha256", "sha256") == "PBKDF2-HMAC-SHA256"

    def test_with_sha512(self):
        assert _normalize_algorithm("PBKDF2-HMAC-SHA512", "sha512") == "PBKDF2-HMAC-SHA512"

    def test_unknown_defaults_to_hash_function(self):
        result = _normalize_algorithm("something", "sha256")
        assert result == "PBKDF2-HMAC-SHA256"


class TestFormatDuration:
    def test_milliseconds(self):
        assert "millisecond" in _format_duration(0.5)

    def test_seconds(self):
        assert "second" in _format_duration(30)

    def test_minutes(self):
        assert "minute" in _format_duration(300)

    def test_hours(self):
        assert "hour" in _format_duration(7200)

    def test_days(self):
        assert "day" in _format_duration(86400 * 5)

    def test_years(self):
        assert "year" in _format_duration(86400 * 365.25 * 10)

    def test_very_small(self):
        assert "millisecond" in _format_duration(0.0001)

    def test_million_years(self):
        assert "million" in _format_duration(86400 * 365.25 * 2_000_000)


# --- analyze_kdf_parameters ---


class TestAnalyzeKdfParameters:
    def test_compliant_params(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 650_000,
            "salt_hex": "aa" * 16,
            "output_length": 32,
            "hash_function": "sha256",
        })
        assert result["iterations_compliant"] is True
        assert result["salt_compliant"] is True
        assert result["output_length_compliant"] is True
        assert result["hash_function_compliant"] is True
        assert result["risk_level"] == "LOW"

    def test_low_iterations(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 100_000,
            "salt_hex": "aa" * 16,
        })
        assert result["iterations_compliant"] is False
        assert result["risk_level"] == "HIGH"

    def test_very_low_iterations(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 1000,
            "salt_hex": "aa" * 16,
        })
        assert result["iterations_compliant"] is False
        assert result["risk_level"] == "CRITICAL"

    def test_short_salt(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 650_000,
            "salt_hex": "aa" * 8,
        })
        assert result["salt_compliant"] is False
        assert result["salt_length_bytes"] == 8

    def test_empty_salt(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 650_000,
            "salt_hex": "",
        })
        assert result["salt_compliant"] is False
        assert result["risk_level"] == "CRITICAL"

    def test_output_exceeds_hash(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 650_000,
            "salt_hex": "aa" * 16,
            "output_length": 64,
            "hash_function": "sha256",
        })
        assert result["output_length_compliant"] is False

    def test_sha1_flagged(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2-HMAC-SHA1",
            "iterations": 1_300_000,
            "salt_hex": "aa" * 16,
            "hash_function": "sha1",
        })
        assert result["hash_function_compliant"] is False

    def test_findings_populated_on_issues(self):
        result = analyze_kdf_parameters.invoke({
            "algorithm": "PBKDF2",
            "iterations": 10_000,
            "salt_hex": "aa" * 4,
        })
        assert len(result["findings"]) >= 2
        assert len(result["recommendations"]) >= 2


# --- benchmark_kdf_cracking ---


class TestBenchmarkKdfCracking:
    def test_returns_all_profiles(self):
        result = benchmark_kdf_cracking.invoke({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 650_000,
            "calibration_rounds": 10,
        })
        assert "local_cpu" in result
        assert "single_gpu" in result
        assert "gpu_cluster_8x" in result
        assert "cloud_100_gpu" in result
        assert "calibration" in result
        assert "assessment" in result

    def test_higher_iterations_slower(self):
        fast = benchmark_kdf_cracking.invoke({
            "iterations": 100_000,
            "calibration_rounds": 10,
        })
        slow = benchmark_kdf_cracking.invoke({
            "iterations": 650_000,
            "calibration_rounds": 10,
        })
        fast_sec = fast["single_gpu"]["time_to_exhaust_seconds"]
        slow_sec = slow["single_gpu"]["time_to_exhaust_seconds"]
        assert slow_sec > fast_sec

    def test_higher_entropy_slower(self):
        low = benchmark_kdf_cracking.invoke({
            "iterations": 650_000,
            "password_entropy_bits": 30.0,
            "calibration_rounds": 10,
        })
        high = benchmark_kdf_cracking.invoke({
            "iterations": 650_000,
            "password_entropy_bits": 60.0,
            "calibration_rounds": 10,
        })
        assert high["single_gpu"]["time_to_exhaust_seconds"] > low["single_gpu"]["time_to_exhaust_seconds"]

    def test_calibration_data(self):
        result = benchmark_kdf_cracking.invoke({
            "calibration_rounds": 50,
        })
        cal = result["calibration"]
        assert cal["rounds"] == 50
        assert cal["duration_ms"] > 0
        assert cal["cpu_iters_per_sec"] > 0


# --- test_2skd_implementation ---


class TestTest2skdImplementation:
    def test_declined(self):
        with patch.object(kdf_mod, "interrupt", return_value=False):
            result = test_2skd_implementation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
            })
        assert "error" in result

    def test_connection_failure(self):
        def mock_http_post(url, payload, **kwargs):
            return (0, {}, "Connection refused", 0.0)

        with (
            patch.object(kdf_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_2skd_implementation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
            })
        assert "error" in result

    def test_successful_verification(self):
        import json

        server_response = json.dumps({
            "salt": "aa" * 16,
            "iterations": 100000,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "B": "deadbeef" * 8,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, server_response, 10.0)

        with (
            patch.object(kdf_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_2skd_implementation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "testpassword",
                "secret_key": "A3-AABBCC-DDEEFF-112233-445566-778899-AABBCC-DDEEFF",
            })

        assert "checks" in result
        assert result["checks"]["key_split_correct"] is True
        assert result["checks"]["secret_key_incorporated"] is True
        assert result["checks"]["password_change_produces_new_auk"] is True
        assert "derivation_details" in result

    def test_no_secret_key(self):
        import json

        server_response = json.dumps({
            "salt": "bb" * 16,
            "iterations": 100000,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "B": "cafebabe" * 8,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, server_response, 10.0)

        with (
            patch.object(kdf_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_2skd_implementation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "testpassword",
            })

        assert result["checks"]["secret_key_incorporated"] is None
        assert any("not provided" in f for f in result["findings"])


# --- kdf_oracle_test ---


class TestKdfOracleTest:
    def test_declined(self):
        with patch.object(kdf_mod, "interrupt", return_value=False):
            result = kdf_oracle_test.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
            })
        assert "error" in result

    def test_rejects_too_few_samples(self):
        result = kdf_oracle_test.invoke({
            "target": "http://example.com",
            "username": "user@example.com",
            "samples": 5,
        })
        assert "error" in result

    def test_no_oracle_detected(self):
        import json

        init_response = json.dumps({
            "salt": "cc" * 16,
            "iterations": 100000,
            "B": "aabb" * 32,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, init_response, 5.0)

        def mock_timed_post(url, payload):
            return (401, '{"error": "invalid"}', 100.0)

        with (
            patch.object(kdf_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
            patch("clearwing.agent.tools.crypto.srp_tools._timed_post", mock_timed_post),
        ):
            result = kdf_oracle_test.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "samples": 20,
                "warmup": 2,
            })

        assert result["oracle_detected"] is False

    def test_timing_oracle_detected(self):
        import json

        init_response = json.dumps({
            "salt": "dd" * 16,
            "iterations": 100000,
            "B": "aabb" * 32,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, init_response, 5.0)

        call_count = [0]

        def mock_timed_post(url, payload):
            call_count[0] += 1
            if "A" in payload and payload["A"] != "0":
                return (401, '{"error": "invalid proof"}', 200.0)
            return (401, '{"error": "bad request"}', 100.0)

        with (
            patch.object(kdf_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
            patch("clearwing.agent.tools.crypto.srp_tools._timed_post", mock_timed_post),
        ):
            result = kdf_oracle_test.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "samples": 20,
                "warmup": 2,
            })

        assert result["oracle_detected"] is True
        assert "timing" in result["oracle_type"] or "response_structure" in result["oracle_type"]


# --- Tool metadata ---


class TestGetKdfTools:
    def test_returns_list(self):
        tools = get_kdf_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_kdf_tools()
        assert len(tools) == 4

    def test_tool_names(self):
        tools = get_kdf_tools()
        names = [t.name for t in tools]
        assert names == ["analyze_kdf_parameters", "benchmark_kdf_cracking", "test_2skd_implementation", "kdf_oracle_test"]
