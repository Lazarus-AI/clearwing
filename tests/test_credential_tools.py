"""Tests for Credential Attack Tools (unit tests, no real network)."""

from __future__ import annotations

from unittest.mock import patch

import clearwing.agent.tools.crypto.credential_tools as cred_mod
from clearwing.agent.tools.crypto.credential_tools import (
    analyze_2skd_entropy,
    enumerate_secret_key_format,
    get_credential_tools,
    offline_crack_setup,
    test_secret_key_validation,
)

# --- analyze_2skd_entropy ---


class TestAnalyze2skdEntropy:
    def test_default_entropy(self):
        result = analyze_2skd_entropy.invoke({})
        assert result["password_entropy_bits"] == 40.0
        assert result["secret_key_bits"] == 128
        assert result["combined_entropy_bits"] == 168.0

    def test_high_entropy_password(self):
        result = analyze_2skd_entropy.invoke({"password_entropy_bits": 80.0})
        assert result["combined_entropy_bits"] == 208.0

    def test_custom_secret_key_bits(self):
        result = analyze_2skd_entropy.invoke({"secret_key_bits": 64})
        assert result["combined_entropy_bits"] == 104.0

    def test_password_only_vs_2skd(self):
        result = analyze_2skd_entropy.invoke({
            "password_entropy_bits": 40.0,
            "iterations": 650000,
        })
        profiles = result["cracking_profiles"]
        for p in profiles:
            pw_sec = p["password_only"]["seconds"]
            skd_sec = p["with_2skd"]["seconds"]
            if pw_sec is not None and skd_sec is not None:
                assert skd_sec > pw_sec

    def test_cracking_profiles_present(self):
        result = analyze_2skd_entropy.invoke({})
        profiles = result["cracking_profiles"]
        assert len(profiles) == 3
        names = {p["name"] for p in profiles}
        assert "single_gpu_rtx4090" in names
        assert "gpu_cluster_8x" in names
        assert "cloud_100_gpu" in names

    def test_cost_estimate_present(self):
        result = analyze_2skd_entropy.invoke({})
        cost = result["cost_estimate_usd"]
        assert "password_only_100gpu" in cost
        assert "with_2skd_100gpu" in cost
        assert "rate" in cost

    def test_assessment_text(self):
        result = analyze_2skd_entropy.invoke({})
        assert "168" in result["assessment"]
        assert "infeasible" in result["assessment"].lower()

    def test_secret_key_is_dominant(self):
        result = analyze_2skd_entropy.invoke({"password_entropy_bits": 40.0, "secret_key_bits": 128})
        assert result["secret_key_is_dominant_factor"] is True

    def test_high_entropy_password_not_dominant(self):
        result = analyze_2skd_entropy.invoke({"password_entropy_bits": 200.0, "secret_key_bits": 128})
        assert result["secret_key_is_dominant_factor"] is False


# --- test_secret_key_validation ---


class TestSecretKeyValidation:
    def test_declined(self):
        with patch.object(cred_mod, "interrupt", return_value=False):
            result = test_secret_key_validation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
            })
        assert "error" in result

    def test_too_few_samples(self):
        result = test_secret_key_validation.invoke({
            "target": "http://example.com",
            "username": "user@example.com",
            "password": "test",
            "samples": 4,
        })
        assert "error" in result

    def test_connection_failure(self):
        def mock_http_post(url, payload, **kwargs):
            return (0, {}, "Connection refused", 0.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_secret_key_validation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
            })
        assert "error" in result

    def test_no_separation_detected(self):
        import json

        server_response = json.dumps({
            "salt": "aa" * 16,
            "iterations": 100000,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "B": "deadbeef" * 8,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, server_response, 5.0)

        def mock_timed_post(url, payload):
            return (401, '{"error": "invalid credentials"}', 100.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
            patch("clearwing.agent.tools.crypto.srp_tools._timed_post", mock_timed_post),
        ):
            result = test_secret_key_validation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
                "secret_key": "A3-AABBCC-DDEEFF-112233-445566-778899-AABBCC-DDEEFF",
                "samples": 20,
                "warmup": 2,
            })

        assert result["factor_separation"] is False
        assert len(result["separation_signals"]) == 0

    def test_timing_separation_detected(self):
        import json
        import random

        server_response = json.dumps({
            "salt": "bb" * 16,
            "iterations": 100000,
            "B": "cafebabe" * 8,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, server_response, 5.0)

        # The tool interleaves calls: wrong_key then wrong_pwd per iteration.
        # With warmup=0, calls go straight to sampling. Odd calls (1,3,5...)
        # are wrong_key, even calls (2,4,6...) are wrong_pwd.
        rng = random.Random(42)
        call_count = [0]

        def mock_timed_post(url, payload):
            call_count[0] += 1
            jitter = rng.uniform(-5, 5)
            if call_count[0] % 2 == 1:
                return (401, '{"error": "invalid"}', 200.0 + jitter)
            return (401, '{"error": "invalid"}', 50.0 + jitter)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
            patch("clearwing.agent.tools.crypto.srp_tools._timed_post", mock_timed_post),
        ):
            result = test_secret_key_validation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
                "samples": 20,
                "warmup": 0,
            })

        assert result["factor_separation"] is True
        assert "timing" in result["separation_signals"]

    def test_response_separation_detected(self):
        import json

        server_response = json.dumps({
            "salt": "cc" * 16,
            "iterations": 100000,
            "B": "aabb" * 16,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, server_response, 5.0)

        call_count = [0]

        def mock_timed_post(url, payload):
            call_count[0] += 1
            if call_count[0] % 2 == 1:
                return (401, '{"error": "wrong key"}', 100.0)
            return (401, '{"error": "wrong password"}', 100.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
            patch("clearwing.agent.tools.crypto.srp_tools._timed_post", mock_timed_post),
        ):
            result = test_secret_key_validation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
                "samples": 20,
                "warmup": 2,
            })

        assert result["factor_separation"] is True
        assert "response_body" in result["separation_signals"]

    def test_no_secret_key_provided(self):
        import json

        server_response = json.dumps({
            "salt": "dd" * 16,
            "iterations": 100000,
            "B": "1234" * 16,
        })

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, server_response, 5.0)

        def mock_timed_post(url, payload):
            return (401, '{"error": "invalid"}', 100.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
            patch("clearwing.agent.tools.crypto.srp_tools._timed_post", mock_timed_post),
        ):
            result = test_secret_key_validation.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
                "password": "test",
                "samples": 20,
                "warmup": 2,
            })

        assert result["secret_key_provided"] is False
        assert "factor_separation" in result


# --- enumerate_secret_key_format ---


class TestEnumerateSecretKeyFormat:
    def test_declined(self):
        with patch.object(cred_mod, "interrupt", return_value=False):
            result = enumerate_secret_key_format.invoke({
                "target": "http://example.com",
            })
        assert "error" in result

    def test_known_format_parsing(self):
        def mock_http_post(url, payload, **kwargs):
            return (404, {}, '{"error": "not found"}', 5.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = enumerate_secret_key_format.invoke({
                "target": "http://example.com",
            })

        fmt = result["format_analysis"]
        assert fmt["prefix"] == "A3"
        assert fmt["segment_count"] == 7
        assert fmt["chars_per_segment"] == 6
        assert fmt["total_random_chars"] == 26

    def test_entropy_calculation(self):
        def mock_http_post(url, payload, **kwargs):
            return (404, {}, '{}', 5.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = enumerate_secret_key_format.invoke({
                "target": "http://example.com",
            })

        fmt = result["format_analysis"]
        assert fmt["total_entropy_bits"] > 100
        assert fmt["charset_size"] == 33

    def test_connection_failure(self):
        def mock_http_post(url, payload, **kwargs):
            return (0, {}, "Connection refused", 0.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = enumerate_secret_key_format.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
            })

        assert "format_analysis" in result
        assert result["enrollment_probe"]["status"] == 0

    def test_with_username_probes_auth(self):
        def mock_http_post(url, payload, **kwargs):
            if "enroll" in url:
                return (404, {}, '{}', 5.0)
            return (200, {}, '{"salt": "aa", "iterations": 100000}', 5.0)

        with (
            patch.object(cred_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = enumerate_secret_key_format.invoke({
                "target": "http://example.com",
                "username": "user@example.com",
            })

        assert "auth_probe" in result
        assert result["auth_probe"]["status"] == 200


# --- offline_crack_setup ---


class TestOfflineCrackSetup:
    def test_hashcat_sha256_mode(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
            "algorithm": "PBKDF2-HMAC-SHA256",
        })
        assert result["hashcat"]["mode"] == 10900

    def test_hashcat_sha1_mode(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "bb" * 16,
            "iterations": 1300000,
            "algorithm": "PBKDF2-HMAC-SHA1",
        })
        assert result["hashcat"]["mode"] == 12000

    def test_hashcat_sha512_mode(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "cc" * 16,
            "iterations": 210000,
            "algorithm": "PBKDF2-HMAC-SHA512",
        })
        assert result["hashcat"]["mode"] == 12100

    def test_hash_format_string(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
            "verifier_hex": "bb" * 32,
        })
        assert "hash_file_content" in result
        hash_str = result["hash_file_content"]
        assert hash_str.startswith("sha256:")
        assert ":650000:" in hash_str

    def test_john_command(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
        })
        assert "john" in result
        assert "PBKDF2-HMAC-SHA256" in result["john"]["format"]
        assert "--wordlist" in result["john"]["command"]

    def test_with_secret_key(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
            "secret_key_hex": "dd" * 32,
        })
        assert result["2skd_active"] is True
        assert len(result["hashcat"]["notes"]) > 0
        assert "custom" in result["hashcat"]["notes"][0].lower()
        assert "INFEASIBLE" in result["feasibility"]

    def test_without_secret_key(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
        })
        assert result["2skd_active"] is False
        assert len(result["hashcat"]["notes"]) == 0

    def test_time_estimates(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
        })
        estimates = result["cracking_estimates"]
        assert "single_gpu_rtx4090" in estimates
        assert "gpu_cluster_8x" in estimates
        assert "cloud_100_gpu" in estimates
        for profile in estimates.values():
            assert "keys_per_sec" in profile
            assert "time_to_exhaust" in profile

    def test_no_hash_file_without_verifier(self):
        result = offline_crack_setup.invoke({
            "salt_hex": "aa" * 16,
            "iterations": 650000,
        })
        assert "hash_file_content" not in result


# --- Tool metadata ---


class TestGetCredentialTools:
    def test_returns_list(self):
        tools = get_credential_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_credential_tools()
        assert len(tools) == 4

    def test_tool_names(self):
        tools = get_credential_tools()
        names = [t.name for t in tools]
        assert names == [
            "analyze_2skd_entropy",
            "test_secret_key_validation",
            "enumerate_secret_key_format",
            "offline_crack_setup",
        ]
