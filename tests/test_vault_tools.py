"""Tests for Vault Encryption Analysis Tools (unit tests, no real network)."""

from __future__ import annotations

import json
from unittest.mock import patch

import clearwing.agent.tools.crypto.vault_tools as vault_mod
from clearwing.agent.tools.crypto.vault_tools import (
    _base64url_decode,
    _base64url_encode,
    _detect_blob_format,
    analyze_key_hierarchy,
    get_vault_tools,
    key_wrap_analysis,
    parse_vault_blob,
    test_aead_integrity,
)

# --- Helpers for building test data ---


def _make_jwe_compact(
    alg: str = "A256KW",
    enc: str = "A256GCM",
    kid: str = "key-1",
    iv_bytes: int = 12,
    ct_bytes: int = 64,
    tag_bytes: int = 16,
    ek_bytes: int = 40,
) -> str:
    header = json.dumps({"alg": alg, "enc": enc, "kid": kid}).encode()
    header_b64 = _base64url_encode(header)
    ek_b64 = _base64url_encode(b"\xaa" * ek_bytes) if ek_bytes else ""
    iv_b64 = _base64url_encode(b"\xbb" * iv_bytes)
    ct_b64 = _base64url_encode(b"\xcc" * ct_bytes)
    tag_b64 = _base64url_encode(b"\xdd" * tag_bytes)
    return f"{header_b64}.{ek_b64}.{iv_b64}.{ct_b64}.{tag_b64}"


def _make_jwe_json(
    alg: str = "A256KW",
    enc: str = "A256GCM",
    iv_bytes: int = 12,
    ct_bytes: int = 64,
    tag_bytes: int = 16,
) -> str:
    header = json.dumps({"alg": alg, "enc": enc}).encode()
    return json.dumps({
        "protected": _base64url_encode(header),
        "encrypted_key": _base64url_encode(b"\xaa" * 40),
        "iv": _base64url_encode(b"\xbb" * iv_bytes),
        "ciphertext": _base64url_encode(b"\xcc" * ct_bytes),
        "tag": _base64url_encode(b"\xdd" * tag_bytes),
    })


def _make_hex_blob(iv_bytes: int = 12, ct_bytes: int = 64, tag_bytes: int = 16) -> str:
    return (b"\xbb" * iv_bytes + b"\xcc" * ct_bytes + b"\xdd" * tag_bytes).hex()


# --- Helper tests ---


class TestDetectBlobFormat:
    def test_jwe_compact(self):
        jwe = _make_jwe_compact()
        assert _detect_blob_format(jwe) == "jwe_compact"

    def test_jwe_json(self):
        jwe_json = _make_jwe_json()
        assert _detect_blob_format(jwe_json) == "jwe_json"

    def test_hex_string(self):
        assert _detect_blob_format("aabbccdd" * 10) == "hex"

    def test_unknown(self):
        assert _detect_blob_format("not a blob at all!@#$") == "unknown"

    def test_empty(self):
        assert _detect_blob_format("") == "unknown"


class TestBase64urlCodec:
    def test_roundtrip(self):
        data = b"\x00\xff\x80\x7f"
        assert _base64url_decode(_base64url_encode(data)) == data

    def test_no_padding(self):
        encoded = _base64url_encode(b"test")
        assert "=" not in encoded
        assert _base64url_decode(encoded) == b"test"

    def test_url_safe_chars(self):
        encoded = _base64url_encode(b"\xfb\xff\xfe")
        assert "+" not in encoded
        assert "/" not in encoded


# --- parse_vault_blob ---


class TestParseVaultBlob:
    def test_jwe_compact_parsing(self):
        jwe = _make_jwe_compact()
        result = parse_vault_blob.invoke({"encrypted_data": jwe})
        assert result["format"] == "jwe_compact"
        assert result["algorithm"] == "A256GCM"
        assert result["encryption"] == "A256GCM"
        assert result["key_management"] == "A256KW"
        assert result["key_id"] == "key-1"
        assert result["iv_length_bytes"] == 12
        assert result["tag_length_bytes"] == 16
        assert result["ciphertext_length_bytes"] == 64
        assert result["encrypted_key_length_bytes"] == 40
        assert result["risk_level"] == "LOW"

    def test_jwe_json_parsing(self):
        jwe_json = _make_jwe_json()
        result = parse_vault_blob.invoke({"encrypted_data": jwe_json})
        assert result["format"] == "jwe_json"
        assert result["encryption"] == "A256GCM"
        assert result["iv_length_bytes"] == 12

    def test_hex_binary_blob(self):
        hex_blob = _make_hex_blob()
        result = parse_vault_blob.invoke({"encrypted_data": hex_blob})
        assert result["format"] == "hex"
        assert result["iv_length_bytes"] == 12
        assert result["tag_length_bytes"] == 16
        assert result["ciphertext_length_bytes"] == 64

    def test_short_iv_flagged(self):
        jwe = _make_jwe_compact(iv_bytes=8)
        result = parse_vault_blob.invoke({"encrypted_data": jwe})
        assert result["iv_length_bytes"] == 8
        assert any("Non-standard IV" in f for f in result["findings"])
        assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_truncated_tag_flagged(self):
        jwe = _make_jwe_compact(tag_bytes=8)
        result = parse_vault_blob.invoke({"encrypted_data": jwe})
        assert result["tag_length_bytes"] == 8
        assert any("Truncated" in f for f in result["findings"])
        assert result["risk_level"] == "HIGH"

    def test_auto_format_detection(self):
        for make_fn, expected_fmt in [
            (lambda: _make_jwe_compact(), "jwe_compact"),
            (lambda: _make_jwe_json(), "jwe_json"),
        ]:
            result = parse_vault_blob.invoke({"encrypted_data": make_fn()})
            assert result["format"] == expected_fmt

    def test_direct_key_agreement_finding(self):
        jwe = _make_jwe_compact(alg="dir", ek_bytes=0)
        result = parse_vault_blob.invoke({"encrypted_data": jwe})
        assert any("dir" in f.lower() or "direct" in f.lower() for f in result["findings"])
        assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_empty_input(self):
        result = parse_vault_blob.invoke({"encrypted_data": ""})
        assert "error" in result

    def test_format_hint_override(self):
        hex_blob = _make_hex_blob()
        result = parse_vault_blob.invoke({"encrypted_data": hex_blob, "format_hint": "hex"})
        assert result["iv_length_bytes"] == 12


# --- analyze_key_hierarchy ---


class TestAnalyzeKeyHierarchy:
    def test_detects_extractable_keys(self):
        session_data = {
            "hierarchy": [
                {"step": 1, "operation": "deriveBits", "algorithm": "PBKDF2", "output_key_hex": "[non-extractable]"},
                {"step": 2, "operation": "importKey", "algorithm": "AES-GCM", "output_key_hex": "aabbccdd" * 8},
            ],
            "captured_keys": [],
            "encryption_operations": [],
        }
        result = analyze_key_hierarchy.invoke({"session_data": session_data})
        assert len(result["extractable_keys"]) == 1
        assert result["risk_level"] == "HIGH"

    def test_detects_iv_reuse(self):
        session_data = {
            "hierarchy": [],
            "captured_keys": [],
            "encryption_operations": [
                {"method": "encrypt", "algorithm": "AES-GCM", "iv_hex": "aabb" * 6, "data_length": 100},
                {"method": "encrypt", "algorithm": "AES-GCM", "iv_hex": "aabb" * 6, "data_length": 200},
            ],
        }
        result = analyze_key_hierarchy.invoke({"session_data": session_data})
        assert len(result["iv_reuse"]) > 0
        assert result["risk_level"] == "CRITICAL"

    def test_detects_key_reuse(self):
        session_data = {
            "hierarchy": [],
            "captured_keys": [
                {"id": 1, "hex": "aabbccdd" * 8, "algorithm": "AES-GCM", "source": "importKey"},
                {"id": 2, "hex": "aabbccdd" * 8, "algorithm": "AES-GCM", "source": "importKey"},
            ],
            "encryption_operations": [],
        }
        result = analyze_key_hierarchy.invoke({"session_data": session_data})
        assert len(result["encryption_key_reuse"]) > 0

    def test_missing_wrapping_layer(self):
        session_data = {
            "hierarchy": [
                {"step": 1, "operation": "deriveBits", "algorithm": "PBKDF2", "output_key_hex": "[non-extractable]"},
                {"step": 2, "operation": "importKey", "algorithm": "AES-GCM", "output_key_hex": "[non-extractable]"},
            ],
            "captured_keys": [],
            "encryption_operations": [
                {"method": "encrypt", "algorithm": "AES-GCM", "iv_hex": "aabb" * 6, "data_length": 100},
            ],
        }
        result = analyze_key_hierarchy.invoke({"session_data": session_data})
        assert any("wrapping" in f.lower() for f in result["findings"])

    def test_full_healthy_hierarchy(self):
        session_data = {
            "hierarchy": [
                {"step": 1, "operation": "deriveBits", "algorithm": "PBKDF2", "output_key_hex": "[non-extractable]"},
                {"step": 2, "operation": "importKey", "algorithm": "AES-GCM", "output_key_hex": "[non-extractable]"},
                {"step": 3, "operation": "unwrapKey", "algorithm": "AES-KW", "output_key_hex": "[non-extractable]"},
                {"step": 4, "operation": "encrypt", "algorithm": "AES-GCM", "output_key_hex": "[non-extractable]"},
            ],
            "captured_keys": [
                {"id": 1, "hex": "[non-extractable]", "algorithm": "AES-GCM", "source": "importKey"},
            ],
            "encryption_operations": [
                {"method": "encrypt", "algorithm": "AES-GCM", "iv_hex": "aabb" * 6, "data_length": 100},
            ],
        }
        result = analyze_key_hierarchy.invoke({"session_data": session_data})
        assert result["risk_level"] == "LOW"
        assert len(result["extractable_keys"]) == 0
        assert len(result["iv_reuse"]) == 0

    def test_empty_session_data(self):
        result = analyze_key_hierarchy.invoke({"session_data": {}})
        assert result["total_steps"] == 0
        assert result["hierarchy_depth"] == 0

    def test_layer_mapping(self):
        session_data = {
            "hierarchy": [
                {"step": 1, "operation": "deriveBits", "algorithm": "PBKDF2", "output_key_hex": "[non-extractable]"},
                {"step": 2, "operation": "unwrapKey", "algorithm": "AES-KW", "output_key_hex": "[non-extractable]"},
            ],
            "captured_keys": [],
            "encryption_operations": [],
        }
        result = analyze_key_hierarchy.invoke({"session_data": session_data})
        mapping = result["layer_mapping"]
        assert mapping["derivation"]["found"] is True
        assert mapping["unwrapping"]["found"] is True


# --- test_aead_integrity ---


class TestTestAeadIntegrity:
    def test_declined(self):
        jwe = _make_jwe_compact()
        with patch.object(vault_mod, "interrupt", return_value=False):
            result = test_aead_integrity.invoke({
                "encrypted_data": jwe,
                "target": "http://example.com",
            })
        assert "error" in result

    def test_all_modifications_rejected(self):
        jwe = _make_jwe_compact()

        def mock_http_post(url, payload, **kwargs):
            return (400, {}, '{"error": "integrity check failed"}', 5.0)

        with (
            patch.object(vault_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_aead_integrity.invoke({
                "encrypted_data": jwe,
                "target": "http://example.com",
                "samples": 1,
            })

        assert len(result["vulnerabilities"]) == 0
        assert result["risk_level"] == "LOW"

    def test_bit_flip_accepted(self):
        jwe = _make_jwe_compact()
        call_count = [0]

        def mock_http_post(url, payload, **kwargs):
            call_count[0] += 1
            return (200, {}, '{"ok": true}', 5.0)

        with (
            patch.object(vault_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_aead_integrity.invoke({
                "encrypted_data": jwe,
                "target": "http://example.com",
                "modifications": "bit_flip",
                "samples": 1,
            })

        assert len(result["vulnerabilities"]) > 0
        assert result["risk_level"] == "CRITICAL"

    def test_tag_substitution_detected(self):
        jwe = _make_jwe_compact()

        def mock_http_post(url, payload, **kwargs):
            return (200, {}, '{"ok": true}', 5.0)

        with (
            patch.object(vault_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_aead_integrity.invoke({
                "encrypted_data": jwe,
                "target": "http://example.com",
                "modifications": "tag_substitution",
                "samples": 1,
            })

        assert any(v["modification"] == "tag_substitution" for v in result["vulnerabilities"])
        assert result["risk_level"] == "CRITICAL"

    def test_connection_failure(self):
        jwe = _make_jwe_compact()

        def mock_http_post(url, payload, **kwargs):
            return (0, {}, "Connection refused", 0.0)

        with (
            patch.object(vault_mod, "interrupt", return_value=True),
            patch("clearwing.agent.tools.crypto.srp_tools._http_post", mock_http_post),
        ):
            result = test_aead_integrity.invoke({
                "encrypted_data": jwe,
                "target": "http://example.com",
                "modifications": "bit_flip",
                "samples": 1,
            })

        assert result["risk_level"] == "LOW"
        assert len(result["vulnerabilities"]) == 0


# --- key_wrap_analysis ---


class TestKeyWrapAnalysis:
    def test_aes_kw_valid_sizes(self):
        wrapped_keys = [
            {"wrapped_key_hex": "aa" * 24, "algorithm": "AES-KW"},
            {"wrapped_key_hex": "bb" * 32, "algorithm": "AES-KW"},
            {"wrapped_key_hex": "cc" * 40, "algorithm": "AES-KW"},
        ]
        result = key_wrap_analysis.invoke({"wrapped_keys": wrapped_keys})
        assert result["aes_kw_analysis"] is not None
        assert len(result["aes_kw_analysis"]["size_anomalies"]) == 0

    def test_aes_kw_size_anomaly(self):
        wrapped_keys = [
            {"wrapped_key_hex": "aa" * 15, "algorithm": "AES-KW"},
        ]
        result = key_wrap_analysis.invoke({"wrapped_keys": wrapped_keys})
        assert len(result["aes_kw_analysis"]["size_anomalies"]) > 0
        assert result["risk_level"] == "MEDIUM"

    def test_rsa_oaep_analysis(self):
        wrapped_keys = [
            {"wrapped_key_hex": "aa" * 256, "algorithm": "RSA-OAEP"},
            {"wrapped_key_hex": "bb" * 256, "algorithm": "RSA-OAEP"},
        ]
        result = key_wrap_analysis.invoke({"wrapped_keys": wrapped_keys})
        assert result["rsa_oaep_analysis"] is not None
        assert result["rsa_oaep_analysis"]["key_count"] == 2

    def test_key_distinguishability(self):
        wrapped_keys = [
            {"wrapped_key_hex": "aa" * 24, "algorithm": "AES-KW"},
            {"wrapped_key_hex": "bb" * 40, "algorithm": "AES-KW"},
        ]
        result = key_wrap_analysis.invoke({"wrapped_keys": wrapped_keys})
        assert result["key_distinguishability"]["distinguishable"] is True

    def test_extractable_after_unwrap(self):
        wrapped_keys = [
            {"wrapped_key_hex": "aa" * 32, "algorithm": "AES-KW"},
        ]
        unwrap_ops = [
            {"algorithm": "AES-KW", "format": "raw", "extractable": True, "usages": ["encrypt"]},
        ]
        result = key_wrap_analysis.invoke({
            "wrapped_keys": wrapped_keys,
            "unwrap_operations": unwrap_ops,
        })
        assert result["unwrap_behavior"]["extractable_after_unwrap"] == 1
        assert result["risk_level"] == "HIGH"

    def test_empty_input(self):
        result = key_wrap_analysis.invoke({"wrapped_keys": []})
        assert result["total_wrapped_keys"] == 0
        assert result["risk_level"] == "UNKNOWN"

    def test_mixed_algorithms(self):
        wrapped_keys = [
            {"wrapped_key_hex": "aa" * 32, "algorithm": "AES-KW"},
            {"wrapped_key_hex": "bb" * 256, "algorithm": "RSA-OAEP"},
        ]
        result = key_wrap_analysis.invoke({"wrapped_keys": wrapped_keys})
        assert len(result["wrapping_algorithms"]) == 2
        assert result["aes_kw_analysis"] is not None
        assert result["rsa_oaep_analysis"] is not None


# --- Tool metadata ---


class TestGetVaultTools:
    def test_returns_list(self):
        tools = get_vault_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_vault_tools()
        assert len(tools) == 4

    def test_tool_names(self):
        tools = get_vault_tools()
        names = [t.name for t in tools]
        assert names == ["parse_vault_blob", "analyze_key_hierarchy", "test_aead_integrity", "key_wrap_analysis"]
