"""Tests for TLS Inspection Tools (unit tests, no real network)."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

import clearwing.agent.tools.scan.tls_tools as tls_mod
from clearwing.agent.tools.scan.tls_tools import (
    _classify_cipher,
    _days_remaining,
    _decode_oid,
    _key_strength_rating,
    _make_context,
    _parse_cert_der,
    _parse_cert_dict,
    _parse_tag_length,
    enumerate_cipher_suites,
    get_tls_tools,
    inspect_certificate,
    scan_tls_config,
    test_tls_downgrade,
)

# --- Helper tests ---


class TestParseTagLength:
    def test_short_form_length(self):
        data = bytes([0x30, 0x03, 0x01, 0x02, 0x03])
        tag, content_start, content_end = _parse_tag_length(data, 0)
        assert tag == 0x30
        assert content_start == 2
        assert content_end == 5

    def test_long_form_length(self):
        data = bytes([0x30, 0x82, 0x01, 0x00]) + b"\x00" * 256
        tag, content_start, content_end = _parse_tag_length(data, 0)
        assert tag == 0x30
        assert content_start == 4
        assert content_end == 260

    def test_offset_past_end_raises(self):
        with pytest.raises(ValueError, match="offset past end"):
            _parse_tag_length(b"\x30\x01", 5)

    def test_truncated_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            _parse_tag_length(b"\x30", 0)


class TestDecodeOid:
    def test_sha256_with_rsa(self):
        oid_bytes = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])
        assert _decode_oid(oid_bytes) == "1.2.840.113549.1.1.11"

    def test_empty(self):
        assert _decode_oid(b"") == ""


class TestParseCertDict:
    def test_basic_cert(self):
        cert_dict = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT",
            "serialNumber": "ABC123",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        }
        result = _parse_cert_dict(cert_dict)
        assert result["subject"]["commonName"] == "example.com"
        assert result["issuer"]["commonName"] == "CA"
        assert result["serial_number"] == "ABC123"
        assert len(result["subject_alt_names"]) == 2
        assert result["subject_alt_names"][0] == {"type": "DNS", "value": "example.com"}

    def test_empty_cert(self):
        result = _parse_cert_dict({})
        assert result["subject"] == {}
        assert result["issuer"] == {}
        assert result["subject_alt_names"] == []


class TestParseCertDer:
    def test_returns_defaults_for_invalid_data(self):
        result = _parse_cert_der(b"\x00\x01\x02")
        assert result["key_bits"] == 0
        assert result["signature_algorithm"] == "unknown"

    def test_returns_defaults_for_empty(self):
        result = _parse_cert_der(b"")
        assert result["key_bits"] == 0


class TestClassifyCipher:
    def test_strong_gcm(self):
        assert _classify_cipher("ECDHE-RSA-AES128-GCM-SHA256") == "strong"

    def test_strong_chacha(self):
        assert _classify_cipher("ECDHE-RSA-CHACHA20-POLY1305") == "strong"

    def test_insecure_rc4(self):
        assert _classify_cipher("RC4-SHA") == "insecure"

    def test_insecure_null(self):
        assert _classify_cipher("NULL-SHA") == "insecure"

    def test_insecure_export(self):
        assert _classify_cipher("EXP-RC4-MD5") == "insecure"

    def test_weak_3des(self):
        assert _classify_cipher("DES-CBC3-SHA") == "weak"


class TestDaysRemaining:
    def test_future_date(self):
        days = _days_remaining("Dec 31 23:59:59 2099 GMT")
        assert days is not None
        assert days > 0

    def test_past_date(self):
        days = _days_remaining("Jan  1 00:00:00 2020 GMT")
        assert days is not None
        assert days < 0

    def test_invalid_format(self):
        assert _days_remaining("not-a-date") is None


class TestKeyStrengthRating:
    def test_strong(self):
        assert _key_strength_rating(2048) == "strong"
        assert _key_strength_rating(4096) == "strong"

    def test_acceptable(self):
        assert _key_strength_rating(1024) == "acceptable"

    def test_weak(self):
        assert _key_strength_rating(512) == "weak"

    def test_unknown(self):
        assert _key_strength_rating(0) == "unknown"


class TestMakeContext:
    def test_default_context(self):
        ctx = _make_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_no_verify(self):
        ctx = _make_context(verify=False)
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_protocol_pinning_tls12(self):
        ctx = _make_context(protocol_version="TLSv1.2")
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2


# --- Tool tests ---


class TestScanTlsConfig:
    def test_connection_failure(self):
        with patch.object(tls_mod, "_tls_connect", side_effect=OSError("refused")):
            result = scan_tls_config.invoke({"host": "example.com"})
        assert "error" in result

    def test_successful_scan(self):
        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = None
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT",
            "serialNumber": "ABC",
            "subjectAltName": (("DNS", "example.com"),),
        }

        with (
            patch.object(tls_mod, "_tls_connect", return_value=(mock_ssock, mock_cert)),
            patch.object(tls_mod, "_fetch_security_headers", return_value={"strict-transport-security": "max-age=31536000"}),
        ):
            result = scan_tls_config.invoke({"host": "example.com"})

        assert result["protocol_version"] == "TLSv1.3"
        assert result["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert result["cipher_bits"] == 256
        assert result["certificate"]["subject"]["commonName"] == "example.com"
        assert "strict-transport-security" in result["security_headers"]


class TestEnumerateCipherSuites:
    def test_declined(self):
        with patch.object(tls_mod, "interrupt", return_value=False):
            result = enumerate_cipher_suites.invoke({"host": "example.com"})
        assert "error" in result

    def test_enumeration(self):
        call_count = [0]
        ciphers = [
            ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
            ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128),
            ("AES256-SHA", "TLSv1.2", 256),
        ]

        def mock_connect(host, port, ctx, timeout=10):
            mock_ssock = MagicMock()
            if call_count[0] < len(ciphers):
                mock_ssock.cipher.return_value = ciphers[call_count[0]]
                call_count[0] += 1
                return mock_ssock, {}
            raise ssl.SSLError("no ciphers")

        with (
            patch.object(tls_mod, "interrupt", return_value=True),
            patch.object(tls_mod, "_tls_connect", side_effect=mock_connect),
            patch.object(tls_mod, "_make_context", return_value=MagicMock(spec=ssl.SSLContext)),
        ):
            result = enumerate_cipher_suites.invoke({"host": "example.com"})

        assert result["total_accepted"] == 3
        assert result["cipher_suites"][0]["name"] == "ECDHE-RSA-AES256-GCM-SHA384"
        assert result["cipher_suites"][0]["preference_order"] == 1
        assert result["cipher_suites"][2]["name"] == "AES256-SHA"

    def test_no_ciphers_accepted(self):
        with (
            patch.object(tls_mod, "interrupt", return_value=True),
            patch.object(tls_mod, "_tls_connect", side_effect=ssl.SSLError("fail")),
            patch.object(tls_mod, "_make_context", return_value=MagicMock(spec=ssl.SSLContext)),
        ):
            result = enumerate_cipher_suites.invoke({"host": "example.com"})

        assert result["total_accepted"] == 0
        assert "No cipher suites accepted" in result["assessment"]


class TestTlsDowngrade:
    def test_declined(self):
        with patch.object(tls_mod, "interrupt", return_value=False):
            result = test_tls_downgrade.invoke({"host": "example.com"})
        assert "error" in result

    def test_no_legacy_accepted(self):
        def mock_connect(host, port, ctx, timeout=10):
            raise ssl.SSLError("protocol version")

        with (
            patch.object(tls_mod, "interrupt", return_value=True),
            patch.object(tls_mod, "_tls_connect", side_effect=mock_connect),
            patch.object(tls_mod, "_make_context", return_value=MagicMock(spec=ssl.SSLContext)),
        ):
            result = test_tls_downgrade.invoke({"host": "example.com"})

        assert result["downgrade_possible"] is False
        assert "correctly rejects" in result["conclusion"]
        assert all(not r["accepted"] for r in result["protocol_results"])

    def test_sslv3_accepted(self):
        call_count = [0]

        def mock_connect(host, port, ctx, timeout=10):
            call_count[0] += 1
            if call_count[0] == 1:  # SSLv3 attempt
                mock_ssock = MagicMock()
                mock_ssock.cipher.return_value = ("DES-CBC3-SHA", "SSLv3", 168)
                return mock_ssock, {}
            raise ssl.SSLError("protocol version")

        with (
            patch.object(tls_mod, "interrupt", return_value=True),
            patch.object(tls_mod, "_tls_connect", side_effect=mock_connect),
            patch.object(tls_mod, "_make_context", return_value=MagicMock(spec=ssl.SSLContext)),
        ):
            result = test_tls_downgrade.invoke({"host": "example.com"})

        assert result["downgrade_possible"] is True
        assert result["protocol_results"][0]["accepted"] is True
        assert result["protocol_results"][0]["protocol"] == "SSLv3"
        assert "POODLE" in str(result["all_vulnerabilities"])


class TestInspectCertificate:
    def test_connection_failure(self):
        with patch.object(tls_mod, "_tls_connect", side_effect=OSError("refused")):
            result = inspect_certificate.invoke({"host": "example.com"})
        assert "error" in result

    def test_valid_certificate(self):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = b"\x30\x00"
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "serialNumber": "ABC",
            "subjectAltName": (("DNS", "example.com"),),
        }

        with (
            patch.object(tls_mod, "_tls_connect", return_value=(mock_ssock, mock_cert)),
            patch.object(tls_mod, "_parse_cert_der", return_value={"key_bits": 2048, "signature_algorithm": "sha256WithRSAEncryption"}),
        ):
            result = inspect_certificate.invoke({"host": "example.com"})

        assert result["key_bits"] == 2048
        assert result["key_strength"] == "strong"
        assert result["signature_algorithm"] == "sha256WithRSAEncryption"
        assert result["trust_assessment"] == "trusted"

    def test_expired_certificate(self):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = b"\x30\x00"
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert"),),),
            "notBefore": "Jan  1 00:00:00 2020 GMT",
            "notAfter": "Jan  1 00:00:00 2021 GMT",
            "serialNumber": "ABC",
            "subjectAltName": (("DNS", "example.com"),),
        }

        with (
            patch.object(tls_mod, "_tls_connect", return_value=(mock_ssock, mock_cert)),
            patch.object(tls_mod, "_parse_cert_der", return_value={"key_bits": 2048, "signature_algorithm": "sha256WithRSAEncryption"}),
        ):
            result = inspect_certificate.invoke({"host": "example.com"})

        assert result["trust_assessment"] == "issues_found"
        assert any("expired" in issue for issue in result["issues"])

    def test_self_signed(self):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = b"\x30\x00"
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "example.com"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "serialNumber": "ABC",
            "subjectAltName": (("DNS", "example.com"),),
        }

        with (
            patch.object(tls_mod, "_tls_connect", return_value=(mock_ssock, mock_cert)),
            patch.object(tls_mod, "_parse_cert_der", return_value={"key_bits": 2048, "signature_algorithm": "sha256WithRSAEncryption"}),
        ):
            result = inspect_certificate.invoke({"host": "example.com"})

        assert any("Self-signed" in issue for issue in result["issues"])

    def test_weak_key(self):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = b"\x30\x00"
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "serialNumber": "ABC",
            "subjectAltName": (("DNS", "example.com"),),
        }

        with (
            patch.object(tls_mod, "_tls_connect", return_value=(mock_ssock, mock_cert)),
            patch.object(tls_mod, "_parse_cert_der", return_value={"key_bits": 512, "signature_algorithm": "sha1WithRSAEncryption"}),
        ):
            result = inspect_certificate.invoke({"host": "example.com"})

        assert result["key_strength"] == "weak"
        assert any("Weak key" in issue for issue in result["issues"])
        assert any("Weak signature" in issue for issue in result["issues"])


# --- Tool metadata ---


class TestGetTlsTools:
    def test_returns_list(self):
        tools = get_tls_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_tls_tools()
        assert len(tools) == 4

    def test_tool_names(self):
        tools = get_tls_tools()
        names = [t.name for t in tools]
        assert names == ["scan_tls_config", "enumerate_cipher_suites", "test_tls_downgrade", "inspect_certificate"]
