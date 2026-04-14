"""Tests for the payloads corpus and encoder modules."""

from __future__ import annotations

import base64

import pytest

from clearwing.exploitation.payloads import (
    ALL_PAYLOADS,
    AUTH_BYPASS_PAYLOADS,
    CMD_INJECTION_PAYLOADS,
    HEADER_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    SQLI_PAYLOADS,
    SSRF_PAYLOADS,
    XSS_PAYLOADS,
    XXE_PAYLOADS,
    Payload,
    PayloadCorpus,
    PayloadEncoder,
)

# --- Payload dataclass ---


class TestPayloadDataclass:
    def test_defaults(self):
        p = Payload(value="test", category="sqli")
        assert p.value == "test"
        assert p.category == "sqli"
        assert p.description == ""
        assert p.encoding == "none"

    def test_custom_fields(self):
        p = Payload(value="x", category="xss", description="desc", encoding="url")
        assert p.description == "desc"
        assert p.encoding == "url"


# --- Payload lists ---


class TestPayloadLists:
    def test_all_payloads_non_empty(self):
        assert len(ALL_PAYLOADS) > 0

    def test_all_payloads_has_90_plus_entries(self):
        assert len(ALL_PAYLOADS) >= 90

    def test_sqli_payloads_count(self):
        assert len(SQLI_PAYLOADS) == 20

    def test_xss_payloads_count(self):
        assert len(XSS_PAYLOADS) == 15

    def test_ssrf_payloads_count(self):
        assert len(SSRF_PAYLOADS) == 13

    def test_path_traversal_payloads_count(self):
        assert len(PATH_TRAVERSAL_PAYLOADS) == 10

    def test_cmd_injection_payloads_count(self):
        assert len(CMD_INJECTION_PAYLOADS) == 12

    def test_xxe_payloads_count(self):
        assert len(XXE_PAYLOADS) == 5

    def test_auth_bypass_payloads_count(self):
        assert len(AUTH_BYPASS_PAYLOADS) == 7

    def test_header_injection_payloads_count(self):
        assert len(HEADER_INJECTION_PAYLOADS) == 8

    def test_all_payloads_sum_matches(self):
        total = (
            len(SQLI_PAYLOADS)
            + len(XSS_PAYLOADS)
            + len(SSRF_PAYLOADS)
            + len(PATH_TRAVERSAL_PAYLOADS)
            + len(CMD_INJECTION_PAYLOADS)
            + len(XXE_PAYLOADS)
            + len(AUTH_BYPASS_PAYLOADS)
            + len(HEADER_INJECTION_PAYLOADS)
        )
        assert len(ALL_PAYLOADS) == total

    def test_each_payload_has_non_empty_value_and_category(self):
        for p in ALL_PAYLOADS:
            assert p.value, f"Payload has empty value: {p}"
            assert p.category, f"Payload has empty category: {p}"


# --- PayloadCorpus ---


class TestPayloadCorpus:
    @pytest.fixture
    def corpus(self):
        return PayloadCorpus()

    def test_get_categories_returns_8(self, corpus):
        cats = corpus.get_categories()
        assert len(cats) == 8
        expected = sorted(
            [
                "sqli",
                "xss",
                "ssrf",
                "path_traversal",
                "cmd_injection",
                "xxe",
                "auth_bypass",
                "header_injection",
            ]
        )
        assert cats == expected

    def test_get_by_category_sqli(self, corpus):
        sqli = corpus.get_by_category("sqli")
        assert len(sqli) == 20

    def test_get_by_category_nonexistent(self, corpus):
        result = corpus.get_by_category("nonexistent")
        assert result == []

    def test_get_all_returns_all(self, corpus):
        all_p = corpus.get_all()
        assert len(all_p) == len(ALL_PAYLOADS)

    def test_add_custom(self, corpus):
        custom = Payload("custom_payload", "custom_cat", "A custom one")
        corpus.add_custom(custom)
        assert corpus.count() == len(ALL_PAYLOADS) + 1
        assert custom in corpus.get_all()

    def test_add_custom_appears_in_category(self, corpus):
        custom = Payload("custom", "sqli", "Custom SQLi")
        corpus.add_custom(custom)
        sqli = corpus.get_by_category("sqli")
        assert custom in sqli
        assert len(sqli) == 21

    def test_count_without_category(self, corpus):
        assert corpus.count() == len(ALL_PAYLOADS)

    def test_count_with_category(self, corpus):
        assert corpus.count("sqli") == 20
        assert corpus.count("xss") == 15
        assert corpus.count("ssrf") == 13

    def test_count_with_nonexistent_category(self, corpus):
        assert corpus.count("nonexistent") == 0

    def test_search_by_value(self, corpus):
        results = corpus.search("alert")
        assert len(results) > 0
        for p in results:
            assert "alert" in p.value.lower() or "alert" in p.description.lower()

    def test_search_by_description(self, corpus):
        results = corpus.search("blind")
        assert len(results) > 0
        for p in results:
            assert "blind" in p.value.lower() or "blind" in p.description.lower()

    def test_search_case_insensitive(self, corpus):
        results_lower = corpus.search("union")
        results_upper = corpus.search("UNION")
        assert results_lower == results_upper

    def test_search_no_match(self, corpus):
        results = corpus.search("zzzznonexistentzzzz")
        assert results == []


# --- PayloadEncoder ---


class TestPayloadEncoder:
    @pytest.fixture
    def encoder(self):
        return PayloadEncoder()

    def test_url_encode(self, encoder):
        result = encoder.url_encode("' OR '1'='1")
        assert "'" not in result or "%27" in result
        assert "%27" in result
        assert " " not in result

    def test_url_encode_special_chars(self, encoder):
        result = encoder.url_encode("<script>alert(1)</script>")
        assert "<" not in result
        assert ">" not in result
        assert "%3C" in result
        assert "%3E" in result

    def test_double_url_encode(self, encoder):
        result = encoder.double_url_encode("' OR '1'='1")
        assert "%25" in result
        # Double encoding means the % from first encoding gets encoded again
        single = encoder.url_encode("' OR '1'='1")
        double = encoder.url_encode(single)
        assert result == double

    def test_base64_encode(self, encoder):
        result = encoder.base64_encode("<script>alert(1)</script>")
        # Verify it's valid base64 by decoding
        decoded = base64.b64decode(result).decode()
        assert decoded == "<script>alert(1)</script>"

    def test_base64_encode_roundtrip(self, encoder):
        payload = "' OR '1'='1"
        encoded = encoder.base64_encode(payload)
        decoded = base64.b64decode(encoded).decode()
        assert decoded == payload

    def test_hex_encode_starts_with_0x(self, encoder):
        result = encoder.hex_encode("test")
        assert result.startswith("0x")

    def test_hex_encode_correct_value(self, encoder):
        result = encoder.hex_encode("A")
        assert result == "0x41"

    def test_hex_encode_multi_char(self, encoder):
        result = encoder.hex_encode("AB")
        assert result == "0x4142"

    def test_unicode_encode(self, encoder):
        result = encoder.unicode_encode("abc")
        assert result == "\\u0061\\u0062\\u0063"

    def test_unicode_encode_special(self, encoder):
        result = encoder.unicode_encode("<")
        assert "\\u003c" in result

    def test_html_entity_encode(self, encoder):
        result = encoder.html_entity_encode("abc")
        assert result == "&#97;&#98;&#99;"

    def test_html_entity_encode_produces_hash_sequences(self, encoder):
        result = encoder.html_entity_encode("<script>")
        assert "&#" in result
        assert ";" in result

    def test_all_encodings_returns_7(self, encoder):
        result = encoder.all_encodings("test")
        assert len(result) == 7
        expected_keys = {"original", "url", "double_url", "base64", "hex", "unicode", "html_entity"}
        assert set(result.keys()) == expected_keys

    def test_all_encodings_original_unchanged(self, encoder):
        payload = "<script>alert(1)</script>"
        result = encoder.all_encodings(payload)
        assert result["original"] == payload

    def test_all_encodings_values_non_empty(self, encoder):
        result = encoder.all_encodings("test")
        for key, value in result.items():
            assert value, f"Encoding '{key}' produced empty result"
