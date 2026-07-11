"""Tests for WebCrypto instrumentation hooks (unit tests, no real browser)."""

import json
from pathlib import Path

import pytest

from clearwing.agent.tools.recon.webcrypto_hooks import (
    _SUBTLE_METHODS,
    _WEBCRYPTO_INSTRUMENT_JS,
    CryptoLog,
    CryptoLogEntry,
    _crypto_logs,
    _hooks_installed,
    clear_webcrypto_log,
    get_webcrypto_log,
    get_webcrypto_tools,
)


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset module-level state between tests."""
    _crypto_logs.clear()
    _hooks_installed.clear()
    yield
    _crypto_logs.clear()
    _hooks_installed.clear()


# --- CryptoLog ---


class TestCryptoLog:
    def test_add_batch(self):
        log = CryptoLog()
        count = log.add_batch([
            {"method": "encrypt", "seq": 0, "durationMs": 1.5},
            {"method": "decrypt", "seq": 1, "durationMs": 2.0},
        ])
        assert count == 2
        assert log.count == 2

    def test_sequential_ids(self):
        log = CryptoLog()
        log.add_batch([{"method": "encrypt", "seq": 0}])
        log.add_batch([{"method": "decrypt", "seq": 1}])
        entries = log.get_all()
        assert entries[0].id == 1
        assert entries[1].id == 2

    def test_get_all_no_filter(self):
        log = CryptoLog()
        log.add_batch([
            {"method": "encrypt", "seq": 0},
            {"method": "deriveBits", "seq": 1},
        ])
        results = log.get_all()
        assert len(results) == 2

    def test_get_all_method_filter(self):
        log = CryptoLog()
        log.add_batch([
            {"method": "encrypt", "seq": 0},
            {"method": "deriveBits", "seq": 1},
            {"method": "encrypt", "seq": 2},
        ])
        results = log.get_all(method_filter="encrypt")
        assert len(results) == 2
        assert all(e.method == "encrypt" for e in results)

    def test_get_all_limit(self):
        log = CryptoLog()
        log.add_batch([{"method": "encrypt", "seq": i} for i in range(10)])
        results = log.get_all(limit=3)
        assert len(results) == 3
        assert results[0].seq == 7

    def test_get_by_id(self):
        log = CryptoLog()
        log.add_batch([
            {"method": "encrypt", "seq": 0},
            {"method": "decrypt", "seq": 1},
        ])
        entry = log.get(2)
        assert entry is not None
        assert entry.method == "decrypt"

    def test_get_nonexistent(self):
        log = CryptoLog()
        assert log.get(999) is None

    def test_clear(self):
        log = CryptoLog()
        log.add_batch([{"method": "encrypt", "seq": 0}])
        assert log.count == 1
        cleared = log.clear()
        assert cleared == 1
        assert log.count == 0

    def test_count_property(self):
        log = CryptoLog()
        assert log.count == 0
        log.add_batch([{"method": "encrypt", "seq": 0}])
        assert log.count == 1

    def test_stack_trace_truncation(self):
        log = CryptoLog()
        long_stack = "a" * 1000
        log.add_batch([{"method": "encrypt", "seq": 0, "stack": long_stack}])
        entry = log.get(1)
        assert len(entry.stack_trace) == 500

    def test_missing_fields_default(self):
        log = CryptoLog()
        log.add_batch([{}])
        entry = log.get(1)
        assert entry.method == "unknown"
        assert entry.algorithm == {}
        assert entry.key_material is None
        assert entry.duration_ms == 0.0

    def test_export(self, tmp_path):
        log = CryptoLog()
        log.add_batch([
            {"method": "encrypt", "seq": 0},
            {"method": "decrypt", "seq": 1},
        ])
        export_path = str(tmp_path / "crypto_log.json")
        log.export(export_path)
        data = json.loads(Path(export_path).read_text())
        assert len(data) == 2
        assert data[0]["method"] == "encrypt"


# --- CryptoLogEntry ---


class TestCryptoLogEntry:
    def test_dataclass_fields(self):
        entry = CryptoLogEntry(
            id=1, seq=0, timestamp="2024-01-01T00:00:00Z",
            method="encrypt",
        )
        assert entry.id == 1
        assert entry.method == "encrypt"
        assert entry.key_material is None


# --- Tool metadata ---


class TestGetWebcryptoTools:
    def test_returns_list(self):
        tools = get_webcrypto_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_webcrypto_tools()
        assert len(tools) == 5

    def test_tool_names(self):
        tools = get_webcrypto_tools()
        names = [t.name for t in tools]
        expected = [
            "install_webcrypto_hooks",
            "get_webcrypto_log",
            "clear_webcrypto_log",
            "extract_srp_values",
            "extract_key_hierarchy",
        ]
        assert names == expected


# --- JS payload ---


class TestJSPayload:
    def test_payload_is_nonempty_string(self):
        assert isinstance(_WEBCRYPTO_INSTRUMENT_JS, str)
        assert len(_WEBCRYPTO_INSTRUMENT_JS) > 100

    def test_payload_contains_guard(self):
        assert "__clearwing_crypto_installed" in _WEBCRYPTO_INSTRUMENT_JS

    def test_payload_contains_flush(self):
        assert "__clearwing_crypto_flush" in _WEBCRYPTO_INSTRUMENT_JS

    def test_payload_hooks_all_methods(self):
        for method in _SUBTLE_METHODS:
            assert method in _WEBCRYPTO_INSTRUMENT_JS, f"Missing hook for {method}"


# --- Error paths (no browser) ---


class TestInstallOnBlankPage:
    def test_succeeds_with_init_script(self):
        result = install_webcrypto_hooks.invoke({})
        assert result["success"] is True
        assert result["methods_hooked"] == _SUBTLE_METHODS


class TestGetLogWithoutHooks:
    def test_returns_error(self):
        result = get_webcrypto_log.invoke({})
        assert "error" in result
        assert result["entries"] == []


class TestClearLogWithoutHooks:
    def test_returns_error(self):
        result = clear_webcrypto_log.invoke({})
        assert "error" in result


# We need this import for the install test
from clearwing.agent.tools.recon.webcrypto_hooks import install_webcrypto_hooks  # noqa: E402
