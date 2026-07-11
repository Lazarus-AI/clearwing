"""Tests for Auth Flow Recorder (unit tests, no real browser)."""

from __future__ import annotations

import threading

import pytest

from clearwing.agent.tools.recon.auth_recorder import (
    AuthFlowEvent,
    AuthFlowRecord,
    _RecordingState,
    _saved_flows,
    diff_auth_flows,
    get_auth_recorder_tools,
    start_auth_recording,
    stop_auth_recording,
)
from clearwing.agent.tools.recon.proxy_tools import _proxy_history
from clearwing.agent.tools.recon.webcrypto_hooks import CryptoLog, _crypto_logs, _hooks_installed

import clearwing.agent.tools.recon.auth_recorder as recorder_mod


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset all module-level state between tests."""
    with recorder_mod._lock:
        recorder_mod._active_recording = None
        _saved_flows.clear()

    _proxy_history.clear()
    _crypto_logs.clear()
    _hooks_installed.clear()

    yield

    with recorder_mod._lock:
        recorder_mod._active_recording = None
        _saved_flows.clear()

    _proxy_history.clear()
    _crypto_logs.clear()
    _hooks_installed.clear()


def _add_proxy_entry(method: str = "POST", url: str = "https://example.com/auth", status_code: int = 200, duration_ms: int = 100, response_body: str = ""):
    return _proxy_history.add(method=method, url=url, status_code=status_code, duration_ms=duration_ms, response_body=response_body)


def _setup_crypto_log(tab_name: str = "default"):
    log = CryptoLog()
    _crypto_logs[tab_name] = log
    _hooks_installed.add(tab_name)
    return log


# --- Data model tests ---


class TestAuthFlowEvent:
    def test_fields(self):
        e = AuthFlowEvent(source="proxy", timestamp="2024-01-01T00:00:00Z", seq=1, event_type="POST /auth")
        assert e.source == "proxy"
        assert e.seq == 1


class TestRecordingState:
    def test_slots(self):
        s = _RecordingState(name="test", tab_name="default", started_at="now", proxy_watermark=1, crypto_watermark=1, cookies_at_start=[])
        assert s.name == "test"
        assert s.proxy_watermark == 1


# --- start_auth_recording ---


class TestStartAuthRecording:
    def test_returns_recording_status(self):
        result = start_auth_recording.invoke({"name": "test_flow"})
        assert result["status"] == "recording"
        assert result["name"] == "test_flow"
        assert result["tab_name"] == "default"

    def test_sets_proxy_watermark(self):
        _add_proxy_entry()
        _add_proxy_entry()
        _add_proxy_entry()
        result = start_auth_recording.invoke({"name": "test_flow"})
        assert result["proxy_watermark"] == 4

    def test_sets_crypto_watermark(self):
        log = _setup_crypto_log()
        log.add_batch([{"method": "encrypt", "seq": 0}, {"method": "decrypt", "seq": 1}])
        result = start_auth_recording.invoke({"name": "test_flow"})
        assert result["crypto_watermark"] == 3

    def test_error_if_already_recording(self):
        start_auth_recording.invoke({"name": "flow_1"})
        result = start_auth_recording.invoke({"name": "flow_2"})
        assert "error" in result
        assert "already active" in result["error"].lower()

    def test_works_without_crypto_log(self):
        result = start_auth_recording.invoke({"name": "test_flow"})
        assert result["crypto_watermark"] == 1


# --- stop_auth_recording ---


class TestStopAuthRecording:
    def test_error_without_start(self):
        result = stop_auth_recording.invoke({})
        assert "error" in result

    def test_collects_new_proxy_entries(self):
        _add_proxy_entry(url="https://example.com/before1")
        _add_proxy_entry(url="https://example.com/before2")

        start_auth_recording.invoke({"name": "test_flow"})

        _add_proxy_entry(url="https://example.com/auth/init")
        _add_proxy_entry(url="https://example.com/auth/verify")
        _add_proxy_entry(url="https://example.com/auth/session")

        result = stop_auth_recording.invoke({})
        assert result["proxy_events"] == 3

    def test_collects_new_crypto_entries(self):
        log = _setup_crypto_log()
        log.add_batch([{"method": "importKey", "seq": 0}])

        start_auth_recording.invoke({"name": "test_flow"})

        log.add_batch([{"method": "deriveBits", "seq": 1}, {"method": "encrypt", "seq": 2}])

        result = stop_auth_recording.invoke({})
        assert result["crypto_events"] == 2

    def test_builds_sorted_timeline(self):
        start_auth_recording.invoke({"name": "test_flow"})

        _proxy_history.add(method="POST", url="https://example.com/auth", status_code=200, duration_ms=50)

        log = _setup_crypto_log()
        log.add_batch([{"method": "deriveBits", "seq": 0}])

        result = stop_auth_recording.invoke({})
        assert result["total_events"] >= 3  # proxy + crypto + cookie

        sources = [e["source"] for e in result["timeline"]]
        assert "proxy" in sources
        assert "crypto" in sources
        assert "cookie" in sources

    def test_saves_flow_for_diff(self):
        start_auth_recording.invoke({"name": "saved_flow"})
        stop_auth_recording.invoke({})
        assert "saved_flow" in _saved_flows

    def test_resets_active_recording(self):
        start_auth_recording.invoke({"name": "flow_1"})
        stop_auth_recording.invoke({})
        result = start_auth_recording.invoke({"name": "flow_2"})
        assert result["status"] == "recording"


# --- diff_auth_flows ---


class TestDiffAuthFlows:
    def _record_flow(self, name: str, proxy_entries: list[dict] | None = None, crypto_entries: list[dict] | None = None):
        """Helper to create a saved flow with given entries."""
        start_auth_recording.invoke({"name": name})
        for p in proxy_entries or []:
            _add_proxy_entry(**p)
        if crypto_entries:
            if "default" not in _crypto_logs:
                _setup_crypto_log()
            _crypto_logs["default"].add_batch(crypto_entries)
        stop_auth_recording.invoke({})

    def test_error_missing_flow(self):
        result = diff_auth_flows.invoke({"flow_a": "nonexistent", "flow_b": "also_missing"})
        assert "error" in result

    def test_diff_identical_flows(self):
        self._record_flow("flow_a", [{"status_code": 200, "duration_ms": 100}])
        self._record_flow("flow_b", [{"status_code": 200, "duration_ms": 100}])
        result = diff_auth_flows.invoke({"flow_a": "flow_a", "flow_b": "flow_b"})
        assert result["event_counts"]["proxy_diff"] == 0
        assert result["response_diffs"] == []
        assert result["crypto_sequence_diffs"]["sequences_match"] is True

    def test_diff_different_status_codes(self):
        self._record_flow("flow_a", [{"status_code": 200, "duration_ms": 100}])
        self._record_flow("flow_b", [{"status_code": 401, "duration_ms": 100}])
        result = diff_auth_flows.invoke({"flow_a": "flow_a", "flow_b": "flow_b"})
        assert len(result["response_diffs"]) == 1
        assert result["response_diffs"][0]["status_a"] == 200
        assert result["response_diffs"][0]["status_b"] == 401

    def test_diff_different_crypto_sequences(self):
        self._record_flow("flow_a", crypto_entries=[{"method": "importKey", "seq": 0}, {"method": "deriveBits", "seq": 1}])
        self._record_flow("flow_b", crypto_entries=[{"method": "importKey", "seq": 0}, {"method": "encrypt", "seq": 1}])
        result = diff_auth_flows.invoke({"flow_a": "flow_a", "flow_b": "flow_b"})
        assert result["crypto_sequence_diffs"]["sequences_match"] is False
        assert result["crypto_sequence_diffs"]["first_divergence_index"] == 1

    def test_diff_timing_differences(self):
        self._record_flow("flow_a", [{"duration_ms": 100}])
        self._record_flow("flow_b", [{"duration_ms": 300}])
        result = diff_auth_flows.invoke({"flow_a": "flow_a", "flow_b": "flow_b"})
        steps = result["timing_diffs"]["steps"]
        assert len(steps) == 1
        assert steps[0]["delta_ms"] == 200

    def test_diff_extra_events_in_one_flow(self):
        self._record_flow("flow_a", [{"status_code": 200}])
        self._record_flow("flow_b", [{"status_code": 200}, {"url": "https://example.com/extra", "status_code": 302}])
        result = diff_auth_flows.invoke({"flow_a": "flow_a", "flow_b": "flow_b"})
        extras = [d for d in result["response_diffs"] if d.get("note") == "extra in flow_b"]
        assert len(extras) == 1


# --- Tool metadata ---


class TestGetAuthRecorderTools:
    def test_returns_list(self):
        tools = get_auth_recorder_tools()
        assert isinstance(tools, list)

    def test_tool_count(self):
        tools = get_auth_recorder_tools()
        assert len(tools) == 3

    def test_tool_names(self):
        tools = get_auth_recorder_tools()
        names = [t.name for t in tools]
        assert names == ["start_auth_recording", "stop_auth_recording", "diff_auth_flows"]
