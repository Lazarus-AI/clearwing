"""Auth Flow Recorder — unified timeline of proxy, crypto, and browser events."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from clearwing.agent.tooling import tool


@dataclass
class AuthFlowEvent:
    """Single entry in the unified auth flow timeline."""

    source: str
    timestamp: str
    seq: int
    event_type: str
    summary: dict = field(default_factory=dict)


@dataclass
class AuthFlowRecord:
    """Complete output of one start/stop recording session."""

    name: str
    tab_name: str
    started_at: str
    stopped_at: str
    events: list[AuthFlowEvent] = field(default_factory=list)
    proxy_events: list[dict] = field(default_factory=list)
    crypto_events: list[dict] = field(default_factory=list)
    cookies_at_start: list[dict] = field(default_factory=list)
    cookies_at_stop: list[dict] = field(default_factory=list)
    srp_values: dict | None = None


class _RecordingState:
    """Internal watermark container for an active recording."""

    __slots__ = ("name", "tab_name", "started_at", "proxy_watermark", "crypto_watermark", "cookies_at_start")

    def __init__(
        self,
        name: str,
        tab_name: str,
        started_at: str,
        proxy_watermark: int,
        crypto_watermark: int,
        cookies_at_start: list[dict],
    ) -> None:
        self.name = name
        self.tab_name = tab_name
        self.started_at = started_at
        self.proxy_watermark = proxy_watermark
        self.crypto_watermark = crypto_watermark
        self.cookies_at_start = cookies_at_start


_active_recording: _RecordingState | None = None
_saved_flows: dict[str, AuthFlowRecord] = {}
_lock = threading.Lock()


def _get_cookies() -> list[dict]:
    try:
        from clearwing.agent.tools.recon.browser_tools import _browser_state

        ctx = _browser_state.get("context")
        if ctx is not None:
            return ctx.cookies()
    except Exception:
        pass
    return []


def _extract_path(url: str) -> str:
    try:
        return urlparse(url).path or url
    except Exception:
        return url


@tool(
    name="start_auth_recording",
    description="Begin recording an authentication flow. Snapshots proxy and crypto state so that stop_auth_recording can capture only new events.",
)
def start_auth_recording(name: str, tab_name: str = "default") -> dict:
    """Start recording an authentication flow.

    Args:
        name: Label for this recording (e.g. "correct_password"). Must be unique among saved flows.
        tab_name: Browser tab to monitor for crypto operations.

    Returns:
        Dict with recording status, watermarks, and instructions.
    """
    global _active_recording  # noqa: PLW0603

    with _lock:
        if _active_recording is not None:
            return {
                "error": f"Recording already active: '{_active_recording.name}'. "
                "Call stop_auth_recording first.",
            }

    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    with _proxy_history._lock:
        proxy_wm = _proxy_history._next_id

    crypto_wm = 1
    try:
        from clearwing.agent.tools.recon.webcrypto_hooks import _crypto_logs, _flush_js_log

        try:
            _flush_js_log(tab_name)
        except Exception:
            pass

        if tab_name in _crypto_logs:
            with _crypto_logs[tab_name]._lock:
                crypto_wm = _crypto_logs[tab_name]._next_id
    except ImportError:
        pass

    cookies = _get_cookies()

    state = _RecordingState(
        name=name,
        tab_name=tab_name,
        started_at=datetime.now(tz=timezone.utc).isoformat(),
        proxy_watermark=proxy_wm,
        crypto_watermark=crypto_wm,
        cookies_at_start=cookies,
    )

    with _lock:
        _active_recording = state

    return {
        "status": "recording",
        "name": name,
        "tab_name": tab_name,
        "proxy_watermark": proxy_wm,
        "crypto_watermark": crypto_wm,
        "cookies_at_start": len(cookies),
        "message": "Recording started. Perform the auth flow, then call stop_auth_recording.",
    }


@tool(
    name="stop_auth_recording",
    description="Stop the active auth flow recording, collect all new proxy/crypto events since start, and return a unified timeline.",
)
def stop_auth_recording() -> dict:
    """Stop the active recording and return the unified flow.

    Returns:
        Dict with timeline, event counts, and SRP extraction results.
    """
    global _active_recording  # noqa: PLW0603

    with _lock:
        if _active_recording is None:
            return {"error": "No active recording. Call start_auth_recording first."}
        state = _active_recording
        _active_recording = None

    stopped_at = datetime.now(tz=timezone.utc).isoformat()

    proxy_entries = _collect_proxy_entries(state.proxy_watermark)
    crypto_entries = _collect_crypto_entries(state.tab_name, state.crypto_watermark)
    cookies_at_stop = _get_cookies()

    events = _build_timeline(proxy_entries, crypto_entries, cookies_at_stop, state.cookies_at_start, stopped_at)

    srp_values = _try_extract_srp(state.tab_name, crypto_entries)

    record = AuthFlowRecord(
        name=state.name,
        tab_name=state.tab_name,
        started_at=state.started_at,
        stopped_at=stopped_at,
        events=events,
        proxy_events=proxy_entries,
        crypto_events=crypto_entries,
        cookies_at_start=state.cookies_at_start,
        cookies_at_stop=cookies_at_stop,
        srp_values=srp_values,
    )

    with _lock:
        _saved_flows[state.name] = record

    new_cookie_names = {c.get("name") for c in cookies_at_stop} - {c.get("name") for c in state.cookies_at_start}

    return {
        "status": "stopped",
        "name": state.name,
        "started_at": state.started_at,
        "stopped_at": stopped_at,
        "proxy_events": len(proxy_entries),
        "crypto_events": len(crypto_entries),
        "total_events": len(events),
        "cookies_at_start": len(state.cookies_at_start),
        "cookies_at_stop": len(cookies_at_stop),
        "new_cookies": sorted(new_cookie_names),
        "srp_values_found": srp_values is not None and bool(srp_values.get("kdf")),
        "timeline": [
            {"seq": e.seq, "source": e.source, "event_type": e.event_type, "timestamp": e.timestamp}
            for e in events
        ],
    }


@tool(
    name="diff_auth_flows",
    description="Compare two recorded auth flows to find differences in responses, timing, crypto operations, and cookies.",
)
def diff_auth_flows(flow_a: str, flow_b: str) -> dict:
    """Compare two named recordings.

    Args:
        flow_a: Name of the first saved flow.
        flow_b: Name of the second saved flow.

    Returns:
        Dict with structured diff across six sections.
    """
    with _lock:
        a = _saved_flows.get(flow_a)
        b = _saved_flows.get(flow_b)

    if a is None:
        return {"error": f"Flow '{flow_a}' not found. Available: {list(_saved_flows.keys())}"}
    if b is None:
        return {"error": f"Flow '{flow_b}' not found. Available: {list(_saved_flows.keys())}"}

    return {
        "flow_a": flow_a,
        "flow_b": flow_b,
        "event_counts": _diff_event_counts(a, b),
        "response_diffs": _diff_responses(a.proxy_events, b.proxy_events),
        "timing_diffs": _diff_timing(a.proxy_events, b.proxy_events),
        "crypto_sequence_diffs": _diff_crypto_sequences(a.crypto_events, b.crypto_events),
        "srp_diffs": _diff_srp_values(a.srp_values, b.srp_values),
        "cookie_diffs": _diff_cookies(a.cookies_at_stop, b.cookies_at_stop),
    }


# --- Internal helpers ---


def _collect_proxy_entries(watermark: int) -> list[dict]:
    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    all_entries = _proxy_history.get_all(limit=10000)
    return [asdict(e) for e in all_entries if e.id >= watermark]


def _collect_crypto_entries(tab_name: str, watermark: int) -> list[dict]:
    try:
        from clearwing.agent.tools.recon.webcrypto_hooks import _crypto_logs, _flush_js_log

        try:
            _flush_js_log(tab_name)
        except Exception:
            pass

        if tab_name not in _crypto_logs:
            return []
        all_entries = _crypto_logs[tab_name].get_all(limit=10000)
        return [asdict(e) for e in all_entries if e.id >= watermark]
    except ImportError:
        return []


def _build_timeline(
    proxy_entries: list[dict],
    crypto_entries: list[dict],
    cookies_at_stop: list[dict],
    cookies_at_start: list[dict],
    stopped_at: str,
) -> list[AuthFlowEvent]:
    events: list[AuthFlowEvent] = []

    for p in proxy_entries:
        events.append(AuthFlowEvent(
            source="proxy",
            timestamp=p["timestamp"],
            seq=p["id"],
            event_type=f"{p['method']} {_extract_path(p['url'])}",
            summary={
                "status_code": p["status_code"],
                "duration_ms": p["duration_ms"],
                "url": p["url"],
                "request_body_length": len(p.get("request_body", "")),
                "response_body_snippet": p.get("response_body", "")[:200],
            },
        ))

    for c in crypto_entries:
        algo = c.get("algorithm") or {}
        km = c.get("key_material")
        events.append(AuthFlowEvent(
            source="crypto",
            timestamp=c["timestamp"],
            seq=c.get("seq", 0),
            event_type=c["method"],
            summary={
                "algorithm": algo.get("name", str(algo)[:50]) if algo else "",
                "key_material": km[:32] if km else None,
                "duration_ms": c.get("duration_ms", 0),
            },
        ))

    new_cookie_names = {c.get("name") for c in cookies_at_stop} - {c.get("name") for c in cookies_at_start}
    events.append(AuthFlowEvent(
        source="cookie",
        timestamp=stopped_at,
        seq=0,
        event_type="cookie_snapshot",
        summary={"count": len(cookies_at_stop), "new_cookies": sorted(new_cookie_names)},
    ))

    events.sort(key=lambda e: e.timestamp)
    return events


def _try_extract_srp(tab_name: str, crypto_entries: list[dict]) -> dict | None:
    if not crypto_entries:
        return None
    try:
        from clearwing.agent.tools.recon.webcrypto_hooks import extract_srp_values

        return extract_srp_values.invoke({"tab_name": tab_name})
    except Exception:
        return None


def _diff_event_counts(a: AuthFlowRecord, b: AuthFlowRecord) -> dict:
    pa, pb = len(a.proxy_events), len(b.proxy_events)
    ca, cb = len(a.crypto_events), len(b.crypto_events)
    return {
        "flow_a": {"proxy": pa, "crypto": ca, "total": pa + ca},
        "flow_b": {"proxy": pb, "crypto": cb, "total": pb + cb},
        "proxy_diff": pb - pa,
        "crypto_diff": cb - ca,
    }


def _diff_responses(proxy_a: list[dict], proxy_b: list[dict]) -> list[dict]:
    diffs: list[dict] = []
    max_len = max(len(proxy_a), len(proxy_b))
    for i in range(max_len):
        a = proxy_a[i] if i < len(proxy_a) else None
        b = proxy_b[i] if i < len(proxy_b) else None
        if a is None:
            diffs.append({"step": i, "note": "extra in flow_b", "url_b": _extract_path(b["url"]), "status_b": b["status_code"]})
            continue
        if b is None:
            diffs.append({"step": i, "note": "extra in flow_a", "url_a": _extract_path(a["url"]), "status_a": a["status_code"]})
            continue

        body_a = a.get("response_body", "")
        body_b = b.get("response_body", "")
        status_diff = a["status_code"] != b["status_code"]
        body_diff = body_a != body_b

        if status_diff or body_diff:
            diffs.append({
                "step": i,
                "url": _extract_path(a["url"]),
                "method": a["method"],
                "status_a": a["status_code"],
                "status_b": b["status_code"],
                "status_differs": status_diff,
                "body_differs": body_diff,
                "body_a_snippet": body_a[:200],
                "body_b_snippet": body_b[:200],
            })
    return diffs


def _diff_timing(proxy_a: list[dict], proxy_b: list[dict]) -> dict:
    steps: list[dict] = []
    paired = min(len(proxy_a), len(proxy_b))
    for i in range(paired):
        da = proxy_a[i].get("duration_ms", 0)
        db = proxy_b[i].get("duration_ms", 0)
        steps.append({
            "step": i,
            "event_type": f"{proxy_a[i]['method']} {_extract_path(proxy_a[i]['url'])}",
            "duration_a_ms": da,
            "duration_b_ms": db,
            "delta_ms": db - da,
        })

    total_a = sum(p.get("duration_ms", 0) for p in proxy_a)
    total_b = sum(p.get("duration_ms", 0) for p in proxy_b)

    return {
        "steps": steps,
        "total_duration_a_ms": total_a,
        "total_duration_b_ms": total_b,
        "total_delta_ms": total_b - total_a,
    }


def _diff_crypto_sequences(crypto_a: list[dict], crypto_b: list[dict]) -> dict:
    methods_a = [c["method"] for c in crypto_a]
    methods_b = [c["method"] for c in crypto_b]

    first_div: int | None = None
    for i in range(min(len(methods_a), len(methods_b))):
        if methods_a[i] != methods_b[i]:
            first_div = i
            break
    if first_div is None and len(methods_a) != len(methods_b):
        first_div = min(len(methods_a), len(methods_b))

    key_diffs: list[dict] = []
    for i in range(min(len(crypto_a), len(crypto_b))):
        km_a = crypto_a[i].get("key_material")
        km_b = crypto_b[i].get("key_material")
        if km_a != km_b:
            key_diffs.append({
                "step": i,
                "method": crypto_a[i]["method"],
                "key_a_hex": (km_a or "")[:32],
                "key_b_hex": (km_b or "")[:32],
            })

    return {
        "flow_a_methods": methods_a,
        "flow_b_methods": methods_b,
        "sequences_match": methods_a == methods_b,
        "first_divergence_index": first_div,
        "key_material_diffs": key_diffs,
    }


def _diff_srp_values(srp_a: dict | None, srp_b: dict | None) -> dict:
    if srp_a is None and srp_b is None:
        return {"available": False}

    kdf_a = (srp_a or {}).get("kdf") or {}
    kdf_b = (srp_b or {}).get("kdf") or {}

    return {
        "available": True,
        "kdf_params_match": kdf_a == kdf_b,
        "kdf_a": kdf_a,
        "kdf_b": kdf_b,
        "derived_key_count_a": len((srp_a or {}).get("derived_keys", [])),
        "derived_key_count_b": len((srp_b or {}).get("derived_keys", [])),
    }


def _diff_cookies(cookies_a: list[dict], cookies_b: list[dict]) -> dict:
    names_a = {c.get("name") for c in cookies_a}
    names_b = {c.get("name") for c in cookies_b}

    return {
        "cookies_a_count": len(cookies_a),
        "cookies_b_count": len(cookies_b),
        "in_a_only": sorted(names_a - names_b),
        "in_b_only": sorted(names_b - names_a),
        "in_both": sorted(names_a & names_b),
    }


def get_auth_recorder_tools() -> list[Any]:
    """Return all auth flow recorder tools."""
    return [start_auth_recording, stop_auth_recording, diff_auth_flows]
