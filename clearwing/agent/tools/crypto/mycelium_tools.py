"""Mycelium pairing protocol analysis tools.

1Password uses the Mycelium protocol for device pairing and cross-device
sign-in. Channels are created pre-auth and exchange encrypted key material
via a simple segment-based REST API.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import interrupt, tool


def _http_request(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> tuple[int, dict[str, str], str, float]:
    """Send an HTTP request and return (status, headers, body, duration_ms)."""
    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
        status = resp.status
        resp_headers = dict(resp.getheaders())
        resp_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers.items()) if e.headers else {}
        resp_body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        duration_ms = (time.time() - start) * 1000
        _proxy_history.add(method=method, url=url, request_headers=req_headers, duration_ms=int(duration_ms))
        return 0, {}, str(e), duration_ms

    duration_ms = (time.time() - start) * 1000
    _proxy_history.add(
        method=method,
        url=url,
        request_headers=req_headers,
        request_body=(body or b"").decode("utf-8", errors="replace")[:10000],
        status_code=status,
        response_headers=resp_headers,
        response_body=resp_body[:10000],
        duration_ms=int(duration_ms),
    )
    return status, resp_headers, resp_body, duration_ms


_DEFAULT_OP_UA = "1|B|2248|clearwing|||Chrome|130.0.0.0|MacOSX|10_15_7|"


@tool(
    name="mycelium_create_channel",
    description=(
        "Create a new Mycelium pairing channel on the target. "
        "Returns the channel UUID, seed, and initiator auth token. "
        "This is a pre-auth endpoint — no credentials required."
    ),
)
def mycelium_create_channel(
    target: str,
    channel_type: str = "u",
    api_path: str = "/api/v2/mycelium",
) -> dict:
    """Create a Mycelium pairing channel.

    Args:
        target: Base URL (e.g. "https://bugbounty-ctf.1password.com").
        channel_type: Channel type — "u" (unencrypted) or "v" (encrypted).
        api_path: API base path for mycelium.

    Returns:
        Dict with channel UUID, seed, initiator auth, and raw response.
    """
    if not interrupt(f"About to create a Mycelium channel on {target}"):
        return {"error": "User declined channel creation."}

    url = f"{target.rstrip('/')}{api_path}/{channel_type}"
    headers = {"OP-User-Agent": _DEFAULT_OP_UA}

    status, resp_headers, body, duration = _http_request(url, "POST", b"{}", headers)

    if status == 0:
        return {"error": f"Connection failed: {body}"}

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {"error": f"Non-JSON response (status {status}): {body[:500]}"}

    return {
        "channel_type": channel_type,
        "channel_uuid": data.get("channelUuid", ""),
        "channel_seed": data.get("channelSeed", ""),
        "initiator_auth": data.get("initiatorAuth", ""),
        "status": status,
        "duration_ms": round(duration, 2),
        "raw_response": data,
    }


@tool(
    name="mycelium_probe_channel",
    description=(
        "Read or write segments on a Mycelium channel using various "
        "authentication headers. Tests whether channel data is accessible "
        "and what auth patterns the server accepts."
    ),
)
def mycelium_probe_channel(
    target: str,
    channel_uuid: str,
    segment: int = 1,
    method: str = "GET",
    auth_header: str = "ChannelAuth",
    auth_value: str = "",
    body: str = "",
    channel_type: str = "u",
    api_path: str = "/api/v2/mycelium",
) -> dict:
    """Read or write a Mycelium channel segment.

    Args:
        target: Base URL.
        channel_uuid: Channel UUID from create_channel.
        segment: Segment number (1-based).
        method: HTTP method — "GET" (read) or "PUT" (write).
        auth_header: Auth header name — "ChannelAuth" or "ChannelJoinAuth".
        auth_value: Auth header value (initiator auth or join auth).
        body: Request body for PUT (as string).
        channel_type: Channel type — "u" or "v".
        api_path: API base path.

    Returns:
        Dict with response status, body, and timing.
    """
    if not interrupt(f"About to {method} segment {segment} on channel {channel_uuid[:8]}..."):
        return {"error": "User declined channel probe."}

    url = f"{target.rstrip('/')}{api_path}/{channel_type}/{channel_uuid}/{segment}"
    headers: dict[str, str] = {"OP-User-Agent": _DEFAULT_OP_UA}
    if auth_value:
        headers[auth_header] = auth_value

    req_body = body.encode("utf-8") if body else None
    if method == "PUT" and not req_body:
        req_body = b""

    status, resp_headers, resp_body, duration = _http_request(url, method, req_body, headers)

    return {
        "channel_uuid": channel_uuid,
        "segment": segment,
        "method": method,
        "auth_header": auth_header,
        "auth_provided": bool(auth_value),
        "status": status,
        "response_body": resp_body[:2000],
        "content_type": resp_headers.get("Content-Type", resp_headers.get("content-type", "")),
        "duration_ms": round(duration, 2),
    }


@tool(
    name="mycelium_fuzz_auth",
    description=(
        "Test Mycelium channel authentication bypass patterns. "
        "Creates a channel, then attempts to read/write segments with "
        "no auth, wrong auth, partial auth, and other header mutations."
    ),
)
def mycelium_fuzz_auth(
    target: str,
    channel_uuid: str = "",
    initiator_auth: str = "",
    channel_seed: str = "",
    channel_type: str = "u",
    api_path: str = "/api/v2/mycelium",
) -> dict:
    """Fuzz Mycelium channel auth headers for bypass patterns.

    Args:
        target: Base URL.
        channel_uuid: Existing channel UUID (creates new if empty).
        initiator_auth: Known initiator auth (from channel creation).
        channel_seed: Known channel seed (from channel creation).
        channel_type: Channel type.
        api_path: API base path.

    Returns:
        Dict with per-vector results and any bypass findings.
    """
    vectors = [
        ("no_auth", "", ""),
        ("empty_channel_auth", "ChannelAuth", ""),
        ("empty_join_auth", "ChannelJoinAuth", ""),
        ("random_channel_auth", "ChannelAuth", os.urandom(32).hex()),
        ("random_join_auth", "ChannelJoinAuth", os.urandom(32).hex()),
        ("seed_as_channel_auth", "ChannelAuth", channel_seed or "placeholder"),
        ("seed_as_join_auth", "ChannelJoinAuth", channel_seed or "placeholder"),
        ("auth_as_join_auth", "ChannelJoinAuth", initiator_auth or "placeholder"),
        ("bearer_token", "Authorization", f"Bearer {initiator_auth or 'test'}"),
        ("zero_auth", "ChannelAuth", "0" * 64),
    ]

    total_requests = len(vectors) * 2 + (2 if not channel_uuid else 0)
    if not interrupt(f"About to send ~{total_requests} auth fuzz requests to {target}"):
        return {"error": "User declined auth fuzzing."}

    if not channel_uuid:
        url = f"{target.rstrip('/')}{api_path}/{channel_type}"
        status, _, body, _ = _http_request(url, "POST", b"{}", {"OP-User-Agent": _DEFAULT_OP_UA})
        if status == 0:
            return {"error": f"Failed to create channel: {body}"}
        try:
            ch_data = json.loads(body)
            channel_uuid = ch_data.get("channelUuid", "")
            initiator_auth = initiator_auth or ch_data.get("initiatorAuth", "")
            channel_seed = channel_seed or ch_data.get("channelSeed", "")
        except (json.JSONDecodeError, TypeError):
            return {"error": f"Invalid channel response: {body[:500]}"}

    if initiator_auth:
        put_url = f"{target.rstrip('/')}{api_path}/{channel_type}/{channel_uuid}/1"
        _http_request(
            put_url, "PUT", b'{"init": true}',
            {"OP-User-Agent": _DEFAULT_OP_UA, "ChannelAuth": initiator_auth},
        )

    results: list[dict[str, Any]] = []
    bypasses: list[dict[str, Any]] = []

    for label, header_name, header_value in vectors:
        for seg_method, seg_num in [("GET", 1), ("PUT", 2)]:
            url = f"{target.rstrip('/')}{api_path}/{channel_type}/{channel_uuid}/{seg_num}"
            headers: dict[str, str] = {"OP-User-Agent": _DEFAULT_OP_UA}
            if header_name and header_value:
                headers[header_name] = header_value

            req_body = b'{"fuzz": true}' if seg_method == "PUT" else None
            status, _, resp_body, duration = _http_request(url, seg_method, req_body, headers)

            entry: dict[str, Any] = {
                "vector": label,
                "method": seg_method,
                "segment": seg_num,
                "status": status,
                "response_preview": resp_body[:200],
                "duration_ms": round(duration, 2),
            }
            results.append(entry)

            if status in (200, 201, 204) and label not in ("seed_as_channel_auth",):
                bypasses.append({
                    "vector": label,
                    "method": seg_method,
                    "segment": seg_num,
                    "severity": "CRITICAL",
                    "description": f"Server accepted {seg_method} with {label} auth pattern",
                })

    return {
        "target": target,
        "channel_uuid": channel_uuid,
        "channel_type": channel_type,
        "vectors_tested": len(vectors),
        "results": results,
        "bypasses": bypasses,
        "summary": (
            f"{len(bypasses)} auth bypass(es) found in {len(results)} probes"
            if bypasses
            else f"All {len(results)} auth bypass attempts properly rejected"
        ),
    }


@tool(
    name="mycelium_test_race",
    description=(
        "Test race conditions on Mycelium channel join. Creates a channel "
        "and fires concurrent join attempts to check if multiple devices "
        "can join simultaneously or if segment data can be intercepted."
    ),
)
def mycelium_test_race(
    target: str,
    concurrent_joins: int = 5,
    channel_type: str = "u",
    api_path: str = "/api/v2/mycelium",
) -> dict:
    """Test race conditions on Mycelium channel join.

    Args:
        target: Base URL.
        concurrent_joins: Number of concurrent join attempts.
        channel_type: Channel type.
        api_path: API base path.

    Returns:
        Dict with race condition analysis.
    """
    import concurrent.futures

    if concurrent_joins > 20:
        concurrent_joins = 20

    total = concurrent_joins + 3
    if not interrupt(f"About to send ~{total} concurrent requests to {target} for race testing"):
        return {"error": "User declined race test."}

    url = f"{target.rstrip('/')}{api_path}/{channel_type}"
    status, _, body, _ = _http_request(url, "POST", b"{}", {"OP-User-Agent": _DEFAULT_OP_UA})
    if status == 0:
        return {"error": f"Failed to create channel: {body}"}

    try:
        ch_data = json.loads(body)
        channel_uuid = ch_data.get("channelUuid", "")
        initiator_auth = ch_data.get("initiatorAuth", "")
    except (json.JSONDecodeError, TypeError):
        return {"error": f"Invalid channel response: {body[:500]}"}

    put_url = f"{target.rstrip('/')}{api_path}/{channel_type}/{channel_uuid}/1"
    _http_request(
        put_url, "PUT", b'{"hello": "initiator"}',
        {"OP-User-Agent": _DEFAULT_OP_UA, "ChannelAuth": initiator_auth},
    )

    def _attempt_join(attempt_id: int) -> dict:
        fake_join_auth = os.urandom(32).hex()
        join_url = f"{target.rstrip('/')}{api_path}/{channel_type}/{channel_uuid}/2"
        s, _, b, d = _http_request(
            join_url, "PUT",
            json.dumps({"join_attempt": attempt_id}).encode(),
            {"OP-User-Agent": _DEFAULT_OP_UA, "ChannelJoinAuth": fake_join_auth},
        )
        read_url = f"{target.rstrip('/')}{api_path}/{channel_type}/{channel_uuid}/1"
        rs, _, rb, rd = _http_request(
            read_url, "GET", None,
            {"OP-User-Agent": _DEFAULT_OP_UA, "ChannelJoinAuth": fake_join_auth},
        )
        return {
            "attempt_id": attempt_id,
            "write_status": s,
            "write_body": b[:200],
            "read_status": rs,
            "read_body": rb[:200],
            "total_ms": round(d + rd, 2),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_joins) as pool:
        futures = [pool.submit(_attempt_join, i) for i in range(concurrent_joins)]
        join_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    join_results.sort(key=lambda x: x["attempt_id"])

    successful_writes = [r for r in join_results if r["write_status"] in (200, 201, 204)]
    successful_reads = [r for r in join_results if r["read_status"] in (200, 201, 204)]

    findings: list[str] = []
    if len(successful_writes) > 1:
        findings.append(
            f"CRITICAL: {len(successful_writes)}/{concurrent_joins} concurrent writes "
            "succeeded — channel may accept multiple joiners."
        )
    if len(successful_reads) > 0:
        findings.append(
            f"WARNING: {len(successful_reads)}/{concurrent_joins} reads with random "
            "join auth succeeded — segment data may be readable without proper auth."
        )
    if not findings:
        findings.append("No race condition detected — all concurrent join attempts properly rejected.")

    return {
        "target": target,
        "channel_uuid": channel_uuid,
        "concurrent_joins": concurrent_joins,
        "successful_writes": len(successful_writes),
        "successful_reads": len(successful_reads),
        "join_results": join_results,
        "findings": findings,
    }


def get_mycelium_tools() -> list[Any]:
    """Return all Mycelium protocol analysis tools."""
    return [mycelium_create_channel, mycelium_probe_channel, mycelium_fuzz_auth, mycelium_test_race]
