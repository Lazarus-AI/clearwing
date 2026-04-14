"""Lightweight HTTP intercepting proxy for request/response logging and replay."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from langchain_core.tools import tool


@dataclass
class ProxyRequest:
    """A captured HTTP request/response pair."""
    id: int
    timestamp: str
    method: str
    url: str
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    duration_ms: int = 0


class ProxyHistory:
    """Thread-safe in-memory store for proxy request/response history."""

    def __init__(self):
        self._entries: list[ProxyRequest] = []
        self._lock = threading.Lock()
        self._next_id = 1

    def add(self, method: str, url: str, request_headers: dict = None,
            request_body: str = "", status_code: int = 0,
            response_headers: dict = None, response_body: str = "",
            duration_ms: int = 0) -> ProxyRequest:
        """Record a request/response pair."""
        with self._lock:
            entry = ProxyRequest(
                id=self._next_id,
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                method=method,
                url=url,
                request_headers=request_headers or {},
                request_body=request_body,
                status_code=status_code,
                response_headers=response_headers or {},
                response_body=response_body[:10000],  # truncate large bodies
                duration_ms=duration_ms,
            )
            self._entries.append(entry)
            self._next_id += 1
        return entry

    def get(self, request_id: int) -> Optional[ProxyRequest]:
        """Get a specific entry by ID."""
        with self._lock:
            for e in self._entries:
                if e.id == request_id:
                    return e
        return None

    def get_all(self, method: str = None, url_contains: str = None,
                status_code: int = None, limit: int = 50) -> list[ProxyRequest]:
        """Get entries with optional filtering."""
        with self._lock:
            results = list(self._entries)

        if method:
            results = [r for r in results if r.method.upper() == method.upper()]
        if url_contains:
            results = [r for r in results if url_contains.lower() in r.url.lower()]
        if status_code:
            results = [r for r in results if r.status_code == status_code]

        return results[-limit:]

    def clear(self):
        """Clear all history."""
        with self._lock:
            self._entries.clear()
            self._next_id = 1

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def export(self, path: str):
        """Export history to a JSON file."""
        with self._lock:
            data = [asdict(e) for e in self._entries]
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


# Module-level shared proxy state
_proxy_history = ProxyHistory()
_proxy_running = False


@tool
def proxy_request(
    method: str,
    url: str,
    headers: dict = None,
    body: str = "",
    follow_redirects: bool = True,
) -> dict:
    """Send an HTTP request through the proxy, logging the request and response.

    All requests/responses are automatically recorded in the proxy history
    for later inspection and replay.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.).
        url: Target URL.
        headers: Optional request headers dict.
        body: Optional request body string.
        follow_redirects: Whether to follow HTTP redirects (default: True).

    Returns:
        Dict with keys: request_id, status_code, response_headers, response_body, duration_ms.
    """
    import urllib.request
    import urllib.error

    req_headers = headers or {}
    start = time.time()

    try:
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8") if body else None,
            headers=req_headers,
            method=method.upper(),
        )

        # Handle redirects
        if not follow_redirects:
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(NoRedirectHandler)
        else:
            opener = urllib.request.build_opener()

        response = opener.open(req, timeout=30)
        status_code = response.status
        resp_headers = dict(response.getheaders())
        resp_body = response.read().decode("utf-8", errors="replace")

    except urllib.error.HTTPError as e:
        status_code = e.code
        resp_headers = dict(e.headers.items()) if e.headers else {}
        resp_body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        entry = _proxy_history.add(
            method=method.upper(), url=url,
            request_headers=req_headers, request_body=body,
            status_code=0, duration_ms=duration_ms,
        )
        return {
            "request_id": entry.id,
            "status_code": 0,
            "response_headers": {},
            "response_body": "",
            "duration_ms": duration_ms,
            "error": str(e),
        }

    duration_ms = int((time.time() - start) * 1000)

    entry = _proxy_history.add(
        method=method.upper(), url=url,
        request_headers=req_headers, request_body=body,
        status_code=status_code,
        response_headers=resp_headers,
        response_body=resp_body,
        duration_ms=duration_ms,
    )

    return {
        "request_id": entry.id,
        "status_code": status_code,
        "response_headers": resp_headers,
        "response_body": resp_body[:5000],  # truncate for LLM context
        "duration_ms": duration_ms,
    }


@tool
def proxy_get_history(
    method: str = None,
    url_contains: str = None,
    status_code: int = None,
    limit: int = 20,
) -> list[dict]:
    """Get proxy request/response history with optional filtering.

    Args:
        method: Filter by HTTP method (GET, POST, etc.).
        url_contains: Filter by URL substring.
        status_code: Filter by response status code.
        limit: Maximum entries to return (default: 20).

    Returns:
        List of request/response summary dicts.
    """
    entries = _proxy_history.get_all(
        method=method, url_contains=url_contains,
        status_code=status_code, limit=limit,
    )
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp,
            "method": e.method,
            "url": e.url,
            "status_code": e.status_code,
            "duration_ms": e.duration_ms,
            "request_body_length": len(e.request_body),
            "response_body_length": len(e.response_body),
        }
        for e in entries
    ]


@tool
def proxy_get_request(request_id: int) -> dict:
    """Get full details of a specific proxy request by ID.

    Args:
        request_id: The request ID from proxy history.

    Returns:
        Full request/response dict, or error if not found.
    """
    entry = _proxy_history.get(request_id)
    if entry is None:
        return {"error": f"Request {request_id} not found"}
    return asdict(entry)


@tool
def proxy_replay(
    request_id: int,
    modify_headers: dict = None,
    modify_body: str = None,
    modify_url: str = None,
) -> dict:
    """Replay a previous request with optional modifications.

    Args:
        request_id: ID of the original request to replay.
        modify_headers: Headers to add/override (merged with original).
        modify_body: New request body (replaces original).
        modify_url: New URL (replaces original).

    Returns:
        Same as proxy_request — the new request/response data.
    """
    original = _proxy_history.get(request_id)
    if original is None:
        return {"error": f"Request {request_id} not found"}

    headers = dict(original.request_headers)
    if modify_headers:
        headers.update(modify_headers)

    body = modify_body if modify_body is not None else original.request_body
    url = modify_url if modify_url is not None else original.url

    return proxy_request.invoke({
        "method": original.method,
        "url": url,
        "headers": headers,
        "body": body,
    })


@tool
def proxy_clear_history() -> dict:
    """Clear all proxy history.

    Returns:
        Confirmation dict.
    """
    count = _proxy_history.count
    _proxy_history.clear()
    return {"cleared": count, "message": f"Cleared {count} entries"}


@tool
def proxy_export_history(path: str = "/tmp/proxy_history.json") -> dict:
    """Export proxy history to a JSON file.

    Args:
        path: File path for the export.

    Returns:
        Dict with keys: success, path, entry_count.
    """
    try:
        _proxy_history.export(path)
        return {"success": True, "path": path, "entry_count": _proxy_history.count}
    except Exception as e:
        return {"success": False, "path": path, "error": str(e)}


def get_proxy_tools() -> list:
    """Return all proxy tools."""
    return [
        proxy_request,
        proxy_get_history,
        proxy_get_request,
        proxy_replay,
        proxy_clear_history,
        proxy_export_history,
    ]
