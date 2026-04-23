"""MITM Proxy — Playwright route-based traffic interception and injection."""

from __future__ import annotations

import fnmatch
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from clearwing.agent.tooling import interrupt, tool


@dataclass
class InterceptRule:
    """Controls which intercepted requests get their bodies logged."""

    id: int
    url_pattern: str
    methods: list[str] = field(default_factory=list)
    log_request_body: bool = True
    log_response_body: bool = True
    enabled: bool = True


_intercept_rules: dict[int, InterceptRule] = {}
_next_rule_id: int = 1
_intercepted_tabs: set[str] = set()
_mitm_request_ids: list[int] = []
_inject_rules: dict[str, dict] = {}
_route_handlers: dict[str, Any] = {}
_lock = threading.Lock()

_TEXT_CONTENT_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
    "application/xhtml",
)


def _is_text_content(content_type: str | None) -> bool:
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct.startswith(_TEXT_CONTENT_PREFIXES)


def _extract_path(url: str) -> str:
    try:
        return urlparse(url).path or url
    except Exception:
        return url


def _matches_rule(url: str, method: str) -> InterceptRule | None:
    path = _extract_path(url)
    for rule in _intercept_rules.values():
        if not rule.enabled:
            continue
        if rule.methods and method.upper() not in rule.methods:
            continue
        if fnmatch.fnmatch(url, rule.url_pattern) or fnmatch.fnmatch(path, rule.url_pattern):
            return rule
    return None


def _matches_inject(url: str) -> dict | None:
    path = _extract_path(url)
    for pattern, inject_def in _inject_rules.items():
        if fnmatch.fnmatch(url, pattern) or fnmatch.fnmatch(path, pattern):
            return inject_def
    return None


@tool(
    name="mitm_start",
    description="Enable MITM interception on a browser tab. All HTTP traffic through the tab will be logged to proxy history for inspection.",
)
def mitm_start(tab_name: str = "default", url_pattern: str = "**/*") -> dict:
    """Start intercepting traffic on a browser tab.

    Args:
        tab_name: Browser tab to intercept.
        url_pattern: Glob pattern for which URLs to intercept.

    Returns:
        Dict with interception status.
    """
    global _next_rule_id  # noqa: PLW0603

    with _lock:
        if tab_name in _intercepted_tabs:
            return {"error": f"Tab '{tab_name}' is already being intercepted. Call mitm_stop first."}

    from clearwing.agent.tools.recon.browser_tools import _get_page
    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    page = _get_page(tab_name)

    def _route_handler(route: Any) -> None:
        request = route.request
        req_method = request.method
        req_url = request.url
        req_headers = dict(request.headers) if request.headers else {}
        req_body = ""
        try:
            req_body = request.post_data or ""
        except Exception:
            pass

        inject_def = _matches_inject(req_url)
        if inject_def is not None:
            start_ns = time.perf_counter_ns()
            route.fulfill(
                status=inject_def.get("status", 200),
                headers=inject_def.get("headers", {}),
                body=inject_def.get("body", ""),
            )
            elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000

            entry = _proxy_history.add(
                method=req_method,
                url=req_url,
                request_headers=req_headers,
                request_body=req_body,
                status_code=inject_def.get("status", 200),
                response_headers=inject_def.get("headers", {}),
                response_body=f"[INJECTED] {inject_def.get('body', '')}"[:10000],
                duration_ms=elapsed_ms,
            )
            with _lock:
                _mitm_request_ids.append(entry.id)
            return

        start_ns = time.perf_counter_ns()
        try:
            response = route.fetch()
        except Exception as exc:
            _proxy_history.add(
                method=req_method,
                url=req_url,
                request_headers=req_headers,
                request_body=req_body,
                status_code=0,
                response_body=f"[FETCH ERROR] {exc}",
            )
            route.abort()
            return

        elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000

        resp_headers = dict(response.headers) if response.headers else {}
        content_type = resp_headers.get("content-type", "")

        rule = _matches_rule(req_url, req_method)
        log_req_body = rule.log_request_body if rule else True
        log_resp_body = rule.log_response_body if rule else True

        resp_body = ""
        if log_resp_body:
            if _is_text_content(content_type):
                try:
                    resp_body = response.text()
                except Exception:
                    resp_body = "[DECODE ERROR]"
            else:
                resp_body = f"[BINARY {content_type}]"

        entry = _proxy_history.add(
            method=req_method,
            url=req_url,
            request_headers=req_headers,
            request_body=req_body if log_req_body else "",
            status_code=response.status,
            response_headers=resp_headers,
            response_body=resp_body,
            duration_ms=elapsed_ms,
        )
        with _lock:
            _mitm_request_ids.append(entry.id)

        route.fulfill(response=response)

    page.route(url_pattern, _route_handler)

    with _lock:
        _intercepted_tabs.add(tab_name)
        _route_handlers[tab_name] = _route_handler

    return {
        "status": "intercepting",
        "tab_name": tab_name,
        "url_pattern": url_pattern,
        "active_rules": len(_intercept_rules),
        "inject_rules": len(_inject_rules),
        "message": "MITM interception active. All matching traffic will be logged to proxy history.",
    }


@tool(
    name="mitm_stop",
    description="Disable MITM interception on a browser tab.",
)
def mitm_stop(tab_name: str = "default") -> dict:
    """Stop intercepting traffic on a browser tab.

    Args:
        tab_name: Browser tab to stop intercepting.

    Returns:
        Dict with status and captured request count.
    """
    with _lock:
        if tab_name not in _intercepted_tabs:
            return {"error": f"Tab '{tab_name}' is not being intercepted."}
        handler = _route_handlers.get(tab_name)

    from clearwing.agent.tools.recon.browser_tools import _get_page

    page = _get_page(tab_name)

    try:
        page.unroute("**/*", handler)
    except Exception:
        try:
            page.unroute("**/*")
        except Exception:
            pass

    with _lock:
        _intercepted_tabs.discard(tab_name)
        _route_handlers.pop(tab_name, None)
        captured_count = len(_mitm_request_ids)

    return {
        "status": "stopped",
        "tab_name": tab_name,
        "total_captured_requests": captured_count,
    }


@tool(
    name="mitm_set_intercept_rule",
    description="Add a rule controlling which intercepted requests get their bodies logged. Without rules, all traffic is logged.",
)
def mitm_set_intercept_rule(
    url_pattern: str,
    methods: str = "",
    log_request_body: bool = True,
    log_response_body: bool = True,
    enabled: bool = True,
) -> dict:
    """Add or update an intercept rule.

    Args:
        url_pattern: fnmatch glob pattern (e.g. "*/api/v1/auth*").
        methods: Comma-separated HTTP methods to match (empty = all).
        log_request_body: Whether to log request bodies for matching requests.
        log_response_body: Whether to log response bodies for matching requests.
        enabled: Whether the rule is active.

    Returns:
        Dict with the created rule.
    """
    global _next_rule_id  # noqa: PLW0603

    method_list = [m.strip().upper() for m in methods.split(",") if m.strip()] if methods else []

    with _lock:
        rule = InterceptRule(
            id=_next_rule_id,
            url_pattern=url_pattern,
            methods=method_list,
            log_request_body=log_request_body,
            log_response_body=log_response_body,
            enabled=enabled,
        )
        _intercept_rules[_next_rule_id] = rule
        _next_rule_id += 1

    return {"status": "rule_added", "rule": asdict(rule)}


@tool(
    name="mitm_get_decrypted_traffic",
    description="Retrieve MITM-captured traffic from proxy history, filtered by URL pattern or method.",
)
def mitm_get_decrypted_traffic(
    url_contains: str = "",
    method: str = "",
    limit: int = 50,
) -> dict:
    """Get captured MITM traffic.

    Args:
        url_contains: Filter to URLs containing this string.
        method: Filter to this HTTP method.
        limit: Maximum number of entries to return.

    Returns:
        Dict with captured traffic entries and count.
    """
    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    with _lock:
        mitm_ids = set(_mitm_request_ids)

    all_entries = _proxy_history.get_all(limit=10000)
    entries = [e for e in all_entries if e.id in mitm_ids]

    if url_contains:
        entries = [e for e in entries if url_contains.lower() in e.url.lower()]
    if method:
        entries = [e for e in entries if e.method.upper() == method.upper()]

    entries = entries[-limit:]

    return {
        "count": len(entries),
        "total_mitm_captured": len(mitm_ids),
        "entries": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "method": e.method,
                "url": e.url,
                "status_code": e.status_code,
                "duration_ms": e.duration_ms,
                "request_body_length": len(e.request_body),
                "response_body_snippet": e.response_body[:500],
            }
            for e in entries
        ],
    }


@tool(
    name="mitm_inject_response",
    description="Set up a response injection rule. Matching requests will receive the injected response instead of the real server response. Requires human approval.",
)
def mitm_inject_response(
    url_pattern: str,
    status: int = 200,
    headers: dict | None = None,
    body: str = "",
    remove: bool = False,
) -> dict:
    """Add or remove a response injection rule.

    Args:
        url_pattern: fnmatch glob pattern for URLs to inject.
        status: HTTP status code for the injected response.
        headers: Response headers for the injected response.
        body: Response body for the injected response.
        remove: If True, remove the injection rule for this pattern.

    Returns:
        Dict confirming the rule was set or removed.
    """
    interrupt(
        f"MITM response injection requested for pattern '{url_pattern}'. "
        f"This will modify live traffic. Approve?"
    )

    if remove:
        removed = _inject_rules.pop(url_pattern, None)
        return {
            "status": "removed" if removed else "not_found",
            "url_pattern": url_pattern,
        }

    _inject_rules[url_pattern] = {
        "status": status,
        "headers": headers or {},
        "body": body,
    }

    return {
        "status": "inject_rule_set",
        "url_pattern": url_pattern,
        "response_status": status,
        "response_body_length": len(body),
        "active_inject_rules": len(_inject_rules),
    }


def get_mitm_tools() -> list[Any]:
    """Return all MITM proxy tools."""
    return [mitm_start, mitm_stop, mitm_set_intercept_rule, mitm_get_decrypted_traffic, mitm_inject_response]
