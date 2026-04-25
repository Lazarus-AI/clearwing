"""JavaScript bundle analysis tools for web application security testing."""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import interrupt, tool

_DEFAULT_PATTERNS: dict[str, str] = {
    "hardcoded_secret": r"""(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']""",
    "flag_format": r"(?:flag|FLAG|ctf|CTF)\{[^}]+\}",
    "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    "internal_url": r"""https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/][^\s"']+""",
    "debug_code": r"\b(?:TODO|FIXME|HACK|XXX|DEBUG|TEMPORARY)\b",
    "console_log": r"console\.\s*(?:log|warn|error|debug)\s*\(",
    "eval_usage": r"\beval\s*\(",
    "innerHTML": r"\.innerHTML\s*=",
    "postMessage_star": r"""postMessage\s*\([^,]+,\s*["']\*["']\)""",
}

_API_ROUTE_PATTERNS: list[str] = [
    r"""["'](/api/v\d+/[a-zA-Z0-9/_-]+)["']""",
    r"""["'](/api/[a-zA-Z0-9/_-]+)["']""",
    r"""(?:path|route|endpoint|url)\s*[:=]\s*["'](/[a-zA-Z0-9/_-]+)["']""",
    r"""fetch\s*\(\s*["'`]([^"'`]*?/api/[^"'`]+)["'`]""",
]


def _fetch_url(url: str, timeout: int = 30) -> tuple[int, str, float]:
    """GET a URL and return (status, body, duration_ms)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 Clearwing/1.0", "Accept": "*/*"},
    )
    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body, (time.time() - start) * 1000
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body, (time.time() - start) * 1000
    except Exception as e:
        return 0, str(e), (time.time() - start) * 1000


def _extract_script_urls(html: str, base_url: str) -> list[str]:
    """Extract script src URLs from HTML."""
    urls: list[str] = []
    for match in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            from urllib.parse import urlparse

            parsed = urlparse(base_url)
            src = f"{parsed.scheme}://{parsed.netloc}{src}"
        elif not src.startswith("http"):
            src = base_url.rstrip("/") + "/" + src
        urls.append(src)
    return urls


@tool(
    name="fetch_js_bundles",
    description=(
        "Fetch a page and download all referenced JavaScript bundles. "
        "Returns bundle URLs, sizes, and content for further analysis."
    ),
)
def fetch_js_bundles(
    target: str,
    page_path: str = "/",
    max_bundles: int = 20,
    max_size_kb: int = 5000,
) -> dict:
    """Fetch all JS bundles from a page.

    Args:
        target: Base URL.
        page_path: Page path to fetch.
        max_bundles: Maximum bundles to download.
        max_size_kb: Maximum bundle size in KB.

    Returns:
        Dict with bundle URLs, sizes, and download status.
    """
    if not interrupt(f"About to fetch JS bundles from {target}{page_path}"):
        return {"error": "User declined bundle fetch."}

    page_url = f"{target.rstrip('/')}{page_path}"
    status, html, _ = _fetch_url(page_url)
    if status == 0:
        return {"error": f"Failed to fetch page: {html}"}

    script_urls = _extract_script_urls(html, target.rstrip("/"))
    if not script_urls:
        return {"error": "No script tags found on page.", "page_status": status}

    bundles: list[dict[str, Any]] = []
    total_bytes = 0

    for url in script_urls[:max_bundles]:
        s, content, ms = _fetch_url(url)
        size_kb = len(content) / 1024
        entry: dict[str, Any] = {
            "url": url,
            "filename": url.split("/")[-1].split("?")[0][:60],
            "status": s,
            "size_kb": round(size_kb, 1),
            "download_ms": round(ms, 1),
        }
        if s == 200 and size_kb <= max_size_kb:
            entry["content"] = content
            total_bytes += len(content)
        elif s == 200:
            entry["content"] = content[:50000]
            entry["truncated"] = True

        bundles.append(entry)

    return {
        "page_url": page_url,
        "page_status": status,
        "bundles_found": len(script_urls),
        "bundles_downloaded": len(bundles),
        "total_size_kb": round(total_bytes / 1024, 1),
        "bundles": bundles,
    }


@tool(
    name="search_bundle_patterns",
    description=(
        "Search downloaded JS bundles for security-relevant patterns: "
        "hardcoded secrets, API keys, debug code, flags, eval usage, "
        "and other configurable regex patterns."
    ),
)
def search_bundle_patterns(
    bundles: list[dict[str, Any]] | None = None,
    target: str = "",
    page_path: str = "/",
    patterns: dict[str, str] | None = None,
    custom_terms: list[str] | None = None,
    context_chars: int = 80,
    max_matches_per_pattern: int = 10,
) -> dict:
    """Search JS bundles for security patterns.

    Args:
        bundles: Pre-fetched bundle list (from fetch_js_bundles). Fetches if None.
        target: Base URL (required if bundles not provided).
        page_path: Page path (if fetching bundles).
        patterns: Regex patterns to search for (defaults to built-in set).
        custom_terms: Additional literal search terms.
        context_chars: Characters of context around each match.
        max_matches_per_pattern: Max matches per pattern per bundle.

    Returns:
        Dict with matches grouped by pattern and bundle.
    """
    if bundles is None:
        if not target:
            return {"error": "Either bundles or target must be provided."}
        if not interrupt(f"About to fetch and search JS bundles from {target}"):
            return {"error": "User declined bundle search."}
        page_url = f"{target.rstrip('/')}{page_path}"
        _, html, _ = _fetch_url(page_url)
        script_urls = _extract_script_urls(html, target.rstrip("/"))
        bundles = []
        for url in script_urls[:15]:
            s, content, ms = _fetch_url(url)
            if s == 200:
                bundles.append({
                    "url": url,
                    "filename": url.split("/")[-1].split("?")[0][:60],
                    "content": content,
                    "size_kb": round(len(content) / 1024, 1),
                })

    search_patterns = dict(_DEFAULT_PATTERNS)
    if patterns:
        search_patterns.update(patterns)

    if custom_terms:
        for term in custom_terms:
            search_patterns[f"custom:{term}"] = re.escape(term)

    all_matches: list[dict[str, Any]] = []
    pattern_counts: dict[str, int] = {}

    for bundle in bundles:
        content = bundle.get("content", "")
        if not content:
            continue
        filename = bundle.get("filename", bundle.get("url", "unknown"))

        for pat_name, pat_regex in search_patterns.items():
            try:
                matches = list(re.finditer(pat_regex, content, re.IGNORECASE))
            except re.error:
                continue

            count = len(matches)
            pattern_counts[pat_name] = pattern_counts.get(pat_name, 0) + count

            for m in matches[:max_matches_per_pattern]:
                start = max(0, m.start() - context_chars)
                end = min(len(content), m.end() + context_chars)
                ctx = content[start:end].replace("\n", " ").strip()

                all_matches.append({
                    "pattern": pat_name,
                    "match": m.group(0)[:200],
                    "context": ctx[:300],
                    "bundle": filename[:60],
                    "offset": m.start(),
                })

    return {
        "bundles_searched": len([b for b in bundles if b.get("content")]),
        "patterns_searched": len(search_patterns),
        "total_matches": len(all_matches),
        "pattern_counts": pattern_counts,
        "matches": all_matches,
    }


@tool(
    name="extract_api_routes",
    description=(
        "Extract API endpoint definitions from JS bundles. Finds "
        "route patterns, fetch calls, and API path constants to "
        "build a map of the application's API surface."
    ),
)
def extract_api_routes(  # noqa: C901
    bundles: list[dict[str, Any]] | None = None,
    target: str = "",
    page_path: str = "/",
    include_methods: bool = True,
) -> dict:
    """Extract API routes from JS bundles.

    Args:
        bundles: Pre-fetched bundle list. Fetches if None.
        target: Base URL (if fetching).
        page_path: Page path (if fetching).
        include_methods: Try to detect HTTP methods for each route.

    Returns:
        Dict with discovered routes, methods, and source bundles.
    """
    if bundles is None:
        if not target:
            return {"error": "Either bundles or target must be provided."}
        if not interrupt(f"About to fetch and analyze JS bundles from {target}"):
            return {"error": "User declined route extraction."}
        page_url = f"{target.rstrip('/')}{page_path}"
        _, html, _ = _fetch_url(page_url)
        script_urls = _extract_script_urls(html, target.rstrip("/"))
        bundles = []
        for url in script_urls[:15]:
            s, content, _ = _fetch_url(url)
            if s == 200:
                bundles.append({
                    "url": url,
                    "filename": url.split("/")[-1].split("?")[0][:60],
                    "content": content,
                })

    routes: dict[str, dict[str, Any]] = {}

    for bundle in bundles:
        content = bundle.get("content", "")
        if not content:
            continue
        filename = bundle.get("filename", "unknown")

        for pattern in _API_ROUTE_PATTERNS:
            for m in re.finditer(pattern, content):
                path = m.group(1) if m.lastindex else m.group(0)
                path = path.strip("\"'`")
                if not path.startswith("/"):
                    continue
                if path in routes:
                    routes[path]["sources"].add(filename)
                    continue

                methods: list[str] = []
                if include_methods:
                    ctx_start = max(0, m.start() - 200)
                    ctx_end = min(len(content), m.end() + 200)
                    ctx = content[ctx_start:ctx_end].upper()
                    for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        if method in ctx:
                            methods.append(method)

                routes[path] = {
                    "path": path,
                    "methods": methods or ["unknown"],
                    "sources": {filename},
                }

        for m in re.finditer(r"""\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]""", content, re.IGNORECASE):
            path = m.group(1).strip()
            method = content[m.start() + 1 : m.start() + 7].strip("(").upper()
            if path.startswith("/"):
                if path not in routes:
                    routes[path] = {"path": path, "methods": [method], "sources": {filename}}
                elif method not in routes[path]["methods"]:
                    routes[path]["methods"].append(method)
                    routes[path]["sources"].add(filename)

    route_list = []
    for path in sorted(routes.keys()):
        entry = routes[path]
        route_list.append({
            "path": entry["path"],
            "methods": entry["methods"],
            "sources": sorted(entry["sources"]),
        })

    api_prefixes: dict[str, int] = {}
    for r in route_list:
        parts = r["path"].split("/")
        if len(parts) >= 3:
            prefix = "/".join(parts[:3])
            api_prefixes[prefix] = api_prefixes.get(prefix, 0) + 1

    return {
        "bundles_analyzed": len([b for b in bundles if b.get("content")]),
        "routes_found": len(route_list),
        "routes": route_list,
        "api_prefixes": dict(sorted(api_prefixes.items(), key=lambda x: -x[1])),
    }


def get_bundle_tools() -> list[Any]:
    """Return all JS bundle analysis tools."""
    return [fetch_js_bundles, search_bundle_patterns, extract_api_routes]
