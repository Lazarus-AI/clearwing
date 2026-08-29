"""External attack-surface discovery tools (passive-first, host-safe).

These populate the *front half* of an engagement that Clearwing otherwise
lacked: given a root domain, find the subdomains, hosts, URLs, and technologies
that make up its attack surface. Everything here is read-only reconnaissance:

- **Passive** sources (certificate transparency via crt.sh, the Wayback Machine,
  and optional Shodan/Censys/GitHub when keys are configured) query public
  third-party archives *about* the target — host-safe, exactly like Clearwing's
  existing NVD/CVE lookups. No `interrupt()` gate is needed.
- **Light active** probing (DNS resolution, HTTP liveness) touches the target
  read-only, matching the existing `proxy_request` / `scan_ports` behavior.

Heavy active enumeration (amass brute force, masscan) is intentionally *not*
here — that belongs in the Kali container (`kali_execute`).

Each tool wraps a plain helper function (e.g. `crtsh_subdomains`) so the ASM
orchestrator and tests can call the logic directly, and so the HTTP fetch is a
single monkeypatchable seam.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

from clearwing.agent.tooling import tool

logger = logging.getLogger(__name__)

_USER_AGENT = "clearwing-asm/0.5 (+https://github.com/Lazarus-AI/clearwing)"
_HTTP_TIMEOUT = 20
_MAX_BYTES = 8_000_000


# --- HTTP seam (monkeypatched in tests) -------------------------------------


def _http_get(url: str, *, timeout: int = _HTTP_TIMEOUT, accept: str = "*/*") -> str:
    """GET *url* and return the (size-capped) body text, or "" on any failure."""
    request = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, "Accept": accept}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read(_MAX_BYTES).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.debug("HTTP GET failed for %s: %s", url, exc)
        return ""


def _http_get_json(url: str, *, timeout: int = _HTTP_TIMEOUT) -> object:
    body = _http_get(url, timeout=timeout, accept="application/json")
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


# --- Passive discovery helpers ----------------------------------------------


def _clean_name(name: str) -> str:
    return name.strip().lower().lstrip("*.").rstrip(".")


def crtsh_subdomains(domain: str) -> list[str]:
    """Subdomains of *domain* from certificate-transparency logs (crt.sh)."""
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    data = _http_get_json(url)
    names: set[str] = set()
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            for raw in str(row.get("name_value", "")).splitlines():
                candidate = _clean_name(raw)
                if candidate == domain or candidate.endswith("." + domain):
                    names.add(candidate)
    return sorted(names)


def crtsh_certs(domain: str) -> list[dict]:
    """Recent certificate records for *domain* (issuer + names + validity)."""
    url = "https://crt.sh/?q=" + urllib.parse.quote(domain) + "&output=json"
    data = _http_get_json(url)
    certs: list[dict] = []
    if isinstance(data, list):
        for row in data[:200]:
            if not isinstance(row, dict):
                continue
            certs.append(
                {
                    "issuer": row.get("issuer_name", ""),
                    "common_name": row.get("common_name", ""),
                    "names": [_clean_name(n) for n in str(row.get("name_value", "")).splitlines()],
                    "not_before": row.get("not_before", ""),
                    "not_after": row.get("not_after", ""),
                }
            )
    return certs


def wayback_urls(domain: str, limit: int = 5000) -> list[str]:
    """Historical URLs for *domain* from the Wayback Machine CDX API."""
    url = (
        "https://web.archive.org/cdx/search/cdx?url="
        + urllib.parse.quote(domain)
        + "/*&output=json&fl=original&collapse=urlkey&limit="
        + str(int(limit))
    )
    data = _http_get_json(url)
    urls: list[str] = []
    if isinstance(data, list) and data:
        # First row is the header (["original"]); the rest are single-item rows.
        for row in data[1:]:
            if isinstance(row, list) and row:
                urls.append(str(row[0]))
    return sorted(set(urls))


def github_subdomains(domain: str, env_var: str = "GITHUB_API_KEY") -> list[str]:
    """Subdomains mined from public GitHub code search (needs a GitHub token)."""
    import re

    token = os.environ.get(env_var, "")
    if not token:
        return []
    query = urllib.parse.quote(f'"{domain}"')
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:  # noqa: S310
            payload = json.loads(response.read(_MAX_BYTES).decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return []
    pattern = re.compile(r"(?:[a-z0-9_-]+\.)+" + re.escape(domain), re.IGNORECASE)
    names = {_clean_name(m.group(0)) for m in pattern.finditer(json.dumps(payload))}
    return sorted(names)


# --- Light active helpers ---------------------------------------------------


def resolve_name(name: str) -> list[str]:
    """Resolve *name* to its IPv4/IPv6 addresses (empty on failure)."""
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos})


def probe_url(url: str, *, timeout: int = 10) -> dict:
    """HTTP(S) liveness probe: status, server, and a light tech fingerprint."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(65536).decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        body = ""
        status = exc.code
    except (urllib.error.URLError, OSError, ValueError):
        return {"url": url, "live": False}
    return {
        "url": url,
        "live": True,
        "status": status,
        "server": headers.get("server", ""),
        "technologies": _fingerprint(headers, body),
    }


_TECH_HEADER_MARKERS = {
    "x-powered-by": None,
    "server": None,
    "x-generator": None,
    "x-aspnet-version": "ASP.NET",
}
_TECH_BODY_MARKERS = {
    "wp-content": "WordPress",
    "/_next/": "Next.js",
    "csrfmiddlewaretoken": "Django",
    "drupal-settings-json": "Drupal",
    "__NUXT__": "Nuxt.js",
}


def _fingerprint(headers: dict[str, str], body: str) -> list[str]:
    techs: set[str] = set()
    for header, label in _TECH_HEADER_MARKERS.items():
        value = headers.get(header, "")
        if value:
            techs.add(label or value.split("/")[0].strip())
    for marker, label in _TECH_BODY_MARKERS.items():
        if marker in body:
            techs.add(label)
    return sorted(t for t in techs if t)


# --- Agent tools ------------------------------------------------------------


@tool
def discover_subdomains(domain: str) -> dict:
    """Enumerate subdomains of a root domain from passive sources.

    Queries certificate-transparency logs (crt.sh) and, when the corresponding
    API keys are configured in the environment, GitHub code search. Read-only:
    it queries public archives, never the target directly.

    Args:
        domain: The root domain, e.g. "example.com".

    Returns:
        {"domain": str, "subdomains": [str], "count": int, "sources": [str]}.
    """
    sources = ["crt.sh"]
    names = set(crtsh_subdomains(domain))
    gh = github_subdomains(domain)
    if gh:
        sources.append("github")
        names.update(gh)
    return {
        "domain": domain,
        "subdomains": sorted(names),
        "count": len(names),
        "sources": sources,
    }


@tool
def lookup_cert_transparency(domain: str) -> dict:
    """Fetch certificate-transparency records for a domain (issuers, names, validity)."""
    certs = crtsh_certs(domain)
    return {"domain": domain, "certificates": certs, "count": len(certs)}


@tool
def discover_wayback_urls(domain: str, limit: int = 5000) -> dict:
    """Discover historical URLs for a domain via the Wayback Machine (passive)."""
    urls = wayback_urls(domain, limit=limit)
    return {"domain": domain, "urls": urls, "count": len(urls)}


@tool
def resolve_hosts(names: list[str]) -> dict:
    """Resolve a list of hostnames to IP addresses via DNS.

    Args:
        names: Hostnames to resolve.

    Returns:
        {"resolved": {name: [ip]}, "unresolved": [name]}.
    """
    resolved: dict[str, list[str]] = {}
    unresolved: list[str] = []
    for name in names:
        ips = resolve_name(name)
        if ips:
            resolved[name] = ips
        else:
            unresolved.append(name)
    return {"resolved": resolved, "unresolved": unresolved}


@tool
def probe_liveness(hosts: list[str]) -> dict:
    """Probe hosts/URLs for HTTP(S) liveness and light technology fingerprints.

    Each entry may be a bare host (both https:// and http:// are tried) or a
    full URL. Read-only GET requests only.

    Returns:
        {"live": [ {url, status, server, technologies} ], "dead": [str]}.
    """
    live: list[dict] = []
    dead: list[str] = []
    for host in hosts:
        candidates = [host] if "://" in host else [f"https://{host}", f"http://{host}"]
        hit = None
        for candidate in candidates:
            result = probe_url(candidate)
            if result.get("live"):
                hit = result
                break
        if hit is not None:
            live.append(hit)
        else:
            dead.append(host)
    return {"live": live, "dead": dead}


@tool
def screenshot_surface(urls: list[str], out_dir: str = "/tmp/asm-screenshots") -> dict:
    """Screenshot each URL and write an HTML thumbnail gallery for triage.

    Loops the Playwright browser tools over the URLs (one shared browser) and
    writes `<out_dir>/gallery.html` linking every capture — fast visual triage
    of a discovered surface.
    """
    from pathlib import Path

    from clearwing.agent.tools.recon.browser_tools import browser_navigate, browser_screenshot

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    shots: list[dict] = []
    for index, url in enumerate(urls):
        path = str(out / f"shot-{index:03d}.png")
        nav = browser_navigate(url)
        if nav.get("status") == "error":
            shots.append({"url": url, "ok": False, "error": nav.get("error", "navigation failed")})
            continue
        shot = browser_screenshot(path=path)
        shots.append({"url": url, "ok": bool(shot.get("success")), "path": path, "title": nav.get("title", "")})
    gallery = out / "gallery.html"
    gallery.write_text(_render_gallery(shots), encoding="utf-8")
    return {"gallery": str(gallery), "screenshots": shots, "count": len(shots)}


def _render_gallery(shots: list[dict]) -> str:
    import html as _html
    from pathlib import Path

    cards = []
    for shot in shots:
        if shot.get("ok"):
            img = f'<img src="{_html.escape(Path(shot["path"]).name)}" loading="lazy">'
        else:
            img = f'<div class="err">{_html.escape(str(shot.get("error", "no capture")))}</div>'
        title = _html.escape(shot.get("title") or shot["url"])
        link = _html.escape(shot["url"])
        cards.append(
            f'<figure>{img}<figcaption>{title}<br><a href="{link}">{link}</a></figcaption></figure>'
        )
    return (
        "<!doctype html><meta charset=utf-8><title>ASM surface gallery</title>"
        "<style>body{font-family:sans-serif;background:#111;color:#eee}"
        "figure{display:inline-block;width:320px;margin:8px;vertical-align:top}"
        "img{width:320px;border:1px solid #333}.err{height:180px;display:flex;"
        "align-items:center;justify-content:center;background:#222;color:#a44}"
        "figcaption{font-size:12px;word-break:break-all}a{color:#6af}</style>"
        "<h1>Attack surface</h1>" + "".join(cards)
    )


def get_discovery_tools() -> list:
    """Return the external-discovery agent tools."""
    return [
        discover_subdomains,
        lookup_cert_transparency,
        discover_wayback_urls,
        resolve_hosts,
        probe_liveness,
        screenshot_surface,
    ]
