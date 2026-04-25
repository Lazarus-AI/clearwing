"""Session and token replay tools for authentication testing."""

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
    cookies: str = "",
    timeout: int = 30,
) -> tuple[int, dict[str, str], str, float]:
    """Send an HTTP request with optional cookies."""
    req_headers: dict[str, str] = {}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

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
        return 0, {}, str(e), (time.time() - start) * 1000

    return status, resp_headers, resp_body, (time.time() - start) * 1000


@tool(
    name="extract_session_tokens",
    description=(
        "Extract authentication tokens, cookies, and session identifiers "
        "from the proxy history. Identifies bearer tokens, session cookies, "
        "CSRF tokens, and custom auth headers."
    ),
)
def extract_session_tokens(  # noqa: C901
    url_filter: str = "",
    include_expired: bool = False,
) -> dict:
    """Extract auth tokens from captured proxy history.

    Args:
        url_filter: Only include requests matching this URL substring.
        include_expired: Include tokens from older requests.

    Returns:
        Dict with categorized tokens (bearer, cookies, headers, csrf).
    """
    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    bearer_tokens: list[dict[str, Any]] = []
    session_cookies: list[dict[str, Any]] = []
    auth_headers: list[dict[str, Any]] = []
    csrf_tokens: list[dict[str, Any]] = []

    seen_values: set[str] = set()

    for entry in _proxy_history.entries:
        entry_dict = entry if isinstance(entry, dict) else (entry.__dict__ if hasattr(entry, "__dict__") else {})
        url = entry_dict.get("url", "")
        if url_filter and url_filter not in url:
            continue

        req_headers = entry_dict.get("request_headers", {})
        resp_headers = entry_dict.get("response_headers", {})
        req_id = entry_dict.get("id", 0)

        for hdr_name, hdr_value in req_headers.items():
            lower_name = hdr_name.lower()
            if lower_name == "authorization" and hdr_value not in seen_values:
                seen_values.add(hdr_value)
                token_type = "bearer" if hdr_value.lower().startswith("bearer ") else "other"
                bearer_tokens.append({
                    "type": token_type,
                    "value": hdr_value[:200],
                    "request_id": req_id,
                    "url": url,
                })
            elif lower_name == "cookie":
                for cookie_pair in hdr_value.split(";"):
                    cookie_pair = cookie_pair.strip()
                    if "=" in cookie_pair:
                        name, _, val = cookie_pair.partition("=")
                        key = f"{name.strip()}={val.strip()[:50]}"
                        if key not in seen_values:
                            seen_values.add(key)
                            session_cookies.append({
                                "name": name.strip(),
                                "value": val.strip()[:200],
                                "request_id": req_id,
                                "url": url,
                            })
            elif lower_name in (
                "x-csrf-token", "x-xsrf-token", "csrf-token",
                "x-request-id", "x-session-id",
            ):
                if hdr_value not in seen_values:
                    seen_values.add(hdr_value)
                    csrf_tokens.append({
                        "header": hdr_name,
                        "value": hdr_value[:200],
                        "request_id": req_id,
                        "url": url,
                    })
            elif lower_name.startswith("x-") and ("auth" in lower_name or "token" in lower_name or "session" in lower_name):
                if hdr_value not in seen_values:
                    seen_values.add(hdr_value)
                    auth_headers.append({
                        "header": hdr_name,
                        "value": hdr_value[:200],
                        "request_id": req_id,
                        "url": url,
                    })

        for hdr_name, hdr_value in resp_headers.items():
            lower_name = hdr_name.lower()
            if lower_name == "set-cookie":
                for cookie_pair in hdr_value.split(","):
                    parts = cookie_pair.strip().split(";")
                    if parts and "=" in parts[0]:
                        name, _, val = parts[0].partition("=")
                        key = f"resp:{name.strip()}={val.strip()[:50]}"
                        if key not in seen_values:
                            seen_values.add(key)
                            flags = [p.strip().lower() for p in parts[1:]]
                            session_cookies.append({
                                "name": name.strip(),
                                "value": val.strip()[:200],
                                "source": "set-cookie",
                                "httponly": any("httponly" in f for f in flags),
                                "secure": any("secure" in f for f in flags),
                                "samesite": next((f.split("=")[-1] for f in flags if "samesite" in f), ""),
                                "request_id": req_id,
                                "url": url,
                            })

    return {
        "bearer_tokens": bearer_tokens,
        "session_cookies": session_cookies,
        "auth_headers": auth_headers,
        "csrf_tokens": csrf_tokens,
        "total_tokens": len(bearer_tokens) + len(session_cookies) + len(auth_headers) + len(csrf_tokens),
    }


@tool(
    name="replay_with_mutations",
    description=(
        "Replay an authentication token against a target URL with various "
        "mutations: truncated, base64-flipped, expired timestamp, "
        "cross-account swap, and nonce reuse."
    ),
)
def replay_with_mutations(
    target_url: str,
    token: str,
    token_header: str = "Authorization",  # noqa: S107
    token_prefix: str = "Bearer ",  # noqa: S107
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
) -> dict:
    """Replay a token with various mutations to test validation.

    Args:
        target_url: URL to send requests to.
        token: The original token value (without prefix).
        token_header: Header name to carry the token.
        token_prefix: Prefix before the token value (e.g. "Bearer ").
        method: HTTP method.
        extra_headers: Additional headers to include.

    Returns:
        Dict with per-mutation results and findings.
    """
    mutations: list[tuple[str, str]] = [
        ("original", token),
        ("empty", ""),
        ("truncated_half", token[: len(token) // 2]),
        ("truncated_1char", token[:-1]),
        ("extended", token + "A"),
        ("null_byte", token + "\x00"),
        ("reversed", token[::-1]),
        ("uppercased", token.upper()),
        ("lowercased", token.lower()),
    ]

    if len(token) > 10:
        flipped = list(token)
        mid = len(flipped) // 2
        flipped[mid] = chr((ord(flipped[mid]) + 1) % 128)
        mutations.append(("bit_flip_middle", "".join(flipped)))

    mutations.append(("random_same_length", os.urandom(len(token) // 2).hex()[:len(token)]))

    total = len(mutations)
    if not interrupt(f"About to send {total} token mutation requests to {target_url}"):
        return {"error": "User declined token replay."}

    results: list[dict[str, Any]] = []
    baseline_status: int | None = None

    for label, mutated_token in mutations:
        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)
        if mutated_token:
            headers[token_header] = f"{token_prefix}{mutated_token}"

        status, resp_headers, resp_body, duration = _http_request(
            target_url, method, None, headers
        )

        if label == "original":
            baseline_status = status

        entry: dict[str, Any] = {
            "mutation": label,
            "status": status,
            "response_preview": resp_body[:300],
            "duration_ms": round(duration, 2),
            "matches_baseline": status == baseline_status,
        }
        results.append(entry)

    findings: list[str] = []
    for r in results:
        if r["mutation"] != "original" and r["status"] == baseline_status and baseline_status in (200, 201):
            findings.append(
                f"WARNING: Mutation '{r['mutation']}' returned same success status "
                f"({r['status']}) as original — token validation may be weak."
            )

    if not findings:
        findings.append("All mutations properly rejected or returned different status than original.")

    return {
        "target_url": target_url,
        "token_header": token_header,
        "baseline_status": baseline_status,
        "mutations_tested": len(mutations),
        "results": results,
        "findings": findings,
    }


@tool(
    name="test_session_fixation",
    description=(
        "Test whether pre-authentication session identifiers persist "
        "after authentication. Captures session tokens before and after "
        "a login attempt to detect session fixation vulnerabilities."
    ),
)
def test_session_fixation(  # noqa: C901
    target: str,
    pre_auth_path: str = "/",
    login_path: str = "/api/v1/auth",
    post_auth_path: str = "/api/v1/account",
    username: str = "",
) -> dict:
    """Test for session fixation by comparing pre/post-auth tokens.

    Args:
        target: Base URL.
        pre_auth_path: Path to visit before auth (to get initial session).
        login_path: Auth endpoint path.
        post_auth_path: Path to visit after auth attempt.
        username: Username for the login attempt.

    Returns:
        Dict with session token comparison and fixation analysis.
    """
    if not interrupt(f"About to test session fixation on {target}"):
        return {"error": "User declined session fixation test."}

    base = target.rstrip("/")

    pre_status, pre_headers, pre_body, _ = _http_request(f"{base}{pre_auth_path}")
    pre_cookies: dict[str, str] = {}
    set_cookie = pre_headers.get("Set-Cookie", pre_headers.get("set-cookie", ""))
    if set_cookie:
        for part in set_cookie.split(","):
            kv = part.strip().split(";")[0]
            if "=" in kv:
                name, _, val = kv.partition("=")
                pre_cookies[name.strip()] = val.strip()

    cookie_string = "; ".join(f"{k}={v}" for k, v in pre_cookies.items())

    login_payload = json.dumps({"email": username or "test@example.com"}).encode()
    login_status, login_headers, login_body, _ = _http_request(
        f"{base}{login_path}", "POST", login_payload,
        {"Content-Type": "application/json"},
        cookies=cookie_string,
    )

    post_cookies: dict[str, str] = dict(pre_cookies)
    login_set_cookie = login_headers.get("Set-Cookie", login_headers.get("set-cookie", ""))
    if login_set_cookie:
        for part in login_set_cookie.split(","):
            kv = part.strip().split(";")[0]
            if "=" in kv:
                name, _, val = kv.partition("=")
                post_cookies[name.strip()] = val.strip()

    unchanged_cookies: list[str] = []
    changed_cookies: list[str] = []
    new_cookies: list[str] = []

    for name in set(list(pre_cookies.keys()) + list(post_cookies.keys())):
        if name in pre_cookies and name in post_cookies:
            if pre_cookies[name] == post_cookies[name]:
                unchanged_cookies.append(name)
            else:
                changed_cookies.append(name)
        elif name in post_cookies:
            new_cookies.append(name)

    session_like = [
        n for n in unchanged_cookies
        if any(kw in n.lower() for kw in ("session", "sid", "token", "auth", "id"))
    ]

    fixation_risk = len(session_like) > 0

    findings: list[str] = []
    if fixation_risk:
        findings.append(
            f"POTENTIAL SESSION FIXATION: Session-like cookies unchanged after auth: "
            f"{', '.join(session_like)}"
        )
    if changed_cookies:
        findings.append(f"Cookies regenerated after auth: {', '.join(changed_cookies)}")
    if new_cookies:
        findings.append(f"New cookies set after auth: {', '.join(new_cookies)}")
    if not findings:
        findings.append("No session cookies detected in pre-auth response.")

    return {
        "target": target,
        "pre_auth_cookies": list(pre_cookies.keys()),
        "post_auth_cookies": list(post_cookies.keys()),
        "unchanged_cookies": unchanged_cookies,
        "changed_cookies": changed_cookies,
        "new_cookies": new_cookies,
        "fixation_risk": fixation_risk,
        "session_like_unchanged": session_like,
        "login_status": login_status,
        "findings": findings,
    }


def get_session_tools() -> list[Any]:
    """Return all session replay tools."""
    return [extract_session_tokens, replay_with_mutations, test_session_fixation]
