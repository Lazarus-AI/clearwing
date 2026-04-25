"""Recovery code analysis tools for 1Password account recovery testing."""

from __future__ import annotations

import json
import math
import os
import time
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import interrupt, tool

_RECOVERY_PREFIX = "1PRK"
_RECOVERY_CHARSET = "0123456789ABCDEFGHJKLMNPQRSTVWXYZ"
_RECOVERY_CHARSET_BITS = math.log2(len(_RECOVERY_CHARSET))
_RECOVERY_RANDOM_CHARS = 52
_RECOVERY_TOTAL_ENTROPY = _RECOVERY_RANDOM_CHARS * _RECOVERY_CHARSET_BITS
_RECOVERY_SEGMENT_LEN = 6
_RECOVERY_SEGMENTS = 9


def _generate_one_code() -> str:
    """Generate a single recovery code in 1PRK format."""
    chars = []
    for _ in range(_RECOVERY_RANDOM_CHARS):
        chars.append(_RECOVERY_CHARSET[int.from_bytes(os.urandom(1)) % len(_RECOVERY_CHARSET)])
    raw = "".join(chars)
    segments = [raw[i : i + _RECOVERY_SEGMENT_LEN] for i in range(0, len(raw), _RECOVERY_SEGMENT_LEN)]
    while len(segments) < _RECOVERY_SEGMENTS:
        extra = "".join(
            _RECOVERY_CHARSET[int.from_bytes(os.urandom(1)) % len(_RECOVERY_CHARSET)]
            for _ in range(_RECOVERY_SEGMENT_LEN)
        )
        segments.append(extra)
    return _RECOVERY_PREFIX + "-" + "-".join(segments[:_RECOVERY_SEGMENTS])


def _http_post(
    url: str, payload: dict, headers: dict[str, str] | None = None, timeout: int = 30
) -> tuple[int, str, float]:
    """POST JSON and return (status, body, duration_ms)."""
    data = json.dumps(payload).encode()
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e), (time.time() - start) * 1000
    return status, body, (time.time() - start) * 1000


@tool(
    name="generate_recovery_codes",
    description=(
        "Generate valid-format 1Password recovery codes (1PRK prefix + "
        "52 base-32 characters). Useful for testing server-side validation."
    ),
)
def generate_recovery_codes(
    count: int = 10,
    prefix: str = "1PRK",
) -> dict:
    """Generate recovery codes in 1Password format.

    Args:
        count: Number of codes to generate (max 100).
        prefix: Recovery code prefix (default "1PRK").

    Returns:
        Dict with generated codes, format spec, and entropy analysis.
    """
    if count > 100:
        count = 100

    codes = [_generate_one_code() for _ in range(count)]

    return {
        "codes": codes,
        "count": len(codes),
        "format": {
            "prefix": prefix,
            "pattern": f"{prefix}-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXX",
            "charset": _RECOVERY_CHARSET,
            "charset_size": len(_RECOVERY_CHARSET),
            "random_chars": _RECOVERY_RANDOM_CHARS,
            "bits_per_char": round(_RECOVERY_CHARSET_BITS, 2),
            "total_entropy_bits": round(_RECOVERY_TOTAL_ENTROPY, 1),
        },
    }


@tool(
    name="test_recovery_acceptance",
    description=(
        "Submit generated recovery codes to server endpoints to test "
        "whether the server performs proper validation or trusts "
        "client-side format checks."
    ),
)
def test_recovery_acceptance(  # noqa: C901
    target: str,
    codes: list[str] | None = None,
    username: str = "",
    count: int = 5,
    recovery_paths: list[str] | None = None,
) -> dict:
    """Test server-side recovery code validation.

    Args:
        target: Base URL.
        codes: Pre-generated codes to test (generates if empty).
        username: Account email for recovery.
        count: Number of codes to generate if none provided.
        recovery_paths: API paths to test (defaults to common patterns).

    Returns:
        Dict with per-endpoint, per-code results and validation findings.
    """
    if recovery_paths is None:
        recovery_paths = [
            "/api/v1/auth/recover",
            "/api/v2/auth/recover",
            "/api/v1/recovery/verify",
            "/api/v2/recovery/verify",
            "/api/v1/auth/recovery-key",
            "/api/v2/auth/recovery-key",
            "/api/v1/account/recover",
            "/api/v2/account/recover",
        ]

    if codes is None:
        codes = [_generate_one_code() for _ in range(count)]

    total_requests = len(codes) * len(recovery_paths)
    if not interrupt(f"About to send {total_requests} recovery code probes to {target}"):
        return {"error": "User declined recovery code testing."}

    results: list[dict[str, Any]] = []
    endpoint_status: dict[str, list[int]] = {}
    accepted: list[dict[str, Any]] = []

    for path in recovery_paths:
        url = f"{target.rstrip('/')}{path}"
        statuses: list[int] = []

        for code in codes:
            payload: dict[str, Any] = {"recoveryCode": code, "recovery_code": code}
            if username:
                payload["email"] = username
                payload["username"] = username

            status, body, duration = _http_post(url, payload)
            statuses.append(status)

            entry: dict[str, Any] = {
                "path": path,
                "code": code[:12] + "...",
                "status": status,
                "response_preview": body[:300],
                "duration_ms": round(duration, 2),
            }
            results.append(entry)

            if status in (200, 201, 202):
                accepted.append(entry)

        endpoint_status[path] = statuses

    endpoint_summary: dict[str, str] = {}
    for path, statuses in endpoint_status.items():
        unique = set(statuses)
        if unique == {404}:
            endpoint_summary[path] = "not_found"
        elif unique == {0}:
            endpoint_summary[path] = "connection_error"
        elif any(s in (200, 201, 202) for s in statuses):
            endpoint_summary[path] = "ACCEPTS_CODES"
        elif any(s in (400, 401, 403, 422) for s in statuses):
            endpoint_summary[path] = "validates_and_rejects"
        else:
            endpoint_summary[path] = f"status_codes={sorted(unique)}"

    findings: list[str] = []
    if accepted:
        findings.append(
            f"CRITICAL: {len(accepted)} recovery code(s) accepted by server. "
            "Server may not be validating recovery codes properly."
        )
    active_endpoints = [p for p, s in endpoint_summary.items() if s not in ("not_found", "connection_error")]
    if active_endpoints:
        findings.append(f"Active recovery endpoints: {', '.join(active_endpoints)}")
    if not findings:
        findings.append("No active recovery endpoints found or all codes rejected.")

    return {
        "target": target,
        "codes_tested": len(codes),
        "endpoints_tested": len(recovery_paths),
        "endpoint_summary": endpoint_summary,
        "accepted_count": len(accepted),
        "accepted": accepted,
        "findings": findings,
        "results": results,
    }


@tool(
    name="analyze_recovery_entropy",
    description=(
        "Calculate the brute-force cost of 1Password recovery codes. "
        "Estimates time to exhaust the keyspace at various attempt rates."
    ),
)
def analyze_recovery_entropy(
    charset_size: int = 33,
    random_chars: int = 52,
    rate_limit_per_sec: float = 10.0,
    lockout_after: int = 0,
) -> dict:
    """Analyze recovery code entropy and brute-force feasibility.

    Args:
        charset_size: Size of the character set.
        random_chars: Number of random characters in the code.
        rate_limit_per_sec: Estimated server rate limit (attempts/sec).
        lockout_after: Account lockout after N failed attempts (0 = no lockout).

    Returns:
        Dict with entropy analysis and brute-force cost estimates.
    """
    bits_per_char = math.log2(charset_size) if charset_size > 1 else 0
    total_bits = random_chars * bits_per_char
    keyspace = charset_size**random_chars

    def _format_time(s: float) -> str:
        if math.isinf(s):
            return "infinite"
        years = s / (86400 * 365.25)
        if years > 1e30:
            return f"~10^{math.log10(years):.0f} years"
        if years > 1e6:
            return f"{years:.2e} years"
        if years > 1:
            return f"{years:.1f} years"
        if s > 86400:
            return f"{s / 86400:.1f} days"
        if s > 3600:
            return f"{s / 3600:.1f} hours"
        return f"{s:.1f} seconds"

    rates = {
        "online_10_per_sec": rate_limit_per_sec,
        "online_100_per_sec": 100.0,
        "online_1000_per_sec": 1000.0,
        "offline_1M_per_sec": 1_000_000.0,
        "offline_1B_per_sec": 1_000_000_000.0,
    }

    estimates: dict[str, dict[str, Any]] = {}
    for label, rate in rates.items():
        secs = keyspace / rate if rate > 0 else float("inf")
        estimates[label] = {
            "attempts_per_sec": rate,
            "time_to_exhaust": _format_time(secs),
        }

    if total_bits >= 256:
        assessment = f"Recovery code has {total_bits:.0f}-bit entropy — exceeds AES-256. Brute force is physically impossible."
    elif total_bits >= 128:
        assessment = f"Recovery code has {total_bits:.0f}-bit entropy — computationally infeasible to brute force."
    elif total_bits >= 80:
        assessment = f"Recovery code has {total_bits:.0f}-bit entropy — strong against online attacks, may be vulnerable to offline."
    else:
        assessment = f"WARNING: Recovery code has only {total_bits:.0f}-bit entropy — may be brute-forceable."

    lockout_note = ""
    if lockout_after > 0:
        lockout_note = (
            f"Account locks after {lockout_after} failed attempts. "
            f"Only {lockout_after}/{keyspace:.2e} of keyspace is searchable per lockout cycle."
        )

    return {
        "charset_size": charset_size,
        "random_chars": random_chars,
        "bits_per_char": round(bits_per_char, 2),
        "total_entropy_bits": round(total_bits, 1),
        "keyspace": f"~10^{math.log10(keyspace):.1f}" if keyspace > 1e15 else keyspace,
        "brute_force_estimates": estimates,
        "rate_limit_per_sec": rate_limit_per_sec,
        "lockout_after": lockout_after,
        "lockout_note": lockout_note,
        "assessment": assessment,
    }


def get_recovery_tools() -> list[Any]:
    """Return all recovery code analysis tools."""
    return [generate_recovery_codes, test_recovery_acceptance, analyze_recovery_entropy]
