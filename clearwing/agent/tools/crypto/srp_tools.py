"""SRP-6a protocol testing tools for security analysis."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import interrupt, tool
from clearwing.crypto.srp import SRP_GROUPS, SRPClient, derive_2skd, parse_secret_key
from clearwing.crypto.stats import cohens_d, compute_stats, welch_t_test

logger = logging.getLogger(__name__)


def _http_post(url: str, payload: dict, *, log: bool = True) -> tuple[int, dict, str, float]:
    """POST JSON and return (status, headers, body, duration_ms)."""
    from clearwing.agent.tools.recon.proxy_tools import _proxy_history

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=30)  # noqa: S310
        status = resp.status
        headers = dict(resp.getheaders())
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        headers = dict(e.headers.items()) if e.headers else {}
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        duration_ms = (time.time() - start) * 1000
        if log:
            _proxy_history.add(
                method="POST",
                url=url,
                request_headers={"Content-Type": "application/json"},
                request_body=json.dumps(payload)[:10000],
                duration_ms=int(duration_ms),
            )
        return 0, {}, str(e), duration_ms

    duration_ms = (time.time() - start) * 1000
    if log:
        _proxy_history.add(
            method="POST",
            url=url,
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps(payload)[:10000],
            status_code=status,
            response_headers=headers,
            response_body=body[:10000],
            duration_ms=int(duration_ms),
        )
    return status, headers, body, duration_ms


def _timed_post(url: str, payload: dict) -> tuple[int, str, float]:
    """POST JSON with high-precision timing, no proxy logging."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    start_ns = time.perf_counter_ns()
    try:
        resp = urllib.request.urlopen(req, timeout=30)  # noqa: S310
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        elapsed_ns = time.perf_counter_ns() - start_ns
        return 0, str(e), elapsed_ns / 1_000_000
    elapsed_ns = time.perf_counter_ns() - start_ns
    return status, body, elapsed_ns / 1_000_000


@tool(
    name="srp_handshake",
    description=(
        "Execute SRP-6a authentication handshake against a target, "
        "capturing all intermediate cryptographic values."
    ),
)
def srp_handshake(
    target: str,
    username: str,
    password: str = "",
    secret_key: str = "",
    group_bits: int = 2048,
    auth_init_path: str = "/api/v1/auth",
    auth_verify_path: str = "/api/v1/auth/verify",
) -> dict:
    """Execute a complete SRP-6a handshake and return all intermediate values.

    Args:
        target: Base URL (e.g. "https://bugbounty-ctf.1password.com").
        username: Account email / identity.
        password: Account password (empty for recon-only mode).
        secret_key: 1Password Secret Key in A3-XXXXXX-... format (optional).
        group_bits: SRP group size (1024, 2048, 4096).
        auth_init_path: API path for auth initialization.
        auth_verify_path: API path for auth verification.

    Returns:
        Dict with all SRP intermediate values, server responses, and success status.
    """
    group = SRP_GROUPS.get(group_bits)
    if not group:
        return {"success": False, "error": f"Unknown SRP group: {group_bits}"}

    client = SRPClient(group)
    result: dict[str, Any] = {"target": target, "username": username, "group_bits": group_bits}

    init_url = f"{target.rstrip('/')}{auth_init_path}"
    status, _, body, ms = _http_post(init_url, {"email": username})
    result["init_response"] = {"status": status, "body": body[:5000], "duration_ms": round(ms, 2)}

    if status == 0:
        return {**result, "success": False, "error": f"Connection failed: {body}"}

    try:
        server_params = json.loads(body)
    except json.JSONDecodeError:
        return {**result, "success": False, "error": f"Non-JSON response (status {status}): {body[:500]}"}

    salt_hex = server_params.get("salt", "")
    B_hex = server_params.get("B", "")
    iterations = server_params.get("iterations", 100000)

    result["server_params"] = {
        "salt_hex": salt_hex,
        "B_hex": B_hex[:64] + ("..." if len(B_hex) > 64 else ""),
        "iterations": iterations,
        "algorithm": server_params.get("algorithm", server_params.get("alg", "unknown")),
        "raw_keys": list(server_params.keys()),
    }

    if not B_hex:
        return {**result, "success": False, "error": "Server did not return B value"}

    try:
        salt = bytes.fromhex(salt_hex)
        B = int(B_hex, 16)
    except ValueError as e:
        return {**result, "success": False, "error": f"Invalid server params: {e}"}

    a, A = client.generate_a()
    result["A_hex"] = format(A, "x")

    if not password:
        verify_url = f"{target.rstrip('/')}{auth_verify_path}"
        status2, _, body2, ms2 = _http_post(verify_url, {"A": format(A, "x"), "M1": "0" * 64})
        result["verify_response"] = {"status": status2, "body": body2[:5000], "duration_ms": round(ms2, 2)}
        return {**result, "success": False, "error": "Recon-only mode (no password)", "recon_only": True}

    if secret_key:
        sk_bytes = parse_secret_key(secret_key)
        auk, x = derive_2skd(password, salt, iterations, sk_bytes)
        result["2skd"] = {"auk_hex": auk.hex(), "x_hex": format(x, "x")}
    else:
        x = client.compute_x(salt, username, password)
        result["2skd"] = None

    u = client.compute_u(A, B)
    if u == 0:
        return {**result, "success": False, "error": "u == 0 — aborting (potential attack)"}

    S = client.compute_S(B, a, u, x)
    K = client.compute_K(S)
    M1 = client.compute_M1(username, salt, A, B, K)

    result.update({
        "u_hex": format(u, "x"),
        "S_hex": format(S, "x"),
        "K_hex": K.hex(),
        "M1_hex": M1.hex(),
    })

    verify_url = f"{target.rstrip('/')}{auth_verify_path}"
    status2, _, body2, ms2 = _http_post(verify_url, {"A": format(A, "x"), "M1": M1.hex()})
    result["verify_response"] = {"status": status2, "body": body2[:5000], "duration_ms": round(ms2, 2)}

    try:
        verify_data = json.loads(body2)
        M2_hex = verify_data.get("M2", "")
        if M2_hex:
            M2 = bytes.fromhex(M2_hex)
            verified = client.verify_M2(A, M1, K, M2)
            result["M2_hex"] = M2_hex
            result["M2_verified"] = verified
            result["success"] = verified
        else:
            result["success"] = False
            result["error"] = f"Auth rejected (status {status2})"
    except (json.JSONDecodeError, ValueError):
        result["success"] = False
        result["error"] = f"Unexpected verify response (status {status2}): {body2[:500]}"

    return result


@tool(
    name="srp_fuzz_parameters",
    description=(
        "Send malformed SRP parameters to test server-side validation "
        "(zero-key attacks, oversized values, truncated proofs)."
    ),
)
def srp_fuzz_parameters(
    target: str,
    username: str,
    test_vectors: str = "zero_key",
    auth_init_path: str = "/api/v1/auth",
    auth_verify_path: str = "/api/v1/auth/verify",
    group_bits: int = 2048,
) -> dict:
    """Send malformed SRP values to probe server validation.

    Args:
        target: Base URL.
        username: Account email.
        test_vectors: Category — "zero_key", "multiples", "malformed", or "all".
        auth_init_path: API path for auth init.
        auth_verify_path: API path for auth verify.
        group_bits: SRP group size.

    Returns:
        Dict with results per vector and any detected vulnerabilities.
    """
    group = SRP_GROUPS.get(group_bits)
    if not group:
        return {"success": False, "error": f"Unknown SRP group: {group_bits}"}

    N = group.N
    vectors: list[tuple[str, str]] = []

    if test_vectors in ("zero_key", "all"):
        vectors.append(("A=0", "0"))

    if test_vectors in ("multiples", "all"):
        vectors.extend([
            ("A=N", format(N, "x")),
            ("A=2N", format(2 * N, "x")),
            ("A=3N", format(3 * N, "x")),
        ])

    if test_vectors in ("malformed", "all"):
        vectors.extend([
            ("A=1", "1"),
            ("A=N-1", format(N - 1, "x")),
            ("A=oversized", format(N * N, "x")),
            ("A=empty", ""),
            ("A=string", "not_a_number"),
        ])

    if not vectors:
        return {"success": False, "error": f"Unknown test_vectors category: {test_vectors}"}

    if not interrupt(
        f"About to send {len(vectors)} malformed SRP parameters to {target} "
        f"(vectors: {', '.join(v[0] for v in vectors)})"
    ):
        return {"success": False, "error": "User declined fuzz test"}

    init_url = f"{target.rstrip('/')}{auth_init_path}"
    status, _, body, _ = _http_post(init_url, {"email": username})
    if status == 0:
        return {"success": False, "error": f"Cannot reach target: {body}"}

    verify_url = f"{target.rstrip('/')}{auth_verify_path}"
    results = []
    vulnerabilities = []

    for label, A_hex in vectors:
        fake_M1 = "0" * 64
        status_v, _, body_v, ms_v = _http_post(verify_url, {"A": A_hex, "M1": fake_M1})
        rejected = status_v >= 400 or status_v == 0
        entry = {
            "vector": label,
            "A_value": A_hex[:64] + ("..." if len(A_hex) > 64 else ""),
            "server_status": status_v,
            "rejected": rejected,
            "response_body": body_v[:1000],
            "response_ms": round(ms_v, 2),
        }
        results.append(entry)

        if not rejected:
            vuln = {
                "vector": label,
                "severity": "CRITICAL",
                "description": (
                    f"Server accepted {label}. If A ≡ 0 (mod N), "
                    f"shared secret S = 0 and session key K = H(0) is predictable."
                ),
            }
            vulnerabilities.append(vuln)
            logger.warning("CRITICAL: Server accepted %s — potential zero-key vulnerability", label)

    return {
        "target": target,
        "vectors_tested": [v[0] for v in vectors],
        "results": results,
        "vulnerabilities": vulnerabilities,
        "summary": (
            f"{len(vulnerabilities)} vulnerabilities found in {len(vectors)} vectors"
            if vulnerabilities
            else f"All {len(vectors)} vectors properly rejected"
        ),
    }


@tool(
    name="srp_extract_verifier_info",
    description="Extract SRP verifier parameters (salt, iterations, group) from the target's auth endpoint.",
)
def srp_extract_verifier_info(
    target: str,
    username: str,
    test_invalid: bool = True,
    auth_init_path: str = "/api/v1/auth",
) -> dict:
    """Probe the auth endpoint for SRP parameters and test for username enumeration.

    Args:
        target: Base URL.
        username: Account email to probe.
        test_invalid: Also probe with an invalid email to detect enumeration.
        auth_init_path: API path for auth init.

    Returns:
        Dict with SRP parameters and username enumeration analysis.
    """
    init_url = f"{target.rstrip('/')}{auth_init_path}"

    status, _, body, ms = _http_post(init_url, {"email": username})
    valid_result: dict[str, Any] = {"status": status, "response_ms": round(ms, 2)}

    if status == 0:
        return {"success": False, "error": f"Cannot reach target: {body}"}

    try:
        data = json.loads(body)
        valid_result.update({
            "salt_hex": data.get("salt", ""),
            "iterations": data.get("iterations"),
            "algorithm": data.get("algorithm", data.get("alg")),
            "response_keys": list(data.keys()),
        })
        if "B" in data:
            B_hex = data["B"]
            valid_result["B_length_hex"] = len(B_hex)
            valid_result["group_bits_estimate"] = len(B_hex) * 4
    except json.JSONDecodeError:
        valid_result["raw_body"] = body[:2000]

    result: dict[str, Any] = {"target": target, "username": username, "valid_user": valid_result}

    if test_invalid:
        import uuid

        fake_email = f"nonexistent-{uuid.uuid4().hex[:8]}@invalid.test"
        status_inv, _, body_inv, ms_inv = _http_post(init_url, {"email": fake_email})
        invalid_result: dict[str, Any] = {"status": status_inv, "response_ms": round(ms_inv, 2)}

        try:
            data_inv = json.loads(body_inv)
            invalid_result["response_keys"] = list(data_inv.keys())
        except json.JSONDecodeError:
            invalid_result["raw_body"] = body_inv[:2000]

        result["invalid_user"] = invalid_result

        timing_diff = abs(ms - ms_inv)
        status_diff = status != status_inv
        try:
            keys_diff = set(json.loads(body).keys()) != set(json.loads(body_inv).keys())
        except (json.JSONDecodeError, AttributeError):
            keys_diff = body != body_inv

        enumerable = status_diff or keys_diff or timing_diff > 50
        signals = []
        if status_diff:
            signals.append("status_code_difference")
        if keys_diff:
            signals.append("response_structure_difference")
        if timing_diff > 50:
            signals.append(f"timing_difference ({timing_diff:.0f}ms)")

        result["username_enumerable"] = enumerable
        result["enumeration_signals"] = signals

    return result


@tool(
    name="srp_timing_attack",
    description="Measure SRP authentication response timing across multiple samples to detect information leakage.",
)
def srp_timing_attack(
    target: str,
    username: str,
    samples: int = 20,
    test_type: str = "username",
    auth_init_path: str = "/api/v1/auth",
    auth_verify_path: str = "/api/v1/auth/verify",
) -> dict:
    """Statistical timing analysis of SRP authentication responses.

    Args:
        target: Base URL.
        username: Known valid account email.
        samples: Total number of requests (split between groups).
        test_type: "username" (valid vs invalid), "password" (varying A), or "proof" (wrong M1).
        auth_init_path: API path for auth init.
        auth_verify_path: API path for auth verify.

    Returns:
        Dict with statistical analysis including t-test, p-value, and effect size.
    """
    if samples < 4:
        return {"success": False, "error": "Need at least 4 samples (2 per group)"}

    if not interrupt(
        f"About to send {samples} authentication requests to {target} for timing analysis"
    ):
        return {"success": False, "error": "User declined timing test"}

    init_url = f"{target.rstrip('/')}{auth_init_path}"
    verify_url = f"{target.rstrip('/')}{auth_verify_path}"
    half = samples // 2

    group_a_times: list[float] = []
    group_b_times: list[float] = []
    label_a = ""
    label_b = ""

    if test_type == "username":
        import uuid

        label_a = "valid_user"
        label_b = "invalid_user"
        fake_email = f"nonexistent-{uuid.uuid4().hex[:8]}@invalid.test"
        for i in range(samples):
            email = username if i < half else fake_email
            _, _, ms = _timed_post(init_url, {"email": email})
            if i < half:
                group_a_times.append(ms)
            else:
                group_b_times.append(ms)

    elif test_type == "password":
        label_a = "random_A"
        label_b = "zero_A"
        for i in range(samples):
            A_val = format(i + 1, "x") if i < half else "0"
            _, _, ms = _timed_post(verify_url, {"A": A_val, "M1": "0" * 64})
            if i < half:
                group_a_times.append(ms)
            else:
                group_b_times.append(ms)

    elif test_type == "proof":
        label_a = "random_M1"
        label_b = "zero_M1"
        group = SRP_GROUPS.get(2048)
        client = SRPClient(group) if group else None
        for i in range(samples):
            if client:
                _, A = client.generate_a()
                A_hex = format(A, "x")
            else:
                A_hex = format(i + 1, "x")
            M1 = format(i, "064x") if i < half else "0" * 64
            _, _, ms = _timed_post(verify_url, {"A": A_hex, "M1": M1})
            if i < half:
                group_a_times.append(ms)
            else:
                group_b_times.append(ms)
    else:
        return {"success": False, "error": f"Unknown test_type: {test_type}"}

    if len(group_a_times) < 2 or len(group_b_times) < 2:
        return {"success": False, "error": "Not enough samples collected"}

    stats_a = compute_stats(group_a_times, label_a)
    stats_b = compute_stats(group_b_times, label_b)
    t_stat, p_value = welch_t_test(group_a_times, group_b_times)
    d = cohens_d(group_a_times, group_b_times)
    significant = p_value < 0.05

    conclusion = (
        f"Statistically significant timing difference detected between {label_a} and {label_b} "
        f"(p={p_value:.2e}, d={d:.2f})."
        if significant
        else f"No significant timing difference between {label_a} and {label_b} (p={p_value:.2e})."
    )

    return {
        "test_type": test_type,
        "samples_per_group": half,
        "group_a": stats_a,
        "group_b": stats_b,
        "t_statistic": round(t_stat, 4),
        "p_value": p_value,
        "cohens_d": round(d, 4),
        "significant": significant,
        "conclusion": conclusion,
    }


def get_srp_tools() -> list:
    """Return all SRP protocol testing tools."""
    return [srp_handshake, srp_fuzz_parameters, srp_extract_verifier_info, srp_timing_attack]
