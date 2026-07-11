"""Credential attack tools — 2SKD entropy analysis and factor separation testing."""

from __future__ import annotations

import base64
import json
import math
import os
from typing import Any

from clearwing.agent.tooling import interrupt, tool
from clearwing.agent.tools.crypto.kdf_tools import (
    _GPU_BENCHMARKS,
    _format_duration,
    _normalize_algorithm,
)
from clearwing.crypto.srp import SRP_GROUPS, SRPClient, derive_2skd, parse_secret_key
from clearwing.crypto.stats import apply_outlier_rejection, cohens_d, compute_stats, welch_t_test

_A100_USD_PER_HOUR = 2.0

_HASHCAT_MODES: dict[str, int] = {
    "PBKDF2-HMAC-SHA256": 10900,
    "PBKDF2-HMAC-SHA1": 12000,
    "PBKDF2-HMAC-SHA512": 12100,
}

_JOHN_FORMATS: dict[str, str] = {
    "PBKDF2-HMAC-SHA256": "PBKDF2-HMAC-SHA256",
    "PBKDF2-HMAC-SHA1": "PBKDF2-HMAC-SHA1",
    "PBKDF2-HMAC-SHA512": "PBKDF2-HMAC-SHA512",
}

_SECRET_KEY_CHARSET = "0123456789ABCDEFGHJKLMNPQRSTVWXYZ"  # noqa: S105
_SECRET_KEY_CHARSET_BITS = math.log2(len(_SECRET_KEY_CHARSET))


@tool(
    name="analyze_2skd_entropy",
    description=(
        "Calculate the effective keyspace of 1Password's combined "
        "(password x Secret Key) 2SKD system. Reports password-only vs "
        "2SKD-protected cracking costs at various GPU price points."
    ),
)
def analyze_2skd_entropy(
    password_entropy_bits: float = 40.0,
    secret_key_bits: int = 128,
    iterations: int = 650000,
    algorithm: str = "PBKDF2-HMAC-SHA256",
) -> dict:
    """Calculate effective keyspace of the 2SKD system.

    Args:
        password_entropy_bits: Estimated password entropy in bits.
        secret_key_bits: Secret Key entropy in bits (default 128).
        iterations: PBKDF2 iteration count.
        algorithm: KDF algorithm name.

    Returns:
        Dict with entropy analysis, cracking cost comparison, and assessment.
    """
    normalized = _normalize_algorithm(algorithm, "sha256")

    combined_bits = password_entropy_bits + secret_key_bits
    password_space = 2**password_entropy_bits
    combined_space = 2**combined_bits

    gpu_data = _GPU_BENCHMARKS.get(normalized, _GPU_BENCHMARKS.get("PBKDF2-HMAC-SHA256", {}))

    def _crack_profile(name: str, iters_per_sec: float) -> dict[str, Any]:
        keys_sec = iters_per_sec / iterations if iterations > 0 else 0
        pw_seconds = password_space / keys_sec if keys_sec > 0 else float("inf")
        combined_seconds = combined_space / keys_sec if keys_sec > 0 else float("inf")
        return {
            "name": name,
            "keys_per_sec": round(keys_sec, 2),
            "password_only": {
                "time": _format_duration(pw_seconds),
                "seconds": round(pw_seconds, 1) if not math.isinf(pw_seconds) else None,
            },
            "with_2skd": {
                "time": _format_duration(combined_seconds),
                "seconds": round(combined_seconds, 1) if not math.isinf(combined_seconds) else None,
            },
        }

    profiles = [
        _crack_profile("single_gpu_rtx4090", gpu_data.get("rtx_4090", 3_000_000)),
        _crack_profile("gpu_cluster_8x", gpu_data.get("8x_rtx_4090", 24_000_000)),
        _crack_profile("cloud_100_gpu", gpu_data.get("cloud_100_gpu", 300_000_000)),
    ]

    cloud_keys_sec = gpu_data.get("cloud_100_gpu", 300_000_000) / iterations if iterations > 0 else 0
    cloud_pw_seconds = password_space / cloud_keys_sec if cloud_keys_sec > 0 else float("inf")
    cloud_combined_seconds = combined_space / cloud_keys_sec if cloud_keys_sec > 0 else float("inf")

    pw_cost_usd = (cloud_pw_seconds / 3600) * _A100_USD_PER_HOUR * 100 if not math.isinf(cloud_pw_seconds) else None
    combined_cost_usd = (
        (cloud_combined_seconds / 3600) * _A100_USD_PER_HOUR * 100
        if not math.isinf(cloud_combined_seconds)
        else None
    )

    if combined_bits >= 256:
        assessment = (
            f"2SKD provides {combined_bits:.0f}-bit combined entropy — "
            "exceeds AES-256 keyspace. Brute force is physically impossible."
        )
    elif combined_bits >= 168:
        assessment = (
            f"2SKD provides {combined_bits:.0f}-bit combined entropy. "
            "Brute force is computationally infeasible with any foreseeable technology."
        )
    elif combined_bits >= 128:
        assessment = (
            f"2SKD provides {combined_bits:.0f}-bit combined entropy. "
            "Resistant to brute force but below ideal 168-bit threshold."
        )
    else:
        assessment = (
            f"WARNING: Combined entropy is only {combined_bits:.0f} bits. "
            "This may be attackable with sufficient resources."
        )

    password_only_assessment = (
        f"Without 2SKD, a {password_entropy_bits:.0f}-bit password alone is crackable "
        f"on a single GPU in {_format_duration(profiles[0]['password_only']['seconds'] or 0)}."
        if profiles[0]["password_only"]["seconds"]
        else f"Without 2SKD, a {password_entropy_bits:.0f}-bit password alone provides insufficient protection."
    )

    return {
        "algorithm": normalized,
        "iterations": iterations,
        "password_entropy_bits": password_entropy_bits,
        "secret_key_bits": secret_key_bits,
        "combined_entropy_bits": combined_bits,
        "password_space": int(password_space) if password_entropy_bits <= 64 else f"2^{password_entropy_bits:.0f}",
        "combined_space": f"2^{combined_bits:.0f}",
        "cracking_profiles": profiles,
        "cost_estimate_usd": {
            "password_only_100gpu": round(pw_cost_usd, 2) if pw_cost_usd is not None else None,
            "with_2skd_100gpu": round(combined_cost_usd, 2) if combined_cost_usd is not None else None,
            "rate": f"${_A100_USD_PER_HOUR}/hr per GPU x 100 GPUs",
        },
        "assessment": assessment,
        "password_only_assessment": password_only_assessment,
        "secret_key_is_dominant_factor": secret_key_bits > password_entropy_bits,
    }


def _analyze_factor_separation(
    *,
    target: str,
    samples_per_group: int,
    sk_provided: bool,
    times_wrong_key: list[float],
    times_wrong_pwd: list[float],
    bodies_wrong_key: list[str],
    bodies_wrong_pwd: list[str],
    statuses_wrong_key: list[int],
    statuses_wrong_pwd: list[int],
    outlier_method: str,
) -> dict:
    """Analyze collected samples for factor separation signals."""
    clean_key = apply_outlier_rejection(times_wrong_key, outlier_method)
    clean_pwd = apply_outlier_rejection(times_wrong_pwd, outlier_method)
    if len(clean_key) < 3:
        clean_key = times_wrong_key
    if len(clean_pwd) < 3:
        clean_pwd = times_wrong_pwd

    stats_key = compute_stats(clean_key, "wrong_secret_key")
    stats_pwd = compute_stats(clean_pwd, "wrong_password")
    t_stat, p_value = welch_t_test(clean_key, clean_pwd)
    d = cohens_d(clean_key, clean_pwd)
    timing_differs = p_value < 0.05 and abs(d) > 0.3

    unique_bodies_key = set(bodies_wrong_key[:5])
    unique_bodies_pwd = set(bodies_wrong_pwd[:5])
    response_differs = unique_bodies_key != unique_bodies_pwd

    unique_statuses_key = set(statuses_wrong_key)
    unique_statuses_pwd = set(statuses_wrong_pwd)
    status_differs = unique_statuses_key != unique_statuses_pwd

    separation_signals: list[str] = []
    if timing_differs:
        separation_signals.append("timing")
    if response_differs:
        separation_signals.append("response_body")
    if status_differs:
        separation_signals.append("status_code")

    factor_separation = len(separation_signals) > 0

    if factor_separation:
        conclusion = (
            f"FACTOR SEPARATION DETECTED via {', '.join(separation_signals)}. "
            f"Server distinguishes wrong-password from wrong-Secret-Key "
            f"(p={p_value:.2e}, d={d:.2f}). Each factor may be attackable independently."
        )
    else:
        conclusion = (
            f"No factor separation detected (p={p_value:.2e}, d={d:.2f}). "
            "Server responses are indistinguishable for wrong-password vs wrong-Secret-Key. "
            "2SKD's combined entropy model appears intact."
        )

    return {
        "target": target,
        "samples_per_group": samples_per_group,
        "secret_key_provided": sk_provided,
        "timing": {
            "wrong_secret_key": stats_key,
            "wrong_password": stats_pwd,
            "t_statistic": round(t_stat, 4),
            "p_value": p_value,
            "cohens_d": round(d, 4),
            "significant": timing_differs,
        },
        "response_analysis": {
            "response_body_differs": response_differs,
            "status_code_differs": status_differs,
            "wrong_key_statuses": sorted(unique_statuses_key),
            "wrong_pwd_statuses": sorted(unique_statuses_pwd),
        },
        "factor_separation": factor_separation,
        "separation_signals": separation_signals,
        "conclusion": conclusion,
    }


@tool(
    name="test_secret_key_validation",
    description=(
        "Test whether the server distinguishes 'wrong password' from "
        "'wrong Secret Key' in its authentication response. If separable, "
        "each factor can be attacked independently — breaking 2SKD's "
        "security model."
    ),
)
def test_secret_key_validation(
    target: str,
    username: str,
    password: str,
    secret_key: str = "",
    samples: int = 20,
    auth_init_path: str = "/api/v1/auth",
    auth_verify_path: str = "/api/v1/auth/verify",
    warmup: int = 5,
    outlier_method: str = "iqr",
) -> dict:
    """Test for factor separation in 2SKD authentication.

    Args:
        target: Base URL.
        username: Account username/email.
        password: Known-correct account password.
        secret_key: Known-correct Secret Key (A3-XXXXXX-... format).
        samples: Timing samples per group.
        auth_init_path: Auth initialization endpoint path.
        auth_verify_path: Auth verification endpoint path.
        warmup: Warmup requests (discarded).
        outlier_method: "iqr", "zscore", or "none".

    Returns:
        Dict with factor separation analysis: timing, response, and conclusion.
    """
    from clearwing.agent.tools.crypto.srp_tools import _http_post, _timed_post

    if samples < 6:
        return {"error": "Need at least 6 samples (3 per comparison group)."}

    total = warmup * 2 + samples * 2
    if not interrupt(
        f"About to send ~{total} requests to {target} for 2SKD factor separation testing"
    ):
        return {"error": "User declined factor separation test."}

    init_url = f"{target.rstrip('/')}{auth_init_path}"
    verify_url = f"{target.rstrip('/')}{auth_verify_path}"

    status, _hdrs, body, _dur = _http_post(init_url, {"email": username})
    if status == 0:
        return {"error": f"Connection failed: {body}"}

    try:
        server_data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {"error": f"Invalid JSON from server (status {status})."}

    salt_hex = server_data.get("salt", "")
    iterations = server_data.get("iterations", 0)
    B_hex = server_data.get("B", "")

    try:
        salt = bytes.fromhex(salt_hex) if salt_hex else b""
    except ValueError:
        salt = salt_hex.encode() if salt_hex else b""

    if not salt or not iterations:
        return {"error": "Server did not return salt or iterations."}

    try:
        B = int(B_hex, 16) if B_hex else 0
    except ValueError:
        B = 0

    group = SRP_GROUPS.get(2048, SRP_GROUPS[1024])
    client = SRPClient(group)

    sk_bytes = parse_secret_key(secret_key) if secret_key else b""

    def _make_verify_payload(pwd: str, sk: bytes) -> dict:
        auk, x = derive_2skd(pwd, salt, iterations, sk if sk else b"\x00" * 32)
        a, A = client.generate_a()
        u = client.compute_u(A, B) if B else 1
        S = client.compute_S(B, a, u, x) if B and u else 0
        K = client.compute_K(S) if S else b"\x00" * 32
        M1 = client.compute_M1(username, salt, A, B, K)
        return {"A": format(A, "x"), "M1": M1.hex()}

    for _ in range(warmup):
        wrong_sk = os.urandom(32)
        _timed_post(verify_url, _make_verify_payload(password, wrong_sk))
        wrong_pw = os.urandom(16).hex()
        _timed_post(verify_url, _make_verify_payload(wrong_pw, sk_bytes if sk_bytes else os.urandom(32)))

    samples_per_group = samples // 2
    times_wrong_key: list[float] = []
    times_wrong_pwd: list[float] = []
    bodies_wrong_key: list[str] = []
    bodies_wrong_pwd: list[str] = []
    statuses_wrong_key: list[int] = []
    statuses_wrong_pwd: list[int] = []

    for _ in range(samples_per_group):
        wrong_sk = os.urandom(32)
        payload_b = _make_verify_payload(password, wrong_sk)
        status_b, body_b, ms_b = _timed_post(verify_url, payload_b)
        if status_b != 0:
            times_wrong_key.append(ms_b)
            bodies_wrong_key.append(body_b)
            statuses_wrong_key.append(status_b)

        wrong_pw = os.urandom(16).hex()
        sk_for_c = sk_bytes if sk_bytes else os.urandom(32)
        payload_c = _make_verify_payload(wrong_pw, sk_for_c)
        status_c, body_c, ms_c = _timed_post(verify_url, payload_c)
        if status_c != 0:
            times_wrong_pwd.append(ms_c)
            bodies_wrong_pwd.append(body_c)
            statuses_wrong_pwd.append(status_c)

    if len(times_wrong_key) < 3 or len(times_wrong_pwd) < 3:
        return {
            "error": f"Too few successful responses (wrong_key={len(times_wrong_key)}, wrong_pwd={len(times_wrong_pwd)})."
        }

    return _analyze_factor_separation(
        target=target,
        samples_per_group=samples_per_group,
        sk_provided=bool(sk_bytes),
        times_wrong_key=times_wrong_key,
        times_wrong_pwd=times_wrong_pwd,
        bodies_wrong_key=bodies_wrong_key,
        bodies_wrong_pwd=bodies_wrong_pwd,
        statuses_wrong_key=statuses_wrong_key,
        statuses_wrong_pwd=statuses_wrong_pwd,
        outlier_method=outlier_method,
    )


@tool(
    name="enumerate_secret_key_format",
    description=(
        "Probe enrollment and authentication endpoints to determine "
        "1Password Secret Key format, entropy, and predictability. "
        "Analyzes A3-XXXXXX-... structure for fixed vs random components."
    ),
)
def enumerate_secret_key_format(
    target: str,
    username: str = "",
    enrollment_path: str = "/api/v1/auth/enroll",
    auth_init_path: str = "/api/v1/auth",
) -> dict:
    """Analyze Secret Key format and entropy.

    Args:
        target: Base URL.
        username: Account username/email (optional, for auth probing).
        enrollment_path: Enrollment endpoint path.
        auth_init_path: Auth initialization endpoint path.

    Returns:
        Dict with format analysis, entropy calculation, and server probing results.
    """
    from clearwing.agent.tools.crypto.srp_tools import _http_post

    if not interrupt(f"About to probe {target} for Secret Key format information"):
        return {"error": "User declined Secret Key format enumeration."}

    format_analysis = {
        "known_format": "A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX",
        "prefix": "A3",
        "prefix_meaning": "Version/account type indicator (fixed, not random)",
        "segment_count": 7,
        "chars_per_segment": 6,
        "total_random_chars": 26,
        "charset": _SECRET_KEY_CHARSET,
        "charset_size": len(_SECRET_KEY_CHARSET),
        "bits_per_char": round(_SECRET_KEY_CHARSET_BITS, 2),
        "total_entropy_bits": round(26 * _SECRET_KEY_CHARSET_BITS, 1),
        "raw_bytes": 128 // 8,
    }

    first_segment_note = (
        "The first segment after A3 may encode the account UUID or "
        "domain-specific identifier. If predictable, effective entropy "
        f"drops to {round(20 * _SECRET_KEY_CHARSET_BITS, 1)} bits."
    )

    enrollment_result: dict[str, Any] = {}
    enroll_url = f"{target.rstrip('/')}{enrollment_path}"
    status, _hdrs, body, _dur = _http_post(enroll_url, {})
    enrollment_result = {
        "endpoint": enroll_url,
        "status": status,
        "reveals_format": False,
        "reveals_generation": False,
    }
    if status and status < 500:
        try:
            enroll_data = json.loads(body)
            if any(k in enroll_data for k in ("secretKey", "secret_key", "key_format", "account_key")):
                enrollment_result["reveals_format"] = True
                enrollment_result["leaked_fields"] = [
                    k for k in enroll_data if "key" in k.lower() or "secret" in k.lower()
                ]
            if any(k in enroll_data for k in ("key_generation", "entropy_source", "rng")):
                enrollment_result["reveals_generation"] = True
        except (json.JSONDecodeError, TypeError):
            enrollment_result["response_type"] = "non-json"

    auth_result: dict[str, Any] = {}
    if username:
        init_url = f"{target.rstrip('/')}{auth_init_path}"
        status, _hdrs, body, _dur = _http_post(init_url, {"email": username})
        auth_result = {
            "endpoint": init_url,
            "status": status,
        }
        if status and status < 500:
            try:
                auth_data = json.loads(body)
                key_hints = [
                    k for k in auth_data if "key" in k.lower() or "secret" in k.lower() or "format" in k.lower()
                ]
                auth_result["key_related_fields"] = key_hints
                auth_result["reveals_key_info"] = len(key_hints) > 0
            except (json.JSONDecodeError, TypeError):
                auth_result["response_type"] = "non-json"

    predictability_risks: list[str] = []
    predictability_risks.append(
        "A3 prefix is fixed — reduces effective entropy by ~10 bits vs fully random."
    )
    predictability_risks.append(first_segment_note)
    if enrollment_result.get("reveals_format") or enrollment_result.get("reveals_generation"):
        predictability_risks.append(
            "Enrollment endpoint leaks key format or generation details."
        )

    effective_entropy = format_analysis["total_entropy_bits"]
    if effective_entropy >= 128:
        entropy_assessment = (
            f"Secret Key provides ~{effective_entropy:.0f} bits of entropy. "
            "Brute force of the key alone is infeasible."
        )
    elif effective_entropy >= 100:
        entropy_assessment = (
            f"Secret Key provides ~{effective_entropy:.0f} bits of entropy. "
            "Strong but below the 128-bit ideal."
        )
    else:
        entropy_assessment = (
            f"WARNING: Secret Key provides only ~{effective_entropy:.0f} bits. "
            "May be attackable if other factors reduce the search space."
        )

    return {
        "format_analysis": format_analysis,
        "predictability_risks": predictability_risks,
        "enrollment_probe": enrollment_result,
        "auth_probe": auth_result,
        "entropy_assessment": entropy_assessment,
    }


@tool(
    name="offline_crack_setup",
    description=(
        "Generate hashcat and john command lines for offline cracking "
        "of captured PBKDF2/SRP parameters. Estimates time-to-crack "
        "and flags when 2SKD makes standard tools insufficient."
    ),
)
def offline_crack_setup(
    salt_hex: str,
    iterations: int,
    algorithm: str = "PBKDF2-HMAC-SHA256",
    verifier_hex: str = "",
    secret_key_hex: str = "",
    wordlist: str = "rockyou.txt",
    password_entropy_bits: float = 40.0,
) -> dict:
    """Generate offline cracking commands and time estimates.

    Args:
        salt_hex: Salt as hex string.
        iterations: PBKDF2 iteration count.
        algorithm: KDF algorithm name.
        verifier_hex: Captured verifier/derived key as hex (if available).
        secret_key_hex: Known Secret Key as hex (if captured).
        wordlist: Wordlist file name for dictionary attack.
        password_entropy_bits: Estimated password entropy for time projection.

    Returns:
        Dict with hashcat/john commands, hash format, and cracking estimates.
    """
    normalized = _normalize_algorithm(algorithm, "sha256")
    hash_fn = "sha256"
    if "SHA1" in normalized:
        hash_fn = "sha1"
    elif "SHA512" in normalized:
        hash_fn = "sha512"

    try:
        salt_bytes = bytes.fromhex(salt_hex) if salt_hex else b""
    except ValueError:
        salt_bytes = salt_hex.encode() if salt_hex else b""

    salt_b64 = base64.b64encode(salt_bytes).decode() if salt_bytes else ""

    verifier_b64 = ""
    if verifier_hex:
        try:
            verifier_b64 = base64.b64encode(bytes.fromhex(verifier_hex)).decode()
        except ValueError:
            verifier_b64 = ""

    hashcat_mode = _HASHCAT_MODES.get(normalized, 10900)
    john_format = _JOHN_FORMATS.get(normalized, "PBKDF2-HMAC-SHA256")

    hash_string = f"{hash_fn}:{iterations}:{salt_b64}:{verifier_b64}" if verifier_b64 else ""

    has_2skd = bool(secret_key_hex)

    hashcat_cmd = f"hashcat -m {hashcat_mode} -a 0 hash.txt {wordlist}"
    hashcat_notes: list[str] = []
    if has_2skd:
        hashcat_notes.append(
            "Standard hashcat PBKDF2 mode does NOT handle the 2SKD XOR step. "
            "You need a custom OpenCL kernel or wrapper script that: "
            "(1) runs PBKDF2 on each candidate password, "
            "(2) XORs with the known Secret Key, "
            "(3) splits into AUK + SRP-x, "
            "(4) computes SRP verifier from x and compares."
        )
        hashcat_notes.append(
            f"Secret Key (hex): {secret_key_hex}"
        )

    john_cmd = f"john --format={john_format} --wordlist={wordlist} hash.txt"
    john_notes: list[str] = []
    if has_2skd:
        john_notes.append(
            "John the Ripper also lacks native 2SKD support. "
            "Use a custom format plugin or external script."
        )

    gpu_data = _GPU_BENCHMARKS.get(normalized, _GPU_BENCHMARKS.get("PBKDF2-HMAC-SHA256", {}))
    password_space = 2**password_entropy_bits

    profiles: dict[str, Any] = {}
    for name, iters_sec in [
        ("single_gpu_rtx4090", gpu_data.get("rtx_4090", 3_000_000)),
        ("gpu_cluster_8x", gpu_data.get("8x_rtx_4090", 24_000_000)),
        ("cloud_100_gpu", gpu_data.get("cloud_100_gpu", 300_000_000)),
    ]:
        keys_sec = iters_sec / iterations if iterations > 0 else 0
        seconds = password_space / keys_sec if keys_sec > 0 else float("inf")
        profiles[name] = {
            "keys_per_sec": round(keys_sec, 2),
            "time_to_exhaust": _format_duration(seconds),
            "time_to_exhaust_seconds": round(seconds, 1) if not math.isinf(seconds) else None,
        }

    if has_2skd:
        feasibility = (
            "INFEASIBLE: Even with the Secret Key known, cracking requires "
            "a custom PBKDF2+XOR+SRP kernel. With Secret Key unknown, the "
            "attack is equivalent to brute-forcing 128+ additional bits."
        )
    else:
        fastest = profiles.get("cloud_100_gpu", {})
        time_str = fastest.get("time_to_exhaust", "unknown")
        feasibility = (
            f"Password-only cracking (no 2SKD): cloud GPU cluster "
            f"can exhaust {password_entropy_bits:.0f}-bit space in {time_str}."
        )

    result: dict[str, Any] = {
        "algorithm": normalized,
        "iterations": iterations,
        "salt_hex": salt_hex,
        "salt_base64": salt_b64,
        "hashcat": {
            "mode": hashcat_mode,
            "command": hashcat_cmd,
            "hash_format": hash_string,
            "notes": hashcat_notes,
        },
        "john": {
            "format": john_format,
            "command": john_cmd,
            "notes": john_notes,
        },
        "cracking_estimates": profiles,
        "password_entropy_bits": password_entropy_bits,
        "2skd_active": has_2skd,
        "feasibility": feasibility,
    }

    if hash_string:
        result["hash_file_content"] = hash_string

    return result


def get_credential_tools() -> list[Any]:
    """Return all credential attack tools."""
    return [
        analyze_2skd_entropy,
        test_secret_key_validation,
        enumerate_secret_key_format,
        offline_crack_setup,
    ]
