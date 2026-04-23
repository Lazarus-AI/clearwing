"""KDF Analysis Tools — assess key derivation function security."""

from __future__ import annotations

import hashlib
import math
import time
from typing import Any

from clearwing.agent.tooling import interrupt, tool
from clearwing.crypto.srp import SRP_GROUPS, SRPClient, derive_2skd, parse_secret_key
from clearwing.crypto.stats import apply_outlier_rejection, cohens_d, compute_stats, welch_t_test

_OWASP_MINIMUMS: dict[str, int] = {
    "PBKDF2-HMAC-SHA256": 600_000,
    "PBKDF2-HMAC-SHA1": 1_300_000,
    "PBKDF2-HMAC-SHA512": 210_000,
}

_HASH_OUTPUT_BYTES: dict[str, int] = {
    "sha1": 20,
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}

_GPU_BENCHMARKS: dict[str, dict[str, int]] = {
    "PBKDF2-HMAC-SHA256": {
        "rtx_4090": 3_000_000,
        "8x_rtx_4090": 24_000_000,
        "cloud_100_gpu": 300_000_000,
    },
    "PBKDF2-HMAC-SHA1": {
        "rtx_4090": 8_000_000,
        "8x_rtx_4090": 64_000_000,
        "cloud_100_gpu": 800_000_000,
    },
    "PBKDF2-HMAC-SHA512": {
        "rtx_4090": 1_500_000,
        "8x_rtx_4090": 12_000_000,
        "cloud_100_gpu": 150_000_000,
    },
}


def _normalize_algorithm(algorithm: str, hash_function: str) -> str:
    algo = algorithm.upper().replace("_", "-").strip()
    if algo in ("PBKDF2", "PBKDF2-SHA256", "PBKDF2-HMAC"):
        algo = f"PBKDF2-HMAC-{hash_function.upper()}"
    elif algo.startswith("PBKDF2-") and "HMAC" not in algo:
        hash_part = algo.split("-", 1)[1]
        algo = f"PBKDF2-HMAC-{hash_part}"
    elif algo.startswith("PBKDF2-HMAC-"):
        pass
    else:
        algo = f"PBKDF2-HMAC-{hash_function.upper()}"
    return algo


def _format_duration(seconds: float) -> str:
    if seconds < 0.001:
        return "< 1 millisecond"
    if seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 86400 * 365.25:
        return f"{seconds / 86400:.1f} days"
    years = seconds / (86400 * 365.25)
    if years < 1000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1000:.1f} thousand years"
    return f"{years / 1_000_000:.1f} million years"


@tool(
    name="analyze_kdf_parameters",
    description=(
        "Assess KDF parameter security against OWASP 2023 benchmarks. "
        "Takes already-extracted parameters (from srp_extract_verifier_info "
        "or webcrypto hooks) and returns a compliance report."
    ),
)
def analyze_kdf_parameters(
    algorithm: str,
    iterations: int,
    salt_hex: str,
    output_length: int = 64,
    hash_function: str = "sha256",
) -> dict:
    """Assess KDF parameters against OWASP best practices.

    Args:
        algorithm: KDF algorithm name (e.g. "PBKDF2-HMAC-SHA256").
        iterations: Iteration count.
        salt_hex: Salt as hex string.
        output_length: Derived key length in bytes.
        hash_function: Underlying hash function (e.g. "sha256").

    Returns:
        Dict with compliance results, risk level, and recommendations.
    """
    normalized = _normalize_algorithm(algorithm, hash_function)
    hash_fn = hash_function.lower()

    owasp_min = _OWASP_MINIMUMS.get(normalized, _OWASP_MINIMUMS.get("PBKDF2-HMAC-SHA256", 600_000))
    iterations_compliant = iterations >= owasp_min
    iterations_ratio = round(iterations / owasp_min, 3) if owasp_min > 0 else 0

    try:
        salt_bytes = bytes.fromhex(salt_hex) if salt_hex else b""
    except ValueError:
        salt_bytes = salt_hex.encode() if salt_hex else b""
    salt_len = len(salt_bytes)
    salt_compliant = salt_len >= 16

    hash_output = _HASH_OUTPUT_BYTES.get(hash_fn, 32)
    output_compliant = output_length <= hash_output

    hash_fn_compliant = hash_fn not in ("sha1", "md5")

    findings: list[str] = []
    recommendations: list[str] = []

    if not iterations_compliant:
        findings.append(
            f"Iteration count {iterations:,} is below OWASP minimum {owasp_min:,} "
            f"({iterations_ratio:.1%} of recommended)."
        )
        recommendations.append(f"Increase iterations to at least {owasp_min:,}.")

    if salt_len == 0:
        findings.append("Salt is empty — rainbow table attacks are feasible.")
        recommendations.append("Use a cryptographically random salt of at least 16 bytes.")
    elif not salt_compliant:
        findings.append(f"Salt is {salt_len} bytes — below 16-byte OWASP recommendation.")
        recommendations.append("Increase salt length to at least 16 bytes.")

    if not output_compliant:
        findings.append(
            f"Output length ({output_length} bytes) exceeds hash output ({hash_output} bytes). "
            "Multi-block PBKDF2 halves effective iteration cost."
        )
        recommendations.append(f"Reduce output length to {hash_output} bytes or less.")

    if not hash_fn_compliant:
        findings.append(f"Hash function '{hash_fn}' is deprecated.")
        recommendations.append("Use SHA-256 or SHA-512.")

    if salt_len == 0 or (iterations_ratio < 0.1 and not iterations_compliant):
        risk_level = "CRITICAL"
    elif not iterations_compliant:
        risk_level = "HIGH"
    elif not salt_compliant or not output_compliant:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not findings:
        findings.append("All KDF parameters meet OWASP 2023 recommendations.")

    return {
        "algorithm": normalized,
        "hash_function": hash_fn,
        "iterations": iterations,
        "owasp_minimum": owasp_min,
        "iterations_compliant": iterations_compliant,
        "iterations_ratio": iterations_ratio,
        "salt_length_bytes": salt_len,
        "salt_compliant": salt_compliant,
        "output_length_bytes": output_length,
        "output_length_compliant": output_compliant,
        "hash_function_compliant": hash_fn_compliant,
        "findings": findings,
        "risk_level": risk_level,
        "recommendations": recommendations,
    }


@tool(
    name="benchmark_kdf_cracking",
    description=(
        "Estimate offline brute-force cost for a KDF configuration. "
        "Runs a local CPU calibration and projects cracking time using "
        "published GPU benchmarks for various attacker profiles."
    ),
)
def benchmark_kdf_cracking(
    algorithm: str = "PBKDF2-HMAC-SHA256",
    iterations: int = 650000,
    password_entropy_bits: float = 40.0,
    calibration_rounds: int = 100,
) -> dict:
    """Estimate time-to-crack for a KDF configuration.

    Args:
        algorithm: KDF algorithm (e.g. "PBKDF2-HMAC-SHA256").
        iterations: Target iteration count.
        password_entropy_bits: Estimated password entropy in bits.
        calibration_rounds: Iterations for local CPU benchmark.

    Returns:
        Dict with cracking time estimates for CPU, GPU, and cloud profiles.
    """
    normalized = _normalize_algorithm(algorithm, "sha256")
    hash_fn = "sha256"
    if "SHA1" in normalized:
        hash_fn = "sha1"
    elif "SHA512" in normalized:
        hash_fn = "sha512"
    elif "SHA384" in normalized:
        hash_fn = "sha384"

    start_ns = time.perf_counter_ns()
    hashlib.pbkdf2_hmac(hash_fn, b"benchmark", b"saltsaltsaltsalt", calibration_rounds, dklen=32)
    elapsed_ns = time.perf_counter_ns() - start_ns
    elapsed_ms = elapsed_ns / 1_000_000

    cpu_iters_per_sec = int(calibration_rounds / (elapsed_ns / 1_000_000_000)) if elapsed_ns > 0 else 1

    password_space = 2 ** password_entropy_bits

    def _profile(iters_per_sec: float) -> dict:
        keys_sec = iters_per_sec / iterations if iterations > 0 else 0
        seconds = password_space / keys_sec if keys_sec > 0 else float("inf")
        return {
            "iterations_per_sec": int(iters_per_sec),
            "keys_per_sec": round(keys_sec, 2),
            "time_to_exhaust": _format_duration(seconds),
            "time_to_exhaust_seconds": round(seconds, 1) if not math.isinf(seconds) else None,
        }

    gpu_data = _GPU_BENCHMARKS.get(normalized, _GPU_BENCHMARKS.get("PBKDF2-HMAC-SHA256", {}))

    result: dict[str, Any] = {
        "algorithm": normalized,
        "iterations": iterations,
        "password_entropy_bits": password_entropy_bits,
        "password_space_size": int(password_space),
        "local_cpu": _profile(cpu_iters_per_sec),
        "single_gpu": _profile(gpu_data.get("rtx_4090", 3_000_000)),
        "gpu_cluster_8x": _profile(gpu_data.get("8x_rtx_4090", 24_000_000)),
        "cloud_100_gpu": _profile(gpu_data.get("cloud_100_gpu", 300_000_000)),
        "calibration": {
            "rounds": calibration_rounds,
            "duration_ms": round(elapsed_ms, 3),
            "cpu_iters_per_sec": cpu_iters_per_sec,
        },
    }

    gpu_keys = gpu_data.get("rtx_4090", 3_000_000) / iterations if iterations > 0 else 0
    gpu_seconds = password_space / gpu_keys if gpu_keys > 0 else float("inf")

    if gpu_seconds < 3600:
        assessment = f"CRITICAL: A single GPU can exhaust {password_entropy_bits}-bit password space in {_format_duration(gpu_seconds)}."
    elif gpu_seconds < 86400 * 30:
        assessment = f"HIGH RISK: A single GPU can crack in {_format_duration(gpu_seconds)}. A GPU cluster reduces this further."
    elif gpu_seconds < 86400 * 365.25:
        assessment = f"MODERATE: Single GPU attack takes {_format_duration(gpu_seconds)}, but GPU clusters are practical."
    else:
        assessment = f"Resistant to offline attack: single GPU would take {_format_duration(gpu_seconds)}."

    result["assessment"] = assessment
    return result


@tool(
    name="test_2skd_implementation",
    description=(
        "Verify 1Password 2SKD implementation correctness by performing "
        "SRP handshakes and checking key derivation properties."
    ),
)
def test_2skd_implementation(
    target: str,
    username: str,
    password: str,
    secret_key: str = "",
    auth_init_path: str = "/api/v1/auth",
    auth_verify_path: str = "/api/v1/auth/verify",
) -> dict:
    """Verify 2SKD key derivation correctness.

    Args:
        target: Base URL.
        username: Account username/email.
        password: Account password.
        secret_key: 1Password Secret Key (A3-XXXXXX-... format).
        auth_init_path: Auth initialization endpoint path.
        auth_verify_path: Auth verification endpoint path.

    Returns:
        Dict with per-check pass/fail results and derivation details.
    """
    from clearwing.agent.tools.crypto.srp_tools import _http_post

    if not interrupt(f"About to perform 2SKD verification handshakes against {target}"):
        return {"error": "User declined 2SKD verification."}

    url = f"{target.rstrip('/')}{auth_init_path}"

    status, _hdrs, body, _dur = _http_post(url, {"email": username})
    if status == 0:
        return {"error": f"Connection failed: {body}"}

    import json

    try:
        server_data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {"error": f"Invalid JSON from server (status {status})."}

    salt_hex = server_data.get("salt", "")
    iterations = server_data.get("iterations", 0)
    algorithm = server_data.get("algorithm", "PBKDF2-HMAC-SHA256")

    try:
        salt = bytes.fromhex(salt_hex) if salt_hex else b""
    except ValueError:
        salt = salt_hex.encode() if salt_hex else b""

    if not salt or not iterations:
        return {"error": "Server did not return salt or iterations."}

    checks: dict[str, bool | None] = {
        "key_split_correct": None,
        "secret_key_incorporated": None,
        "password_change_produces_new_auk": None,
        "iteration_count_plausible": None,
    }
    findings: list[str] = []

    sk_bytes = parse_secret_key(secret_key) if secret_key else b""

    start_ns = time.perf_counter_ns()
    auk, srp_x = derive_2skd(password, salt, iterations, sk_bytes if sk_bytes else b"\x00" * 32)
    derivation_ns = time.perf_counter_ns() - start_ns
    derivation_ms = derivation_ns / 1_000_000

    # Check 1: key split correctness
    expected_half = 32  # default dk_len=64, split in half
    checks["key_split_correct"] = len(auk) == expected_half and srp_x > 0
    if not checks["key_split_correct"]:
        findings.append(f"Key split unexpected: AUK={len(auk)} bytes, SRP-x={'zero' if srp_x == 0 else 'nonzero'}.")

    # Check 2: secret key incorporation
    if sk_bytes:
        auk_no_sk, _ = derive_2skd(password, salt, iterations, b"\x00" * len(sk_bytes))
        checks["secret_key_incorporated"] = auk != auk_no_sk
        if not checks["secret_key_incorporated"]:
            findings.append("CRITICAL: Secret Key XOR has no effect — AUK is identical with and without Secret Key.")
    else:
        checks["secret_key_incorporated"] = None
        findings.append("Secret Key not provided — skipping incorporation check.")

    # Check 3: different password produces different AUK
    auk_alt, _ = derive_2skd("different_password_for_test", salt, iterations, sk_bytes if sk_bytes else b"\x00" * 32)
    checks["password_change_produces_new_auk"] = auk != auk_alt
    if not checks["password_change_produces_new_auk"]:
        findings.append("CRITICAL: Different password produces same AUK.")

    # Check 4: iteration count plausibility (timing-based)
    expected_ms_per_100k = derivation_ms / (iterations / 100_000) if iterations > 0 else 0
    checks["iteration_count_plausible"] = expected_ms_per_100k > 1.0  # at least 1ms per 100k iterations
    if not checks["iteration_count_plausible"]:
        findings.append(
            f"Derivation completed in {derivation_ms:.1f}ms for {iterations:,} iterations — "
            "suspiciously fast, iterations may not be applied."
        )

    passed = [v for v in checks.values() if v is not None]
    all_passed = all(passed) if passed else False

    if not findings:
        findings.append("All 2SKD checks passed.")

    return {
        "target": target,
        "server_params": {
            "salt_hex": salt_hex,
            "iterations": iterations,
            "algorithm": algorithm,
        },
        "checks": checks,
        "derivation_details": {
            "auk_hex": auk.hex(),
            "srp_x_hex": format(srp_x, "x"),
            "auk_length_bytes": len(auk),
            "derivation_time_ms": round(derivation_ms, 2),
        },
        "findings": findings,
        "all_passed": all_passed,
    }


@tool(
    name="kdf_oracle_test",
    description=(
        "Test if the server leaks KDF correctness information through "
        "timing differences or response variations between valid and "
        "invalid credential formats."
    ),
)
def kdf_oracle_test(
    target: str,
    username: str,
    samples: int = 30,
    auth_init_path: str = "/api/v1/auth",
    auth_verify_path: str = "/api/v1/auth/verify",
    warmup: int = 5,
    outlier_method: str = "iqr",
) -> dict:
    """Test for KDF oracle information leakage.

    Args:
        target: Base URL.
        username: Account username/email.
        samples: Total timing samples (split between two groups).
        auth_init_path: Auth initialization endpoint path.
        auth_verify_path: Auth verification endpoint path.
        warmup: Warmup requests (discarded).
        outlier_method: "iqr", "zscore", or "none".

    Returns:
        Dict with timing analysis, response comparison, and oracle detection.
    """
    from clearwing.agent.tools.crypto.srp_tools import _http_post, _timed_post

    if samples < 10:
        return {"error": "Need at least 10 samples for meaningful oracle test."}

    total = warmup + samples
    if not interrupt(
        f"About to send ~{total} requests to {target} for KDF oracle testing"
    ):
        return {"error": "User declined KDF oracle test."}

    init_url = f"{target.rstrip('/')}{auth_init_path}"
    verify_url = f"{target.rstrip('/')}{auth_verify_path}"

    status, _hdrs, body, _dur = _http_post(init_url, {"email": username})
    if status == 0:
        return {"error": f"Connection failed: {body}"}

    import json
    import os

    try:
        json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {"error": f"Invalid JSON from init endpoint (status {status})."}

    group = SRP_GROUPS.get(2048, SRP_GROUPS[1024])
    client = SRPClient(group)
    _a, A = client.generate_a()

    # Group A: properly formatted SRP verify with random M1
    # Group B: SRP verify with zero A value (different server code path)
    payload_a = {"A": format(A, "x"), "M1": os.urandom(32).hex()}
    payload_b = {"A": "0", "M1": os.urandom(32).hex()}

    for _ in range(warmup):
        _timed_post(verify_url, payload_a)
        _timed_post(verify_url, payload_b)

    samples_per_group = samples // 2
    times_a: list[float] = []
    times_b: list[float] = []
    bodies_a: list[str] = []
    bodies_b: list[str] = []

    for _ in range(samples_per_group):
        status_a, body_a, ms_a = _timed_post(verify_url, payload_a)
        if status_a != 0:
            times_a.append(ms_a)
            bodies_a.append(body_a)

        status_b, body_b, ms_b = _timed_post(verify_url, payload_b)
        if status_b != 0:
            times_b.append(ms_b)
            bodies_b.append(body_b)

    if len(times_a) < 3 or len(times_b) < 3:
        return {"error": f"Too few successful responses (A={len(times_a)}, B={len(times_b)})."}

    clean_a = apply_outlier_rejection(times_a, outlier_method)
    clean_b = apply_outlier_rejection(times_b, outlier_method)
    if len(clean_a) < 3:
        clean_a = times_a
    if len(clean_b) < 3:
        clean_b = times_b

    stats_a = compute_stats(clean_a, "valid_format")
    stats_b = compute_stats(clean_b, "zero_A")
    t_stat, p_value = welch_t_test(clean_a, clean_b)
    d = cohens_d(clean_a, clean_b)
    timing_significant = p_value < 0.05

    unique_bodies_a = set(bodies_a[:5])
    unique_bodies_b = set(bodies_b[:5])
    response_structure_differs = unique_bodies_a != unique_bodies_b

    oracle_types: list[str] = []
    if timing_significant and d > 0.3:
        oracle_types.append("timing")
    if response_structure_differs:
        oracle_types.append("response_structure")

    oracle_detected = len(oracle_types) > 0

    if oracle_detected:
        conclusion = (
            f"KDF oracle detected via {', '.join(oracle_types)}. "
            f"Server differentiates request formats (p={p_value:.2e}, d={d:.2f})."
        )
    else:
        conclusion = f"No KDF oracle detected (p={p_value:.2e}, d={d:.2f})."

    return {
        "target": target,
        "samples_per_group": samples_per_group,
        "timing": {
            "group_a": stats_a,
            "group_b": stats_b,
            "t_statistic": round(t_stat, 4),
            "p_value": p_value,
            "cohens_d": round(d, 4),
            "significant": timing_significant,
        },
        "response_analysis": {
            "response_structure_differs": response_structure_differs,
        },
        "oracle_detected": oracle_detected,
        "oracle_type": oracle_types,
        "conclusion": conclusion,
    }


def get_kdf_tools() -> list[Any]:
    """Return all KDF analysis tools."""
    return [analyze_kdf_parameters, benchmark_kdf_cracking, test_2skd_implementation, kdf_oracle_test]
