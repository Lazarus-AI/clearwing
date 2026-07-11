"""Timing Side-Channel Framework — general-purpose timing attack tools."""

from __future__ import annotations

import random
import time
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import interrupt, tool
from clearwing.crypto.stats import (
    apply_outlier_rejection,
    cohens_d,
    compute_extended_stats,
    compute_stats,
    welch_t_test,
)


def _timed_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = 30,
) -> tuple[int, str, float]:
    """Send HTTP request with ns-precision timing. No proxy logging."""
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    if data and "Content-Type" not in (headers or {}):
        req.add_header("Content-Type", "application/json")

    start_ns = time.perf_counter_ns()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
        status = resp.status
        resp_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        return 0, str(e), elapsed_ms
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    return status, resp_body, elapsed_ms


@tool(
    name="timing_probe",
    description=(
        "Profile HTTP endpoint response timing with statistical analysis. "
        "Sends N requests and returns distribution statistics with "
        "percentiles, confidence intervals, and histogram."
    ),
)
def timing_probe(
    target: str,
    method: str = "GET",
    path: str = "/",
    headers: dict | None = None,
    body: str = "",
    samples: int = 50,
    warmup: int = 5,
    outlier_method: str = "iqr",
    outlier_threshold: float = 1.5,
) -> dict:
    """Profile an endpoint's response timing.

    Args:
        target: Base URL (e.g. "https://example.com").
        method: HTTP method.
        path: URL path appended to target.
        headers: Optional request headers.
        body: Optional request body.
        samples: Number of timed requests to send.
        warmup: Number of warmup requests (discarded).
        outlier_method: "iqr", "zscore", or "none".
        outlier_threshold: Threshold for outlier rejection.

    Returns:
        Dict with extended statistics, outlier info, and raw timings.
    """
    if samples < 5:
        return {"error": "Need at least 5 samples for meaningful statistics."}

    total = warmup + samples
    if not interrupt(f"About to send {total} requests to {target}{path} for timing analysis"):
        return {"error": "User declined timing probe."}

    url = f"{target.rstrip('/')}{path}"
    req_headers = headers or {}
    req_body = body or None

    for _ in range(warmup):
        _timed_request(url, method, req_headers, req_body)

    raw_times: list[float] = []
    errors = 0
    for _ in range(samples):
        status, _, ms = _timed_request(url, method, req_headers, req_body)
        if status == 0:
            errors += 1
            continue
        raw_times.append(ms)

    if len(raw_times) < 3:
        return {"error": f"Too few successful responses ({len(raw_times)} of {samples})."}

    cleaned = apply_outlier_rejection(raw_times, outlier_method, outlier_threshold)
    if len(cleaned) < 3:
        cleaned = raw_times

    return {
        "target": f"{target}{path}",
        "method": method,
        "samples": samples,
        "warmup": warmup,
        "raw_count": len(raw_times),
        "cleaned_count": len(cleaned),
        "outliers_removed": len(raw_times) - len(cleaned),
        "errors": errors,
        "outlier_method": outlier_method,
        "stats": compute_extended_stats(cleaned, "timing_probe"),
        "raw_times_ms": [round(t, 3) for t in raw_times],
    }


@tool(
    name="timing_compare",
    description=(
        "Compare response timing of two HTTP request variants to detect "
        "timing side channels. Uses interleaved sampling and Welch's t-test "
        "for statistical significance."
    ),
)
def timing_compare(
    target: str,
    method_a: str = "POST",
    path_a: str = "/",
    headers_a: dict | None = None,
    body_a: str = "",
    label_a: str = "group_a",
    method_b: str = "POST",
    path_b: str = "/",
    headers_b: dict | None = None,
    body_b: str = "",
    label_b: str = "group_b",
    samples: int = 50,
    warmup: int = 5,
    outlier_method: str = "iqr",
    outlier_threshold: float = 1.5,
) -> dict:
    """Compare timing of two request variants with interleaved sampling.

    Args:
        target: Base URL.
        method_a: HTTP method for variant A.
        path_a: URL path for variant A.
        headers_a: Optional headers for variant A.
        body_a: Optional body for variant A.
        label_a: Label for variant A.
        method_b: HTTP method for variant B.
        path_b: URL path for variant B.
        headers_b: Optional headers for variant B.
        body_b: Optional body for variant B.
        label_b: Label for variant B.
        samples: Total requests per group.
        warmup: Warmup requests (alternating, discarded).
        outlier_method: "iqr", "zscore", or "none".
        outlier_threshold: Threshold for outlier rejection.

    Returns:
        Dict with per-group stats, t-test, effect size, and conclusion.
    """
    if samples < 10:
        return {"error": "Need at least 10 samples (5 per group) for meaningful comparison."}

    total = warmup + samples * 2
    if not interrupt(f"About to send {total} requests to {target} for timing comparison"):
        return {"error": "User declined timing comparison."}

    url_a = f"{target.rstrip('/')}{path_a}"
    url_b = f"{target.rstrip('/')}{path_b}"
    hdrs_a = headers_a or {}
    hdrs_b = headers_b or {}
    body_a_val = body_a or None
    body_b_val = body_b or None

    for i in range(warmup):
        if i % 2 == 0:
            _timed_request(url_a, method_a, hdrs_a, body_a_val)
        else:
            _timed_request(url_b, method_b, hdrs_b, body_b_val)

    times_a: list[float] = []
    times_b: list[float] = []
    errors = 0

    for _i in range(samples):
        status_a, _, ms_a = _timed_request(url_a, method_a, hdrs_a, body_a_val)
        if status_a != 0:
            times_a.append(ms_a)
        else:
            errors += 1

        status_b, _, ms_b = _timed_request(url_b, method_b, hdrs_b, body_b_val)
        if status_b != 0:
            times_b.append(ms_b)
        else:
            errors += 1

    if len(times_a) < 3 or len(times_b) < 3:
        return {"error": f"Too few successful responses (A={len(times_a)}, B={len(times_b)})."}

    clean_a = apply_outlier_rejection(times_a, outlier_method, outlier_threshold)
    clean_b = apply_outlier_rejection(times_b, outlier_method, outlier_threshold)
    if len(clean_a) < 3:
        clean_a = times_a
    if len(clean_b) < 3:
        clean_b = times_b

    stats_a = compute_extended_stats(clean_a, label_a)
    stats_b = compute_extended_stats(clean_b, label_b)
    t_stat, p_value = welch_t_test(clean_a, clean_b)
    d = cohens_d(clean_a, clean_b)
    significant = p_value < 0.05

    import statistics as _st

    mean_diff = _st.mean(clean_a) - _st.mean(clean_b)
    import math

    se_diff = math.sqrt(
        (_st.variance(clean_a) / len(clean_a) if len(clean_a) > 1 else 0)
        + (_st.variance(clean_b) / len(clean_b) if len(clean_b) > 1 else 0)
    )
    margin = 1.96 * se_diff
    diff_ci = (round(mean_diff - margin, 3), round(mean_diff + margin, 3))

    conclusion = (
        f"Statistically significant timing difference detected between {label_a} and {label_b} "
        f"(p={p_value:.2e}, d={d:.2f})."
        if significant
        else f"No significant timing difference between {label_a} and {label_b} (p={p_value:.2e})."
    )

    return {
        "target": target,
        "samples_per_group": samples,
        "interleaved": True,
        "errors": errors,
        "group_a": stats_a,
        "group_b": stats_b,
        "t_statistic": round(t_stat, 4),
        "p_value": p_value,
        "cohens_d": round(d, 4),
        "significant": significant,
        "mean_difference_ms": round(mean_diff, 3),
        "difference_ci_95": list(diff_ci),
        "conclusion": conclusion,
    }


def _rank_candidates(
    candidates: list[str],
    candidate_times: dict[str, list[float]],
    outlier_method: str,
    outlier_threshold: float,
    select: str,
    position: int,
) -> tuple[list[dict], dict[str, Any], str]:
    results: list[dict] = []
    for c in candidates:
        raw = candidate_times[c]
        if len(raw) < 2:
            results.append({"char": c, "mean_ms": 0, "median_ms": 0, "stdev_ms": 0, "n": len(raw), "rank": 0})
            continue
        cleaned = apply_outlier_rejection(raw, outlier_method, outlier_threshold)
        if len(cleaned) < 2:
            cleaned = raw
        stats = compute_stats(cleaned, c)
        results.append({
            "char": c,
            "mean_ms": stats["mean_ms"],
            "median_ms": stats["median_ms"],
            "stdev_ms": stats["stdev_ms"],
            "n": stats["n"],
            "rank": 0,
        })

    results.sort(key=lambda r: r["mean_ms"], reverse=(select == "max"))
    for i, r in enumerate(results):
        r["rank"] = i + 1

    best = results[0] if results else None
    second = results[1] if len(results) > 1 else None

    if not best or not second:
        return results, {}, ""

    best_times = apply_outlier_rejection(candidate_times[best["char"]], outlier_method, outlier_threshold)
    second_times = apply_outlier_rejection(candidate_times[second["char"]], outlier_method, outlier_threshold)
    if len(best_times) < 2:
        best_times = candidate_times[best["char"]]
    if len(second_times) < 2:
        second_times = candidate_times[second["char"]]

    if len(best_times) < 2 or len(second_times) < 2:
        return results, {"char": best["char"], "mean_ms": best["mean_ms"]}, "Insufficient data for significance test."

    t_stat, p_val = welch_t_test(best_times, second_times)
    d = cohens_d(best_times, second_times)
    sig = p_val < 0.05
    best_candidate: dict[str, Any] = {
        "char": best["char"],
        "mean_ms": best["mean_ms"],
        "vs_second": {
            "second_char": second["char"],
            "t_statistic": round(t_stat, 4),
            "p_value": p_val,
            "significant": sig,
            "cohens_d": round(d, 4),
        },
    }
    direction = "longer" if select == "max" else "shorter"
    if sig:
        conclusion = (
            f"Candidate '{best['char']}' at position {position} has significantly "
            f"{direction} response time than runner-up "
            f"'{second['char']}' (p={p_val:.2e}, d={d:.2f})."
        )
    else:
        conclusion = (
            f"No significant timing difference between top candidates "
            f"'{best['char']}' and '{second['char']}' at position {position} (p={p_val:.2e})."
        )
    return results, best_candidate, conclusion


@tool(
    name="timing_bitwise_probe",
    description=(
        "Byte-at-a-time timing attack: test each candidate character at a "
        "given position in a request field. Identifies the candidate producing "
        "the longest or shortest response, indicating a match."
    ),
)
def timing_bitwise_probe(
    target: str,
    method: str = "POST",
    path: str = "/",
    headers: dict | None = None,
    body_template: str = "",
    field_placeholder: str = "{{PROBE}}",
    known_prefix: str = "",
    charset: str = "0123456789abcdef",
    position: int = 0,
    samples_per_candidate: int = 10,
    warmup: int = 3,
    outlier_method: str = "iqr",
    outlier_threshold: float = 1.5,
    select: str = "max",
) -> dict:
    """Byte-at-a-time timing attack.

    Args:
        target: Base URL.
        method: HTTP method.
        path: URL path.
        headers: Optional request headers.
        body_template: Request body with placeholder (e.g. '{"token": "{{PROBE}}"}').
        field_placeholder: Placeholder string to replace with probe value.
        known_prefix: Already-recovered prefix.
        charset: Characters to test at the current position.
        position: Character position being probed (for reporting).
        samples_per_candidate: Timing samples per candidate character.
        warmup: Warmup requests (discarded).
        outlier_method: "iqr", "zscore", or "none".
        outlier_threshold: Threshold for outlier rejection.
        select: "max" (longest response = match) or "min" (shortest = match).

    Returns:
        Dict with ranked candidates, best candidate with significance test, and conclusion.
    """
    if not charset:
        return {"error": "charset must not be empty."}
    if samples_per_candidate < 3:
        return {"error": "Need at least 3 samples per candidate."}

    total = warmup + len(charset) * samples_per_candidate
    if not interrupt(
        f"About to send {total} requests to {target}{path} for bitwise timing probe "
        f"(charset={len(charset)} chars, {samples_per_candidate} samples each)"
    ):
        return {"error": "User declined bitwise probe."}

    url = f"{target.rstrip('/')}{path}"
    req_headers = headers or {}
    candidates = list(charset)

    def _build_body(candidate: str) -> str | None:
        probe_value = known_prefix + candidate
        result = body_template.replace(field_placeholder, probe_value)
        return result if result else None

    for _ in range(warmup):
        body = _build_body(candidates[0])
        _timed_request(url, method, req_headers, body)

    candidate_times: dict[str, list[float]] = {c: [] for c in candidates}

    for _round in range(samples_per_candidate):
        order = list(candidates)
        random.shuffle(order)
        for c in order:
            body = _build_body(c)
            status, _, ms = _timed_request(url, method, req_headers, body)
            if status != 0:
                candidate_times[c].append(ms)

    ranked, best_candidate, conclusion = _rank_candidates(
        candidates, candidate_times, outlier_method, outlier_threshold, select, position,
    )

    return {
        "target": f"{target}{path}",
        "position": position,
        "known_prefix": known_prefix,
        "charset_size": len(candidates),
        "samples_per_candidate": samples_per_candidate,
        "select": select,
        "candidates": ranked,
        "best_candidate": best_candidate,
        "conclusion": conclusion,
    }


def get_timing_tools() -> list[Any]:
    """Return all timing side-channel tools."""
    return [timing_probe, timing_compare, timing_bitwise_probe]
