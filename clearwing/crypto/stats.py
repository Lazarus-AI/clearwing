"""Pure-Python statistical primitives for timing side-channel analysis."""

from __future__ import annotations

import math
import statistics


def compute_stats(times: list[float], label: str) -> dict:
    """Basic descriptive statistics for a timing sample."""
    return {
        "label": label,
        "mean_ms": round(statistics.mean(times), 3),
        "median_ms": round(statistics.median(times), 3),
        "stdev_ms": round(statistics.stdev(times), 3) if len(times) > 1 else 0.0,
        "min_ms": round(min(times), 3),
        "max_ms": round(max(times), 3),
        "n": len(times),
    }


def welch_t_test(a: list[float], b: list[float]) -> tuple[float, float]:
    """Welch's t-test (unequal variance) — returns (t_statistic, p_value)."""
    n1, n2 = len(a), len(b)
    m1, m2 = statistics.mean(a), statistics.mean(b)
    v1 = statistics.variance(a) if n1 > 1 else 0.0
    v2 = statistics.variance(b) if n2 > 1 else 0.0

    se = math.sqrt(v1 / n1 + v2 / n2) if (v1 / n1 + v2 / n2) > 0 else 1e-10
    t = (m1 - m2) / se

    num = (v1 / n1 + v2 / n2) ** 2
    denom = (v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1) if (n1 > 1 and n2 > 1) else 1
    df = num / denom if denom > 0 else 1

    p = t_to_p(abs(t), df)
    return t, p


def t_to_p(t: float, df: float) -> float:
    """Approximate two-tailed p-value from t-statistic."""
    if df > 30:
        p = math.erfc(abs(t) / math.sqrt(2))
        return p
    x = df / (df + t * t)
    p = regularized_beta(x, df / 2, 0.5)
    return p


def regularized_beta(x: float, a: float, b: float, iterations: int = 200) -> float:
    """Regularized incomplete beta function via continued fraction."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0

    ln_prefix = a * math.log(x) + b * math.log(1 - x) - math.log(a)
    try:
        ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    except ValueError:
        return 0.5

    f = 1.0
    c = 1.0
    d = 1.0 - (a + b) * x / (a + 1)
    if abs(d) < 1e-30:
        d = 1e-30
    d = 1.0 / d
    f = d

    for m in range(1, iterations + 1):
        num = m * (b - m) * x / ((a + 2 * m - 1) * (a + 2 * m))
        d = 1.0 + num * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + num / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        f *= d * c

        num = -(a + m) * (a + b + m) * x / ((a + 2 * m) * (a + 2 * m + 1))
        d = 1.0 + num * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + num / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        delta = d * c
        f *= delta

        if abs(delta - 1.0) < 1e-10:
            break

    try:
        result = math.exp(ln_prefix - ln_beta) * f
    except OverflowError:
        return 0.5
    return min(max(result, 0.0), 1.0)


def cohens_d(a: list[float], b: list[float]) -> float:
    """Cohen's d effect size."""
    m1, m2 = statistics.mean(a), statistics.mean(b)
    v1 = statistics.variance(a) if len(a) > 1 else 0.0
    v2 = statistics.variance(b) if len(b) > 1 else 0.0
    pooled_std = math.sqrt((v1 + v2) / 2)
    return abs(m1 - m2) / pooled_std if pooled_std > 0 else 0.0


def percentiles(times: list[float], pcts: list[float] | None = None) -> dict[str, float]:
    """Percentile computation via linear interpolation."""
    if pcts is None:
        pcts = [5, 25, 50, 75, 95]
    sorted_t = sorted(times)
    n = len(sorted_t)
    result: dict[str, float] = {}
    for p in pcts:
        rank = (p / 100) * (n - 1)
        lo = int(rank)
        hi = min(lo + 1, n - 1)
        frac = rank - lo
        result[f"p{int(p)}"] = round(sorted_t[lo] + frac * (sorted_t[hi] - sorted_t[lo]), 3)
    return result


def reject_outliers_iqr(times: list[float], factor: float = 1.5) -> list[float]:
    """Remove outliers outside [Q1 - factor*IQR, Q3 + factor*IQR]."""
    if len(times) < 4:
        return list(times)
    pcts = percentiles(times, [25, 75])
    q1 = pcts["p25"]
    q3 = pcts["p75"]
    iqr = q3 - q1
    lo = q1 - factor * iqr
    hi = q3 + factor * iqr
    return [t for t in times if lo <= t <= hi]


def reject_outliers_zscore(times: list[float], threshold: float = 3.0) -> list[float]:
    """Remove values more than threshold standard deviations from mean."""
    if len(times) < 3:
        return list(times)
    mean = statistics.mean(times)
    stdev = statistics.stdev(times)
    if stdev == 0:
        return list(times)
    return [t for t in times if abs(t - mean) / stdev <= threshold]


_T_CRITICAL_95: dict[int, float] = {
    2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
    7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201,
    12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120,
    17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 25: 2.060,
    30: 2.042,
}


def confidence_interval(times: list[float], confidence: float = 0.95) -> tuple[float, float]:
    """Confidence interval for the mean."""
    n = len(times)
    if n < 2:
        m = times[0] if times else 0.0
        return (m, m)
    mean = statistics.mean(times)
    se = statistics.stdev(times) / math.sqrt(n)

    if confidence != 0.95 or n - 1 > 30:
        z = 1.96 if confidence == 0.95 else 2.576 if confidence == 0.99 else 1.645
        margin = z * se
    else:
        df = n - 1
        t_crit = _T_CRITICAL_95.get(df)
        if t_crit is None:
            closest = min(_T_CRITICAL_95, key=lambda k: abs(k - df))
            t_crit = _T_CRITICAL_95[closest]
        margin = t_crit * se

    return (round(mean - margin, 3), round(mean + margin, 3))


def histogram(times: list[float], bins: int = 10) -> list[dict]:
    """Equal-width histogram with bin edges and counts."""
    if not times:
        return []
    lo, hi = min(times), max(times)
    if lo == hi:
        return [{"bin_start": round(lo, 3), "bin_end": round(hi, 3), "count": len(times), "pct": 100.0}]
    width = (hi - lo) / bins
    n = len(times)
    result: list[dict] = []
    for i in range(bins):
        edge_lo = lo + i * width
        edge_hi = lo + (i + 1) * width
        count = sum(1 for t in times if (edge_lo <= t < edge_hi) or (i == bins - 1 and t == edge_hi))
        result.append({
            "bin_start": round(edge_lo, 3),
            "bin_end": round(edge_hi, 3),
            "count": count,
            "pct": round(100 * count / n, 1),
        })
    return result


def compute_extended_stats(times: list[float], label: str) -> dict:
    """Descriptive statistics with percentiles, confidence interval, and histogram."""
    base = compute_stats(times, label)
    base["percentiles"] = percentiles(times)
    base["confidence_interval_95"] = list(confidence_interval(times))
    base["histogram"] = histogram(times)
    return base


def apply_outlier_rejection(
    times: list[float],
    method: str = "iqr",
    threshold: float = 1.5,
) -> list[float]:
    """Apply outlier rejection by method name."""
    if method == "none":
        return list(times)
    if method == "zscore":
        return reject_outliers_zscore(times, threshold)
    return reject_outliers_iqr(times, threshold)
