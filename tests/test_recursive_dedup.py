"""Report-quality helpers for the recursive flow: dedup + ranking.

Recursive deepening re-emits the same lead many times (e.g. lodepng: 45 raw ->
6 unique, one lead x18). `_dedup_rank_recursive_findings` collapses duplicates
to one record per (file, line, finding_type), keeping the strongest instance,
and ranks the survivors strongest-first. Detection/verification are untouched.
"""

from clearwing.sourcehunt.runner import (
    _dedup_rank_recursive_findings,
    _recursive_finding_rank,
    _recursive_fixpoint_completion,
    _recursive_scope_excluded,
    _select_recursive_findings_for_verification,
)


def test_dedup_collapses_duplicate_leads_keeping_strongest() -> None:
    findings = [
        {
            "file": "a.c",
            "line_number": 10,
            "finding_type": "oob",
            "severity": "low",
            "evidence_level": "suspicion",
        },
        {
            "file": "a.c",
            "line_number": 10,
            "finding_type": "oob",
            "severity": "high",
            "evidence_level": "crash_reproduced",
            "verified": True,
        },
        {
            "file": "a.c",
            "line_number": 10,
            "finding_type": "oob",
            "severity": "medium",
            "evidence_level": "root_cause_explained",
        },
    ]
    out = _dedup_rank_recursive_findings(findings)
    assert len(out) == 1
    # the strongest instance survives (verified, high, crash_reproduced)
    assert out[0]["verified"] is True
    assert out[0]["severity"] == "high"


def test_dedup_ranks_strongest_first() -> None:
    findings = [
        {
            "file": "x.c",
            "line_number": 1,
            "finding_type": "info_leak",
            "severity": "info",
            "evidence_level": "suspicion",
        },
        {
            "file": "y.c",
            "line_number": 2,
            "finding_type": "uaf",
            "severity": "high",
            "evidence_level": "crash_reproduced",
            "verified": True,
        },
        {
            "file": "z.c",
            "line_number": 3,
            "finding_type": "overflow",
            "severity": "medium",
            "evidence_level": "static_corroboration",
        },
    ]
    out = _dedup_rank_recursive_findings(findings)
    assert [f["severity"] for f in out] == ["high", "medium", "info"]
    assert out[0]["verified"] is True


def test_dedup_retains_distinct_and_keyless_findings() -> None:
    findings = [
        {"file": "a.c", "line_number": 10, "finding_type": "oob", "severity": "low"},
        {"file": "a.c", "line_number": 11, "finding_type": "oob", "severity": "low"},
        {"file": "", "line_number": None, "finding_type": None, "severity": "medium"},
    ]
    out = _dedup_rank_recursive_findings(findings)
    # two distinct keyed + one keyless passthrough
    assert len(out) == 3


def test_dedup_normalizes_workspace_path() -> None:
    # same lead reported with an absolute sandbox path and a repo-relative path
    findings = [
        {
            "file": "/workspace/lodepng_util.cpp",
            "line_number": 199,
            "finding_type": "out_of_bounds_read",
            "severity": "high",
            "evidence_level": "static_corroboration",
        },
        {
            "file": "lodepng_util.cpp",
            "line_number": 199,
            "finding_type": "out_of_bounds_read",
            "severity": "high",
            "evidence_level": "crash_reproduced",
            "verified": True,
        },
    ]
    out = _dedup_rank_recursive_findings(findings)
    assert len(out) == 1
    assert out[0]["evidence_level"] == "crash_reproduced"


def test_finding_rank_ordering() -> None:
    verified_high = {"verified": True, "severity": "high", "evidence_level": "crash_reproduced"}
    plain_low = {"severity": "low", "evidence_level": "suspicion"}
    assert _recursive_finding_rank(verified_high) > _recursive_finding_rank(plain_low)


def test_verification_budget_prefers_strongest_and_normalizes_paths() -> None:
    weak = {
        "file": "/workspace/src/parser.c",
        "line_number": 12,
        "finding_type": "overflow",
        "severity": "low",
        "evidence_level": "suspicion",
    }
    strong = {
        "file": "src/parser.c",
        "line_number": 12,
        "finding_type": "overflow",
        "severity": "high",
        "evidence_level": "crash_reproduced",
        "verified": True,
    }
    distinct = {
        "file": "src/decoder.c",
        "line_number": 7,
        "finding_type": "out_of_bounds_read",
        "severity": "medium",
    }
    seen: set[tuple[str, int, str]] = set()

    selected, deferred, remaining = _select_recursive_findings_for_verification(
        [weak, distinct, strong], seen, 1
    )

    assert selected == [strong]
    assert deferred == 1
    assert remaining == 0
    assert len(seen) == 2


def test_recursive_scope_excludes_non_shipping_paths_and_root_harnesses() -> None:
    excluded_dirs = {"tests", "vendor"}
    suffixes = ("_test", "_fuzzer")

    assert _recursive_scope_excluded("tests/parser.c", excluded_dirs, suffixes)
    assert _recursive_scope_excluded("parser_fuzzer.c", excluded_dirs, suffixes)
    assert not _recursive_scope_excluded("src/parser.c", excluded_dirs, suffixes)
    assert not _recursive_scope_excluded("tests/parser.c", set(), suffixes)


def test_fixpoint_preserves_completed_degraded_policy() -> None:
    incomplete, detail = _recursive_fixpoint_completion("fixpoint", True, 3, 2)
    assert incomplete is False
    assert detail == (
        "Verification bounded to top-N by convergence policy; "
        "2 verified, 3 leads deferred unverified"
    )

    incomplete, detail = _recursive_fixpoint_completion("max_iterations", True, 3, 2)
    assert incomplete is True
    assert detail is None
