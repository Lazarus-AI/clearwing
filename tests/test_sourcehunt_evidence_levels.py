"""Unit tests for the evidence ladder.

The evidence_level field gates downstream budget allocation in the source-hunt
pipeline. These tests pin down the ordering and the budget-gate filter.
"""
from __future__ import annotations

import pytest

from clearwing.sourcehunt.state import (
    EVIDENCE_LEVELS,
    evidence_at_or_above,
    evidence_compare,
    filter_by_evidence,
)


class TestEvidenceLevelsOrdering:
    """The ladder is a strict total ordering."""

    def test_ladder_is_six_levels(self):
        assert len(EVIDENCE_LEVELS) == 6

    def test_ladder_order(self):
        assert EVIDENCE_LEVELS == (
            "suspicion",
            "static_corroboration",
            "crash_reproduced",
            "root_cause_explained",
            "exploit_demonstrated",
            "patch_validated",
        )


class TestEvidenceCompare:
    def test_equal(self):
        assert evidence_compare("crash_reproduced", "crash_reproduced") == 0

    def test_lower(self):
        assert evidence_compare("suspicion", "crash_reproduced") == -1

    def test_higher(self):
        assert evidence_compare("patch_validated", "exploit_demonstrated") == 1


class TestEvidenceAtOrAbove:
    def test_self(self):
        for level in EVIDENCE_LEVELS:
            assert evidence_at_or_above(level, level)

    def test_above_threshold(self):
        assert evidence_at_or_above("crash_reproduced", "static_corroboration")
        assert evidence_at_or_above("patch_validated", "suspicion")

    def test_below_threshold(self):
        assert not evidence_at_or_above("suspicion", "crash_reproduced")
        assert not evidence_at_or_above("static_corroboration", "exploit_demonstrated")


class TestFilterByEvidence:
    """The budget-gate filter — the function the Exploiter uses to decide
    which findings deserve expensive agent budget."""

    def _findings(self, *levels):
        return [{"id": f"f{i}", "evidence_level": lvl} for i, lvl in enumerate(levels)]

    def test_filter_keeps_at_or_above(self):
        findings = self._findings(
            "suspicion",
            "static_corroboration",
            "crash_reproduced",
            "root_cause_explained",
        )
        kept = filter_by_evidence(findings, "crash_reproduced")
        assert len(kept) == 2
        assert {f["id"] for f in kept} == {"f2", "f3"}

    def test_filter_drops_all_below(self):
        findings = self._findings("suspicion", "static_corroboration")
        kept = filter_by_evidence(findings, "crash_reproduced")
        assert kept == []

    def test_missing_evidence_level_treated_as_suspicion(self):
        findings = [{"id": "noisy"}]   # no evidence_level field
        # Suspicion >= suspicion → kept
        assert filter_by_evidence(findings, "suspicion") == findings
        # Suspicion < crash_reproduced → dropped
        assert filter_by_evidence(findings, "crash_reproduced") == []

    def test_exploiter_gate(self):
        """The exploiter only runs on findings >= crash_reproduced."""
        findings = [
            {"id": "ranker_only", "evidence_level": "suspicion"},
            {"id": "regex_hit", "evidence_level": "static_corroboration"},
            {"id": "asan_crash", "evidence_level": "crash_reproduced"},
            {"id": "explained", "evidence_level": "root_cause_explained"},
        ]
        eligible = filter_by_evidence(findings, "crash_reproduced")
        assert {f["id"] for f in eligible} == {"asan_crash", "explained"}

    def test_auto_patcher_gate(self):
        """The auto-patcher only runs on findings >= root_cause_explained."""
        findings = [
            {"id": "a", "evidence_level": "crash_reproduced"},
            {"id": "b", "evidence_level": "root_cause_explained"},
            {"id": "c", "evidence_level": "exploit_demonstrated"},
        ]
        eligible = filter_by_evidence(findings, "root_cause_explained")
        assert {f["id"] for f in eligible} == {"b", "c"}

    def test_gold_standard(self):
        """patch_validated is the highest level — only itself qualifies."""
        findings = [
            {"id": "x", "evidence_level": "exploit_demonstrated"},
            {"id": "y", "evidence_level": "patch_validated"},
        ]
        kept = filter_by_evidence(findings, "patch_validated")
        assert [f["id"] for f in kept] == ["y"]
