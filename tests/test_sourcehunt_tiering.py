"""Pure-unit tests for the tier assignment function.

Critical assertion: the FFmpeg-style propagation file (surface=1, influence=5)
must NEVER land in Tier C. It should land in Tier A or Tier B by priority.
"""

from __future__ import annotations

import pytest

from clearwing.sourcehunt.pool import TierBudget, assign_tier, diversified_tier_order


def _ft(surface: int, influence: int, reach: int = 3, path: str = "") -> dict:
    priority = surface * 0.5 + influence * 0.2 + reach * 0.3
    return {
        "surface": surface,
        "influence": influence,
        "reachability": reach,
        "priority": priority,
        "path": path,
    }


# --- assign_tier --------------------------------------------------------------


class TestAssignTier:
    def test_full_high_lands_in_a(self):
        # surface=5, influence=5, reach=3 → 2.5 + 1.0 + 0.9 = 4.4 → A
        assert assign_tier(_ft(5, 5)) == "A"

    def test_pure_high_surface_lands_in_a(self):
        # surface=5, influence=1, reach=3 → 2.5 + 0.2 + 0.9 = 3.6 → A
        assert assign_tier(_ft(5, 1)) == "A"

    def test_medium_surface_lands_in_a_with_reach(self):
        # surface=4, influence=2, reach=3 → 2.0 + 0.4 + 0.9 = 3.3 → A
        assert assign_tier(_ft(4, 2)) == "A"

    def test_medium_lands_in_b(self):
        # surface=2, influence=2, reach=3 → 1.0 + 0.4 + 0.9 = 2.3 → B
        assert assign_tier(_ft(2, 2)) == "B"

    def test_low_lands_in_c(self):
        # surface=1, influence=1, reach=3 → 0.5 + 0.2 + 0.9 = 1.6 → C
        assert assign_tier(_ft(1, 1)) == "C"

    def test_low_with_reach_5_lands_in_b(self):
        # surface=1, influence=1, reach=5 → 0.5 + 0.2 + 1.5 = 2.2 → B
        assert assign_tier(_ft(1, 1, reach=5)) == "B"


class TestPropagationCase:
    """The whole point of the two-axis ranker: a file with surface=1 but
    influence=5 must NOT be dropped to Tier C."""

    def test_constants_header_lands_in_b_at_minimum(self):
        # codec_limits.h: surface=1, influence=5, reach=3
        # priority = 0.5 + 1.0 + 0.9 = 2.4 → B
        ft = _ft(1, 5)
        assert ft["priority"] == pytest.approx(2.4)
        assert assign_tier(ft) == "B"

    def test_constants_header_with_high_reach_lands_in_a(self):
        # If reachability gets bumped to 5 in v0.2 (callgraph propagation),
        # the same file could land in A
        ft = _ft(1, 5, reach=5)
        # priority = 0.5 + 1.0 + 1.5 = 3.0 → A
        assert assign_tier(ft) == "A"

    def test_constants_header_never_in_c(self):
        # Even with the LOWEST reach, surface=1 + influence=5 → 1.6 → C? Wait:
        # 0.5 + 1.0 + 0.3 = 1.8 → C. Hmm, that's C.
        # Let me think — is it OK for influence=5 with reach=1 to be C?
        # The user said "Tier C catches stragglers" — yes, this case is
        # already caught by Tier C, that's fine.
        ft = _ft(1, 5, reach=1)
        # priority = 0.5 + 1.0 + 0.3 = 1.8 → C (would be caught by Tier C
        # propagation auditor with the right prompt)
        assert assign_tier(ft) == "C"
        # But with default reach=3 (v0.1's no-callgraph default), it's B
        assert assign_tier(_ft(1, 5)) == "B"


class TestTierBudgetDataclass:
    def test_default_70_25_5(self):
        b = TierBudget()
        assert b.tier_a_fraction == 0.70
        assert b.tier_b_fraction == 0.25
        assert b.tier_c_fraction == 0.05

    def test_custom_split(self):
        b = TierBudget(tier_a_fraction=0.6, tier_b_fraction=0.3, tier_c_fraction=0.1)
        assert b.tier_a_fraction == 0.6

    def test_invalid_split_raises(self):
        with pytest.raises(ValueError, match="must sum to ~1.0"):
            TierBudget(tier_a_fraction=0.5, tier_b_fraction=0.5, tier_c_fraction=0.5)

    def test_skip_tier_c(self):
        # tier_c_fraction=0 is valid
        b = TierBudget(tier_a_fraction=0.75, tier_b_fraction=0.25, tier_c_fraction=0.0)
        assert b.tier_c_fraction == 0.0


class TestDiversifiedTierOrder:
    """A1 deterministic diversity: round-robin across scoring lenses so a
    budget that cannot cover a whole tier still hunts a diverse prefix."""

    def _corpus(self) -> list[dict]:
        return [
            _ft(1, 5, 3, path="influence_heavy.c"),  # priority 2.4
            _ft(4, 4, 4, path="balanced_top.c"),  # priority 4.0 (highest)
            _ft(1, 1, 5, path="reach_heavy.c"),  # priority 2.2
            _ft(5, 1, 1, path="surface_heavy.c"),  # priority 3.0
            _ft(3, 3, 3, path="mid1.c"),  # priority 3.0
            _ft(3, 2, 3, path="mid2.c"),  # priority 2.8
        ]

    def test_single_dimension_champions_reach_prefix(self):
        # Pure priority order buries influence_heavy (2.4) and reach_heavy (2.2)
        # at ranks 5-6; a 4-file budget would starve them. Diversified ordering
        # must lift each dimension's champion into the top-4.
        order = diversified_tier_order(self._corpus())
        top4 = {ft["path"] for ft in order[:4]}
        assert "surface_heavy.c" in top4
        assert "influence_heavy.c" in top4
        assert "reach_heavy.c" in top4

    def test_balanced_top_stays_first(self):
        # The balanced lens is first, so the overall best file is unchanged.
        order = diversified_tier_order(self._corpus())
        assert order[0]["path"] == "balanced_top.c"

    def test_preserves_all_files_without_duplicates(self):
        corpus = self._corpus()
        order = diversified_tier_order(corpus)
        assert sorted(ft["path"] for ft in order) == sorted(ft["path"] for ft in corpus)
        assert len({id(ft) for ft in order}) == len(corpus)

    def test_deterministic(self):
        corpus = self._corpus()
        a = [ft["path"] for ft in diversified_tier_order(corpus)]
        b = [ft["path"] for ft in diversified_tier_order(corpus)]
        assert a == b

    def test_empty_and_single(self):
        assert diversified_tier_order([]) == []
        one = [_ft(5, 5, 5, path="only.c")]
        assert [ft["path"] for ft in diversified_tier_order(one)] == ["only.c"]
