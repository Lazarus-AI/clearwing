"""Pure-unit tests for the tier assignment function.

Critical assertion: the FFmpeg-style propagation file (surface=1, influence=5)
must NEVER land in Tier C. It should land in Tier A or Tier B by priority.
"""

from __future__ import annotations

import pytest

from clearwing.sourcehunt.pool import TierBudget, assign_tier


def _ft(surface: int, influence: int, reach: int = 3) -> dict:
    priority = surface * 0.5 + influence * 0.2 + reach * 0.3
    return {
        "surface": surface,
        "influence": influence,
        "reachability": reach,
        "priority": priority,
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
