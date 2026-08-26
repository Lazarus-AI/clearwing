from unittest.mock import patch

from clearwing.ui.llm_activity import (
    _estimated_remaining_seconds,
    _fmt_duration,
    _reasoning_preview,
    _timestamped_event,
)


def test_fmt_duration_uses_compact_wall_clock_units() -> None:
    assert _fmt_duration(42) == "42s"
    assert _fmt_duration(125) == "2m 5s"
    assert _fmt_duration(7380) == "2h 3m"


def test_wall_clock_estimate_tracks_observed_budget_pace() -> None:
    # $2 spent in 60 seconds against a $10 budget projects four more minutes.
    assert _estimated_remaining_seconds(60, 2, 10) == 240


def test_wall_clock_estimate_waits_for_a_useful_rate() -> None:
    assert _estimated_remaining_seconds(4, 1, 10) is None
    assert _estimated_remaining_seconds(60, 0, 10) is None
    assert _estimated_remaining_seconds(60, 1, None) is None


def test_live_feed_event_gets_local_wall_clock_timestamp() -> None:
    with patch("clearwing.ui.llm_activity.time.strftime", return_value="21:17:42"):
        event = _timestamped_event({"text": "investigating"})

    assert event["ts"] == "21:17:42"


def test_reasoning_preview_prefers_latest_paragraph() -> None:
    assert _reasoning_preview("Old exploration.\n\nVerify the branch cache next.") == (
        "Verify the branch cache next."
    )


def test_reasoning_preview_keeps_the_recent_tail_when_long() -> None:
    preview = _reasoning_preview("x" * 300, limit=40)
    assert preview == "…" + "x" * 39
