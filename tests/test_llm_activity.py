from unittest.mock import patch

from clearwing.ui.llm_activity import (
    _estimated_remaining_seconds,
    _fmt_duration,
    _reasoning_preview,
    _timestamped_event,
    _trace_context_header,
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


def test_trace_context_header_displays_root_hunt_ids() -> None:
    header = _trace_context_header(
        lambda: (
            "656901efba4302f09db3999290711fb0",
            "8f1b7ac92e644691",
        )
    )

    assert header is not None
    assert header.plain == (
        "trace-id 656901efba4302f09db3999290711fb0"
        "  ·  span-id 8f1b7ac92e644691"
    )


def test_trace_context_header_shows_pending_until_root_span_starts() -> None:
    header = _trace_context_header(lambda: (None, None))

    assert header is not None
    assert header.plain == "trace-id pending  ·  span-id pending"
