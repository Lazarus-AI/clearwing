"""Wiring test: Ranker._apply_sink_class_boost (Recursive SourceHunt §5).

Verifies that semantic sink-class tags lift surface to the class floor and add a
continuous tie-breaker, while files without sink_classes (legacy/staged) are
unchanged. Runs in CI where deps resolve.
"""

from clearwing.sourcehunt.ranker import Ranker


def _ft(**kw):
    base = {
        "surface": 3,
        "influence": 3,
        "reachability": 3,
        "priority": 0.0,
        "tags": [],
        "sink_classes": [],
        "taint_hits": 0,
        "imports_by": 0,
        "surface_rationale": "",
    }
    base.update(kw)
    return base


def test_no_sink_class_is_noop():
    r = Ranker(None)  # llm unused by this method
    ft = _ft()
    ft["priority"] = r._compute_priority(ft)  # 3*0.5+3*0.2+3*0.3 = 3.0
    r._apply_sink_class_boost(ft)
    assert ft["surface"] == 3 and ft["priority"] == 3.0


def test_sink_class_lifts_surface_and_breaks_tie():
    r = Ranker(None)
    peer = _ft()
    peer["priority"] = r._compute_priority(peer)  # 3.0 (the median-tie value)

    target = _ft(
        sink_classes=["live_identifier_aliases_reserved_sentinel"],
        taint_hits=2,
        imports_by=40,
    )
    target["priority"] = r._compute_priority(target)  # base 3.0 before boost
    r._apply_sink_class_boost(target)

    assert target["surface"] == 5  # representation-domain-collision floor
    assert target["priority"] > peer["priority"]  # lifted above the tie
    assert "sink-class" in target["surface_rationale"]


def test_index_oob_uses_lower_floor():
    r = Ranker(None)
    ft = _ft(sink_classes=["allocation_access_extent_contrast"])
    ft["priority"] = r._compute_priority(ft)
    r._apply_sink_class_boost(ft)
    assert ft["surface"] == 4  # non-sentinel sink floor
