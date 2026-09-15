"""Tests for semantic sink-class detection + tag-driven ranking (改修2)."""

from clearwing.sourcehunt.sink_class_detectors import (
    DETECTOR_SET_VERSION,
    detect_sink_classes,
    sink_class_tags,
)
from clearwing.sourcehunt.tag_ranker import (
    RankWeights,
    retuned_surface,
    tag_driven_priority,
)

# Mimics the real libavcodec/h264_slice.c representation-domain-collision:
# slice_table memset to -1 (=0xFFFF sentinel), slice_num = ++current_slice,
# used as an index/mask, and compared to the 0xFFFF sentinel.
SENTINEL_COLLISION_C = """
static int h264_slice_header_init(H264Context *h, H264SliceContext *sl) {
    memset(h->slice_table, -1, (h->mb_height * h->mb_stride - 1) * sizeof(*h->slice_table));
    sl->slice_num = ++h->current_slice;
    if (sl->slice_num)
        h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)] = sl->resync_mb_y;
    if (h->slice_table[top_xy] == 0xFFFF)
        return 0;
    return 1;
}
"""

# A benign file with an incremented counter but no sentinel-on-array indexing.
BENIGN_COUNTER_C = """
static int next_id(Ctx *c) {
    int n = ++c->counter;
    log_line("id=%d", n);
    return n;
}
"""


def test_representation_domain_collision_fires_on_sentinel_pattern():
    hits = detect_sink_classes("libavcodec/h264_slice.c", SENTINEL_COLLISION_C)
    tags = sink_class_tags(hits)
    assert "sink_representation_domain_collision" in tags
    hit = next(h for h in hits if h.tag == "sink_representation_domain_collision")
    assert hit.suspected_mechanism == "live_identifier_aliases_reserved_sentinel"


def test_representation_domain_collision_precise_on_benign():
    hits = detect_sink_classes("util/counter.c", BENIGN_COUNTER_C)
    assert "sink_representation_domain_collision" not in sink_class_tags(hits)


def test_detector_set_version_is_stamped():
    assert DETECTOR_SET_VERSION  # non-empty; used as a ledger salvage trigger


def test_sink_class_lifts_surface():
    hits = detect_sink_classes("libavcodec/h264_slice.c", SENTINEL_COLLISION_C)
    # base surface 3 (memory_unsafe only) → lifted to the collision floor (5)
    assert retuned_surface(3, hits) == 5
    assert retuned_surface(3, []) == 3  # no hit → unchanged


def test_tag_driven_priority_breaks_tie_and_lifts_target():
    hits = detect_sink_classes("libavcodec/h264_slice.c", SENTINEL_COLLISION_C)
    # Target: base surface 3, but a sink-class hit.
    target = tag_driven_priority(
        base_surface=3, influence=3, reachability=3, sink_hits=hits, fan_in=40, taint_hits=2
    )
    # A tied peer with the same base scores but no semantic hit.
    peer = tag_driven_priority(
        base_surface=3, influence=3, reachability=3, sink_hits=[], fan_in=0, taint_hits=0
    )
    assert target > peer  # tie broken + lifted
    # And it should clear a parser-tagged decoy that lacks the sink class:
    parser_decoy = tag_driven_priority(
        base_surface=4, influence=3, reachability=3, sink_hits=[], fan_in=10, taint_hits=0
    )
    assert target > parser_decoy


def test_reachability_contributes_when_real():
    w = RankWeights()
    low = tag_driven_priority(base_surface=3, influence=3, reachability=1, sink_hits=[])
    high = tag_driven_priority(base_surface=3, influence=3, reachability=5, sink_hits=[])
    assert high > low  # revived reachability axis is no longer a dead constant
