"""Semantic sink-class detectors for Recursive SourceHunt preprocess (改修2).

These are *general*, source-derived compound detectors — no target-specific
knowledge. Each recognizes a high-severity vulnerability CLASS that the
filename/extension heuristics miss, and emits a semantic tag the tag-driven
ranker uses to lift the file (see :mod:`tag_ranker`).

The flagship detector is ``representation-domain-collision`` (a live value
aliasing a reserved sentinel — e.g. an incremented id colliding with a 0xFFFF
"unowned" marker used as an array/state index). Empirically this compound
pattern is highly discriminating: on FFmpeg it fires on exactly 1 of 4979 files
(``libavcodec/h264_slice.c``, the real bug) and 0 of FreeRDP (a different OOB
class), so it is precise per-class rather than a broad density signal.

Implementation is a regex prototype (matches the validated proof-of-concept);
production should port these to tree-sitter / dataflow. Detector identity and
``suspected_mechanism`` mirror the proof engine's ``CandidatePipeline``
generators so the two stay aligned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Detector-set version — bump when detectors change. The hunt ledger uses this
# as a salvage trigger (capability change re-opens prior benign verdicts).
DETECTOR_SET_VERSION = "sink-v1"


@dataclass(frozen=True)
class SinkClassHit:
    detector: str  # e.g. "representation-domain-collision"
    suspected_mechanism: str  # mirrors proof CandidatePipeline mechanisms
    tag: str  # semantic tag consumed by the ranker
    evidence: list[str] = field(default_factory=list)
    weight: float = 1.0  # contribution to the continuous priority term (0..1)


# --- patterns (general, no target-specific tokens) --------------------------

_SENT_ON_ARRAY = re.compile(
    r"\w+\s*\[[^\]\n]{1,80}\]\s*(?:==|!=)\s*"
    r"(?:0x0*[fF]{3,}|0x[fF]{4}|-\s*1|U?INT\d*_MAX|U?SHRT_MAX|UINT\d*_MAX)"
)
_MEMSET_SENTINEL = re.compile(r"memset\s*\([^,;\n]+,\s*(?:-\s*1|0x[fF]{2,}|255|65535)\s*,")
_ID_FROM_INCR = re.compile(r"(\w+)\s*=\s*\+\+\s*\w+")
_INDEXED_WRITE = re.compile(r"\w+\s*\[[^\]\n]{1,80}\]\s*=\s*[^=]")
_MEM_WRITE_CALL = re.compile(r"\b(?:memcpy|memmove|memset|strcpy|strcat|sprintf)\s*\(")
_FREE_CALL = re.compile(r"\b(?:free|kfree|av_free|av_freep|release|Release|Destroy|delete)\s*\(\s*(\w+)")


def _incr_id_used_as_index(text: str) -> tuple[bool, list[str]]:
    ids = {m.group(1) for m in _ID_FROM_INCR.finditer(text)}
    ev: list[str] = []
    for i in ids:
        if re.search(r"\[[^\]\n]*\b" + re.escape(i) + r"\b[^\]\n]*\]", text) or re.search(
            r"\b" + re.escape(i) + r"\b\s*[&%]", text
        ):
            ev.append(i)
    return (bool(ev), ev)


def _detect_representation_domain_collision(path: str, text: str) -> SinkClassHit | None:
    """Live identifier aliasing a reserved sentinel used for indexing/state.

    Compound: (sentinel compared against an array element OR a memset that
    establishes a reserved sentinel over an array) AND (an increment-produced
    identifier used as an array index or bit-mask). This co-occurrence is rare
    and marks the representation-domain-collision class (CWE-787-ish).
    """
    sent = bool(_SENT_ON_ARRAY.search(text)) or bool(_MEMSET_SENTINEL.search(text))
    idx, ids = _incr_id_used_as_index(text)
    if sent and idx:
        return SinkClassHit(
            detector="representation-domain-collision",
            suspected_mechanism="live_identifier_aliases_reserved_sentinel",
            tag="sink_representation_domain_collision",
            evidence=[f"incr_id={','.join(sorted(ids))}", "sentinel_on_array"],
            weight=1.0,
        )
    return None


def _detect_index_oob_write(path: str, text: str) -> SinkClassHit | None:
    """High density of computed-index writes / raw memory writes (coarse)."""
    loc = max(1, text.count("\n"))
    writes = len(_INDEXED_WRITE.findall(text)) + len(_MEM_WRITE_CALL.findall(text))
    density = writes / loc * 1000.0
    if writes >= 8 and density >= 20.0:
        return SinkClassHit(
            detector="index-oob-write",
            suspected_mechanism="allocation_access_extent_contrast",
            tag="sink_index_oob_write",
            evidence=[f"indexed_writes={writes}", f"per_kloc={density:.1f}"],
            weight=min(1.0, density / 60.0),
        )
    return None


def _detect_lifecycle_uaf(path: str, text: str) -> SinkClassHit | None:
    """free(x)/release(x) followed later by a use of x (coarse UAF hint)."""
    for m in _FREE_CALL.finditer(text):
        var = m.group(1)
        after = text[m.end() :]
        # subsequent deref/index/call use of the same variable
        if re.search(r"\b" + re.escape(var) + r"\b\s*(?:->|\[|\.)", after) or re.search(
            r"\(\s*" + re.escape(var) + r"\b", after
        ):
            return SinkClassHit(
                detector="lifecycle-uaf",
                suspected_mechanism="dereference_after_release",
                tag="sink_lifecycle_uaf",
                evidence=[f"released_then_used={var}"],
                weight=0.6,
            )
    return None


_DETECTORS = (
    _detect_representation_domain_collision,
    _detect_index_oob_write,
    _detect_lifecycle_uaf,
)


def detect_sink_classes(path: str, content: str) -> list[SinkClassHit]:
    """Run all sink-class detectors on one file's source text."""
    hits: list[SinkClassHit] = []
    for det in _DETECTORS:
        try:
            hit = det(path, content)
        except re.error:
            hit = None
        if hit is not None:
            hits.append(hit)
    return hits


def sink_class_tags(hits: list[SinkClassHit]) -> list[str]:
    return [h.tag for h in hits]
