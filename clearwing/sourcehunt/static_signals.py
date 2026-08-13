"""Target-blind static security signals shared by ranking and hunter tools."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class StaticSignal:
    """A language-generic source pattern used only to prioritize review."""

    name: str
    pattern: re.Pattern[str]
    weight: int


@dataclass(frozen=True)
class StaticSignalScore:
    """Auditable evidence behind one file's deterministic ranking score."""

    score: float
    counts: dict[str, int]
    top_anchor_scores: tuple[int, ...]

    @property
    def diversity(self) -> int:
        return len(self.counts)


STATIC_SECURITY_SIGNALS: tuple[StaticSignal, ...] = (
    StaticSignal(
        "memory_operation",
        re.compile(r"\b(?:memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf)\s*\("),
        7,
    ),
    StaticSignal(
        "allocation_lifetime",
        re.compile(r"\b(?:malloc|calloc|realloc|free|new|delete|alloc|release|unref)\b"),
        6,
    ),
    StaticSignal(
        "representation_transition",
        re.compile(
            r"(?:\(\s*(?:u?int(?:8|16|32)_t|char|short)\s*\)|"
            r"=\s*(?:\+\+|--)[^;]+|[^;]+(?:\+\+|--)\s*;)"
        ),
        5,
    ),
    StaticSignal(
        "reserved_value_state",
        re.compile(r"(?:\bmemset\b[^;]*(?:-1|0x[fF]{2,})|(?:==|!=)\s*(?:-1|0x[fF]{2,}))"),
        5,
    ),
    StaticSignal(
        "size_arithmetic",
        re.compile(
            r"\b(?:size|len|count|width|height|offset|stride|index|idx)\w*\b"
            r"[^;]*(?:\+|-|\*|<<|>>)"
        ),
        4,
    ),
    StaticSignal(
        "input_boundary",
        re.compile(r"\b(?:parse|decode|read|get_bits|packet|header|request|input)\w*\b", re.I),
        3,
    ),
    StaticSignal(
        "pointer_index",
        re.compile(r"(?:->\w+\s*\[[^]]+\]|\b\w+\s*\[[^]]+\]\s*=|\*\s*\([^)]*[+-][^)]*\))"),
        3,
    ),
    StaticSignal(
        "security_guard",
        re.compile(r"\bif\s*\([^)]*(?:<=|>=|<|>|==|!=)[^)]*\)"),
        1,
    ),
)


_NON_PRODUCTION_COMPONENT = re.compile(
    r"^(?:tests?|docs?|examples?|benchmarks?|fuzz(?:er|ers|ing)?)$",
    re.I,
)
_NON_PRODUCTION_TOKEN = re.compile(
    r"(?:^|[_-])(?:test|tests|example|examples|benchmark|benchmarks|fuzz|fuzzer|fuzzers)"
    r"(?:[_-]|$)",
    re.I,
)


def is_production_source_path(path: str) -> bool:
    """Exclude generic test, documentation, example, benchmark, and fuzz paths."""

    parts = PurePosixPath(path.replace("\\", "/")).parts
    return not any(
        _NON_PRODUCTION_COMPONENT.match(part)
        or _NON_PRODUCTION_TOKEN.search(PurePosixPath(part).stem)
        for part in parts
    )


def line_security_signals(line: str) -> list[tuple[str, int]]:
    """Return generic signal categories and weights present on one line."""

    return [
        (signal.name, signal.weight)
        for signal in STATIC_SECURITY_SIGNALS
        if signal.pattern.search(line)
    ]


def score_source_security_signals(
    source: str,
    *,
    saturation_count: int = 5,
    max_anchors: int = 8,
) -> StaticSignalScore:
    """Score source without target, repository, or known-answer hints.

    Each category saturates after repeated evidence so large files and dense
    memory-operation loops cannot dominate by volume alone. A bounded set of
    the strongest individual lines preserves local signal interactions.
    """

    counts: Counter[str] = Counter()
    anchor_scores: list[int] = []
    for line in source.splitlines():
        matches = line_security_signals(line)
        if not matches:
            continue
        counts.update(name for name, _weight in matches)
        anchor_scores.append(sum(weight for _name, weight in matches))

    saturation_denominator = math.log1p(max(1, saturation_count))
    coverage_score = sum(
        signal.weight
        * min(1.0, math.log1p(counts[signal.name]) / saturation_denominator)
        for signal in STATIC_SECURITY_SIGNALS
    )
    top_anchor_scores = tuple(sorted(anchor_scores, reverse=True)[:max_anchors])
    diversity_score = 2.0 * len(counts)
    local_evidence_score = 0.5 * sum(top_anchor_scores)
    return StaticSignalScore(
        score=coverage_score + diversity_score + local_evidence_score,
        counts=dict(sorted(counts.items())),
        top_anchor_scores=top_anchor_scores,
    )


__all__ = [
    "STATIC_SECURITY_SIGNALS",
    "StaticSignal",
    "StaticSignalScore",
    "is_production_source_path",
    "line_security_signals",
    "score_source_security_signals",
]
