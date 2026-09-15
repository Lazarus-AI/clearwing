"""Tag-driven ranking re-tuning for Recursive SourceHunt (改修2).

The base ranker scores ``priority = surface*0.5 + influence*0.2 +
reachability*0.3`` (+parser/fuzzable boost). Two problems on real repos:
* the parser tag dominates ``surface`` (state/logic bugs stay at 3);
* integer 1–5 axes give a coarse priority with huge ties (54% of FFmpeg files
  share one value), and ``reachability`` is a dead constant.

This module re-tunes ranking using the semantic sink-class tags produced in
preprocess (:mod:`sink_class_detectors`) and adds a *continuous* static term so
ties break and the true sink surfaces. It does not require a budget/tier cut —
the Recursive mission walks candidates in priority order to fixpoint.

Design ref: Recursive SourceHunt design v1, §5.
"""

from __future__ import annotations

from dataclasses import dataclass

from .sink_class_detectors import SinkClassHit

# Which sink classes justify a high surface, and the floor they impose.
_SURFACE_FLOOR = {
    "sink_representation_domain_collision": 5,
    "sink_index_oob_write": 4,
    "sink_lifecycle_uaf": 4,
}


@dataclass(frozen=True)
class RankWeights:
    w_surface: float = 0.5
    w_influence: float = 0.2
    w_reachability: float = 0.3
    w_static: float = 0.6  # weight of the continuous static term (tie-breaker/lift)


def retuned_surface(base_surface: int, sink_hits: list[SinkClassHit]) -> int:
    """Lift ``surface`` to the floor implied by any sink-class hit.

    A semantic sink-class match is a stronger surface signal than a filename
    'parser' tag, so it raises surface regardless of the LLM's base guess.
    """
    surface = int(base_surface)
    for h in sink_hits:
        surface = max(surface, _SURFACE_FLOOR.get(h.tag, 0))
    return max(1, min(5, surface))


def _static_feature(
    sink_hits: list[SinkClassHit],
    *,
    fan_in: int = 0,
    taint_hits: int = 0,
    fan_in_norm: int = 50,
    taint_norm: int = 5,
) -> float:
    """Continuous 0..~1.x signal from semantic evidence — breaks integer ties.

    Combines the strongest sink-class hit weight with normalized fan-in and
    taint-hit counts. Deterministic and monotone in evidence strength.
    """
    sink = max((h.weight for h in sink_hits), default=0.0)
    fi = min(1.0, fan_in / fan_in_norm) if fan_in_norm else 0.0
    ta = min(1.0, taint_hits / taint_norm) if taint_norm else 0.0
    # sink dominates; fan-in and taint refine ordering within a class
    return sink + 0.3 * fi + 0.3 * ta


def tag_driven_priority(
    *,
    base_surface: int,
    influence: int,
    reachability: int,
    sink_hits: list[SinkClassHit],
    fan_in: int = 0,
    taint_hits: int = 0,
    weights: RankWeights | None = None,
) -> float:
    """Continuous priority with sink-class-lifted surface + static tie-breaker."""
    w = weights or RankWeights()
    surface = retuned_surface(base_surface, sink_hits)
    static = _static_feature(sink_hits, fan_in=fan_in, taint_hits=taint_hits)
    return (
        surface * w.w_surface
        + influence * w.w_influence
        + reachability * w.w_reachability
        + w.w_static * static
    )
