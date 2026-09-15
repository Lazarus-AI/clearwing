"""Recursive SourceHunt — HuntFn adapter and callgraph neighbor expansion (§6).

Bridges the pure-logic :class:`RecursiveOrchestrator` to the runner's real
per-unit hunt/verify machinery. Two concerns live here, both kept free of the
runner's heavy construction context so they are unit-testable on their own:

1. :func:`callgraph_file_neighbors` — given a file that produced a finding,
   returns the neighboring files worth deepening into (callers + callees).
2. :class:`RecursiveHuntFn` — wraps an injected per-unit ``hunt_and_verify``
   callable and returns a :class:`Verdict`, attaching callgraph neighbors as
   recursion frontier when the unit yields a finding.

The one runtime seam that *does* need the runner (constructing the Hunter /
verifier and calling ``_hunt`` + ``_verify`` for a single file) is passed in as
``hunt_and_verify`` so this module stays deterministic and dependency-light.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from clearwing.sourcehunt.hunt_ledger import HuntUnit
from clearwing.sourcehunt.recursive_orchestrator import Verdict

# (outcome, confidence, finding_ids) returned by the injected per-unit hunt.
HuntAndVerify = Callable[[HuntUnit], "UnitHuntResult"]


@dataclass
class UnitHuntResult:
    """Outcome of hunting + verifying a single unit (file/symbol)."""

    outcome: str  # "finding" | "benign" | "error"
    confidence: float
    finding_ids: list[str] = field(default_factory=list)
    # Files implicated by the findings, used to seed callgraph expansion. When
    # empty the adapter falls back to the unit's own file.
    finding_files: list[str] = field(default_factory=list)


def callgraph_file_neighbors(callgraph: Any, file_path: str) -> set[str]:
    """Return files adjacent to ``file_path`` in the callgraph (both directions).

    A memory bug that surfaces in one file is frequently *reachable from* or
    *reaches into* a neighbor: the caller that supplies the tainted length, or
    the callee that performs the write. We deepen into both:

    - callers: files that call any function defined in ``file_path``
    - callees: files that define any function called from ``file_path``

    ``file_path`` itself is never returned. Safe on a ``None`` / empty
    callgraph (returns an empty set), so the orchestrator degrades to a flat
    frontier when reachability analysis was disabled on a large repo.
    """
    if callgraph is None:
        return set()

    neighbors: set[str] = set()

    # Upstream: who calls into this file.
    try:
        neighbors |= callgraph.callers_of_file(file_path)
    except Exception:  # pragma: no cover - defensive against partial graphs
        pass

    # Downstream: files defining the functions this file calls.
    try:
        called_names = callgraph.calls_out.get(file_path, set())
        for name in called_names:
            neighbors |= callgraph.defined_in.get(name, set())
    except Exception:  # pragma: no cover
        pass

    neighbors.discard(file_path)
    return neighbors


@dataclass
class RecursiveHuntFn:
    """Callable adapter: HuntUnit -> Verdict, with callgraph deepening.

    ``hunt_and_verify`` runs the real per-unit hunt+verify and returns a
    :class:`UnitHuntResult`. ``callgraph`` (optional) drives neighbor expansion
    on findings; ``unit_for_file`` builds a :class:`HuntUnit` for a neighbor
    file (so artifact_id / digest are carried forward consistently).
    ``neighbor_priority`` scores a freshly discovered neighbor.
    """

    hunt_and_verify: HuntAndVerify
    unit_for_file: Callable[[str], HuntUnit | None]
    callgraph: Any = None
    neighbor_priority: float = 3.0

    def __call__(self, unit: HuntUnit) -> Verdict:
        res = self.hunt_and_verify(unit)
        if res.outcome != "finding":
            return Verdict(res.outcome, res.confidence, list(res.finding_ids))

        # A finding: expand the recursion frontier to callgraph neighbors of
        # every file the findings touched (fall back to the unit's own file).
        seed_files = list(res.finding_files) or [unit.file_path]
        neighbor_files: set[str] = set()
        for f in seed_files:
            neighbor_files |= callgraph_file_neighbors(self.callgraph, f)

        neighbors: list[tuple[float, HuntUnit]] = []
        for nf in sorted(neighbor_files):
            nunit = self.unit_for_file(nf)
            if nunit is not None:
                neighbors.append((self.neighbor_priority, nunit))

        return Verdict(
            "finding",
            res.confidence,
            list(res.finding_ids),
            neighbors=neighbors,
        )
