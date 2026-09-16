"""Tests for the Recursive SourceHunt HuntFn adapter (§6 real-pipeline seam)."""

from dataclasses import dataclass, field

from clearwing.sourcehunt.hunt_ledger import HuntUnit
from clearwing.sourcehunt.recursive_hunt_adapter import (
    RecursiveHuntFn,
    UnitHuntResult,
    callgraph_file_neighbors,
)


@dataclass
class _FakeCallGraph:
    """Minimal stand-in exposing the two APIs the adapter uses."""

    file_callers: dict = field(default_factory=dict)  # file -> {caller files}
    calls_out: dict = field(default_factory=dict)  # file -> {called names}
    defined_in: dict = field(default_factory=dict)  # name -> {defining files}

    def callers_of_file(self, f):
        return set(self.file_callers.get(f, set()))


def _unit(f):
    return HuntUnit("art", "dig", f)


def test_neighbors_union_callers_and_callees():
    cg = _FakeCallGraph(
        file_callers={"target.c": {"caller.c"}},
        calls_out={"target.c": {"helper"}},
        defined_in={"helper": {"callee.c"}},
    )
    n = callgraph_file_neighbors(cg, "target.c")
    assert n == {"caller.c", "callee.c"}


def test_neighbors_excludes_self_and_handles_none():
    cg = _FakeCallGraph(
        file_callers={"a.c": {"a.c", "b.c"}},
        calls_out={"a.c": {"f"}},
        defined_in={"f": {"a.c", "c.c"}},
    )
    assert callgraph_file_neighbors(cg, "a.c") == {"b.c", "c.c"}
    assert callgraph_file_neighbors(None, "a.c") == set()


def test_benign_returns_no_neighbors():
    fn = RecursiveHuntFn(
        hunt_and_verify=lambda u: UnitHuntResult("benign", 0.8),
        unit_for_file=_unit,
        callgraph=_FakeCallGraph(),
    )
    v = fn(_unit("x.c"))
    assert v.outcome == "benign" and v.neighbors == []


def test_finding_expands_to_callgraph_neighbors():
    cg = _FakeCallGraph(
        file_callers={"x.c": {"up.c"}},
        calls_out={"x.c": {"g"}},
        defined_in={"g": {"down.c"}},
    )
    fn = RecursiveHuntFn(
        hunt_and_verify=lambda u: UnitHuntResult("finding", 0.9, ["F-1"]),
        unit_for_file=_unit,
        callgraph=cg,
        neighbor_priority=3.5,
    )
    v = fn(_unit("x.c"))
    assert v.outcome == "finding" and v.finding_ids == ["F-1"]
    got = {(p, u.file_path) for p, u in v.neighbors}
    assert got == {(3.5, "up.c"), (3.5, "down.c")}


def test_finding_uses_finding_files_when_present():
    cg = _FakeCallGraph(file_callers={"other.c": {"seed.c"}})
    fn = RecursiveHuntFn(
        hunt_and_verify=lambda u: UnitHuntResult("finding", 0.9, ["F"], finding_files=["other.c"]),
        unit_for_file=_unit,
        callgraph=cg,
    )
    v = fn(_unit("x.c"))
    # Expansion is seeded from finding_files (other.c), not the unit file (x.c).
    assert {u.file_path for _, u in v.neighbors} == {"seed.c"}


def test_unit_for_file_none_drops_neighbor():
    cg = _FakeCallGraph(file_callers={"x.c": {"skip.c", "keep.c"}})
    fn = RecursiveHuntFn(
        hunt_and_verify=lambda u: UnitHuntResult("finding", 0.9, ["F"]),
        unit_for_file=lambda f: None if f == "skip.c" else _unit(f),
        callgraph=cg,
    )
    v = fn(_unit("x.c"))
    assert {u.file_path for _, u in v.neighbors} == {"keep.c"}
