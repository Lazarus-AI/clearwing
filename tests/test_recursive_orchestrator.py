"""Tests for the Recursive SourceHunt orchestrator (§6 loop + §10 resilience)."""

import time

from clearwing.sourcehunt.hunt_ledger import (
    HuntLedger,
    HuntUnit,
    SalvagePolicy,
    SqliteHuntLedgerStore,
    VerdictContext,
)
from clearwing.sourcehunt.recursive_orchestrator import (
    InMemoryCheckpointStore,
    RecursiveConfig,
    RecursiveOrchestrator,
    Verdict,
)

_CTX = VerdictContext("glm-local", "sink-v1", "c1", verifier_confidence=0.9)


def _unit(f: str) -> HuntUnit:
    return HuntUnit("art", "dig", f)


def _ledger() -> HuntLedger:
    return HuntLedger(
        SqliteHuntLedgerStore(), SalvagePolicy(cooldown_seconds=1000.0, max_retries=1)
    )


def _benign(_u):
    return Verdict("benign", 0.9)


def test_basic_loop_reaches_fixpoint():
    o = RecursiveOrchestrator(_ledger(), _benign, _CTX)
    r = o.run("run", [(5.0, _unit("a.c")), (4.0, _unit("b.c"))])
    assert r.hunted == 2 and r.excluded == 0 and r.stopped_reason == "fixpoint"


def test_recursive_expansion_reaches_neighbors():
    def hunt(u):
        if u.file_path == "a.c":
            return Verdict("finding", 0.9, ["F-a"], neighbors=[(3.0, _unit("b.c"))])
        return Verdict("benign", 0.8)

    o = RecursiveOrchestrator(_ledger(), hunt, _CTX)
    r = o.run("run", [(5.0, _unit("a.c"))])
    assert r.hunted == 2 and r.findings == ["F-a"]


def test_excludes_pre_benign_unit():
    ledger = _ledger()
    ledger.record_benign(_unit("b.c"), _CTX, now=1000.0)
    seen: list[str] = []

    def hunt(u):
        seen.append(u.file_path)
        return Verdict("benign", 0.9)

    o = RecursiveOrchestrator(ledger, hunt, _CTX, now=lambda: 1001.0)
    r = o.run("run", [(5.0, _unit("b.c")), (4.0, _unit("c.c"))])
    assert r.excluded == 1 and "b.c" not in seen and "c.c" in seen


def test_visited_prevents_infinite_loop():
    def hunt(_u):
        return Verdict("finding", 0.9, ["F"], neighbors=[(9.0, _unit("a.c"))])

    o = RecursiveOrchestrator(_ledger(), hunt, _CTX)
    r = o.run("run", [(5.0, _unit("a.c"))])
    assert r.hunted == 1


def test_watchdog_kills_and_continues():
    killed: list[str] = []

    def slow(_u):
        time.sleep(0.5)
        return Verdict("benign", 0.9)

    o = RecursiveOrchestrator(
        _ledger(),
        slow,
        _CTX,
        config=RecursiveConfig(unit_hard_timeout=0.15),
        kill_fn=lambda u: killed.append(u.file_path),
    )
    t0 = time.time()
    r = o.run("run", [(5.0, _unit("z.c"))])
    assert killed and r.errors >= 1 and (time.time() - t0) < 5.0


def test_resume_from_checkpoint():
    cs = InMemoryCheckpointStore()
    o1 = RecursiveOrchestrator(
        _ledger(), _benign, _CTX, checkpoint_store=cs, config=RecursiveConfig(max_iterations=1)
    )
    r1 = o1.run("run", [(5.0, _unit("a.c")), (4.0, _unit("b.c")), (3.0, _unit("c.c"))])
    o2 = RecursiveOrchestrator(
        _ledger(), _benign, _CTX, checkpoint_store=cs, config=RecursiveConfig(max_iterations=100)
    )
    r2 = o2.run("run", None, resume=True)
    assert r1.stopped_reason == "max_iterations" and (r1.hunted + r2.hunted) == 3


def test_max_iterations_safety_valve():
    o = RecursiveOrchestrator(_ledger(), _benign, _CTX, config=RecursiveConfig(max_iterations=2))
    r = o.run("run", [(5.0, _unit(f"{i}.c")) for i in range(5)])
    assert r.stopped_reason == "max_iterations"


# --- §10.1 persistent cross-process checkpoint / resume ---------------------


def test_sqlite_checkpoint_persists_and_resumes_across_instances():
    """A run stopped by max_iterations leaves a checkpoint in a file-backed
    store; a fresh orchestrator+store over the same file resumes and finishes."""
    import tempfile

    from clearwing.sourcehunt.recursive_orchestrator import SqliteCheckpointStore

    dbfile = tempfile.mkdtemp() + "/ckpt.db"
    units = [(5.0, _unit(f"{i}.c")) for i in range(4)]

    cs1 = SqliteCheckpointStore(dbfile)
    o1 = RecursiveOrchestrator(
        _ledger(), _benign, _CTX, checkpoint_store=cs1, config=RecursiveConfig(max_iterations=2)
    )
    r1 = o1.run("run-x", units)
    assert r1.stopped_reason == "max_iterations"

    # Fresh store instance over the same file must see the checkpoint.
    cs2 = SqliteCheckpointStore(dbfile)
    assert cs2.load("run-x") is not None
    o2 = RecursiveOrchestrator(
        _ledger(), _benign, _CTX, checkpoint_store=cs2, config=RecursiveConfig(max_iterations=100)
    )
    assert o2.has_resumable("run-x")
    r2 = o2.run("run-x", None, resume=True)
    assert (r1.hunted + r2.hunted) == 4 and r2.stopped_reason == "fixpoint"


def test_sqlite_checkpoint_deleted_on_fixpoint():
    """A run that reaches fixpoint deletes its checkpoint so a later run starts
    fresh (does not 'resume' a finished run)."""
    import tempfile

    from clearwing.sourcehunt.recursive_orchestrator import SqliteCheckpointStore

    dbfile = tempfile.mkdtemp() + "/ckpt.db"
    cs = SqliteCheckpointStore(dbfile)
    o = RecursiveOrchestrator(_ledger(), _benign, _CTX, checkpoint_store=cs)
    r = o.run("run-y", [(5.0, _unit("a.c"))])
    assert r.stopped_reason == "fixpoint"
    assert cs.load("run-y") is None  # cleared
    assert not o.has_resumable("run-y")
