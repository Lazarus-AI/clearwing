"""Recursive deepening orchestrator for the Recursive SourceHunt mission.

Implements the §6 loop and the §10 resilience (resume + watchdog) over the
backbone (:mod:`hunt_ledger`, :mod:`prepare_cache`) and the semantic ranking
(:mod:`tag_ranker`, :mod:`sink_class_detectors`).

Loop: a priority queue seeded from the ranker; pop the highest-priority unit;
skip it if the ledger says exclude (already benign / not re-eligible); otherwise
hunt+verify it; on a confirmed/suspected finding, recursively expand to
callgraph/taint neighbors; continue to fixpoint (queue empty) or a safety cap.

The hunt+verify step and the neighbor-expansion step are injected
(:class:`HuntFn` / neighbors returned in the :class:`Verdict`) so this module is
pure control logic — production wires the real hunter/verifier/proof engine and
callgraph, tests use fakes. The watchdog enforces a per-unit hard timeout and
invokes a kill callback (SIGTERM→SIGKILL of the unit's sandbox subprocess in
production; the cancel API does not reap zombies, so the watchdog kills
directly), marks the unit error, and continues so one zombie never stalls the
run. Design ref: v1 §6 & §10.
"""

from __future__ import annotations

import heapq
import itertools
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from .hunt_ledger import HuntLedger, HuntUnit, VerdictContext


@dataclass
class Verdict:
    outcome: str  # "benign" | "finding" | "error"
    confidence: float = 0.0
    finding_ids: list[str] = field(default_factory=list)
    neighbors: list[tuple[float, HuntUnit]] = field(default_factory=list)  # (priority, unit)


# A hunt unit is hunted+verified by this injected callable.
HuntFn = Callable[[HuntUnit], Verdict]
# Optional kill callback for the watchdog (production: SIGTERM→SIGKILL the PID).
KillFn = Callable[[HuntUnit], None]


@dataclass
class RecursiveConfig:
    max_iterations: int = 100_000  # safety valve, NOT a budget
    unit_hard_timeout: float = 1800.0  # seconds per unit before force-kill
    checkpoint_every: int = 1  # persist checkpoint every N completed units


@dataclass
class RecursionCheckpoint:
    run_id: str
    queue: list[tuple[float, int, dict]]  # (neg_priority, seq, unit_dict)
    visited: list[str]
    iterations: int
    updated_at: float


class CheckpointStore(Protocol):
    def save(self, ckpt: RecursionCheckpoint) -> None: ...
    def load(self, run_id: str) -> Optional[RecursionCheckpoint]: ...
    def delete(self, run_id: str) -> None: ...


@dataclass
class RunResult:
    run_id: str
    hunted: int
    excluded: int
    findings: list[str]
    errors: int
    iterations: int
    stopped_reason: str  # "fixpoint" | "max_iterations"


class RecursiveOrchestrator:
    def __init__(
        self,
        ledger: HuntLedger,
        hunt_fn: HuntFn,
        context: VerdictContext,
        *,
        checkpoint_store: Optional["CheckpointStore"] = None,
        config: RecursiveConfig | None = None,
        kill_fn: Optional[KillFn] = None,
        now: Callable[[], float] = time.time,
        sample_draw: Callable[[], float] = lambda: 1.0,
    ):
        self.ledger = ledger
        self.hunt_fn = hunt_fn
        self.context = context
        self.checkpoint_store = checkpoint_store
        self.config = config or RecursiveConfig()
        self.kill_fn = kill_fn
        self._now = now
        self._sample_draw = sample_draw
        self._seq = itertools.count()

    # --- resume support -----------------------------------------------------
    def has_resumable(self, run_id: str) -> bool:
        if self.checkpoint_store is None:
            return False
        return self.checkpoint_store.load(run_id) is not None

    def run(
        self,
        run_id: str,
        seed_units: list[tuple[float, HuntUnit]] | None = None,
        *,
        resume: bool = False,
    ) -> RunResult:
        heap: list[tuple[float, int, HuntUnit]] = []
        visited: set[str] = set()
        iterations = 0

        if resume and self.checkpoint_store is not None:
            ckpt = self.checkpoint_store.load(run_id)
            if ckpt is not None:
                visited = set(ckpt.visited)
                iterations = ckpt.iterations
                for neg_pri, seq, ud in ckpt.queue:
                    heapq.heappush(heap, (neg_pri, seq, HuntUnit(**ud)))
        if not heap:
            for pri, unit in seed_units or []:
                heapq.heappush(heap, (-pri, next(self._seq), unit))

        hunted = excluded = errors = 0
        findings: list[str] = []
        stopped = "fixpoint"

        completed = 0
        while heap:
            if iterations >= self.config.max_iterations:
                stopped = "max_iterations"
                break
            iterations += 1
            neg_pri, _seq, unit = heapq.heappop(heap)
            if unit.key() in visited:
                continue

            decision = self.ledger.should_hunt(
                unit, self.context, now=self._now(), sample_draw=self._sample_draw()
            )
            if not decision.hunt:
                visited.add(unit.key())
                excluded += 1
                continue

            self.ledger.record_start(unit)
            verdict = self._hunt_with_watchdog(unit)
            visited.add(unit.key())

            if verdict.outcome == "finding":
                self.ledger.record_finding(unit, self.context, verdict.finding_ids, now=self._now())
                findings.extend(verdict.finding_ids)
                hunted += 1
                # recursive deepening: expand to neighbors
                for npri, nunit in verdict.neighbors:
                    if nunit.key() not in visited:
                        heapq.heappush(heap, (-npri, next(self._seq), nunit))
            elif verdict.outcome == "benign":
                self.ledger.record_benign(unit, self.context, now=self._now())
                hunted += 1
            else:  # error (incl. watchdog kill)
                self.ledger.record_error(unit, now=self._now())
                errors += 1
                # bounded retry is decided by the ledger on the next visit; we
                # remove from visited so a retry can re-enter within this run.
                d2 = self.ledger.should_hunt(unit, self.context, now=self._now())
                if d2.hunt and d2.reason == "retry_error":
                    visited.discard(unit.key())
                    heapq.heappush(heap, (neg_pri, next(self._seq), unit))

            completed += 1
            if self.checkpoint_store is not None and completed % self.config.checkpoint_every == 0:
                self._save_checkpoint(run_id, heap, visited, iterations)

        # Terminal checkpoint handling: a fixpoint (queue drained) means the run
        # is genuinely done — delete the checkpoint so a later invocation over
        # the same source starts fresh rather than "resuming" a finished run.
        # A non-fixpoint stop (max_iterations, or an interruption that never
        # reaches here) leaves the last checkpoint in place so it is resumable.
        if self.checkpoint_store is not None:
            if stopped == "fixpoint":
                self.checkpoint_store.delete(run_id)
            else:
                self._save_checkpoint(run_id, heap, visited, iterations)
        return RunResult(
            run_id=run_id,
            hunted=hunted,
            excluded=excluded,
            findings=findings,
            errors=errors,
            iterations=iterations,
            stopped_reason=stopped,
        )

    # --- watchdog -----------------------------------------------------------
    def _hunt_with_watchdog(self, unit: HuntUnit) -> Verdict:
        """Run hunt_fn under a hard timeout; on overrun, force-kill and error.

        In production the unit runs as a sandbox subprocess; ``kill_fn`` issues
        SIGTERM→SIGKILL of that PID (cancel does not reap zombies). Here we
        enforce the wall-clock cap; the timed-out worker is abandoned and the
        unit is marked error (→ bounded retry by the ledger).
        """
        # Not a `with` block: on timeout we must NOT wait for the runaway task
        # (that would negate the timeout). shutdown(wait=False) lets the loop
        # proceed; in production kill_fn ends the real sandbox subprocess so the
        # worker returns promptly.
        pool = ThreadPoolExecutor(max_workers=1)
        fut = pool.submit(self.hunt_fn, unit)
        try:
            result = fut.result(timeout=self.config.unit_hard_timeout)
            pool.shutdown(wait=False)
            return result
        except FutureTimeout:
            if self.kill_fn is not None:
                try:
                    self.kill_fn(unit)
                except Exception:
                    pass
            pool.shutdown(wait=False)
            return Verdict(outcome="error", confidence=0.0)
        except Exception:
            pool.shutdown(wait=False)
            return Verdict(outcome="error", confidence=0.0)

    def _save_checkpoint(
        self,
        run_id: str,
        heap: list[tuple[float, int, HuntUnit]],
        visited: set[str],
        iterations: int,
    ) -> None:
        assert self.checkpoint_store is not None
        queue = [
            (neg_pri, seq, {"artifact_id": u.artifact_id, "source_digest": u.source_digest,
                            "file_path": u.file_path, "symbol": u.symbol})
            for (neg_pri, seq, u) in heap
        ]
        self.checkpoint_store.save(
            RecursionCheckpoint(
                run_id=run_id,
                queue=queue,
                visited=sorted(visited),
                iterations=iterations,
                updated_at=self._now(),
            )
        )


class InMemoryCheckpointStore:
    """Reference checkpoint store (within-process resume only)."""

    def __init__(self) -> None:
        self._by_run: dict[str, RecursionCheckpoint] = {}

    def save(self, ckpt: RecursionCheckpoint) -> None:
        self._by_run[ckpt.run_id] = ckpt

    def load(self, run_id: str) -> Optional[RecursionCheckpoint]:
        return self._by_run.get(run_id)

    def delete(self, run_id: str) -> None:
        self._by_run.pop(run_id, None)


class SqliteCheckpointStore:
    """Persistent checkpoint store — cross-process resume of a recursive run.

    A file ``path`` lets a run interrupted by a crash / OOM / container restart
    resume from its last checkpoint on the next invocation (§10.1). A run that
    reaches its fixpoint deletes its checkpoint, so only genuinely-unfinished
    runs are resumable. ``check_same_thread=False`` + lock because the
    orchestrator drives it from an ``asyncio.to_thread`` worker.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS recursion_checkpoint "
            "(run_id TEXT PRIMARY KEY, json TEXT NOT NULL)"
        )
        self._db.commit()

    def save(self, ckpt: RecursionCheckpoint) -> None:
        payload = json.dumps(
            {
                "run_id": ckpt.run_id,
                "queue": ckpt.queue,
                "visited": ckpt.visited,
                "iterations": ckpt.iterations,
                "updated_at": ckpt.updated_at,
            }
        )
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO recursion_checkpoint (run_id, json) VALUES (?,?)",
                (ckpt.run_id, payload),
            )
            self._db.commit()

    def load(self, run_id: str) -> Optional[RecursionCheckpoint]:
        with self._lock:
            row = self._db.execute(
                "SELECT json FROM recursion_checkpoint WHERE run_id=?", (run_id,)
            ).fetchone()
        if not row:
            return None
        d = json.loads(row[0])
        # JSON turns each (neg_pri, seq, unit_dict) tuple into a list; the resume
        # path unpacks it positionally, so lists are fine — normalize to tuples.
        queue = [tuple(item) for item in d.get("queue", [])]
        return RecursionCheckpoint(
            run_id=d["run_id"],
            queue=queue,
            visited=list(d.get("visited", [])),
            iterations=int(d.get("iterations", 0)),
            updated_at=float(d.get("updated_at", 0.0)),
        )

    def delete(self, run_id: str) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM recursion_checkpoint WHERE run_id=?", (run_id,)
            )
            self._db.commit()
