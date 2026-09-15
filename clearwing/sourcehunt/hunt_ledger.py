"""Hunt-state ledger for the Recursive SourceHunt mission.

Tracks, per hunt unit ``(artifact_id, source_digest, file_path[, symbol])``,
whether the unit has been hunted and the verdict context, so that:

* R1 (exclusion) — already-hunted units are skipped by default, reallocating
  finite compute to unvisited/changed units;
* R2 (salvage)   — a "benign" verdict is never a *permanent* exclusion: it is
  re-eligible when the content changed, the analysis capability changed
  (model / detector set / config), the benign verdict had low confidence, or a
  post-cooldown variance sample selects it (to catch LLM-variance re-detection).

Design ref: Recursive SourceHunt design v1, §4a. Storage is abstracted behind
:class:`HuntLedgerStore`; a SQLite reference implementation is provided so the
logic runs and is testable standalone, and can later be backed by a host
artifact store without changing the policy code.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional, Protocol


class HuntState(str, Enum):
    NOT_HUNTED = "not_hunted"
    IN_PROGRESS = "in_progress"
    BENIGN = "benign"
    FINDING = "finding"
    ERROR = "error"


@dataclass(frozen=True)
class VerdictContext:
    """The analysis capability under which a verdict was reached.

    A benign verdict is only trustworthy for the *same* capability; any change
    here re-opens the unit for salvage.
    """

    model_id: str = ""
    detector_set_version: str = ""
    analysis_config_version: str = ""
    verifier_confidence: float = 0.0  # 0..1 (evidence strength of the verdict)


@dataclass
class HuntUnit:
    """Identity of a hunt unit. ``source_digest`` is part of the identity, so a
    content change naturally produces a distinct (not-yet-hunted) unit."""

    artifact_id: str
    source_digest: str
    file_path: str
    symbol: Optional[str] = None

    def key(self) -> str:
        return "|".join([self.artifact_id, self.source_digest, self.file_path, self.symbol or ""])


@dataclass
class HuntRecord:
    unit: HuntUnit
    state: HuntState = HuntState.NOT_HUNTED
    last_hunted_at: Optional[float] = None  # None => never hunted
    hunt_count: int = 0
    context: VerdictContext = field(default_factory=VerdictContext)
    finding_ids: list[str] = field(default_factory=list)
    retry_count: int = 0
    cooldown_until: Optional[float] = None
    variance_sampled_at: Optional[float] = None


@dataclass(frozen=True)
class SalvagePolicy:
    confidence_threshold: float = 0.7  # benign below this is re-eligible sooner
    cooldown_seconds: float = 7 * 24 * 3600.0  # decay before variance sampling
    variance_sample_rate: float = 0.05  # fraction of eligible benign re-drawn/run
    max_retries: int = 3  # error retries before quarantine


@dataclass(frozen=True)
class EligibilityDecision:
    hunt: bool
    reason: str


class HuntLedgerStore(Protocol):
    def get(self, key: str) -> Optional[HuntRecord]: ...
    def put(self, record: HuntRecord) -> None: ...
    def list_by_state(self, state: HuntState) -> list[HuntRecord]: ...


class HuntLedger:
    """Policy layer over a :class:`HuntLedgerStore`.

    ``should_hunt`` is the §4a.4 re-eligibility decision; it is pure given
    ``now`` and ``sample_draw`` (a 0..1 value, injected for deterministic tests
    and for centralized per-run sampling-quota control).
    """

    def __init__(self, store: "HuntLedgerStore", policy: SalvagePolicy | None = None):
        self.store = store
        self.policy = policy or SalvagePolicy()

    # --- decision -----------------------------------------------------------
    def should_hunt(
        self,
        unit: HuntUnit,
        current: VerdictContext,
        *,
        now: float | None = None,
        sample_draw: float = 1.0,
    ) -> EligibilityDecision:
        now = time.time() if now is None else now
        rec = self.store.get(unit.key())

        # Never seen (or content changed → distinct key) → hunt.
        if rec is None or rec.state in (HuntState.NOT_HUNTED, HuntState.ERROR):
            if rec is not None and rec.state == HuntState.ERROR:
                if rec.retry_count >= self.policy.max_retries:
                    return EligibilityDecision(False, "quarantined_error")
                return EligibilityDecision(True, "retry_error")
            return EligibilityDecision(True, "not_hunted")

        if rec.state == HuntState.IN_PROGRESS:
            # Interrupted/crashed mid-hunt (see §10): re-hunt idempotently.
            return EligibilityDecision(True, "resume_in_progress")

        if rec.state == HuntState.FINDING:
            if self._capability_changed(rec.context, current):
                return EligibilityDecision(True, "reverify_finding_capability_change")
            return EligibilityDecision(False, "track_finding")

        # rec.state == BENIGN → salvage rules
        if self._capability_changed(rec.context, current):
            return EligibilityDecision(True, "salvage_capability_change")
        if rec.context.verifier_confidence < self.policy.confidence_threshold:
            return EligibilityDecision(True, "salvage_low_confidence")
        if rec.cooldown_until is not None and now >= rec.cooldown_until:
            if sample_draw < self.policy.variance_sample_rate:
                return EligibilityDecision(True, "salvage_variance_sample")
        return EligibilityDecision(False, "excluded_benign")

    @staticmethod
    def _capability_changed(prev: VerdictContext, cur: VerdictContext) -> bool:
        return (
            prev.model_id != cur.model_id
            or prev.detector_set_version != cur.detector_set_version
            or prev.analysis_config_version != cur.analysis_config_version
        )

    # --- transitions --------------------------------------------------------
    def record_start(self, unit: HuntUnit) -> HuntRecord:
        rec = self.store.get(unit.key()) or HuntRecord(unit=unit)
        rec.state = HuntState.IN_PROGRESS
        self.store.put(rec)
        return rec

    def record_benign(
        self, unit: HuntUnit, context: VerdictContext, *, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        rec = self.store.get(unit.key()) or HuntRecord(unit=unit)
        rec.state = HuntState.BENIGN
        rec.last_hunted_at = now
        rec.hunt_count += 1
        rec.context = context
        rec.cooldown_until = now + self.policy.cooldown_seconds
        self.store.put(rec)

    def record_finding(
        self,
        unit: HuntUnit,
        context: VerdictContext,
        finding_ids: list[str],
        *,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        rec = self.store.get(unit.key()) or HuntRecord(unit=unit)
        rec.state = HuntState.FINDING
        rec.last_hunted_at = now
        rec.hunt_count += 1
        rec.context = context
        rec.finding_ids = list(finding_ids)
        self.store.put(rec)

    def record_error(self, unit: HuntUnit, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        rec = self.store.get(unit.key()) or HuntRecord(unit=unit)
        rec.state = HuntState.ERROR
        rec.last_hunted_at = now
        rec.retry_count += 1
        self.store.put(rec)


# --- SQLite reference store --------------------------------------------------


class SqliteHuntLedgerStore:
    """SQLite-backed ledger store. A file ``path`` persists the ledger across
    runs (the point of §4a: R1 exclusion / R2 salvage only work when verdicts
    survive between runs); ``:memory:`` stays available for tests.

    ``check_same_thread=False`` + a lock: the recursive orchestrator's
    ``run()`` executes on an ``asyncio.to_thread`` worker (a different thread
    from where the runner constructs this store), and its ledger reads/writes
    are serialized by the orchestrator's single-threaded loop, so a shared
    connection guarded by one lock is safe.
    """

    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS hunt_ledger (key TEXT PRIMARY KEY, json TEXT NOT NULL, state TEXT NOT NULL)"
        )
        self._db.commit()

    def get(self, key: str) -> Optional[HuntRecord]:
        with self._lock:
            row = self._db.execute("SELECT json FROM hunt_ledger WHERE key=?", (key,)).fetchone()
        return _record_from_json(row[0]) if row else None

    def put(self, record: HuntRecord) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hunt_ledger (key, json, state) VALUES (?,?,?)",
                (record.unit.key(), _record_to_json(record), record.state.value),
            )
            self._db.commit()

    def list_by_state(self, state: HuntState) -> list[HuntRecord]:
        with self._lock:
            rows = self._db.execute(
                "SELECT json FROM hunt_ledger WHERE state=?", (state.value,)
            ).fetchall()
        return [_record_from_json(r[0]) for r in rows]


def _record_to_json(rec: HuntRecord) -> str:
    d = asdict(rec)
    d["state"] = rec.state.value
    return json.dumps(d)


def _record_from_json(s: str) -> HuntRecord:
    d = json.loads(s)
    unit = HuntUnit(**d["unit"])
    ctx = VerdictContext(**d.get("context", {}))
    return HuntRecord(
        unit=unit,
        state=HuntState(d["state"]),
        last_hunted_at=d.get("last_hunted_at"),
        hunt_count=d.get("hunt_count", 0),
        context=ctx,
        finding_ids=d.get("finding_ids", []),
        retry_count=d.get("retry_count", 0),
        cooldown_until=d.get("cooldown_until"),
        variance_sampled_at=d.get("variance_sampled_at"),
    )
