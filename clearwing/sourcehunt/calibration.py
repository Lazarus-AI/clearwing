"""Severity calibration tracking (spec 009).

Tracks agreement between discoverer, validator, and human severity
assessments over time. Target: 89% exact match (Glasswing reference).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import threading
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# Module-level lock so concurrent in-process CalibrationStore instances
# (e.g. CLI + test + another thread) serialize against each other even
# when they point at the same file via different instances.
_STORE_LOCK = threading.Lock()

#: Severity values accepted across calibration. Validated by the
#: pydantic model — a typo writes a loud ValidationError instead of
#: silently corrupting the exact-match / within-one ratio math.
Severity = Literal["critical", "high", "medium", "low", "info"]


@contextlib.contextmanager
def _calibration_lock(path: Path):
    """Serialize calibration-log reads/writes.

    Acquires the module-level threading lock (in-process) and an
    exclusive `flock` on a sidecar `.lock` file (cross-process).
    Any code that reads-then-writes the calibration JSONL must hold
    this — otherwise a concurrent `append` between load and write
    silently drops records (the bug this fix addresses).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with _STORE_LOCK:
        with open(lock_path, "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class CalibrationRecord(BaseModel):
    """One row in the severity-calibration JSONL.

    Immutable after construction (`frozen=True`) so callers can't
    mutate in-place and desync with the on-disk representation —
    updates go through `model_copy(update=...)`.

    `extra="ignore"` lets us load historical rows that predate newer
    fields without blowing up; the discarded keys are logged by the
    reader if useful.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    finding_id: str
    session_id: str
    cwe: str
    discoverer_severity: Severity
    validator_severity: Severity | None = None
    human_severity: Severity | None = None
    axes: dict[str, bool] = Field(default_factory=dict)
    timestamp: str = ""
    exact_match: bool | None = None
    within_one: bool | None = None


class CalibrationStore:
    """Append-only JSONL store for severity calibration records."""

    @staticmethod
    def _default_path() -> Path:
        from clearwing.core.config import clearwing_home

        return clearwing_home() / "sourcehunt" / "calibration.jsonl"

    def __init__(self, path: Path | str | None = None):
        self._path = Path(path) if path else self._default_path()

    def append(self, record: CalibrationRecord) -> None:
        line = record.model_dump_json() + "\n"
        try:
            with _calibration_lock(self._path):
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(line)
        except OSError:
            logger.warning("Failed to write calibration record", exc_info=True)

    def record_human_verdict(
        self,
        finding_id: str,
        session_id: str,
        human_severity: Severity,
    ) -> None:
        # Hold the lock across the whole read-modify-write. Without this,
        # any concurrent `append()` landing between the load and the
        # rewrite is silently dropped when the temp file is renamed
        # over the data file.
        with _calibration_lock(self._path):
            records = self._load_all_unlocked()
            updated = []
            for r in records:
                if r.finding_id == finding_id and r.session_id == session_id:
                    patch: dict[str, Any] = {"human_severity": human_severity}
                    if r.validator_severity:
                        patch["exact_match"] = r.validator_severity == human_severity
                        v_rank = _SEVERITY_RANK[r.validator_severity]
                        h_rank = _SEVERITY_RANK[human_severity]
                        patch["within_one"] = abs(v_rank - h_rank) <= 1
                    updated.append(r.model_copy(update=patch))
                else:
                    updated.append(r)
            self._write_all_unlocked(updated)

    def load_all(self) -> list[CalibrationRecord]:
        # Public read: acquires the lock so a caller iterating results
        # doesn't race against concurrent writes. For the
        # read-modify-write internal path, `_load_all_unlocked` is used
        # while the caller already holds the lock.
        with _calibration_lock(self._path):
            return self._load_all_unlocked()

    def _load_all_unlocked(self) -> list[CalibrationRecord]:
        if not self._path.exists():
            return []
        records = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                # `extra="ignore"` on the model lets historical rows with
                # retired fields still load; a schema addition won't
                # break the whole file.
                records.append(CalibrationRecord.model_validate_json(line))
            except (ValueError, json.JSONDecodeError):
                # `ValueError` covers pydantic `ValidationError`.
                logger.warning("Skipping malformed calibration row: %r", line[:80])
                continue
        return records

    def stats(self) -> dict[str, Any]:
        records = self.load_all()
        with_human = [r for r in records if r.human_severity is not None]
        if not with_human:
            return {
                "total_records": len(records),
                "human_reviewed": 0,
                "exact_match_rate": 0.0,
                "within_one_rate": 0.0,
            }
        exact = sum(1 for r in with_human if r.exact_match is True)
        within = sum(1 for r in with_human if r.within_one is True)
        return {
            "total_records": len(records),
            "human_reviewed": len(with_human),
            "exact_match_rate": exact / len(with_human),
            "within_one_rate": within / len(with_human),
        }

    def _write_all_unlocked(self, records: list[CalibrationRecord]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for r in records:
                f.write(r.model_dump_json() + "\n")
        tmp.replace(self._path)
