"""Disclosure workflow database — SQLite storage for spec 011.

Tracks findings through the human-validation and coordinated-disclosure
lifecycle. Three tables: findings (state + metadata), reviews (audit trail),
timelines (90+45 day CVD deadlines).

DB location: ~/.clearwing/sourcehunt/disclosures.db
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from clearwing.reporting.safety import redact_text, redact_tree

from .state import DisclosureState

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    repo_url TEXT NOT NULL,
    session_id TEXT NOT NULL,
    file TEXT,
    line_number INTEGER,
    finding_type TEXT,
    cwe TEXT,
    severity TEXT,
    severity_verified TEXT,
    evidence_level TEXT,
    description TEXT,
    poc TEXT,
    crash_evidence TEXT,
    stability_classification TEXT,
    stability_success_rate REAL,
    severity_disagreement TEXT,
    state TEXT NOT NULL DEFAULT 'pending_review',
    priority_score REAL DEFAULT 0.0,
    queued_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    reviewer TEXT,
    review_notes TEXT,
    batch_key TEXT,
    finding_json TEXT
);

CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    action TEXT NOT NULL,
    reviewer TEXT NOT NULL DEFAULT 'cli',
    reason TEXT,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS timelines (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id),
    disclosed_at REAL,
    deadline_90 REAL,
    deadline_extended REAL,
    extension_granted INTEGER DEFAULT 0,
    public_at REAL,
    patched_at REAL
);

CREATE INDEX IF NOT EXISTS idx_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_repo ON findings(repo_url);
CREATE INDEX IF NOT EXISTS idx_batch ON findings(batch_key);
CREATE INDEX IF NOT EXISTS idx_priority ON findings(priority_score DESC);
"""

_SEVERITY_SCORES = {
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 40,
    "info": 20,
}

_VALID_TRANSITIONS: dict[DisclosureState, set[DisclosureState]] = {
    DisclosureState.PENDING_REVIEW: {
        DisclosureState.IN_REVIEW,
        DisclosureState.REJECTED,
    },
    DisclosureState.IN_REVIEW: {
        DisclosureState.VALIDATED,
        DisclosureState.REJECTED,
        DisclosureState.NEEDS_REVISION,
    },
    DisclosureState.NEEDS_REVISION: {
        DisclosureState.IN_REVIEW,
        DisclosureState.REJECTED,
    },
    DisclosureState.VALIDATED: {
        DisclosureState.PENDING_DISCLOSURE,
    },
    DisclosureState.PENDING_DISCLOSURE: {
        DisclosureState.DISCLOSED,
    },
    DisclosureState.DISCLOSED: {
        DisclosureState.ACKNOWLEDGED,
        DisclosureState.WONTFIX,
        DisclosureState.PUBLIC,
    },
    DisclosureState.ACKNOWLEDGED: {
        DisclosureState.PATCH_IN_PROGRESS,
        DisclosureState.WONTFIX,
        DisclosureState.PUBLIC,
    },
    DisclosureState.PATCH_IN_PROGRESS: {
        DisclosureState.PATCHED,
        DisclosureState.PUBLIC,
    },
    DisclosureState.PATCHED: {
        DisclosureState.PUBLIC,
    },
}

_DAY = 86400


def _default_db_path() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "sourcehunt" / "disclosures.db"


def _compute_priority(finding: dict) -> float:
    sev = (finding.get("severity_verified") or finding.get("severity") or "info").lower()
    score = float(_SEVERITY_SCORES.get(sev, 20))
    if finding.get("severity_disagreement"):
        score += 50
    if finding.get("stability_classification") == "stable":
        score += 10
    return score


def _batch_key_for(finding: dict, repo_url: str) -> str:
    return redact_text(repo_url)


class DisclosureDB:
    """SQLite-backed disclosure workflow storage."""

    def __init__(self, path: Path | None = None):
        self._path = path or _default_db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def queue_findings(
        self,
        findings: list[dict],
        repo_url: str,
        session_id: str,
    ) -> int:
        """Insert findings into the disclosure queue. Returns count inserted."""
        now = time.time()
        count = 0
        for f in findings:
            fid = f.get("id", "")
            if not fid:
                continue
            priority = _compute_priority(f)
            batch_key = _batch_key_for(f, repo_url)
            try:
                self._conn.execute(
                    """INSERT OR IGNORE INTO findings
                    (id, repo_url, session_id, file, line_number, finding_type,
                     cwe, severity, severity_verified, evidence_level,
                     description, poc, crash_evidence,
                     stability_classification, stability_success_rate,
                     severity_disagreement, state, priority_score,
                     queued_at, updated_at, batch_key, finding_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        fid,
                        redact_text(repo_url),
                        session_id,
                        f.get("file"),
                        f.get("line_number"),
                        f.get("finding_type", ""),
                        f.get("cwe", ""),
                        f.get("severity", "info"),
                        f.get("severity_verified"),
                        f.get("evidence_level", "suspicion"),
                        redact_text((f.get("description") or "")[:2000]),
                        redact_text((f.get("poc") or "")[:5000]),
                        redact_text((f.get("crash_evidence") or "")[:2000]),
                        f.get("stability_classification"),
                        f.get("stability_success_rate"),
                        f.get("severity_disagreement"),
                        DisclosureState.PENDING_REVIEW.value,
                        priority,
                        now,
                        now,
                        batch_key,
                        json.dumps(redact_tree(f), default=str)[:50000],
                    ),
                )
                count += 1
            except sqlite3.Error:
                logger.debug("Failed to queue finding %s", fid, exc_info=True)
        self._conn.commit()
        return count

    def transition(
        self,
        finding_id: str,
        new_state: DisclosureState,
        reviewer: str = "cli",
        reason: str = "",
    ) -> None:
        """Transition a finding to a new state with audit record."""
        row = self._conn.execute(
            "SELECT state FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Finding {finding_id} not found")

        current = DisclosureState(row["state"])
        allowed = _VALID_TRANSITIONS.get(current, set())
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition: {current.value} -> {new_state.value} "
                f"(allowed: {', '.join(s.value for s in allowed)})"
            )

        now = time.time()
        self._conn.execute(
            "UPDATE findings SET state = ?, updated_at = ?, reviewer = ? WHERE id = ?",
            (new_state.value, now, reviewer, finding_id),
        )
        self._conn.execute(
            "INSERT INTO reviews (finding_id, action, reviewer, reason, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (finding_id, new_state.value, reviewer, reason, now),
        )
        self._conn.commit()

    def start_timeline(self, finding_id: str) -> None:
        """Start the 90-day CVD clock for a disclosed finding."""
        now = time.time()
        deadline_90 = now + 90 * _DAY
        self._conn.execute(
            """INSERT OR REPLACE INTO timelines
            (finding_id, disclosed_at, deadline_90, extension_granted)
            VALUES (?, ?, ?, 0)""",
            (finding_id, now, deadline_90),
        )
        self._conn.commit()

    def grant_extension(self, finding_id: str) -> None:
        """Grant a 45-day extension (patch in progress)."""
        row = self._conn.execute(
            "SELECT deadline_90 FROM timelines WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"No timeline for finding {finding_id}")
        deadline_extended = row["deadline_90"] + 45 * _DAY
        self._conn.execute(
            "UPDATE timelines SET deadline_extended = ?, extension_granted = 1 "
            "WHERE finding_id = ?",
            (deadline_extended, finding_id),
        )
        self._conn.commit()

    def get_queue(
        self,
        state: str | None = None,
        repo_url: str | None = None,
    ) -> list[dict]:
        """Get findings filtered by state/repo, ordered by priority."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if state:
            query += " AND state = ?"
            params.append(state)
        if repo_url:
            query += " AND repo_url = ?"
            params.append(redact_text(repo_url))
        query += " ORDER BY priority_score DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict | None:
        """Get a single finding by ID."""
        row = self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_reviews(self, finding_id: str) -> list[dict]:
        """Get audit trail for a finding."""
        rows = self._conn.execute(
            "SELECT * FROM reviews WHERE finding_id = ? ORDER BY timestamp",
            (finding_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_timeline(self, finding_id: str) -> dict | None:
        """Get timeline for a finding."""
        row = self._conn.execute(
            "SELECT * FROM timelines WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_approaching_deadlines(self, days_threshold: int = 30) -> list[dict]:
        """Return findings with deadlines within the threshold."""
        now = time.time()
        cutoff = now + days_threshold * _DAY
        rows = self._conn.execute(
            """SELECT f.*, t.disclosed_at, t.deadline_90, t.deadline_extended,
                      t.extension_granted
            FROM findings f
            JOIN timelines t ON f.id = t.finding_id
            WHERE f.state IN ('disclosed', 'acknowledged', 'patch_in_progress')
              AND (
                  (t.extension_granted = 0 AND t.deadline_90 <= ?)
                  OR (t.extension_granted = 1 AND t.deadline_extended <= ?)
              )
            ORDER BY COALESCE(t.deadline_extended, t.deadline_90) ASC""",
            (cutoff, cutoff),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_dashboard_stats(self) -> dict[str, Any]:
        """Aggregate counts for the status dashboard."""
        state_counts: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT state, COUNT(*) as cnt FROM findings GROUP BY state"
        ).fetchall():
            state_counts[row["state"]] = row["cnt"]

        repo_counts: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT repo_url, COUNT(*) as cnt FROM findings GROUP BY repo_url"
        ).fetchall():
            repo_counts[row["repo_url"]] = row["cnt"]

        total = sum(state_counts.values())
        return {
            "total": total,
            "by_state": state_counts,
            "by_repo": repo_counts,
        }

    def get_batch(self, batch_key: str) -> list[dict]:
        """Get all findings sharing a batch key."""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE batch_key = ? ORDER BY priority_score DESC",
            (batch_key,),
        ).fetchall()
        return [dict(row) for row in rows]
