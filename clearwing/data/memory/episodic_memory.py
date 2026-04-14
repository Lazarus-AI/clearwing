"""Episodic memory — records and recalls time-ordered penetration testing events."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Valid event types
EVENT_TYPES = (
    "port_found",
    "service_detected",
    "vuln_found",
    "exploit_attempted",
    "exploit_succeeded",
    "command_executed",
    "note_added",
)


@dataclass
class Episode:
    """A single recorded event in episodic memory."""

    id: int
    target: str
    session_id: str
    timestamp: str
    event_type: str
    content: str
    metadata: dict = field(default_factory=dict)


class EpisodicMemory:
    """SQLite-backed episodic memory with FTS5 full-text search."""

    _lock = threading.Lock()

    def __init__(
        self,
        db_path: str = "~/.clearwing/memory.db",
        session_id: str = "",
    ) -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id
        self._init_db()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS episodes (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    target     TEXT    NOT NULL,
                    session_id TEXT    NOT NULL,
                    timestamp  TEXT    NOT NULL,
                    event_type TEXT    NOT NULL,
                    content    TEXT    NOT NULL,
                    metadata_json TEXT
                )
                """
            )
            # FTS5 virtual table for full-text search on content
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts
                USING fts5(
                    content,
                    content=episodes,
                    content_rowid=id
                )
                """
            )
            # Triggers to keep FTS index in sync
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS episodes_ai AFTER INSERT ON episodes BEGIN
                    INSERT INTO episodes_fts(rowid, content)
                    VALUES (new.id, new.content);
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS episodes_ad AFTER DELETE ON episodes BEGIN
                    INSERT INTO episodes_fts(episodes_fts, rowid, content)
                    VALUES ('delete', old.id, old.content);
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS episodes_au AFTER UPDATE ON episodes BEGIN
                    INSERT INTO episodes_fts(episodes_fts, rowid, content)
                    VALUES ('delete', old.id, old.content);
                    INSERT INTO episodes_fts(rowid, content)
                    VALUES (new.id, new.content);
                END
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        target: str,
        event_type: str,
        content: str,
        metadata: dict | None = None,
        session_id: str | None = None,
    ) -> Episode:
        """Insert a new episode and return it."""
        sid = session_id or self.session_id
        ts = datetime.now(tz=timezone.utc).isoformat()
        meta_json = json.dumps(metadata) if metadata else "{}"

        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO episodes (target, session_id, timestamp, event_type, content, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (target, sid, ts, event_type, content, meta_json),
            )
            conn.commit()
            row_id = cursor.lastrowid

        return Episode(
            id=row_id,
            target=target,
            session_id=sid,
            timestamp=ts,
            event_type=event_type,
            content=content,
            metadata=metadata or {},
        )

    def recall(self, target: str, limit: int = 50) -> list[Episode]:
        """Return the most recent episodes for *target*."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, target, session_id, timestamp, event_type, content, metadata_json
                FROM episodes
                WHERE target = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (target, limit),
            ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    def recall_by_type(self, target: str, event_type: str) -> list[Episode]:
        """Return all episodes of *event_type* for *target*."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, target, session_id, timestamp, event_type, content, metadata_json
                FROM episodes
                WHERE target = ? AND event_type = ?
                ORDER BY timestamp DESC
                """,
                (target, event_type),
            ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    def search(self, target: str, query: str) -> list[Episode]:
        """Full-text search over episode content for a given *target*."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT e.id, e.target, e.session_id, e.timestamp, e.event_type,
                       e.content, e.metadata_json
                FROM episodes e
                JOIN episodes_fts f ON e.id = f.rowid
                WHERE episodes_fts MATCH ? AND e.target = ?
                ORDER BY rank
                """,
                (query, target),
            ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_episode(row: tuple) -> Episode:
        return Episode(
            id=row[0],
            target=row[1],
            session_id=row[2],
            timestamp=row[3],
            event_type=row[4],
            content=row[5],
            metadata=json.loads(row[6]) if row[6] else {},
        )
