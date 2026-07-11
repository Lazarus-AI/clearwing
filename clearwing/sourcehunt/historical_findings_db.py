"""Historical findings database for cross-campaign dedup (spec 005).

SQLite database at ~/.clearwing/sourcehunt/historical_findings.db.
Read once at campaign start, written once at campaign end.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    file TEXT,
    line_number INTEGER,
    finding_type TEXT,
    primitive_type TEXT,
    cluster_id TEXT,
    cwe TEXT,
    severity TEXT,
    description TEXT,
    code_snippet TEXT,
    evidence_level TEXT,
    repo_url TEXT,
    campaign_session_id TEXT,
    discovered_at REAL,
    verified INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_repo ON findings(repo_url);
CREATE INDEX IF NOT EXISTS idx_cwe ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_primitive ON findings(primitive_type);
CREATE INDEX IF NOT EXISTS idx_file ON findings(file);
"""

_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN crypto_protocol TEXT",
    "ALTER TABLE findings ADD COLUMN algorithm TEXT",
    "ALTER TABLE findings ADD COLUMN crypto_attack_class TEXT",
    "ALTER TABLE findings ADD COLUMN key_material_exposed TEXT",
]


def _default_db_path() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "sourcehunt" / "historical_findings.db"


class HistoricalFindingsDB:
    """Cross-campaign findings database."""

    def __init__(self, path: Path | None = None):
        self._path = path or _default_db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        for migration in _MIGRATIONS:
            try:
                self._conn.execute(migration)
            except sqlite3.OperationalError:
                pass
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def ingest_campaign(
        self,
        findings: list[Finding],
        repo_url: str,
        session_id: str,
    ) -> int:
        """Insert findings from a completed campaign. Returns count inserted."""
        count = 0
        now = time.time()
        for f in findings:
            fid = f.get("id", "")
            if not fid:
                continue
            try:
                self._conn.execute(
                    """INSERT OR IGNORE INTO findings
                    (id, file, line_number, finding_type, primitive_type,
                     cluster_id, cwe, severity, description, code_snippet,
                     evidence_level, repo_url, campaign_session_id,
                     discovered_at, verified,
                     crypto_protocol, algorithm, crypto_attack_class,
                     key_material_exposed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?)""",
                    (
                        fid,
                        f.get("file"),
                        f.get("line_number"),
                        f.get("finding_type", ""),
                        f.get("primitive_type", ""),
                        f.get("cluster_id", ""),
                        f.get("cwe", ""),
                        f.get("severity", "info"),
                        f.get("description", "")[:2000],
                        f.get("code_snippet", "")[:1000],
                        f.get("evidence_level", "suspicion"),
                        repo_url,
                        session_id,
                        now,
                        1 if f.get("verified") else 0,
                        f.get("crypto_protocol"),
                        f.get("algorithm"),
                        f.get("crypto_attack_class"),
                        f.get("key_material_exposed"),
                    ),
                )
                count += 1
            except sqlite3.Error:
                logger.debug("Failed to insert finding %s", fid, exc_info=True)
        self._conn.commit()
        return count

    def query_prior(
        self,
        repo_url: str,
        cwe: str | None = None,
        file: str | None = None,
    ) -> list[dict]:
        """Return historical findings for this repo."""
        query = "SELECT * FROM findings WHERE repo_url = ?"
        params: list[Any] = [repo_url]
        if cwe:
            query += " AND cwe = ?"
            params.append(cwe)
        if file:
            query += " AND file = ?"
            params.append(file)
        query += " ORDER BY discovered_at DESC LIMIT 200"
        try:
            rows = self._conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            logger.debug("Historical query failed", exc_info=True)
            return []

    def is_known(self, finding: Finding, repo_url: str) -> bool:
        """Check if a finding with this file+line+cwe already exists."""
        file_path = finding.get("file")
        line = finding.get("line_number")
        cwe = finding.get("cwe", "")
        if not file_path or not cwe:
            return False
        try:
            row = self._conn.execute(
                "SELECT 1 FROM findings WHERE repo_url = ? AND file = ? AND line_number = ? AND cwe = ? LIMIT 1",
                (repo_url, file_path, line, cwe),
            ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False
