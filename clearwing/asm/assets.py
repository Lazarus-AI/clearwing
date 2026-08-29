"""Scope-keyed asset inventory with delta detection.

Modeled on :class:`clearwing.sourcehunt.historical_findings_db.HistoricalFindingsDB`
— a small SQLite store whose whole job is answering "is this new since last
time?". Here the key is the engagement *scope* (the analog of that store's
``repo_url``) and the rows are discovered assets.

The store is authoritative for the temporal delta (``first_seen`` / ``last_seen``
and the "which of these did we not know about?" answer). A separate projection
into the knowledge graph (see :mod:`clearwing.asm.discovery`) makes the same
assets queryable and visualizable; this module never depends on that graph.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.reporting.safety import redact_text

logger = logging.getLogger(__name__)

#: The kinds of asset the inventory tracks. Kept deliberately small and flat;
#: hierarchy is expressed via ``parent_id`` rather than distinct tables.
ASSET_TYPES = (
    "domain",  # a root domain in scope, e.g. example.com
    "subdomain",  # a discovered name, e.g. api.example.com
    "host",  # a resolvable/live host (name or ip acting as one)
    "ip",  # a resolved address
    "port",  # an open port on a host: "<host>:<port>/<proto>"
    "service",  # a service on a port: "<port_id>:<name>"
    "url",  # a discovered URL
    "technology",  # a fingerprinted technology on a host/url
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    parent_id TEXT,
    source TEXT,
    metadata_json TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_asset_scope ON assets(scope);
CREATE INDEX IF NOT EXISTS idx_asset_scope_type ON assets(scope, asset_type);
CREATE INDEX IF NOT EXISTS idx_asset_parent ON assets(parent_id);
"""


def _default_db_path() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "asm" / "assets.db"


@dataclass
class Asset:
    """One node of an attack surface, keyed deterministically within a scope."""

    scope: str
    asset_type: str
    value: str
    parent_id: str | None = None
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: float | None = None
    last_seen: float | None = None
    status: str = "active"

    @property
    def id(self) -> str:
        """Deterministic id — identical (scope, type, value) is the same asset."""
        return self.compute_id(self.scope, self.asset_type, self.value)

    @staticmethod
    def compute_id(scope: str, asset_type: str, value: str) -> str:
        digest = hashlib.sha256(f"{scope}|{asset_type}|{value}".encode()).hexdigest()
        return f"asset-{digest[:24]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scope": self.scope,
            "asset_type": self.asset_type,
            "value": self.value,
            "parent_id": self.parent_id,
            "source": self.source,
            "metadata": dict(self.metadata),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status,
        }


class AssetStore:
    """Cross-run asset inventory. Idempotent ingest; returns the delta."""

    def __init__(self, path: Path | None = None):
        self._path = path or _default_db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> AssetStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- ingest ---------------------------------------------------------

    def record_observations(self, scope: str, assets: list[Asset]) -> list[Asset]:
        """Upsert *assets* under *scope*; return only the ones that were NEW.

        A previously-unseen asset is inserted (and returned as part of the
        delta); an already-known one has its ``last_seen`` (and any richer
        metadata/parent) refreshed but is not returned. This is the primitive
        the monitor uses to act only on genuinely new surface.
        """
        now = time.time()
        new_assets: list[Asset] = []
        for asset in assets:
            if asset.asset_type not in ASSET_TYPES:
                logger.debug("Skipping asset of unknown type %r", asset.asset_type)
                continue
            asset.scope = scope
            asset_id = asset.id
            existing = self._conn.execute(
                "SELECT first_seen FROM assets WHERE id = ?", (asset_id,)
            ).fetchone()
            metadata_json = json.dumps(_redact_metadata(asset.metadata), sort_keys=True)
            if existing is None:
                asset.first_seen = now
                asset.last_seen = now
                self._conn.execute(
                    """INSERT INTO assets
                    (id, scope, asset_type, value, parent_id, source,
                     metadata_json, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        asset_id,
                        scope,
                        asset.asset_type,
                        redact_text(asset.value),
                        asset.parent_id,
                        asset.source,
                        metadata_json,
                        now,
                        now,
                        asset.status,
                    ),
                )
                new_assets.append(asset)
            else:
                asset.first_seen = existing["first_seen"]
                asset.last_seen = now
                # Refresh last_seen and enrich parent/source/metadata in place.
                self._conn.execute(
                    """UPDATE assets SET last_seen = ?,
                       parent_id = COALESCE(?, parent_id),
                       source = CASE WHEN ? != '' THEN ? ELSE source END,
                       metadata_json = ?, status = ?
                       WHERE id = ?""",
                    (
                        now,
                        asset.parent_id,
                        asset.source,
                        asset.source,
                        metadata_json,
                        asset.status,
                        asset_id,
                    ),
                )
        self._conn.commit()
        return new_assets

    # -- query ----------------------------------------------------------

    def is_new(self, scope: str, asset: Asset) -> bool:
        """True if this exact asset has never been recorded for the scope."""
        row = self._conn.execute(
            "SELECT 1 FROM assets WHERE id = ? LIMIT 1",
            (Asset.compute_id(scope, asset.asset_type, asset.value),),
        ).fetchone()
        return row is None

    def known_assets(self, scope: str, asset_type: str | None = None) -> list[Asset]:
        query = "SELECT * FROM assets WHERE scope = ?"
        params: list[Any] = [scope]
        if asset_type is not None:
            query += " AND asset_type = ?"
            params.append(asset_type)
        query += " ORDER BY asset_type, value"
        rows = self._conn.execute(query, params).fetchall()
        return [_row_to_asset(row) for row in rows]

    def deltas_since(self, scope: str, since_ts: float) -> list[Asset]:
        """Assets first seen at or after *since_ts* — the "what's new" view."""
        rows = self._conn.execute(
            "SELECT * FROM assets WHERE scope = ? AND first_seen >= ? "
            "ORDER BY first_seen DESC",
            (scope, since_ts),
        ).fetchall()
        return [_row_to_asset(row) for row in rows]

    def scopes(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT scope FROM assets ORDER BY scope"
        ).fetchall()
        return [row["scope"] for row in rows]

    def stats(self, scope: str) -> dict[str, int]:
        """Count of assets per type for a scope (for reports / `asm list`)."""
        rows = self._conn.execute(
            "SELECT asset_type, COUNT(*) AS n FROM assets WHERE scope = ? "
            "GROUP BY asset_type",
            (scope,),
        ).fetchall()
        return {row["asset_type"]: row["n"] for row in rows}


def _redact_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in metadata.items():
        out[key] = redact_text(value) if isinstance(value, str) else value
    return out


def _row_to_asset(row: sqlite3.Row) -> Asset:
    try:
        metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
    except (json.JSONDecodeError, TypeError):
        metadata = {}
    return Asset(
        scope=row["scope"],
        asset_type=row["asset_type"],
        value=row["value"],
        parent_id=row["parent_id"],
        source=row["source"] or "",
        metadata=metadata if isinstance(metadata, dict) else {},
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        status=row["status"],
    )


__all__ = ["ASSET_TYPES", "Asset", "AssetStore"]
