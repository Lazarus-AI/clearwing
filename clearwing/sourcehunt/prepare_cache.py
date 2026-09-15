"""Reusable preprocess (prepare) cache for the Recursive SourceHunt mission.

Preprocess is expensive (clone + enumerate + tag + callgraph/taint). The
Recursive mission stores its result keyed by the *source artifact* so a later
run on the same source can restore it instead of recomputing.

Cache key = ``(artifact_id, source_digest, preprocess_schema_version)``:
* ``artifact_id``   — the host's source-artifact identifier;
* ``source_digest`` — content hash; changed content ⇒ miss (same family as the
  proof snapshot ``dirty_tree_digest``);
* ``preprocess_schema_version`` — bumped when the stored payload shape changes.

The stored payload is the extended ``PreprocessResult.to_checkpoint()`` dict
(file_targets + tags + callgraph + taint_paths + static hints). Storage is
abstracted behind :class:`PrepareCacheStore`; a SQLite reference impl is
provided (pluggable to a host artifact store later). Design ref: v1 §4.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Protocol

PREPROCESS_SCHEMA_VERSION = "1"


def compute_source_digest(rel_path_bytes: Iterable[tuple[str, bytes]]) -> str:
    """Content digest over (relative_path, content) pairs, order-independent.

    Callers pass the enumerated source files; the digest is stable regardless
    of iteration order so the same tree always maps to the same key.
    """
    h = hashlib.sha256()
    for rel, content in sorted(rel_path_bytes, key=lambda x: x[0]):
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(content).digest())
        h.update(b"\0")
    return h.hexdigest()


@dataclass(frozen=True)
class PrepareCacheKey:
    artifact_id: str
    source_digest: str
    schema_version: str = PREPROCESS_SCHEMA_VERSION

    def as_str(self) -> str:
        return f"{self.artifact_id}:{self.source_digest}:{self.schema_version}"


@dataclass
class PrepareCacheEntry:
    key: PrepareCacheKey
    payload: dict[str, Any]  # PreprocessResult.to_checkpoint() (extended)
    created_at: float


class PrepareCacheStore(Protocol):
    def get(self, key: str) -> Optional[PrepareCacheEntry]: ...
    def put(self, entry: PrepareCacheEntry) -> None: ...


class PrepareCache:
    """Policy layer: lookup/store preprocess results by source artifact."""

    def __init__(self, store: "PrepareCacheStore"):
        self.store = store

    def get(self, artifact_id: str, source_digest: str) -> Optional[dict[str, Any]]:
        key = PrepareCacheKey(artifact_id, source_digest)
        entry = self.store.get(key.as_str())
        return entry.payload if entry else None

    def put(self, artifact_id: str, source_digest: str, payload: dict[str, Any]) -> None:
        key = PrepareCacheKey(artifact_id, source_digest)
        self.store.put(PrepareCacheEntry(key=key, payload=payload, created_at=time.time()))

    def hit(self, artifact_id: str, source_digest: str) -> bool:
        return self.get(artifact_id, source_digest) is not None


class SqlitePrepareCacheStore:
    """SQLite-backed prepare cache. A file ``path`` persists preprocess results
    across runs (§4: an artifact re-hunted at the same content skips the heavy
    preprocess); ``:memory:`` stays available for tests. ``check_same_thread=
    False`` + lock so a connection created on one thread can be used on another
    (mirrors the ledger store)."""

    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS prepare_cache "
            "(key TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at REAL NOT NULL)"
        )
        self._db.commit()

    def get(self, key: str) -> Optional[PrepareCacheEntry]:
        with self._lock:
            row = self._db.execute(
                "SELECT key, payload, created_at FROM prepare_cache WHERE key=?", (key,)
            ).fetchone()
        if not row:
            return None
        art, dig, schema = row[0].split(":", 2)
        return PrepareCacheEntry(
            key=PrepareCacheKey(art, dig, schema),
            payload=json.loads(row[1]),
            created_at=row[2],
        )

    def put(self, entry: PrepareCacheEntry) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO prepare_cache (key, payload, created_at) VALUES (?,?,?)",
                (entry.key.as_str(), json.dumps(entry.payload), entry.created_at),
            )
            self._db.commit()
