"""Semantic memory — long-term knowledge store with optional vector search."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Knowledge categories
CATEGORIES = (
    "successful_exploits",
    "tool_usage_patterns",
    "target_profiles",
    "custom_techniques",
)


@dataclass
class Knowledge:
    """A single piece of stored knowledge."""

    id: int
    category: str
    content: str
    metadata: dict = field(default_factory=dict)
    created_at: str = ""


class SemanticMemory:
    """SQLite-backed semantic memory with optional embedding-based vector search.

    If ``sentence-transformers`` and ``numpy`` are installed, embeddings are
    generated with the ``all-MiniLM-L6-v2`` model and cosine similarity is
    used for retrieval.  Otherwise the system falls back to FTS5 keyword search.
    """

    _lock = threading.Lock()

    # Lazy-loaded sentence-transformer model (class-level so it's shared)
    _model: object | None = None
    _model_checked: bool = False

    def __init__(self, db_path: str = "~/.clearwing/memory.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Lazy embedding model
    # ------------------------------------------------------------------

    @classmethod
    def _get_model(cls):
        """Load the SentenceTransformer model on first use."""
        if not cls._model_checked:
            try:
                from sentence_transformers import SentenceTransformer

                cls._model = SentenceTransformer("all-MiniLM-L6-v2")
            except ImportError:
                cls._model = None
            cls._model_checked = True
        return cls._model

    def _encode(self, text: str) -> bytes | None:
        """Return embedding bytes or None if unavailable."""
        model = self._get_model()
        if model is None:
            return None
        import numpy as np

        vec = model.encode(text)
        return vec.astype(np.float32).tobytes()

    @staticmethod
    def _bytes_to_vector(raw: bytes):
        """Deserialize stored embedding bytes back to a numpy array."""
        import numpy as np

        return np.frombuffer(raw, dtype=np.float32)

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
                CREATE TABLE IF NOT EXISTS knowledge (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    category      TEXT NOT NULL,
                    content       TEXT NOT NULL,
                    embedding     BLOB,
                    metadata_json TEXT,
                    created_at    TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts
                USING fts5(
                    content,
                    content=knowledge,
                    content_rowid=id
                )
                """
            )
            # Triggers to keep FTS index in sync
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge BEGIN
                    INSERT INTO knowledge_fts(rowid, content)
                    VALUES (new.id, new.content);
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, content)
                    VALUES ('delete', old.id, old.content);
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, content)
                    VALUES ('delete', old.id, old.content);
                    INSERT INTO knowledge_fts(rowid, content)
                    VALUES (new.id, new.content);
                END
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(
        self,
        category: str,
        content: str,
        metadata: Optional[dict] = None,
    ) -> Knowledge:
        """Persist a piece of knowledge, optionally with an embedding vector."""
        ts = datetime.now(tz=timezone.utc).isoformat()
        meta_json = json.dumps(metadata) if metadata else "{}"
        embedding = self._encode(content)

        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO knowledge (category, content, embedding, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (category, content, embedding, meta_json, ts),
            )
            conn.commit()
            row_id = cursor.lastrowid

        return Knowledge(
            id=row_id,
            category=category,
            content=content,
            metadata=metadata or {},
            created_at=ts,
        )

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 5,
    ) -> list[Knowledge]:
        """Search knowledge — vector similarity first, FTS5 fallback."""
        # Try vector search
        results = self._vector_search(query, category, top_k)
        if results is not None:
            return results
        # Fall back to FTS5
        return self._fts_search(query, category, top_k)

    # ------------------------------------------------------------------
    # Search strategies
    # ------------------------------------------------------------------

    def _vector_search(
        self,
        query: str,
        category: Optional[str],
        top_k: int,
    ) -> list[Knowledge] | None:
        """Cosine-similarity search. Returns None if embeddings are unavailable."""
        model = self._get_model()
        if model is None:
            return None

        try:
            import numpy as np
        except ImportError:
            return None

        query_vec = model.encode(query).astype(np.float32)

        with self._lock, self._get_connection() as conn:
            if category:
                rows = conn.execute(
                    """
                    SELECT id, category, content, embedding, metadata_json, created_at
                    FROM knowledge
                    WHERE category = ? AND embedding IS NOT NULL
                    """,
                    (category,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, category, content, embedding, metadata_json, created_at
                    FROM knowledge
                    WHERE embedding IS NOT NULL
                    """
                ).fetchall()

        if not rows:
            return None

        scored: list[tuple[float, Knowledge]] = []
        for row in rows:
            stored_vec = self._bytes_to_vector(row[3])
            # Cosine similarity
            denom = (np.linalg.norm(query_vec) * np.linalg.norm(stored_vec))
            if denom == 0:
                sim = 0.0
            else:
                sim = float(np.dot(query_vec, stored_vec) / denom)
            scored.append((sim, self._row_to_knowledge(row)))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [k for _, k in scored[:top_k]]

    def _fts_search(
        self,
        query: str,
        category: Optional[str],
        top_k: int,
    ) -> list[Knowledge]:
        """FTS5 keyword search fallback."""
        with self._lock, self._get_connection() as conn:
            if category:
                rows = conn.execute(
                    """
                    SELECT k.id, k.category, k.content, k.embedding,
                           k.metadata_json, k.created_at
                    FROM knowledge k
                    JOIN knowledge_fts f ON k.id = f.rowid
                    WHERE knowledge_fts MATCH ? AND k.category = ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (query, category, top_k),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT k.id, k.category, k.content, k.embedding,
                           k.metadata_json, k.created_at
                    FROM knowledge k
                    JOIN knowledge_fts f ON k.id = f.rowid
                    WHERE knowledge_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (query, top_k),
                ).fetchall()
        return [self._row_to_knowledge(r) for r in rows]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_knowledge(row: tuple) -> Knowledge:
        return Knowledge(
            id=row[0],
            category=row[1],
            content=row[2],
            metadata=json.loads(row[4]) if row[4] else {},
            created_at=row[5],
        )
