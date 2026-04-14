"""Mechanism-level cross-run memory.

Stores *mechanisms*, not findings. A mechanism is an abstract pattern like:
"length field trusted before allocation; 16-bit user-controlled value widened
to size_t; mitigated by validating upper bound."

Mechanisms are extracted from verified findings via a short LLM pass, and
persisted to an append-only JSONL file at ~/.clearwing/sourcehunt/mechanisms.jsonl.
On subsequent runs, top-N relevant mechanisms are injected into hunter
prompts as "patterns known to produce vulnerabilities in similar codebases."

v0.3 shipped with plain keyword-overlap recall. v0.4 adds two additional
recall backends with automatic backend selection:

    keyword  — language + tag overlap (v0.3 default)
    tfidf    — pure-python TF-IDF over the mechanism text (v0.4 default)
    chromadb — optional chromadb-backed embeddings (best but needs install)

JSONL remains the portable persistence format — both vector backends read
from it at load time, so a store written by one client is readable by any
other.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from .state import SourceFinding

logger = logging.getLogger(__name__)


# --- Default store location --------------------------------------------------


def default_store_path() -> Path:
    home = os.environ.get("CLEARWING_HOME") or os.path.expanduser("~/.clearwing")
    return Path(home) / "sourcehunt" / "mechanisms.jsonl"


# --- Mechanism data class ---------------------------------------------------


@dataclass
class Mechanism:
    """An abstract vulnerability pattern extracted from a verified finding."""
    id: str
    summary: str              # one-sentence abstract mechanism
    cwe: str
    language: str
    tags: list[str]           # e.g. ["length_field", "widening", "memcpy"]
    keywords: list[str]       # for cheap keyword-match recall
    what_made_it_exploitable: str
    source_finding_id: str
    source_repo: str = ""
    first_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "summary": self.summary,
            "cwe": self.cwe,
            "language": self.language,
            "tags": self.tags,
            "keywords": self.keywords,
            "what_made_it_exploitable": self.what_made_it_exploitable,
            "source_finding_id": self.source_finding_id,
            "source_repo": self.source_repo,
            "first_seen": self.first_seen,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Mechanism":
        return cls(
            id=d["id"],
            summary=d["summary"],
            cwe=d.get("cwe", ""),
            language=d.get("language", ""),
            tags=list(d.get("tags", [])),
            keywords=list(d.get("keywords", [])),
            what_made_it_exploitable=d.get("what_made_it_exploitable", ""),
            source_finding_id=d.get("source_finding_id", ""),
            source_repo=d.get("source_repo", ""),
            first_seen=float(d.get("first_seen", time.time())),
        )


# --- Extraction prompt ------------------------------------------------------


MECHANISM_EXTRACTION_PROMPT = """You are extracting an ABSTRACT vulnerability mechanism from a verified finding. The goal is to produce a pattern that might apply to OTHER codebases, not a description of this specific file.

Given the finding below, return ONLY a JSON object:
{
  "summary": "one sentence — abstract mechanism, no file names or line numbers",
  "tags": ["list", "of", "mechanism_tags"],
  "keywords": ["words", "that", "identify", "related", "code"],
  "what_made_it_exploitable": "brief — what turned a near-miss into a real bug"
}

Examples:

Input: memcpy with user-controlled length field in app/parse_packet.c line 47
Output: {
  "summary": "length field from network header trusted before allocation; memcpy copies more bytes than target buffer size",
  "tags": ["length_field", "untrusted_input", "memcpy", "heap_overflow"],
  "keywords": ["length", "memcpy", "header", "malloc", "bounds"],
  "what_made_it_exploitable": "the length field was a 32-bit integer but allocator used a 16-bit local, so attacker-chosen sizes wrapped around"
}

Input: f-string SQL query in app/views.py line 120
Output: {
  "summary": "user input interpolated into SQL query via f-string without parameterization",
  "tags": ["sql_injection", "string_interpolation", "unparameterized_query"],
  "keywords": ["f-string", "execute", "format", "select", "WHERE"],
  "what_made_it_exploitable": "the caller's sanitization only escaped single quotes; backticks passed through unchanged"
}

Return ONLY the JSON object."""


# --- Extractor --------------------------------------------------------------


class MechanismExtractor:
    """Extracts abstract mechanisms from verified findings via an LLM pass."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def extract(
        self,
        finding: SourceFinding,
        source_repo: str = "",
    ) -> Optional[Mechanism]:
        """Extract a Mechanism from one verified finding. Returns None on failure."""
        user_msg = self._build_user_message(finding)
        try:
            response = self.llm.invoke([
                SystemMessage(content=MECHANISM_EXTRACTION_PROMPT),
                HumanMessage(content=user_msg),
            ])
        except Exception:
            logger.debug("Mechanism extraction LLM call failed", exc_info=True)
            return None

        content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = self._parse_response(content)
        if not parsed:
            return None

        return Mechanism(
            id=f"mech-{uuid.uuid4().hex[:10]}",
            summary=parsed.get("summary", ""),
            cwe=finding.get("cwe", ""),
            language=_language_from_file(finding.get("file", "")),
            tags=list(parsed.get("tags", [])),
            keywords=list(parsed.get("keywords", [])),
            what_made_it_exploitable=parsed.get("what_made_it_exploitable", ""),
            source_finding_id=finding.get("id", ""),
            source_repo=source_repo,
        )

    def _build_user_message(self, finding: SourceFinding) -> str:
        view = {
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "cwe": finding.get("cwe"),
            "finding_type": finding.get("finding_type"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
            "crash_evidence": (finding.get("crash_evidence") or "")[:1500],
        }
        return f"Finding:\n{json.dumps(view, indent=2)}\n"

    def _parse_response(self, content: str) -> Optional[dict]:
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None


# --- Store ------------------------------------------------------------------


RecallBackend = str   # "keyword" | "tfidf" | "chromadb" | "auto"


def _detect_best_backend() -> str:
    """Pick the best available recall backend.

    Precedence: chromadb > tfidf > keyword. The tfidf path is pure Python
    and always available, so it's the practical default unless chromadb is
    explicitly installed.
    """
    try:
        import chromadb  # noqa: F401
        return "chromadb"
    except ImportError:
        return "tfidf"


class MechanismStore:
    """Append-only JSONL store for mechanisms with pluggable recall.

    Thread safety: v0.4 still appends unlocked (each write is one line;
    POSIX guarantees atomicity up to PIPE_BUF). Concurrent readers may
    observe in-flight writes as truncated JSON and skip the bad line.
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        backend: RecallBackend = "auto",
    ):
        self.path = path or default_store_path()
        self.backend = _detect_best_backend() if backend == "auto" else backend
        # chromadb client is constructed lazily in _recall_chromadb
        self._chromadb_client = None
        self._chromadb_collection = None

    def append(self, mechanism: Mechanism) -> None:
        """Append a mechanism as one JSONL line.

        Also invalidates any cached chromadb collection so the next recall
        call sees the new entry. TF-IDF recall reads from the file each
        call, so it doesn't need invalidation.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(mechanism.to_dict()) + "\n")
        # Drop chromadb cache so the next recall rebuilds it
        self._chromadb_collection = None

    def load_all(self) -> list[Mechanism]:
        """Read every mechanism in the store. Returns [] if the file doesn't exist."""
        if not self.path.exists():
            return []
        out: list[Mechanism] = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(Mechanism.from_dict(json.loads(line)))
                except Exception:
                    logger.debug("Malformed mechanism line, skipping")
        return out

    def recall(
        self,
        language: str,
        tags: list[str],
        top_n: int = 3,
        query_text: Optional[str] = None,
    ) -> list[Mechanism]:
        """Retrieve relevant mechanisms from the store.

        Dispatches to one of three backends based on self.backend:
            keyword  — v0.3 language + tag overlap
            tfidf    — v0.4 pure-python TF-IDF over mechanism text
            chromadb — v0.4 optional ANN via sentence-transformers embeddings

        Args:
            language: primary language of the target being scanned
            tags: tags present on the file set
            top_n: max mechanisms to return
            query_text: optional free-form query text to boost relevance.
                When None, the query is assembled from language + tags.
        """
        mechanisms = self.load_all()
        if not mechanisms:
            return []
        if self.backend == "chromadb":
            result = self._recall_chromadb(mechanisms, language, tags, top_n, query_text)
            if result is not None:
                return result
            # Fall through to tfidf on chromadb errors
        if self.backend in ("tfidf", "chromadb"):
            return self._recall_tfidf(mechanisms, language, tags, top_n, query_text)
        return self._recall_keyword(mechanisms, language, tags, top_n)

    # --- keyword backend (v0.3 default) -------------------------------------

    @staticmethod
    def _recall_keyword(
        mechanisms: list[Mechanism],
        language: str,
        tags: list[str],
        top_n: int,
    ) -> list[Mechanism]:
        scored: list[tuple[float, Mechanism]] = []
        tag_set = set(tags)
        for m in mechanisms:
            score = 0.0
            if m.language and m.language == language:
                score += 2.0
            score += len(set(m.tags) & tag_set)
            for kw in m.keywords:
                for t in tags:
                    if kw.lower() in t.lower():
                        score += 0.5
                        break
            if score > 0:
                scored.append((score, m))
        scored.sort(key=lambda kv: -kv[0])
        return [m for _, m in scored[:top_n]]

    # --- tfidf backend (v0.4 default) ---------------------------------------

    def _recall_tfidf(
        self,
        mechanisms: list[Mechanism],
        language: str,
        tags: list[str],
        top_n: int,
        query_text: Optional[str],
    ) -> list[Mechanism]:
        """Pure-Python TF-IDF over the mechanism corpus.

        Cheap — the store typically holds at most a few thousand mechanisms
        at any time, and each one is tens of words. Python tokenization +
        dict math is more than fast enough for interactive use.

        Scoring:
            - TF-IDF cosine similarity between query and mechanism document
            - Language-match boost (+0.5 to final score) to match the v0.3
              preference for same-language mechanisms
        """
        # 1. Build the corpus of mechanism documents
        docs = [self._mechanism_to_doc(m) for m in mechanisms]
        if not any(docs):
            return []

        # 2. Tokenize and compute TF per doc
        tokenized = [_tokenize(d) for d in docs]
        tf_per_doc = [Counter(tokens) for tokens in tokenized]

        # 3. Compute document frequency
        df: dict[str, int] = Counter()
        for tokens in tokenized:
            for term in set(tokens):
                df[term] += 1

        # 4. IDF
        n_docs = len(tokenized) or 1
        idf: dict[str, float] = {
            term: math.log((n_docs + 1) / (df[term] + 1)) + 1.0
            for term in df
        }

        # 5. TF-IDF vectors (as sparse dicts)
        def vectorize(token_list: list[str]) -> dict[str, float]:
            tf = Counter(token_list)
            if not tf:
                return {}
            return {t: (count / len(token_list)) * idf.get(t, 0.0)
                    for t, count in tf.items()}

        doc_vecs = [vectorize(tokens) for tokens in tokenized]

        # 6. Build the query vector
        query_parts: list[str] = []
        if query_text:
            query_parts.append(query_text)
        if language:
            query_parts.append(language)
        query_parts.extend(tags)
        query_doc = " ".join(query_parts)
        query_tokens = _tokenize(query_doc)
        if not query_tokens:
            # Fall back to keyword if there's nothing to vectorize
            return self._recall_keyword(mechanisms, language, tags, top_n)
        query_vec = vectorize(query_tokens)

        # 7. Score by cosine similarity + language boost
        scored: list[tuple[float, Mechanism]] = []
        for m, doc_vec in zip(mechanisms, doc_vecs):
            score = _cosine_similarity(query_vec, doc_vec)
            if m.language and m.language == language:
                score += 0.5
            if score > 0:
                scored.append((score, m))
        scored.sort(key=lambda kv: -kv[0])
        return [m for _, m in scored[:top_n]]

    # --- chromadb backend (v0.4 optional) -----------------------------------

    def _recall_chromadb(
        self,
        mechanisms: list[Mechanism],
        language: str,
        tags: list[str],
        top_n: int,
        query_text: Optional[str],
    ) -> Optional[list[Mechanism]]:
        """chromadb-backed recall. Returns None on import / runtime error
        so the caller falls back to TF-IDF."""
        try:
            import chromadb
        except ImportError:
            return None

        try:
            if self._chromadb_collection is None:
                # In-memory ephemeral client — the authoritative store is
                # the JSONL file, so we don't need on-disk persistence in
                # chromadb itself.
                if self._chromadb_client is None:
                    self._chromadb_client = chromadb.EphemeralClient()
                # Rebuild the collection from the current mechanism set
                coll_name = f"mechanisms_{uuid.uuid4().hex[:8]}"
                self._chromadb_collection = self._chromadb_client.create_collection(
                    name=coll_name,
                )
                docs = [self._mechanism_to_doc(m) for m in mechanisms]
                ids = [m.id for m in mechanisms]
                metadatas = [
                    {"language": m.language, "tags": ",".join(m.tags),
                     "cwe": m.cwe}
                    for m in mechanisms
                ]
                self._chromadb_collection.add(
                    documents=docs,
                    ids=ids,
                    metadatas=metadatas,
                )

            # Query
            query_parts = []
            if query_text:
                query_parts.append(query_text)
            if language:
                query_parts.append(language)
            query_parts.extend(tags)
            query = " ".join(query_parts) or "vulnerability"

            result = self._chromadb_collection.query(
                query_texts=[query],
                n_results=min(top_n, len(mechanisms)),
            )
        except Exception:
            logger.debug("chromadb recall failed", exc_info=True)
            return None

        returned_ids = (result.get("ids") or [[]])[0]
        id_to_mech = {m.id: m for m in mechanisms}
        out: list[Mechanism] = []
        for mid in returned_ids:
            if mid in id_to_mech:
                out.append(id_to_mech[mid])
        return out

    @staticmethod
    def _mechanism_to_doc(m: Mechanism) -> str:
        """Render a mechanism as a single text doc for vector embedding."""
        parts = [m.summary]
        if m.tags:
            parts.append(" ".join(m.tags))
        if m.keywords:
            parts.append(" ".join(m.keywords))
        if m.what_made_it_exploitable:
            parts.append(m.what_made_it_exploitable)
        if m.cwe:
            parts.append(m.cwe)
        return "  ".join(p for p in parts if p)

    def clear(self) -> None:
        """Delete the store file. Used for tests and explicit resets."""
        if self.path.exists():
            self.path.unlink()


# --- Helper -----------------------------------------------------------------


def format_mechanisms_for_prompt(mechanisms: list[Mechanism]) -> str:
    """Render mechanisms as a block to inject into a hunter prompt."""
    if not mechanisms:
        return ""
    lines = ["## Patterns known to produce vulnerabilities in similar codebases"]
    for i, m in enumerate(mechanisms, 1):
        lines.append(f"{i}. {m.summary}")
        if m.what_made_it_exploitable:
            lines.append(f"   Exploitable when: {m.what_made_it_exploitable}")
        if m.tags:
            lines.append(f"   Tags: {', '.join(m.tags)}")
    return "\n".join(lines)


_LANG_EXT = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".py": "python",
    ".js": "javascript", ".ts": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java",
}


# --- Pure-python TF-IDF helpers --------------------------------------------


# Tokens we strip because they're too common to discriminate. Deliberately
# short — security terminology is specific enough that a general-purpose
# stopword list would hurt recall.
_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "has", "have", "in", "into", "is", "it", "its", "not", "of", "on",
    "or", "that", "the", "this", "to", "was", "were", "will", "with",
})


def _tokenize(text: str) -> list[str]:
    """Lowercase + alphanumeric tokenization with stopword removal.

    Splits on any non-alphanumeric character, keeps tokens of length >= 2,
    drops stopwords. Production-tuned for mechanism text (short, technical).
    """
    if not text:
        return []
    tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
    return [t for t in tokens if len(t) >= 2 and t not in _STOPWORDS]


def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    """Cosine similarity between two sparse TF-IDF vectors."""
    if not a or not b:
        return 0.0
    # Dot product over the smaller of the two keysets
    if len(a) > len(b):
        a, b = b, a
    dot = sum(a[t] * b.get(t, 0.0) for t in a)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _language_from_file(path: str) -> str:
    if not path:
        return ""
    ext = os.path.splitext(path)[1].lower()
    return _LANG_EXT.get(ext, "")
