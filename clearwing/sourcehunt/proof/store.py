"""Append-only persistence for proof-carrying sourcehunt sessions."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TypeVar

from .models import (
    Action,
    Assumption,
    Candidate,
    Certificate,
    Claim,
    ContextPacket,
    Derivation,
    Evidence,
    Fact,
    Obligation,
    RepositorySnapshot,
    StrictModel,
    ThreatModel,
)

RecordT = TypeVar("RecordT", bound=StrictModel)

_COLLECTIONS: dict[type[StrictModel], Path] = {
    RepositorySnapshot: Path("snapshots/snapshots.jsonl"),
    Fact: Path("facts/facts.jsonl"),
    Evidence: Path("evidence/evidence.jsonl"),
    Claim: Path("claims/claims.jsonl"),
    Assumption: Path("assumptions/assumptions.jsonl"),
    ThreatModel: Path("threats/threat-models.jsonl"),
    Candidate: Path("candidates/candidates.jsonl"),
    Obligation: Path("obligations/obligations.jsonl"),
    Action: Path("actions/action-log.jsonl"),
    Derivation: Path("derivations/derivations.jsonl"),
    ContextPacket: Path("context-packets/packets.jsonl"),
    Certificate: Path("certificates/certificates.jsonl"),
}


class ProofStore:
    """Session-local append-only JSONL records and immutable artifacts.

    Every update is a new record revision. Artifact bytes are addressed by
    SHA-256, so evidence can be independently checked and safely shared by
    multiple candidates.
    """

    def __init__(self, session_dir: str | Path):
        self.root = Path(session_dir).expanduser().resolve()
        self._lock = threading.RLock()
        self._create_layout()

    def _create_layout(self) -> None:
        directories = {path.parent for path in _COLLECTIONS.values()} | {
            Path("artifacts/sha256"),
            Path("proof-graphs"),
            Path("falsification"),
            Path("certificates/findings"),
            Path("certificates/rejections"),
            Path("certificates/incomplete"),
        }
        for relative in directories:
            (self.root / relative).mkdir(parents=True, exist_ok=True)

    def path_for(self, model_type: type[StrictModel]) -> Path:
        for registered, relative in _COLLECTIONS.items():
            if issubclass(model_type, registered):
                return self.root / relative
        raise TypeError(f"No proof-store collection registered for {model_type!r}")

    def append(self, record: StrictModel) -> StrictModel:
        """Durably append one immutable record."""

        path = self.path_for(type(record))
        encoded = (
            json.dumps(
                record.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if isinstance(record, Certificate):
                self._write_certificate_view(record)
        return record

    def append_many(self, records: Iterable[StrictModel]) -> list[StrictModel]:
        result: list[StrictModel] = []
        for record in records:
            result.append(self.append(record))
        return result

    def read_all(self, model_type: type[RecordT]) -> list[RecordT]:
        """Read valid records, tolerating only a truncated final JSONL line."""

        path = self.path_for(model_type)
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
        records: list[RecordT] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                if index == len(lines) - 1:
                    break
                raise
            records.append(model_type.model_validate(payload))
        return records

    def latest(self, model_type: type[RecordT]) -> dict[str, RecordT]:
        """Return the highest revision for every logical entity."""

        latest: dict[str, RecordT] = {}
        for record in self.read_all(model_type):
            logical_id = getattr(record, "logical_id", None) or record.id
            previous = latest.get(logical_id)
            revision = int(getattr(record, "revision", 1))
            if previous is None or revision >= int(getattr(previous, "revision", 1)):
                latest[logical_id] = record
        return latest

    def get(
        self,
        model_type: type[RecordT],
        record_id: str,
        *,
        latest: bool = True,
    ) -> RecordT | None:
        records = list(self.latest(model_type).values()) if latest else self.read_all(model_type)
        for record in records:
            if getattr(record, "id", "") == record_id:
                return record
            if getattr(record, "logical_id", "") == record_id:
                return record
        return None

    def store_artifact(
        self,
        data: bytes | str,
        *,
        media_type: str = "application/octet-stream",
        name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Store immutable content and return (artifact URI, SHA-256 digest)."""

        payload = data.encode("utf-8") if isinstance(data, str) else data
        digest = hashlib.sha256(payload).hexdigest()
        directory = self.root / "artifacts" / "sha256" / digest[:2]
        target = directory / digest
        with self._lock:
            directory.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                self._atomic_write(target, payload)
            self._append_jsonl(
                self.root / "artifacts" / "index.jsonl",
                {
                    "digest": digest,
                    "uri": f"sha256:{digest}",
                    "bytes": len(payload),
                    "media_type": media_type,
                    "name": name,
                    "metadata": metadata or {},
                },
            )
        return f"sha256:{digest}", digest

    def read_artifact(self, uri_or_digest: str) -> bytes:
        digest = uri_or_digest.removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("Invalid SHA-256 artifact identifier")
        path = self.root / "artifacts" / "sha256" / digest[:2] / digest
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"Artifact digest mismatch: {digest}")
        return payload

    def write_graph(self, candidate_id: str, payload: dict[str, Any]) -> Path:
        path = self._safe_named_path("proof-graphs", candidate_id, ".json")
        self._atomic_json(path, payload)
        return path

    def write_falsification(self, candidate_id: str, payload: dict[str, Any]) -> Path:
        path = self._safe_named_path("falsification", candidate_id, ".json")
        self._atomic_json(path, payload)
        return path

    def write_manifest(self, payload: dict[str, Any]) -> Path:
        path = self.root / "manifest.json"
        self._atomic_json(path, payload)
        return path

    def latest_threats(self, snapshot_id: str) -> dict[str, ThreatModel]:
        """Return threat models by either logical or immutable identifier."""

        result: dict[str, ThreatModel] = {}
        for threat in self.latest(ThreatModel).values():
            if threat.snapshot_id != snapshot_id:
                continue
            result[threat.logical_id] = threat
            result[threat.id] = threat
        return result

    def write_json(self, relative_path: str | Path, payload: dict[str, Any]) -> Path:
        """Atomically write a derived, reproducible session view."""

        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"Unsafe proof-store relative path: {relative}")
        path = (self.root / relative).resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"Proof-store path escapes session: {relative}") from exc
        self._atomic_json(path, payload)
        return path

    def _write_certificate_view(self, certificate: Certificate) -> None:
        kind_dir = {
            "finding": "findings",
            "rejection": "rejections",
            "incomplete": "incomplete",
        }[certificate.kind.value]
        path = self._safe_named_path(
            f"certificates/{kind_dir}",
            certificate.id,
            ".json",
        )
        self._atomic_json(path, certificate.model_dump(mode="json"))

    def _safe_named_path(self, directory: str, identifier: str, suffix: str) -> Path:
        safe = "".join(char for char in identifier if char.isalnum() or char in {"-", "_", "."})
        if not safe or safe != identifier:
            raise ValueError(f"Unsafe proof artifact identifier: {identifier!r}")
        return self.root / directory / f"{safe}{suffix}"

    def _append_jsonl(self, path: Path, payload: dict[str, Any]) -> None:
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _atomic_json(self, path: Path, payload: dict[str, Any]) -> None:
        encoded = (json.dumps(payload, sort_keys=True, indent=2, default=str) + "\n").encode(
            "utf-8"
        )
        self._atomic_write(path, encoded)

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
