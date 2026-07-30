"""Atomic DTO files plus an external SQLite resume index."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import cast

from clearwing.reporting.safety import redact_tree
from clearwing.sourcehunt.artifact_store import ArtifactStore
from clearwing.sourcehunt.paths import resolve_repo_file, safe_repo_relative_path

from .models import RemediationDTO

_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediations (
    remediation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    dto_path TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediation_fingerprint
    ON remediations(fingerprint);
CREATE INDEX IF NOT EXISTS idx_remediation_status
    ON remediations(status);
"""


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned[:120] or "finding"


class RemediationStore:
    """Persist redacted DTOs and encrypted exact diffs outside the target repo."""

    def __init__(self, output_dir: str | Path):
        self.root = Path(output_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._conn = sqlite3.connect(str(self.root / "remediation.db"))
        os.chmod(self.root / "remediation.db", 0o600)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._artifacts = ArtifactStore(base_dir=self.root / ".artifacts")

    def close(self) -> None:
        self._conn.close()

    def save(self, dto: RemediationDTO) -> Path:
        dto.touch()
        if dto.proposed_fix is not None and dto.proposed_fix.diff:
            artifact = self._artifacts.store_remediation_patch(
                dto.remediation_id,
                dto.proposed_fix.diff.encode("utf-8"),
            )
            dto.proposed_fix.encrypted_diff_path = str(artifact)

        finding_dir = self.root / "findings" / _safe_id(dto.finding.id)
        finding_dir.mkdir(parents=True, exist_ok=True)
        target = finding_dir / f"{_safe_id(dto.remediation_id)}.json"
        payload = redact_tree(dto.model_dump(mode="json"))
        descriptor, temporary = tempfile.mkstemp(
            prefix="remediation-",
            suffix=".json.tmp",
            dir=str(finding_dir),
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

        self._conn.execute(
            """INSERT INTO remediations
               (remediation_id, run_id, finding_id, fingerprint, status,
                dto_path, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(remediation_id) DO UPDATE SET
                 run_id=excluded.run_id,
                 finding_id=excluded.finding_id,
                 fingerprint=excluded.fingerprint,
                 status=excluded.status,
                 dto_path=excluded.dto_path,
                 updated_at=excluded.updated_at""",
            (
                dto.remediation_id,
                dto.run_id,
                dto.finding.id,
                dto.fingerprint,
                dto.status,
                str(target),
                time.time(),
            ),
        )
        self._conn.commit()
        return target

    def store_backups(self, dto: RemediationDTO, backups: dict[str, bytes]) -> None:
        for relative_path, content in backups.items():
            artifact = self._artifacts.store_remediation_backup(
                dto.remediation_id,
                relative_path,
                content,
            )
            dto.application.encrypted_backup_paths[relative_path] = str(artifact)

    def restore_backups(self, dto: RemediationDTO, repo: str | Path) -> None:
        root = Path(repo).resolve()
        targets: list[tuple[str, Path, Path]] = []
        for relative_path, artifact_path in dto.application.encrypted_backup_paths.items():
            relative = safe_repo_relative_path(relative_path)
            target = root / (relative or "")
            resolved = resolve_repo_file(root, relative_path)
            if relative is None or resolved is None or resolved != target:
                raise RuntimeError(
                    f"refusing persisted rollback for unsafe target {relative_path!r}"
                )
            current = target.read_bytes() if target.is_file() else b""
            expected_after = dto.application.after_sha256.get(relative_path)
            if expected_after and hashlib.sha256(current).hexdigest() != expected_after:
                raise RuntimeError(
                    f"refusing persisted rollback because {relative_path} changed after apply"
                )
            targets.append((relative_path, target, Path(artifact_path)))
        # Decrypt only after every current target has passed the hash guard.
        backups: list[tuple[Path, bytes]] = []
        for relative_path, target, stored_path in targets:
            content = self._artifacts.retrieve(
                stored_path,
                operator="remediation-workflow",
                approved_by="remediation-rollback",
            )
            expected_before = dto.application.before_sha256.get(relative_path)
            if not expected_before or hashlib.sha256(content).hexdigest() != expected_before:
                raise RuntimeError(
                    f"encrypted rollback snapshot failed integrity check: {relative_path}"
                )
            backups.append((target, content))
        for target, content in backups:
            target.write_bytes(content)

    def load(self, path: str | Path) -> RemediationDTO:
        source = Path(path).expanduser().resolve()
        source.relative_to(self.root)
        dto = cast(
            RemediationDTO,
            RemediationDTO.model_validate_json(source.read_text(encoding="utf-8")),
        )
        fix = dto.proposed_fix
        if fix is not None and fix.encrypted_diff_path:
            raw = self._artifacts.retrieve(
                Path(fix.encrypted_diff_path),
                operator="remediation-workflow",
                approved_by="remediation-resume",
            )
            if hashlib.sha256(raw).hexdigest() != fix.diff_sha256:
                raise ValueError("encrypted remediation patch failed integrity check")
            fix.diff = raw.decode("utf-8")
        return dto

    def find_by_fingerprint(self, fingerprint: str) -> RemediationDTO | None:
        row = self._conn.execute(
            "SELECT dto_path FROM remediations WHERE fingerprint = ? "
            "ORDER BY updated_at DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()
        if row is None:
            return None
        try:
            return self.load(row["dto_path"])
        except FileNotFoundError:
            return None

    def load_all(self) -> list[RemediationDTO]:
        rows = self._conn.execute(
            "SELECT dto_path FROM remediations ORDER BY updated_at DESC"
        ).fetchall()
        output: list[RemediationDTO] = []
        for row in rows:
            output.append(self.load(row["dto_path"]))
        return output

    def status_counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS count FROM remediations GROUP BY status"
        ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}
