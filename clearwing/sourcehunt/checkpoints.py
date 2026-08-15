"""Durable stage checkpoints for the legacy sourcehunt pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, TypeAdapter

from clearwing.findings.types import Finding

from .preprocessor import PreprocessResult

PREPROCESS_CHECKPOINT_SCHEMA_VERSION = 1
PREPROCESSOR_VERSION = 1
RANK_CHECKPOINT_SCHEMA_VERSION = 1
RANKER_VERSION = 1
HUNT_CHECKPOINT_SCHEMA_VERSION = 1
HUNTER_VERSION = 1
VERIFY_CHECKPOINT_SCHEMA_VERSION = 1
VERIFIER_VERSION = 1
EXPLOIT_CHECKPOINT_SCHEMA_VERSION = 1
EXPLOITER_VERSION = 1


class PreprocessFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_url: str
    branch: str
    source_digest: str
    options: dict[str, Any]
    preprocessor_version: Literal[1] = PREPROCESSOR_VERSION


class PreprocessCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = PREPROCESS_CHECKPOINT_SCHEMA_VERSION
    stage: Literal["preprocess"] = "preprocess"
    status: Literal["completed"] = "completed"
    session_id: str
    fingerprint: PreprocessFingerprint
    result_path: Literal["result.json"] = "result.json"
    result_sha256: str
    metrics: dict[str, int]


def source_tree_digest(
    repo_path: str | Path,
    *,
    exclude: Path | None = None,
) -> str:
    """Hash source-tree paths and contents without depending on Git state."""

    root = Path(repo_path).resolve()
    excluded = exclude.resolve() if exclude is not None else None
    digest = hashlib.sha256()
    skipped = {".git", ".clearwing", "node_modules", "__pycache__"}
    for path in sorted(
        candidate
        for candidate in root.rglob("*")
        if candidate.is_file() and not candidate.is_symlink()
    ):
        if excluded is not None and (path == excluded or excluded in path.parents):
            continue
        if any(part in skipped for part in path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


class PreprocessCheckpointStore:
    def __init__(self, session_dir: Path, session_id: str):
        self.directory = session_dir / "checkpoints" / "preprocess"
        self.output_root = session_dir.parent
        self.session_id = session_id
        self.envelope_path = self.directory / "checkpoint.json"
        self.result_path = self.directory / "result.json"

    def load(
        self,
        *,
        repo_url: str,
        branch: str,
        options: dict[str, Any],
    ) -> PreprocessResult | None:
        try:
            envelope = PreprocessCheckpoint.model_validate_json(
                self.envelope_path.read_text(encoding="utf-8")
            )
            if envelope.session_id != self.session_id:
                return None
            if envelope.fingerprint.repo_url != repo_url:
                return None
            if envelope.fingerprint.branch != branch or envelope.fingerprint.options != options:
                return None
            payload = (self.directory / envelope.result_path).read_bytes()
            if hashlib.sha256(payload).hexdigest() != envelope.result_sha256:
                return None
            result = PreprocessResult.model_validate_json(payload)
            if not Path(result.repo_path).is_dir():
                return None
            if source_tree_digest(
                result.repo_path, exclude=self.output_root
            ) != envelope.fingerprint.source_digest:
                return None
            return result
        except (OSError, ValueError, TypeError):
            return None

    def save(
        self,
        result: PreprocessResult,
        *,
        repo_url: str,
        branch: str,
        options: dict[str, Any],
    ) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump_json(indent=2).encode("utf-8")
        envelope = PreprocessCheckpoint(
            session_id=self.session_id,
            fingerprint=PreprocessFingerprint(
                repo_url=repo_url,
                branch=branch,
                source_digest=source_tree_digest(result.repo_path, exclude=self.output_root),
                options=options,
            ),
            result_sha256=hashlib.sha256(payload).hexdigest(),
            metrics={
                "files": len(result.file_targets),
                "static_findings": len(result.static_findings),
                "semgrep_findings": len(result.semgrep_findings),
                "taint_paths": len(result.taint_paths),
            },
        )
        self._atomic_write(self.result_path, payload)
        self._atomic_write(
            self.envelope_path,
            envelope.model_dump_json(indent=2).encode("utf-8"),
        )

    @staticmethod
    def _atomic_write(target: Path, payload: bytes) -> None:
        fd, temporary = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


def preprocess_result_digest(result: PreprocessResult) -> str:
    payload = json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RankFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preprocess_digest: str
    options: dict[str, Any]
    ranker_version: Literal[1] = RANKER_VERSION


class RankCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = RANK_CHECKPOINT_SCHEMA_VERSION
    stage: Literal["rank"] = "rank"
    status: Literal["completed"] = "completed"
    session_id: str
    fingerprint: RankFingerprint
    result_path: Literal["result.json"] = "result.json"
    result_sha256: str
    metrics: dict[str, int]


class RankCheckpointStore:
    def __init__(self, session_dir: Path, session_id: str):
        self.directory = session_dir / "checkpoints" / "rank"
        self.session_id = session_id
        self.envelope_path = self.directory / "checkpoint.json"
        self.result_path = self.directory / "result.json"

    def load(self, *, preprocess_digest: str, options: dict[str, Any]) -> list[dict] | None:
        try:
            envelope = RankCheckpoint.model_validate_json(
                self.envelope_path.read_text(encoding="utf-8")
            )
            if envelope.session_id != self.session_id:
                return None
            if envelope.fingerprint.preprocess_digest != preprocess_digest:
                return None
            if envelope.fingerprint.options != options:
                return None
            payload = (self.directory / envelope.result_path).read_bytes()
            if hashlib.sha256(payload).hexdigest() != envelope.result_sha256:
                return None
            result = json.loads(payload)
            if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
                return None
            return result
        except (OSError, ValueError, TypeError):
            return None

    def save(self, files: list[dict], *, preprocess_digest: str, options: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(files, indent=2, sort_keys=True).encode("utf-8")
        envelope = RankCheckpoint(
            session_id=self.session_id,
            fingerprint=RankFingerprint(
                preprocess_digest=preprocess_digest,
                options=options,
            ),
            result_sha256=hashlib.sha256(payload).hexdigest(),
            metrics={"files": len(files)},
        )
        PreprocessCheckpointStore._atomic_write(self.result_path, payload)
        PreprocessCheckpointStore._atomic_write(
            self.envelope_path,
            envelope.model_dump_json(indent=2).encode("utf-8"),
        )


def ranked_targets_digest(files: list[dict]) -> str:
    payload = json.dumps(files, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class HuntResult(BaseModel):
    """Complete hand-off from the hunt stage to verification."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    findings: list[Finding]
    files_hunted: int = 0
    spent_per_tier: dict[str, float]
    band_stats: dict[str, Any] | None = None
    subsystems_hunted: int = 0
    subsystem_spent_usd: float = 0.0


class HuntFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ranked_targets_digest: str
    options: dict[str, Any]
    hunter_version: Literal[1] = HUNTER_VERSION


class HuntCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = HUNT_CHECKPOINT_SCHEMA_VERSION
    stage: Literal["hunt"] = "hunt"
    status: Literal["completed", "budget_exhausted"]
    session_id: str
    fingerprint: HuntFingerprint
    result_path: Literal["result.json"] = "result.json"
    result_sha256: str
    metrics: dict[str, int | float]


class HuntCheckpointStore:
    """Persist and restore a terminal hunt result.

    Both a normally completed hunt and a hunt stopped by the run budget are
    terminal, restorable states. Mid-hunt state is deliberately not modeled.
    """

    def __init__(self, session_dir: Path, session_id: str):
        self.directory = session_dir / "checkpoints" / "hunt"
        self.session_id = session_id
        self.envelope_path = self.directory / "checkpoint.json"
        self.result_path = self.directory / "result.json"
        self.last_status: Literal["completed", "budget_exhausted"] | None = None

    def load(
        self,
        *,
        ranked_targets_digest: str,
        options: dict[str, Any],
    ) -> HuntResult | None:
        self.last_status = None
        try:
            envelope = HuntCheckpoint.model_validate_json(
                self.envelope_path.read_text(encoding="utf-8")
            )
            if envelope.session_id != self.session_id:
                return None
            if envelope.fingerprint.ranked_targets_digest != ranked_targets_digest:
                return None
            if envelope.fingerprint.options != options:
                return None
            payload = (self.directory / envelope.result_path).read_bytes()
            if hashlib.sha256(payload).hexdigest() != envelope.result_sha256:
                return None
            result = HuntResult.model_validate_json(payload)
            self.last_status = envelope.status
            return result
        except (OSError, ValueError, TypeError):
            return None

    def save(
        self,
        result: HuntResult,
        *,
        status: Literal["completed", "budget_exhausted"],
        ranked_targets_digest: str,
        options: dict[str, Any],
    ) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump_json(indent=2).encode("utf-8")
        envelope = HuntCheckpoint(
            status=status,
            session_id=self.session_id,
            fingerprint=HuntFingerprint(
                ranked_targets_digest=ranked_targets_digest,
                options=options,
            ),
            result_sha256=hashlib.sha256(payload).hexdigest(),
            metrics={
                "findings": len(result.findings),
                "files_hunted": result.files_hunted,
                "subsystems_hunted": result.subsystems_hunted,
                "subsystem_spent_usd": result.subsystem_spent_usd,
            },
        )
        PreprocessCheckpointStore._atomic_write(self.result_path, payload)
        # The envelope is written last and acts as the completed-stage marker.
        PreprocessCheckpointStore._atomic_write(
            self.envelope_path,
            envelope.model_dump_json(indent=2).encode("utf-8"),
        )


def findings_digest(findings: list[Finding]) -> str:
    payload = json.dumps(
        TypeAdapter(list[Finding]).dump_python(findings, mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class VerificationResult(BaseModel):
    """Complete hand-off from verification to exploitation."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    findings: list[Finding]
    verified_findings: list[Finding]
    rejected_findings: list[Finding]


class VerificationFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hunt_findings_digest: str
    options: dict[str, Any]
    verifier_version: Literal[1] = VERIFIER_VERSION


class VerificationCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = VERIFY_CHECKPOINT_SCHEMA_VERSION
    stage: Literal["verify"] = "verify"
    status: Literal["completed", "degraded", "skipped", "budget_exhausted"]
    session_id: str
    fingerprint: VerificationFingerprint
    result_path: Literal["result.json"] = "result.json"
    result_sha256: str
    metrics: dict[str, int]


class VerificationCheckpointStore:
    def __init__(self, session_dir: Path, session_id: str):
        self.directory = session_dir / "checkpoints" / "verify"
        self.session_id = session_id
        self.envelope_path = self.directory / "checkpoint.json"
        self.result_path = self.directory / "result.json"
        self.last_status: str | None = None

    def load(
        self, *, hunt_findings_digest: str, options: dict[str, Any]
    ) -> VerificationResult | None:
        self.last_status = None
        try:
            envelope = VerificationCheckpoint.model_validate_json(
                self.envelope_path.read_text(encoding="utf-8")
            )
            if envelope.session_id != self.session_id:
                return None
            if envelope.fingerprint.hunt_findings_digest != hunt_findings_digest:
                return None
            if envelope.fingerprint.options != options:
                return None
            payload = (self.directory / envelope.result_path).read_bytes()
            if hashlib.sha256(payload).hexdigest() != envelope.result_sha256:
                return None
            result = VerificationResult.model_validate_json(payload)
            self.last_status = envelope.status
            return result
        except (OSError, ValueError, TypeError):
            return None

    def save(
        self,
        result: VerificationResult,
        *,
        status: Literal["completed", "degraded", "skipped", "budget_exhausted"],
        hunt_findings_digest: str,
        options: dict[str, Any],
    ) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump_json(indent=2).encode("utf-8")
        envelope = VerificationCheckpoint(
            status=status,
            session_id=self.session_id,
            fingerprint=VerificationFingerprint(
                hunt_findings_digest=hunt_findings_digest,
                options=options,
            ),
            result_sha256=hashlib.sha256(payload).hexdigest(),
            metrics={
                "findings": len(result.findings),
                "verified": len(result.verified_findings),
                "rejected": len(result.rejected_findings),
            },
        )
        PreprocessCheckpointStore._atomic_write(self.result_path, payload)
        PreprocessCheckpointStore._atomic_write(
            self.envelope_path,
            envelope.model_dump_json(indent=2).encode("utf-8"),
        )


def verification_result_digest(result: VerificationResult) -> str:
    payload = json.dumps(
        result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ExploitationResult(BaseModel):
    """Complete hand-off from exploitation to reporting."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    findings: list[Finding]
    verified_findings: list[Finding]
    exploited_findings: list[Finding]


class ExploitationFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verification_result_digest: str
    options: dict[str, Any]
    exploiter_version: Literal[1] = EXPLOITER_VERSION


class ExploitationCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = EXPLOIT_CHECKPOINT_SCHEMA_VERSION
    stage: Literal["exploit"] = "exploit"
    status: Literal["completed", "skipped", "budget_exhausted"]
    session_id: str
    fingerprint: ExploitationFingerprint
    result_path: Literal["result.json"] = "result.json"
    result_sha256: str
    metrics: dict[str, int]


class ExploitationCheckpointStore:
    def __init__(self, session_dir: Path, session_id: str):
        self.directory = session_dir / "checkpoints" / "exploit"
        self.session_id = session_id
        self.envelope_path = self.directory / "checkpoint.json"
        self.result_path = self.directory / "result.json"
        self.last_status: str | None = None

    def load(
        self, *, verification_result_digest: str, options: dict[str, Any]
    ) -> ExploitationResult | None:
        self.last_status = None
        try:
            envelope = ExploitationCheckpoint.model_validate_json(
                self.envelope_path.read_text(encoding="utf-8")
            )
            if envelope.session_id != self.session_id:
                return None
            if envelope.fingerprint.verification_result_digest != verification_result_digest:
                return None
            if envelope.fingerprint.options != options:
                return None
            payload = (self.directory / envelope.result_path).read_bytes()
            if hashlib.sha256(payload).hexdigest() != envelope.result_sha256:
                return None
            result = ExploitationResult.model_validate_json(payload)
            self.last_status = envelope.status
            return result
        except (OSError, ValueError, TypeError):
            return None

    def save(
        self,
        result: ExploitationResult,
        *,
        status: Literal["completed", "skipped", "budget_exhausted"],
        verification_result_digest: str,
        options: dict[str, Any],
    ) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump_json(indent=2).encode("utf-8")
        envelope = ExploitationCheckpoint(
            status=status,
            session_id=self.session_id,
            fingerprint=ExploitationFingerprint(
                verification_result_digest=verification_result_digest,
                options=options,
            ),
            result_sha256=hashlib.sha256(payload).hexdigest(),
            metrics={
                "findings": len(result.findings),
                "verified": len(result.verified_findings),
                "exploited": len(result.exploited_findings),
            },
        )
        PreprocessCheckpointStore._atomic_write(self.result_path, payload)
        PreprocessCheckpointStore._atomic_write(
            self.envelope_path,
            envelope.model_dump_json(indent=2).encode("utf-8"),
        )
