"""Portable checkpoint bundles for the legacy sourcehunt pipeline."""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from clearwing.findings.types import Finding

from .preprocessor import PreprocessResult
from .state import FileTarget

CHECKPOINT_SCHEMA_VERSION: Literal[2] = 2
StageStatus = Literal["completed", "skipped", "budget_exhausted", "degraded"]

logger = logging.getLogger(__name__)


def _canonical_value(value: Any) -> Any:
    """Convert checkpoint inputs into deterministic JSON-compatible values."""

    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="json"))
    if is_dataclass(value) and not isinstance(value, type):
        return _canonical_value(asdict(value))
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_canonical_value(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ),
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def checkpoint_digest(value: Any) -> str:
    """Return a stable digest for a stage input."""

    payload = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def portable_file_targets(files: list[FileTarget]) -> list[FileTarget]:
    """Copy file targets without worker-local absolute paths."""

    portable: list[FileTarget] = []
    for target in files:
        item = deepcopy(dict(target))
        item.pop("absolute_path", None)
        portable.append(cast(FileTarget, item))
    return portable


def portable_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Normalize run-local IDs while retaining each finding's semantic payload."""

    portable: list[dict[str, Any]] = []
    for finding in findings:
        item = asdict(finding)
        if finding.discovered_by == "source_analyzer":
            stable_id = finding.extra.get("stable_finding_id")
            if stable_id:
                item["id"] = stable_id
        portable.append(item)
    return portable


def _validate_repo_relative_path(value: str | None, *, field: str) -> None:
    """Reject paths that cannot be interpreted within the resumed repository."""

    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if value == "":
        return
    if "\x00" in value:
        raise ValueError(f"{field} contains a NUL byte")

    posix_path = PurePosixPath(value.replace("\\", "/"))
    windows_path = PureWindowsPath(value)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
    ):
        raise ValueError(f"{field} must be repository-relative")
    if ".." in posix_path.parts or ".." in windows_path.parts:
        raise ValueError(f"{field} must not traverse outside the repository")


def _validate_finding_paths(findings: list[Finding]) -> None:
    for finding in findings:
        _validate_repo_relative_path(finding.file, field="finding.file")
        trace = finding.vulnerability_trace
        if not isinstance(trace, dict):
            continue
        steps = trace.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or "file" not in step:
                continue
            _validate_repo_relative_path(
                step.get("file"),
                field=f"finding.vulnerability_trace.steps[{index}].file",
            )


def split_portable_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Partition untrusted findings by whether all source paths are repository-relative."""

    accepted: list[Finding] = []
    rejected: list[Finding] = []
    for finding in findings:
        if finding.file is None or finding.file == "":
            rejected.append(finding)
            continue
        try:
            _validate_finding_paths([finding])
        except ValueError:
            rejected.append(finding)
        else:
            accepted.append(finding)
    return accepted, rejected


def _strip_exploit_transcript_paths(result: ExploitationResult) -> None:
    for finding in [*result.verified, *result.exploited]:
        finding.extra.pop("exploit_transcript_path", None)


class PreprocessCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = CHECKPOINT_SCHEMA_VERSION
    commit_sha: str | None
    options: dict[str, Any]
    result: dict[str, Any]

    @classmethod
    def from_result(
        cls,
        result: PreprocessResult,
        *,
        options: dict[str, Any],
    ) -> PreprocessCheckpoint:
        return cls(
            commit_sha=repository_commit_sha(result.repo_path),
            options=deepcopy(options),
            result=deepcopy(result.to_checkpoint()),
        )

    def restore(
        self,
        *,
        repo_path: str,
        options: dict[str, Any],
    ) -> PreprocessResult | None:
        current_commit = repository_commit_sha(repo_path)
        if current_commit is None or current_commit != self.commit_sha:
            logger.error(
                "Preprocess checkpoint commit mismatch (checkpoint=%s, checkout=%s)",
                self.commit_sha,
                current_commit,
            )
            return None
        if self.options != options:
            logger.error("Preprocess checkpoint options do not match this run")
            return None
        try:
            return PreprocessResult.from_checkpoint(deepcopy(self.result), repo_path)
        except (OSError, ValueError):
            logger.error("Preprocess checkpoint result is invalid", exc_info=True)
            return None


class RankCheckpoint(BaseModel):
    """Portable state produced by the ranking stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = CHECKPOINT_SCHEMA_VERSION
    input_digest: str
    options: dict[str, Any]
    ranked_file_targets: list[FileTarget]

    @classmethod
    def from_result(
        cls,
        files: list[FileTarget],
        *,
        options: dict[str, Any],
        input_digest: str,
    ) -> RankCheckpoint:
        return cls(
            input_digest=input_digest,
            options=deepcopy(options),
            ranked_file_targets=portable_file_targets(files),
        )

    def restore(
        self,
        files: list[FileTarget],
        *,
        options: dict[str, Any],
        input_digest: str,
    ) -> list[FileTarget] | None:
        if self.options != options or self.input_digest != input_digest:
            logger.error("Rank checkpoint inputs do not match this run")
            return None
        if len(files) != len(self.ranked_file_targets):
            logger.error("Rank checkpoint file count does not match preprocessing")
            return None

        restored: list[FileTarget] = []
        for current, saved in zip(files, self.ranked_file_targets, strict=True):
            if current.get("path") != saved.get("path"):
                logger.error("Rank checkpoint files do not match preprocessing")
                return None
            rebound = deepcopy(dict(saved))
            if "absolute_path" in current:
                rebound["absolute_path"] = current["absolute_path"]
            restored.append(cast(FileTarget, rebound))
        return restored


class HuntResult(BaseModel):
    """State handed from all source hunting to downstream phases."""

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding]
    files_hunted: int = 0
    spent_per_tier: dict[str, float]
    band_stats: dict[str, Any] | None = None
    per_file_status: StageStatus = "completed"
    subsystems_hunted: int = 0
    subsystem_spent_usd: float = 0.0
    subsystem_status: StageStatus = "skipped"
    status: StageStatus = "completed"


class HuntCheckpoint(BaseModel):
    """Portable state produced by the source-hunt stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = CHECKPOINT_SCHEMA_VERSION
    input_digest: str
    options: dict[str, Any]
    resume_inputs: dict[str, Any] = Field(default_factory=dict)
    result: HuntResult

    @model_validator(mode="after")
    def _validate_paths(self) -> HuntCheckpoint:
        _validate_finding_paths(self.result.findings)
        return self

    @classmethod
    def from_result(
        cls,
        result: HuntResult,
        *,
        options: dict[str, Any],
        input_digest: str,
        resume_inputs: dict[str, Any] | None = None,
    ) -> HuntCheckpoint:
        _validate_finding_paths(result.findings)
        return cls(
            input_digest=input_digest,
            options=deepcopy(options),
            resume_inputs=deepcopy(resume_inputs or {}),
            result=result.model_copy(deep=True),
        )

    def restore(self, *, options: dict[str, Any], input_digest: str) -> HuntResult | None:
        if self.options != options or self.input_digest != input_digest:
            logger.error("Hunt checkpoint inputs do not match this run")
            return None
        _validate_finding_paths(self.result.findings)
        return cast(HuntResult, self.result.model_copy(deep=True))


class VerificationResult(BaseModel):
    """State handed from verification to exploitation."""

    model_config = ConfigDict(extra="forbid")

    verified: list[Finding]
    rejected: list[Finding]
    status: StageStatus = "completed"


class VerificationCheckpoint(BaseModel):
    """Portable state produced by the verification stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = CHECKPOINT_SCHEMA_VERSION
    input_digest: str
    options: dict[str, Any]
    result: VerificationResult

    @model_validator(mode="after")
    def _validate_paths(self) -> VerificationCheckpoint:
        _validate_finding_paths([*self.result.verified, *self.result.rejected])
        return self

    @classmethod
    def from_result(
        cls,
        result: VerificationResult,
        *,
        options: dict[str, Any],
        input_digest: str,
    ) -> VerificationCheckpoint:
        _validate_finding_paths([*result.verified, *result.rejected])
        return cls(
            input_digest=input_digest,
            options=deepcopy(options),
            result=result.model_copy(deep=True),
        )

    def restore(
        self,
        *,
        options: dict[str, Any],
        input_digest: str,
    ) -> VerificationResult | None:
        if self.options != options or self.input_digest != input_digest:
            logger.error("Verification checkpoint inputs do not match this run")
            return None
        _validate_finding_paths([*self.result.verified, *self.result.rejected])
        return cast(VerificationResult, self.result.model_copy(deep=True))


class ExploitationResult(BaseModel):
    """State handed from exploitation to reporting and optional follow-ups."""

    model_config = ConfigDict(extra="forbid")

    verified: list[Finding]
    exploited: list[Finding]
    status: StageStatus = "completed"


class ExploitationCheckpoint(BaseModel):
    """Portable state produced by the exploitation stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = CHECKPOINT_SCHEMA_VERSION
    input_digest: str
    options: dict[str, Any]
    resume_verified: list[Finding] = Field(default_factory=list)
    resume_all_findings: list[Finding] = Field(default_factory=list)
    result: ExploitationResult

    @model_validator(mode="after")
    def _validate_and_strip_nonportable_paths(self) -> ExploitationCheckpoint:
        _validate_finding_paths(
            [
                *self.resume_verified,
                *self.resume_all_findings,
                *self.result.verified,
                *self.result.exploited,
            ]
        )
        for finding in [*self.resume_verified, *self.resume_all_findings]:
            finding.extra.pop("exploit_transcript_path", None)
        _strip_exploit_transcript_paths(self.result)
        return self

    @classmethod
    def from_result(
        cls,
        result: ExploitationResult,
        *,
        options: dict[str, Any],
        input_digest: str,
        resume_verified: list[Finding] | None = None,
        resume_all_findings: list[Finding] | None = None,
    ) -> ExploitationCheckpoint:
        _validate_finding_paths(
            [
                *(resume_verified or []),
                *(resume_all_findings or []),
                *result.verified,
                *result.exploited,
            ]
        )
        snapshot = result.model_copy(deep=True)
        _strip_exploit_transcript_paths(snapshot)
        saved_verified = deepcopy(resume_verified or [])
        saved_all_findings = deepcopy(resume_all_findings or [])
        for finding in [*saved_verified, *saved_all_findings]:
            finding.extra.pop("exploit_transcript_path", None)
        return cls(
            input_digest=input_digest,
            options=deepcopy(options),
            resume_verified=saved_verified,
            resume_all_findings=saved_all_findings,
            result=snapshot,
        )

    def restore(
        self,
        *,
        options: dict[str, Any],
        input_digest: str,
    ) -> ExploitationResult | None:
        if self.options != options or self.input_digest != input_digest:
            logger.error("Exploitation checkpoint inputs do not match this run")
            return None
        _validate_finding_paths(
            [
                *self.resume_verified,
                *self.resume_all_findings,
                *self.result.verified,
                *self.result.exploited,
            ]
        )
        restored = cast(ExploitationResult, self.result.model_copy(deep=True))
        _strip_exploit_transcript_paths(restored)
        return restored


class SourceHuntCheckpoint(BaseModel):
    """Stage-keyed sourcehunt checkpoint passed across the bridge boundary."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2] = CHECKPOINT_SCHEMA_VERSION
    preprocess: PreprocessCheckpoint | None = None
    rank: RankCheckpoint | None = None
    hunt: HuntCheckpoint | None = None
    verification: VerificationCheckpoint | None = None
    exploitation: ExploitationCheckpoint | None = None

    @classmethod
    def from_input(
        cls,
        value: SourceHuntCheckpoint | dict[str, Any] | str,
    ) -> SourceHuntCheckpoint:
        """Validate a bridge-provided checkpoint object or serialized JSON blob."""

        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            return cast(SourceHuntCheckpoint, cls.model_validate_json(value))
        return cast(SourceHuntCheckpoint, cls.model_validate(value))


def repository_commit_sha(repo_path: str | Path) -> str | None:
    """Return the checkout's full HEAD SHA, or None for a non-Git source tree."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(Path(repo_path).resolve()), "rev-parse", "--verify", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = completed.stdout.strip()
    if completed.returncode != 0 or len(sha) != 40:
        return None
    return sha.lower()
