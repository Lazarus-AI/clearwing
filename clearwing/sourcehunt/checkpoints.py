"""Portable checkpoint bundles for the legacy sourcehunt pipeline."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from clearwing.findings.types import Finding

from .preprocessor import PreprocessResult
from .state import FileTarget

CHECKPOINT_SCHEMA_VERSION = 1

logger = logging.getLogger(__name__)


class PreprocessCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
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
            options=options,
            result=result.to_checkpoint(),
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
            return PreprocessResult.from_checkpoint(self.result, repo_path)
        except (OSError, ValueError):
            logger.error("Preprocess checkpoint result is invalid", exc_info=True)
            return None


class RankCheckpoint(BaseModel):
    """Portable state produced by the completed ranking stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
    options: dict[str, Any]
    ranked_file_targets: list[FileTarget]

    @classmethod
    def from_result(
        cls,
        files: list[FileTarget],
        *,
        options: dict[str, Any],
    ) -> RankCheckpoint:
        ranked_targets = []
        for target in files:
            portable = dict(target)
            portable.pop("absolute_path", None)
            ranked_targets.append(portable)
        return cls(
            options=options,
            ranked_file_targets=ranked_targets,
        )

    def restore(
        self,
        files: list[FileTarget],
        *,
        options: dict[str, Any],
    ) -> list[FileTarget] | None:
        if self.options != options:
            logger.error("Rank checkpoint options do not match this run")
            return None
        if len(files) != len(self.ranked_file_targets):
            logger.error("Rank checkpoint file count does not match preprocessing")
            return None

        restored: list[FileTarget] = []
        for current, saved in zip(files, self.ranked_file_targets, strict=True):
            if current.get("path") != saved.get("path"):
                logger.error("Rank checkpoint files do not match preprocessing")
                return None
            rebound = dict(saved)
            if "absolute_path" in current:
                rebound["absolute_path"] = current["absolute_path"]
            restored.append(rebound)
        return restored


class HuntResult(BaseModel):
    """State handed from all source hunting to downstream phases."""

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding]
    files_hunted: int = 0
    spent_per_tier: dict[str, float]
    band_stats: dict[str, Any] | None = None
    subsystems_hunted: int = 0
    subsystem_spent_usd: float = 0.0


class HuntCheckpoint(BaseModel):
    """Portable state produced by the completed source-hunt stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
    options: dict[str, Any]
    result: HuntResult

    @classmethod
    def from_result(cls, result: HuntResult, *, options: dict[str, Any]) -> HuntCheckpoint:
        return cls(options=options, result=result)

    def restore(self, *, options: dict[str, Any]) -> HuntResult | None:
        if self.options != options:
            logger.error("Hunt checkpoint options do not match this run")
            return None
        return self.result.model_copy(deep=True)


class VerificationResult(BaseModel):
    """State handed from verification to exploitation."""

    model_config = ConfigDict(extra="forbid")

    verified: list[Finding]
    rejected: list[Finding]
    status: str = "completed"


class VerificationCheckpoint(BaseModel):
    """Portable state produced by the completed verification stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
    options: dict[str, Any]
    result: VerificationResult

    @classmethod
    def from_result(
        cls, result: VerificationResult, *, options: dict[str, Any]
    ) -> VerificationCheckpoint:
        return cls(options=options, result=result)

    def restore(self, *, options: dict[str, Any]) -> VerificationResult | None:
        if self.options != options:
            logger.error("Verification checkpoint options do not match this run")
            return None
        return self.result.model_copy(deep=True)


class ExploitationResult(BaseModel):
    """State handed from exploitation to reporting and optional follow-ups."""

    model_config = ConfigDict(extra="forbid")

    verified: list[Finding]
    exploited: list[Finding]


class ExploitationCheckpoint(BaseModel):
    """Portable state produced by the completed exploitation stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
    options: dict[str, Any]
    result: ExploitationResult

    @classmethod
    def from_result(
        cls, result: ExploitationResult, *, options: dict[str, Any]
    ) -> ExploitationCheckpoint:
        return cls(options=options, result=result)

    def restore(self, *, options: dict[str, Any]) -> ExploitationResult | None:
        if self.options != options:
            logger.error("Exploitation checkpoint options do not match this run")
            return None
        return self.result.model_copy(deep=True)


class SourceHuntCheckpoint(BaseModel):
    """Stage-keyed sourcehunt checkpoint passed across the bridge boundary."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
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

        if isinstance(value, str):
            return cls.model_validate_json(value)
        return cls.model_validate(value)

    @classmethod
    def from_file(cls, path: str | Path) -> SourceHuntCheckpoint:
        """Load and validate a checkpoint from its host-selected JSON path."""

        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))

    def dump(self, path: str | Path) -> Path:
        """Atomically write the complete checkpoint model to a JSON file."""

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = self.model_dump_json(indent=2).encode("utf-8") + b"\n"
        descriptor, temporary = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return target


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
