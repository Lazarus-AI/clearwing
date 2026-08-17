"""Portable checkpoint bundles for the legacy sourcehunt pipeline."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .preprocessor import PreprocessResult

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


def parse_checkpoint(
    value: PreprocessCheckpoint | dict[str, Any] | str | None,
) -> PreprocessCheckpoint | None:
    """Validate a bridge-provided checkpoint object or serialized JSON blob."""

    if value is None:
        return None
    if isinstance(value, PreprocessCheckpoint):
        return value.model_copy(deep=True)
    if isinstance(value, str):
        return PreprocessCheckpoint.model_validate_json(value)
    return PreprocessCheckpoint.model_validate(value)


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
