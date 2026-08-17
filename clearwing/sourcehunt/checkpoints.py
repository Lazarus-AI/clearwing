"""Portable checkpoint bundles for the legacy sourcehunt pipeline."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .preprocessor import PreprocessResult

CHECKPOINT_SCHEMA_VERSION = 1

logger = logging.getLogger(__name__)


class PreprocessCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit_sha: str | None
    options: dict[str, Any]
    result: dict[str, Any]


class CheckpointBundle(BaseModel):
    """Portable preprocessing checkpoint representation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
    flow: Literal["legacy"] = "legacy"
    preprocess: PreprocessCheckpoint | None = None


CheckpointInput = CheckpointBundle | dict[str, Any] | str | None


def parse_checkpoint(value: CheckpointInput) -> CheckpointBundle | None:
    """Validate a bridge-provided checkpoint object or serialized JSON blob."""

    if value is None:
        return None
    if isinstance(value, CheckpointBundle):
        return value.model_copy(deep=True)
    if isinstance(value, str):
        return CheckpointBundle.model_validate_json(value)
    return CheckpointBundle.model_validate(value)


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


class CheckpointBundleStore:
    """Read and atomically publish one portable checkpoint document."""

    def __init__(self, session_dir: Path, bundle: CheckpointInput = None):
        self.session_dir = session_dir
        self.path = session_dir / "checkpoint.json"
        self.bundle = parse_checkpoint(bundle) or CheckpointBundle()

    def save(self) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(
            self.path,
            self.bundle.model_dump_json(indent=2).encode("utf-8"),
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


class PreprocessCheckpointStore:
    def __init__(self, bundle_store: CheckpointBundleStore):
        self.bundle_store = bundle_store

    def load(
        self,
        *,
        repo_path: str,
        options: dict[str, Any],
    ) -> PreprocessResult | None:
        checkpoint = self.bundle_store.bundle.preprocess
        if checkpoint is None:
            return None
        current_commit = repository_commit_sha(repo_path)
        if current_commit is None or current_commit != checkpoint.commit_sha:
            logger.warning(
                "Preprocess checkpoint commit mismatch (checkpoint=%s, checkout=%s)",
                checkpoint.commit_sha,
                current_commit,
            )
            return None
        if checkpoint.options != options:
            logger.warning("Preprocess checkpoint options do not match this run")
            return None
        try:
            return PreprocessResult.from_checkpoint(checkpoint.result, repo_path)
        except (OSError, ValueError):
            return None

    def save(
        self,
        result: PreprocessResult,
        *,
        options: dict[str, Any],
    ) -> None:
        self.bundle_store.bundle.preprocess = PreprocessCheckpoint(
            commit_sha=repository_commit_sha(result.repo_path),
            options=options,
            result=result.to_checkpoint(),
        )
        self.bundle_store.save()
