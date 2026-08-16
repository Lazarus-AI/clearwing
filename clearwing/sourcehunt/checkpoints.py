"""Portable checkpoint bundles for the legacy sourcehunt pipeline."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from clearwing.analysis.source_analyzer import AnalyzerFinding as StaticFinding

from .callgraph import CallGraph
from .preprocessor import PreprocessResult
from .state import FileTarget
from .taint import TaintPath

CHECKPOINT_BUNDLE_SCHEMA_VERSION = 1
PREPROCESS_CHECKPOINT_SCHEMA_VERSION = 1
PREPROCESSOR_VERSION = 1
RANK_CHECKPOINT_SCHEMA_VERSION = 1
RANKER_VERSION = 1

logger = logging.getLogger(__name__)


class PortablePreprocessResult(BaseModel):
    """Preprocessing handoff without worker-local filesystem paths."""

    model_config = ConfigDict(extra="forbid")

    file_targets: list[FileTarget]
    static_findings: list[StaticFinding]
    semgrep_findings: list[dict[str, Any]] = Field(default_factory=list)
    callgraph: CallGraph | None = None
    fuzz_corpora: list[dict[str, Any]] = Field(default_factory=list)
    taint_paths: list[TaintPath] = Field(default_factory=list)

    @classmethod
    def from_result(cls, result: PreprocessResult) -> PortablePreprocessResult:
        targets = []
        for target in result.file_targets:
            portable = dict(target)
            portable.pop("absolute_path", None)
            targets.append(portable)
        return cls(
            file_targets=targets,
            static_findings=result.static_findings,
            semgrep_findings=result.semgrep_findings,
            callgraph=result.callgraph,
            fuzz_corpora=result.fuzz_corpora,
            taint_paths=result.taint_paths,
        )

    def materialize(self, repo_path: str | Path) -> PreprocessResult:
        """Rebind relative targets to a newly materialized checkout."""

        root = Path(repo_path).resolve()
        targets: list[FileTarget] = []
        for target in self.file_targets:
            relative = Path(str(target.get("path") or ""))
            if not relative.parts or relative.is_absolute():
                raise ValueError("checkpoint file target must be repository-relative")
            absolute = (root / relative).resolve()
            if not absolute.is_relative_to(root):
                raise ValueError("checkpoint file target escapes repository")
            if not absolute.is_file():
                raise ValueError(f"checkpoint file target is missing: {relative.as_posix()}")
            rebound = dict(target)
            rebound["path"] = relative.as_posix()
            rebound["absolute_path"] = str(absolute)
            targets.append(rebound)
        return PreprocessResult(
            repo_path=str(root),
            file_targets=targets,
            static_findings=self.static_findings,
            semgrep_findings=self.semgrep_findings,
            callgraph=self.callgraph,
            fuzz_corpora=self.fuzz_corpora,
            taint_paths=self.taint_paths,
        )


class PreprocessCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = PREPROCESS_CHECKPOINT_SCHEMA_VERSION
    stage: Literal["preprocess"] = "preprocess"
    status: Literal["completed"] = "completed"
    repo_url: str
    branch: str
    commit_sha: str | None
    options: dict[str, Any]
    preprocessor_version: Literal[1] = PREPROCESSOR_VERSION
    metrics: dict[str, int]
    result: PortablePreprocessResult


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
    fingerprint: RankFingerprint
    metrics: dict[str, int]
    result: list[dict[str, Any]]


class CheckpointBundle(BaseModel):
    """Self-contained HTTP and filesystem checkpoint representation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_BUNDLE_SCHEMA_VERSION
    flow: Literal["legacy"] = "legacy"
    preprocess: PreprocessCheckpoint | None = None
    rank: RankCheckpoint | None = None


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


def preprocess_result_digest(result: PreprocessResult) -> str:
    payload = json.dumps(
        _canonicalize(PortablePreprocessResult.from_result(result).model_dump(mode="python")),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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


def _canonicalize(value: Any) -> Any:
    """Normalize unordered nested values before checkpoint fingerprinting."""

    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        normalized = [_canonicalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


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
    ) -> PreprocessResult | None:
        checkpoint = self.bundle_store.bundle.preprocess
        if checkpoint is None:
            return None
        current_commit = repository_commit_sha(repo_path)
        if current_commit != checkpoint.commit_sha:
            logger.warning(
                "Preprocess checkpoint commit mismatch (checkpoint=%s, checkout=%s)",
                checkpoint.commit_sha,
                current_commit,
            )
            return None
        try:
            return checkpoint.result.materialize(repo_path)
        except (OSError, ValueError):
            return None

    def save(
        self,
        result: PreprocessResult,
        *,
        repo_url: str,
        branch: str,
        options: dict[str, Any],
    ) -> None:
        self.bundle_store.bundle.preprocess = PreprocessCheckpoint(
            repo_url=repo_url,
            branch=branch,
            commit_sha=repository_commit_sha(result.repo_path),
            options=options,
            metrics={
                "files": len(result.file_targets),
                "static_findings": len(result.static_findings),
                "semgrep_findings": len(result.semgrep_findings),
                "taint_paths": len(result.taint_paths),
            },
            result=PortablePreprocessResult.from_result(result),
        )
        # A new preprocessing handoff invalidates every downstream checkpoint.
        self.bundle_store.bundle.rank = None
        self.bundle_store.save()


class RankCheckpointStore:
    def __init__(self, bundle_store: CheckpointBundleStore):
        self.bundle_store = bundle_store

    def load(self, *, preprocess_digest: str, options: dict[str, Any]) -> list[dict] | None:
        checkpoint = self.bundle_store.bundle.rank
        if checkpoint is None:
            return None
        if checkpoint.fingerprint.preprocess_digest != preprocess_digest:
            return None
        if checkpoint.fingerprint.options != options:
            return None
        return [dict(item) for item in checkpoint.result]

    def save(self, files: list[dict], *, preprocess_digest: str, options: dict[str, Any]) -> None:
        self.bundle_store.bundle.rank = RankCheckpoint(
            fingerprint=RankFingerprint(
                preprocess_digest=preprocess_digest,
                options=options,
            ),
            metrics={"files": len(files)},
            result=files,
        )
        self.bundle_store.save()
