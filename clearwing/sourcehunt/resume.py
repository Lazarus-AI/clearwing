"""Crash-safe memoization for standalone SourceHunt sessions."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import tempfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding
from clearwing.runners.parallel.executor import TargetResult

_SCHEMA_VERSION = 1
_SESSION_ID = re.compile(r"^sh-[A-Za-z0-9_-]+$")
_WORK_ID = re.compile(r"^work-[a-f0-9]{16}$")
_RANK_FIELDS = (
    "surface",
    "influence",
    "reachability",
    "priority",
    "surface_rationale",
    "influence_rationale",
    "reachability_rationale",
)


class SourceHuntResumeError(ValueError):
    """A requested resume session is invalid, incompatible, or busy."""


def session_directory(output_dir: str | Path, session_id: str) -> Path:
    """Resolve a safe, bare SourceHunt session ID below an output root."""

    if not _SESSION_ID.fullmatch(session_id):
        raise SourceHuntResumeError(
            f"Invalid sourcehunt session ID {session_id!r}; expected a value like sh-535ed81b"
        )
    return Path(output_dir).expanduser().resolve() / session_id


class SourceHuntSessionLock:
    """Prevent two processes from writing one standalone session."""

    def __init__(self, session_dir: str | Path):
        self.path = Path(session_dir) / ".resume.lock"
        self._stream: Any = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        stream = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            stream.close()
            raise SourceHuntResumeError(
                f"Sourcehunt session {self.path.parent.name!r} is already running"
            ) from exc
        stream.seek(0)
        stream.truncate()
        stream.write(f"pid={os.getpid()}\n")
        stream.flush()
        self._stream = stream

    def release(self) -> None:
        if self._stream is None:
            return
        try:
            fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        finally:
            self._stream.close()
            self._stream = None


def fingerprint_source(repo_path: str | Path, files: list[dict[str, Any]]) -> str:
    """Hash the selected relative paths and their complete file bytes."""

    repository = Path(repo_path).resolve()
    selected: list[tuple[str, Path]] = []
    for target in files:
        relative = str(target.get("path") or "")
        relative_path = Path(relative)
        absolute = Path(str(target.get("absolute_path") or repository / relative_path)).resolve()
        expected = (repository / relative_path).resolve()
        if (
            not relative
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or absolute != expected
            or not absolute.is_relative_to(repository)
        ):
            raise SourceHuntResumeError(f"Selected source input {relative!r} is invalid")
        selected.append((relative_path.as_posix(), absolute))
    if len(selected) != len({relative for relative, _ in selected}):
        raise SourceHuntResumeError("Selected source inputs contain duplicate paths")

    digest = hashlib.sha256()
    for relative, absolute in sorted(selected):
        try:
            content = absolute.read_bytes()
        except OSError as exc:
            raise SourceHuntResumeError(
                f"Unable to fingerprint selected source input {relative!r}: {exc}"
            ) from exc
        for value in (relative.encode(), content):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return digest.hexdigest()


def fingerprint_invocation(options: dict[str, Any]) -> str:
    """Hash behavior-affecting options without credentials or model routing."""

    encoded = json.dumps(options, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


class SourceHuntCheckpoint:
    """One session manifest and immutable completed-work results."""

    def __init__(self, session_dir: str | Path, *, resuming: bool):
        self.session_dir = Path(session_dir)
        self.path = self.session_dir / "checkpoint.json"
        self.work_dir = self.session_dir / "work-results"
        self.resuming = resuming
        self._manifest: dict[str, Any] | None = None

    def prepare(
        self,
        *,
        invocation_fingerprint: str,
        source_fingerprint: str,
        source_paths: list[str],
    ) -> list[dict[str, Any]] | None:
        """Create or validate the session and return a complete cached rank plan."""

        if self.resuming:
            manifest = _read_json(self.path)
            if not self._valid_manifest(manifest):
                raise SourceHuntResumeError(
                    f"Session {self.session_dir.name!r} has no valid resumable checkpoint"
                )
            if manifest["invocation_fingerprint"] != invocation_fingerprint:
                raise SourceHuntResumeError(
                    "Resume options do not match the original sourcehunt invocation"
                )
            if manifest["source_fingerprint"] != source_fingerprint:
                raise SourceHuntResumeError(
                    "Selected source inputs changed since this sourcehunt session began"
                )
            if manifest["source_paths"] != sorted(source_paths):
                raise SourceHuntResumeError(
                    "Selected source inputs changed since this sourcehunt session began"
                )
            self._manifest = manifest
        else:
            if self.path.exists():
                raise SourceHuntResumeError(f"Session checkpoint already exists: {self.path}")
            self._manifest = {
                "schema_version": _SCHEMA_VERSION,
                "session_id": self.session_dir.name,
                "invocation_fingerprint": invocation_fingerprint,
                "source_fingerprint": source_fingerprint,
                "source_paths": sorted(source_paths),
                "rank_plan": None,
            }
            _atomic_json(self.path, self._manifest)
        return self._rank_plan(self._manifest.get("rank_plan"))

    def save_rank_plan(self, files: list[dict[str, Any]]) -> None:
        if self._manifest is None:
            raise SourceHuntResumeError("Sourcehunt checkpoint has not been prepared")
        by_path = []
        for target in files:
            item = {"path": target.get("path", "")}
            item.update({field: target.get(field) for field in _RANK_FIELDS})
            by_path.append(item)
        self._manifest["rank_plan"] = by_path
        _atomic_json(self.path, self._manifest)

    def apply_rank_plan(
        self, files: list[dict[str, Any]], plan: list[dict[str, Any]]
    ) -> None:
        by_path = {item["path"]: item for item in plan}
        for target in files:
            cached = by_path[str(target.get("path") or "")]
            target.update({field: cached[field] for field in _RANK_FIELDS})

    def load(self, work_id: str) -> TargetResult | None:
        if not _WORK_ID.fullmatch(work_id):
            return None
        payload = _read_json(self.work_dir / f"{work_id}.json")
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != _SCHEMA_VERSION
            or payload.get("work_id") != work_id
            or not isinstance(payload.get("result"), dict)
        ):
            return None
        result = payload["result"]
        allowed_fields = set(TargetResult.__dataclass_fields__)
        if (
            result.get("status") != "completed"
            or not isinstance(result.get("findings"), list)
            or not set(result).issubset(allowed_fields)
            or not all(field in result for field in ("target", "status", "tier", "band"))
        ):
            return None
        try:
            findings = [_finding(item) for item in result["findings"]]
            if any(finding is None for finding in findings):
                return None
            target_result = TargetResult(
                **{
                    key: value
                    for key, value in result.items()
                    if key in TargetResult.__dataclass_fields__ and key != "findings"
                },
                findings=[finding for finding in findings if finding is not None],
            )
            if (
                target_result.status != "completed"
                or target_result.tier not in {"A", "B", "C"}
                or target_result.band not in {"fast", "standard", "deep"}
                or not math.isfinite(float(target_result.cost_usd))
                or target_result.cost_usd < 0
                or target_result.tokens_used < 0
            ):
                return None
            return target_result
        except (TypeError, ValueError):
            return None

    def save(self, work_id: str, result: TargetResult) -> None:
        if not _WORK_ID.fullmatch(work_id) or result.status != "completed":
            return
        path = self.work_dir / f"{work_id}.json"
        if self.load(work_id) is not None:
            return
        _atomic_json(
            path,
            {
                "schema_version": _SCHEMA_VERSION,
                "work_id": work_id,
                "result": _json_value(result),
            },
        )

    def _rank_plan(self, value: Any) -> list[dict[str, Any]] | None:
        if not isinstance(value, list) or self._manifest is None:
            return None
        paths = self._manifest["source_paths"]
        if len(value) != len(paths):
            return None
        plan: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                return None
            if any(field not in item for field in _RANK_FIELDS):
                return None
            if any(not isinstance(item[field], int) for field in _RANK_FIELDS[:3]):
                return None
            priority = item["priority"]
            if not isinstance(priority, (int, float)) or not math.isfinite(float(priority)):
                return None
            if any(not isinstance(item[field], str) for field in _RANK_FIELDS[4:]):
                return None
            plan.append(dict(item))
        if sorted(item["path"] for item in plan) != paths:
            return None
        return plan

    def _valid_manifest(self, value: Any) -> bool:
        return (
            isinstance(value, dict)
            and value.get("schema_version") == _SCHEMA_VERSION
            and value.get("session_id") == self.session_dir.name
            and isinstance(value.get("invocation_fingerprint"), str)
            and isinstance(value.get("source_fingerprint"), str)
            and isinstance(value.get("source_paths"), list)
            and all(isinstance(path, str) and path for path in value["source_paths"])
            and value["source_paths"] == sorted(set(value["source_paths"]))
        )


def _finding(value: Any) -> Finding | None:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
        return None
    try:
        return Finding(
            **{key: item for key, item in value.items() if key in Finding.__dataclass_fields__}
        )
    except (TypeError, ValueError):
        return None


def _json_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
