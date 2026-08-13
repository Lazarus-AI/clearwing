"""Immutable completion records for resumable standalone sourcehunts."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding

SESSION_SCHEMA_VERSION = 1
RANK_PLAN_SCHEMA_VERSION = 1
WORK_RESULT_SCHEMA_VERSION = 1
SESSION_FILENAME = "session.json"
RANK_PLAN_FILENAME = "rank-plan.json"
WORK_RESULTS_DIRNAME = "work-results"
SESSION_LOCK_FILENAME = ".sourcehunt.lock"
_SESSION_ID = re.compile(r"^sh-[A-Za-z0-9_-]+$")
_WORK_ID = re.compile(r"^work-[a-f0-9]{16}$")
_RANK_INTEGER_FIELDS = (
    "surface",
    "influence",
    "reachability",
    "loc",
    "static_hint",
    "semgrep_hint",
    "taint_hits",
    "imports_by",
    "transitive_callers",
)
_RANK_RATIONALE_FIELDS = (
    "surface_rationale",
    "influence_rationale",
    "reachability_rationale",
)


class SourceHuntResumeError(ValueError):
    """A resumable session is missing, malformed, incompatible, or busy."""


@dataclass(frozen=True, slots=True)
class CompletedWork:
    """One successfully committed hunt work result."""

    work_id: str
    file: str
    tier: str
    band: str
    attempt: int
    entry_point: dict[str, Any] | None
    seed_context: str | None
    seed_transcript: str | None
    findings: list[Finding]
    clusters: list[dict[str, Any]]
    cost_usd: float
    tokens_used: int
    stop_reason: str
    promotion_transcript: str | None


class SourceHuntSessionLock:
    """Advisory process lock preventing concurrent writers to one session."""

    def __init__(self, session_dir: str | Path):
        self.path = Path(session_dir) / SESSION_LOCK_FILENAME
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


def resolve_session_dir(output_dir: str | Path, session_id: str) -> Path:
    """Resolve a safe bare session ID below the configured output root."""

    if not _SESSION_ID.fullmatch(session_id):
        raise SourceHuntResumeError(
            f"Invalid sourcehunt session ID {session_id!r}; expected a value like sh-535ed81b"
        )
    return Path(output_dir).expanduser().resolve() / session_id


def _json_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def deterministic_work_id(
    session_id: str,
    *,
    file: str,
    tier: str,
    band: str,
    attempt: int,
    entry_point: dict[str, Any] | None,
    seed_context: str | None,
    seed_transcript: str | None,
) -> str:
    """Identify one hunt invocation from all behavior-affecting inputs."""

    payload = {
        "session_id": session_id,
        "file": file,
        "tier": tier,
        "band": band,
        "attempt": attempt,
        "entry_point": entry_point,
        "seed_context": seed_context,
        "seed_transcript": seed_transcript,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"work-{hashlib.sha256(encoded).hexdigest()[:16]}"


def source_input_identity(
    repo_path: str | Path,
    file_targets: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Hash exactly the selected source paths and their complete contents."""

    repository = Path(repo_path).resolve()
    selected: list[tuple[str, Path]] = []
    for target in file_targets:
        relative = Path(str(target.get("path") or "")).as_posix()
        if not relative:
            continue
        relative_path = Path(relative)
        absolute = Path(str(target.get("absolute_path") or repository / relative_path)).resolve()
        expected_absolute = (repository / relative_path).resolve()
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or absolute != expected_absolute
            or not absolute.is_relative_to(repository)
        ):
            raise SourceHuntResumeError(
                f"Selected source input {relative!r} is outside the repository"
            )
        selected.append((relative, absolute))

    if len(selected) != len({relative for relative, _ in selected}):
        raise SourceHuntResumeError("Selected source inputs contain duplicate paths")

    digest = hashlib.sha256()
    paths: list[str] = []
    for relative, absolute in sorted(selected):
        try:
            content = absolute.read_bytes()
        except OSError as exc:
            raise SourceHuntResumeError(
                f"Unable to fingerprint selected source input {relative!r}: {exc}"
            ) from exc
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        paths.append(relative)
    return {
        "algorithm": "sha256-path-content-v1",
        "fingerprint": digest.hexdigest(),
        "paths": paths,
    }


class SourceHuntResumeStore:
    """Session metadata plus immutable rank and work completion records."""

    def __init__(self, session_dir: str | Path, session: dict[str, Any] | None = None):
        self.session_dir = Path(session_dir)
        self.session_path = self.session_dir / SESSION_FILENAME
        self.rank_plan_path = self.session_dir / RANK_PLAN_FILENAME
        self.work_results_dir = self.session_dir / WORK_RESULTS_DIRNAME
        self._session = session
        self._completed_work: dict[str, CompletedWork] | None = None

    @property
    def session_id(self) -> str:
        return self.session_dir.name

    @classmethod
    def load(cls, session_dir: str | Path) -> SourceHuntResumeStore:
        store = cls(session_dir)
        payload = _read_json(store.session_path)
        if payload is None:
            raise SourceHuntResumeError(
                f"Session {store.session_id!r} has no valid {SESSION_FILENAME}; "
                "legacy standalone sourcehunt sessions are not resumable"
            )
        store._validate_session(payload)
        store._session = payload
        return store

    def create_session(
        self,
        *,
        repository: dict[str, Any],
        config: dict[str, Any],
        source_identity: dict[str, Any],
    ) -> None:
        if self.session_path.exists():
            raise SourceHuntResumeError(f"Session metadata already exists: {self.session_path}")
        payload = {
            "schema_version": SESSION_SCHEMA_VERSION,
            "session_id": self.session_id,
            "repository": _json_value(repository),
            "config": _json_value(config),
            "source_identity": _json_value(source_identity),
        }
        self._validate_session(payload)
        _atomic_json(self.session_path, payload)
        self._session = payload

    def config(self) -> dict[str, Any]:
        return dict(self._required_session()["config"])

    def validate_source_identity(self, actual: dict[str, Any]) -> None:
        expected = self._required_session()["source_identity"]
        if actual != expected:
            raise SourceHuntResumeError(
                "Selected source inputs changed since this sourcehunt session began"
            )

    def load_rank_plan(self) -> list[dict[str, Any]] | None:
        payload = _read_json(self.rank_plan_path)
        if payload is None or payload.get("schema_version") != RANK_PLAN_SCHEMA_VERSION:
            return None
        targets = payload.get("targets")
        if not isinstance(targets, list):
            return None
        validated = [self._rank_target(target) for target in targets]
        if any(target is None for target in validated):
            return None
        complete_targets = [target for target in validated if target is not None]
        expected_paths = self._required_session()["source_identity"]["paths"]
        actual_paths = [target["path"] for target in complete_targets]
        if len(actual_paths) != len(set(actual_paths)) or sorted(actual_paths) != sorted(
            expected_paths
        ):
            return None
        return complete_targets

    def save_rank_plan(self, targets: list[dict[str, Any]]) -> None:
        if self.load_rank_plan() is not None:
            return
        payload = {
            "schema_version": RANK_PLAN_SCHEMA_VERSION,
            "targets": _json_value(targets),
        }
        _atomic_json(self.rank_plan_path, payload)
        if self.load_rank_plan() is None:
            raise SourceHuntResumeError("Unable to validate committed rank plan")

    def load_completed_work(self) -> dict[str, CompletedWork]:
        if self._completed_work is not None:
            return dict(self._completed_work)
        completed: dict[str, CompletedWork] = {}
        if self.work_results_dir.is_dir():
            for path in sorted(self.work_results_dir.glob("work-*.json")):
                result = self._load_work_result(path)
                if result is not None:
                    completed[result.work_id] = result
        self._completed_work = completed
        return dict(completed)

    def save_work_result(
        self,
        *,
        work_id: str,
        file: str,
        tier: str,
        band: str,
        attempt: int,
        entry_point: dict[str, Any] | None,
        seed_context: str | None,
        seed_transcript: str | None,
        findings: Iterable[Finding],
        clusters: Iterable[dict[str, Any]] = (),
        cost_usd: float,
        tokens_used: int,
        stop_reason: str,
        promotion_transcript: str | None,
    ) -> CompletedWork:
        if not _WORK_ID.fullmatch(work_id):
            raise SourceHuntResumeError(f"Invalid sourcehunt work ID {work_id!r}")
        payload = {
            "schema_version": WORK_RESULT_SCHEMA_VERSION,
            "work_id": work_id,
            "work": {
                "file": file,
                "tier": tier,
                "band": band,
                "attempt": attempt,
                "entry_point": _json_value(entry_point),
                "seed_context": seed_context,
                "seed_transcript": seed_transcript,
            },
            "result": {
                "status": "completed",
                "findings": _json_value(list(findings)),
                "clusters": _json_value(list(clusters)),
                "cost_usd": cost_usd,
                "tokens_used": tokens_used,
                "stop_reason": stop_reason,
                "promotion_transcript": promotion_transcript,
            },
        }
        path = self.work_results_dir / f"{work_id}.json"
        if path.exists():
            existing = self._load_work_result(path)
            if existing is not None:
                return existing
            # Invalid/truncated records are not completions. Replace them
            # only after this rerun completes successfully.
        _atomic_json(path, payload)
        result = self._load_work_result(path)
        if result is None:  # pragma: no cover - validates our own serialization
            raise SourceHuntResumeError(f"Unable to validate committed work result {path}")
        if self._completed_work is not None:
            self._completed_work[work_id] = result
        return result

    def completed_findings(self) -> list[Finding]:
        findings: dict[str, Finding] = {}
        for result in self.load_completed_work().values():
            for finding in result.findings:
                findings.setdefault(finding.id, finding)
        return list(findings.values())

    def completed_clusters(self) -> list[dict[str, Any]]:
        """Merge the referenced cluster descriptors stored with work results."""

        clusters: dict[str, dict[str, Any]] = {}
        for result in self.load_completed_work().values():
            for item in result.clusters:
                cluster_id = item["cluster_id"]
                clusters.setdefault(
                    cluster_id,
                    {
                        "cluster_id": cluster_id,
                        "root_cause_summary": item["root_cause_summary"],
                        "primitive_type": item["primitive_type"],
                        "cwe": item["cwe"],
                        "finding_ids": [],
                        "file_paths": [],
                    },
                )
        return list(clusters.values())

    def completed_target_count(self) -> int:
        return len({result.file for result in self.load_completed_work().values()})

    def _load_work_result(self, path: Path) -> CompletedWork | None:
        payload = _read_json(path)
        if payload is None or payload.get("schema_version") != WORK_RESULT_SCHEMA_VERSION:
            return None
        work_id = payload.get("work_id")
        work = payload.get("work")
        result = payload.get("result")
        if (
            not isinstance(work_id, str)
            or not _WORK_ID.fullmatch(work_id)
            or path.name != f"{work_id}.json"
            or not isinstance(work, dict)
            or not isinstance(result, dict)
            or result.get("status") != "completed"
            or not isinstance(result.get("findings"), list)
            or not isinstance(result.get("clusters", []), list)
        ):
            return None
        try:
            file = work["file"]
            tier = work["tier"]
            band = work["band"]
            attempt = work["attempt"]
            if (
                not isinstance(file, str)
                or file not in self._required_session()["source_identity"]["paths"]
                or not isinstance(tier, str)
                or not isinstance(band, str)
                or not isinstance(attempt, int)
                or isinstance(attempt, bool)
            ):
                return None
            entry_point = (
                dict(work["entry_point"])
                if isinstance(work.get("entry_point"), dict)
                else None
            )
            if (
                work.get("entry_point") is not None
                and (
                    entry_point is None
                    or not self._valid_entry_point(entry_point)
                )
            ):
                return None
            seed_context = work.get("seed_context")
            seed_transcript = work.get("seed_transcript")
            if not isinstance(seed_context, (str, type(None))) or not isinstance(
                seed_transcript,
                (str, type(None)),
            ):
                return None
            expected_id = deterministic_work_id(
                self.session_id,
                file=file,
                tier=tier,
                band=band,
                attempt=attempt,
                entry_point=entry_point,
                seed_context=seed_context,
                seed_transcript=seed_transcript,
            )
            if (
                work_id != expected_id
                or tier not in {"A", "B", "C"}
                or band not in {"fast", "standard", "deep"}
                or attempt < 0
            ):
                return None
            findings = [self._finding(item) for item in result["findings"]]
            if any(finding is None for finding in findings):
                return None
            clusters = [self._cluster(item) for item in result.get("clusters", [])]
            if any(cluster is None for cluster in clusters):
                return None
            raw_cost = result.get("cost_usd", 0.0)
            tokens_used = result.get("tokens_used", 0)
            stop_reason = result.get("stop_reason", "completed")
            promotion_transcript = result.get("promotion_transcript")
            if (
                not isinstance(raw_cost, (int, float))
                or isinstance(raw_cost, bool)
                or not isinstance(tokens_used, int)
                or isinstance(tokens_used, bool)
                or not isinstance(stop_reason, str)
                or not isinstance(promotion_transcript, (str, type(None)))
            ):
                return None
            cost_usd = float(raw_cost)
            if not math.isfinite(cost_usd) or cost_usd < 0 or tokens_used < 0:
                return None
            return CompletedWork(
                work_id=work_id,
                file=file,
                tier=tier,
                band=band,
                attempt=attempt,
                entry_point=entry_point,
                seed_context=seed_context,
                seed_transcript=seed_transcript,
                findings=[finding for finding in findings if finding is not None],
                clusters=[cluster for cluster in clusters if cluster is not None],
                cost_usd=cost_usd,
                tokens_used=tokens_used,
                stop_reason=stop_reason,
                promotion_transcript=promotion_transcript,
            )
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _finding(value: Any) -> Finding | None:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), str)
            or not value["id"]
        ):
            return None
        fields = Finding.__dataclass_fields__
        try:
            return Finding(**{key: item for key, item in value.items() if key in fields})
        except Exception:
            return None

    @staticmethod
    def _rank_target(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict) or "absolute_path" in value:
            return None
        path = value.get("path")
        if (
            not isinstance(path, str)
            or not path
            or any(
                not isinstance(value.get(field), int)
                or isinstance(value.get(field), bool)
                or value[field] < 0
                for field in _RANK_INTEGER_FIELDS
            )
            or not isinstance(value.get("priority"), (int, float))
            or isinstance(value.get("priority"), bool)
            or not math.isfinite(float(value["priority"]))
            or value.get("tier") not in {"A", "B", "C"}
            or not isinstance(value.get("tags"), list)
            or not all(isinstance(tag, str) for tag in value["tags"])
            or not isinstance(value.get("language"), str)
            or any(
                not isinstance(value.get(field), str)
                for field in _RANK_RATIONALE_FIELDS
            )
            or not isinstance(value.get("defines_constants"), bool)
            or not isinstance(value.get("has_fuzz_entry_point"), bool)
            or not isinstance(value.get("fuzz_harness_path"), (str, type(None)))
        ):
            return None
        return dict(value)

    @staticmethod
    def _valid_entry_point(value: dict[str, Any]) -> bool:
        return (
            set(value)
            == {
                "file_path",
                "function_name",
                "start_line",
                "end_line",
                "entry_type",
                "description",
            }
            and all(
                isinstance(value[field], str)
                for field in (
                    "file_path",
                    "function_name",
                    "entry_type",
                    "description",
                )
            )
            and all(
                isinstance(value[field], int)
                and not isinstance(value[field], bool)
                and value[field] >= 0
                for field in ("start_line", "end_line")
            )
        )

    @staticmethod
    def _cluster(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        if (
            not isinstance(value.get("cluster_id"), str)
            or not isinstance(value.get("root_cause_summary"), str)
            or not isinstance(value.get("primitive_type"), str)
            or not isinstance(value.get("cwe"), str)
        ):
            return None
        return {
            "cluster_id": value["cluster_id"],
            "root_cause_summary": value["root_cause_summary"],
            "primitive_type": value["primitive_type"],
            "cwe": value["cwe"],
            # Membership is reconstructed from canonical findings, so only
            # bounded descriptors are accepted from completion files.
            "finding_ids": [],
            "file_paths": [],
        }

    def _required_session(self) -> dict[str, Any]:
        if self._session is None:
            raise SourceHuntResumeError("Sourcehunt session metadata has not been loaded")
        return self._session

    def _validate_session(self, payload: dict[str, Any]) -> None:
        if payload.get("schema_version") != SESSION_SCHEMA_VERSION:
            raise SourceHuntResumeError(
                f"Unsupported sourcehunt session schema {payload.get('schema_version')!r}"
            )
        if payload.get("session_id") != self.session_id or not _SESSION_ID.fullmatch(
            str(payload.get("session_id") or "")
        ):
            raise SourceHuntResumeError("Sourcehunt session ID does not match its directory")
        for key in ("repository", "config", "source_identity"):
            if not isinstance(payload.get(key), dict):
                raise SourceHuntResumeError(f"Sourcehunt session field {key!r} is invalid")
        identity = payload["source_identity"]
        paths = identity.get("paths")
        if (
            identity.get("algorithm") != "sha256-path-content-v1"
            or not isinstance(identity.get("fingerprint"), str)
            or re.fullmatch(r"[a-f0-9]{64}", identity["fingerprint"]) is None
            or not isinstance(paths, list)
            or not all(
                isinstance(path, str)
                and path
                and not Path(path).is_absolute()
                and ".." not in Path(path).parts
                for path in paths
            )
            or len(paths) != len(set(paths))
        ):
            raise SourceHuntResumeError("Sourcehunt source identity is invalid")
