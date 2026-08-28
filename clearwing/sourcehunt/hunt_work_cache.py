"""Incremental per-work-item cache for the source-hunt stage.

The checkpoint system (:mod:`clearwing.sourcehunt.checkpoints`) resumes the
legacy pipeline at *stage* granularity: a stage is restored only when it ran to
completion. That leaves a gap — a hunt interrupted part way through (crash,
Ctrl-C, budget kill) has no ``HuntCheckpoint`` yet, so the whole hunt re-runs
and every already-finished file is hunted again.

``HuntWorkCache`` fills that gap *inside* the checkpoint system rather than
adding a second resume path. As each hunter work item (a file/band/attempt/
context combination) completes, its :class:`TargetResult` is written
write-once to ``<session>/hunt-work/<work_id>.json``. On a resumed run the
:class:`~clearwing.sourcehunt.pool.HunterPool` looks each work item up by its
deterministic id and reuses the completed result instead of re-running it, so
only unfinished work runs again. Compatibility (same repo, same options,
unchanged sources) is already enforced by the surrounding checkpoint stages —
this cache only stores and returns immutable completed results, and treats
anything missing, malformed, or not ``completed`` as absent so the work simply
re-runs.
"""

from __future__ import annotations

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
_WORK_ID = re.compile(r"^work-[a-f0-9]{16}$")


class HuntWorkCache:
    """A directory of immutable, completed per-work-item hunter results."""

    def __init__(self, work_dir: str | Path):
        self.work_dir = Path(work_dir)

    def load(self, work_id: str) -> TargetResult | None:
        """Return the cached completed result for *work_id*, or None.

        Returns None for any id that is missing, malformed, schema-mismatched,
        or not a ``completed`` result — the caller then re-runs the work.
        """
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
        """Persist a completed *result* under *work_id*, write-once.

        Non-completed results and ids that already exist are ignored, so the
        first successful result for a work item is authoritative and later
        attempts never overwrite it.
        """
        if not _WORK_ID.fullmatch(work_id) or result.status != "completed":
            return
        if self.load(work_id) is not None:
            return
        _atomic_json(
            self.work_dir / f"{work_id}.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "work_id": work_id,
                "result": _json_value(result),
            },
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


__all__ = ["HuntWorkCache"]
