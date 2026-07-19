"""Versioned sourcehunt checkpoint substrate.

This module provides a deterministic, append-only checkpoint store used by
native sourcehunt stages (ranker/hunter/verifier/exploiter). Checkpoints are
scoped to a strict compatibility fingerprint so replay only occurs when the
repo, execution inputs, and runtime policy match.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CHECKPOINT_SCHEMA_VERSION = 1


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def checkpoint_stage_key(value: Any) -> str:
    """Return a deterministic key used for idempotent stage records."""
    return _stable_hash(value)


def build_checkpoint_fingerprint(
    *,
    repo_url: str,
    repo_path: str,
    branch: str,
    commit_hint: str | None,
    command_args: dict[str, Any],
    model_route: dict[str, Any],
    runtime_tuning: dict[str, Any],
    stage_inputs: dict[str, Any],
) -> dict[str, Any]:
    """Build the strict compatibility fingerprint for a sourcehunt run."""
    normalized = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "repo_url": str(repo_url or "").strip(),
        "repo_path": str(repo_path or "").strip(),
        "branch": str(branch or "").strip(),
        "commit_hint": str(commit_hint or "").strip() or None,
        "command_args_sha256": _stable_hash(command_args),
        "model_route_sha256": _stable_hash(model_route),
        "runtime_tuning_sha256": _stable_hash(runtime_tuning),
        "stage_inputs_sha256": _stable_hash(stage_inputs),
        # Keep compact diagnostics so operators can inspect mismatch causes
        # without loading the full payloads.
        "stage_input_counts": {
            "files": len(stage_inputs.get("files", []))
            if isinstance(stage_inputs.get("files"), list)
            else 0,
            "static_findings": int(stage_inputs.get("static_findings", 0) or 0),
            "semgrep_findings": int(stage_inputs.get("semgrep_findings", 0) or 0),
        },
    }
    normalized["fingerprint_sha256"] = _stable_hash(normalized)
    return normalized


@dataclass(frozen=True)
class CheckpointInitResult:
    enabled: bool
    resumable: bool
    generation_id: str
    reason: str | None = None


class SourceHuntCheckpointStore:
    """Append-only checkpoint store with deterministic replay semantics."""

    def __init__(self, root_dir: Path):
        self._root_dir = Path(root_dir)
        self._fingerprint: dict[str, Any] | None = None
        self._generation_id: str | None = None
        self._generation_dir: Path | None = None
        self._records_dir: Path | None = None
        self._manifest_path: Path | None = None
        self._manifest: dict[str, Any] | None = None
        self._stage_cache: dict[str, dict[str, Any]] = {}
        self._enabled = False
        self._resumable = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def resumable(self) -> bool:
        return self._resumable

    @property
    def generation_id(self) -> str:
        return self._generation_id or "disabled"

    @property
    def manifest(self) -> dict[str, Any] | None:
        return self._manifest

    def initialize(
        self,
        *,
        session_id: str,
        fingerprint: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> CheckpointInitResult:
        """Activate the store for a specific compatibility fingerprint."""
        self._fingerprint = dict(fingerprint)
        generation_id = str(fingerprint.get("fingerprint_sha256") or "").strip()
        if not generation_id:
            generation_id = _stable_hash(fingerprint)
        generation_id = generation_id[:24]
        self._generation_id = generation_id
        self._generation_dir = self._root_dir / generation_id
        self._records_dir = self._generation_dir / "records"
        self._manifest_path = self._generation_dir / "manifest.json"
        self._stage_cache = {}
        self._enabled = True
        self._resumable = False

        try:
            self._records_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            logger.warning("sourcehunt checkpoint setup failed", exc_info=True)
            self._enabled = False
            return CheckpointInitResult(
                enabled=False,
                resumable=False,
                generation_id=generation_id,
                reason="directory_setup_failed",
            )

        existing = self._read_manifest()
        if existing is not None:
            existing_fingerprint = existing.get("fingerprint")
            if existing.get("schema_version") == CHECKPOINT_SCHEMA_VERSION and existing_fingerprint == fingerprint:
                self._manifest = existing
                self._resumable = True
                return CheckpointInitResult(
                    enabled=True,
                    resumable=True,
                    generation_id=generation_id,
                )
            # Incompatible manifest in same generation directory should be
            # extremely rare; fail closed to avoid replaying stale records.
            self._enabled = False
            return CheckpointInitResult(
                enabled=False,
                resumable=False,
                generation_id=generation_id,
                reason="incompatible_manifest",
            )

        self._manifest = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "session_id": session_id,
            "generation_id": generation_id,
            "created_at": _utc_now_iso(),
            "updated_at": _utc_now_iso(),
            "fingerprint": fingerprint,
            "stages": {},
            "metadata": metadata or {},
        }
        self._write_manifest()
        return CheckpointInitResult(
            enabled=True,
            resumable=False,
            generation_id=generation_id,
        )

    def stage_records(self, stage: str) -> dict[str, Any]:
        """Return all records for *stage*, indexed by deterministic key."""
        if not self._enabled:
            return {}
        stage_key = self._normalize_stage(stage)
        cached = self._stage_cache.get(stage_key)
        if cached is not None:
            return dict(cached)
        loaded = self._load_stage_records(stage_key)
        self._stage_cache[stage_key] = loaded
        return dict(loaded)

    def get(self, stage: str, key: str) -> Any | None:
        if not self._enabled:
            return None
        stage_key = self._normalize_stage(stage)
        key_text = self._normalize_key(key)
        records = self._stage_cache.get(stage_key)
        if records is None:
            records = self._load_stage_records(stage_key)
            self._stage_cache[stage_key] = records
        return records.get(key_text)

    def append(self, stage: str, key: str, payload: Any) -> bool:
        """Append a stage record once; returns False on idempotent replay."""
        if not self._enabled:
            return False
        if self._records_dir is None:
            return False
        stage_key = self._normalize_stage(stage)
        key_text = self._normalize_key(key)
        records = self._stage_cache.get(stage_key)
        if records is None:
            records = self._load_stage_records(stage_key)
            self._stage_cache[stage_key] = records
        if key_text in records:
            return False

        stage_path = self._records_dir / f"{stage_key}.jsonl"
        record = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "stage": stage_key,
            "key": key_text,
            "recorded_at": _utc_now_iso(),
            "payload": payload,
        }
        stage_path.parent.mkdir(parents=True, exist_ok=True)
        with stage_path.open("a", encoding="utf-8") as handle:
            handle.write(_stable_json(record))
            handle.write("\n")

        records[key_text] = payload
        if self._manifest is not None:
            stages = self._manifest.setdefault("stages", {})
            stage_meta = stages.setdefault(stage_key, {})
            stage_meta["record_count"] = len(records)
            stage_meta["updated_at"] = _utc_now_iso()
            self._manifest["updated_at"] = _utc_now_iso()
            self._write_manifest()
        return True

    def stats(self) -> dict[str, Any]:
        if not self._enabled:
            return {
                "enabled": False,
                "resumable": False,
                "generation_id": self.generation_id,
                "stages": {},
            }
        manifest = self._manifest or {}
        return {
            "enabled": True,
            "resumable": self._resumable,
            "generation_id": self.generation_id,
            "stages": manifest.get("stages", {}),
            "updated_at": manifest.get("updated_at"),
        }

    def _normalize_stage(self, stage: str) -> str:
        return str(stage or "").strip().lower() or "unknown_stage"

    def _normalize_key(self, key: str) -> str:
        normalized = str(key or "").strip()
        if normalized:
            return normalized
        return checkpoint_stage_key({"fallback_key": _utc_now_iso()})

    def _read_manifest(self) -> dict[str, Any] | None:
        if self._manifest_path is None or not self._manifest_path.exists():
            return None
        try:
            return json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("sourcehunt checkpoint manifest read failed", exc_info=True)
            return None

    def _write_manifest(self) -> None:
        if self._manifest_path is None or self._manifest is None:
            return
        tmp_path = self._manifest_path.with_suffix(".json.tmp")
        text = json.dumps(self._manifest, indent=2, sort_keys=True, default=str)
        tmp_path.write_text(text, encoding="utf-8")
        os.replace(tmp_path, self._manifest_path)

    def _load_stage_records(self, stage_key: str) -> dict[str, Any]:
        if self._records_dir is None:
            return {}
        stage_path = self._records_dir / f"{stage_key}.jsonl"
        if not stage_path.exists():
            return {}
        loaded: dict[str, Any] = {}
        for raw in stage_path.read_text(encoding="utf-8").splitlines():
            text = raw.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except Exception:
                logger.debug(
                    "sourcehunt checkpoint row parse failed (stage=%s)",
                    stage_key,
                    exc_info=True,
                )
                continue
            key = str(row.get("key") or "").strip()
            if not key or key in loaded:
                continue
            loaded[key] = row.get("payload")
        return loaded

