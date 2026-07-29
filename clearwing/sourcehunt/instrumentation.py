"""Durable, stage-level instrumentation for sourcehunt evaluation.

The event log is intentionally independent from the UI event bus.  UI events
are ephemeral; these records are the authoritative, session-local account of
which inputs entered each stage and why a stage completed, degraded, or
failed.  Stable child identifiers also let spend, trajectory, tool, and
finding records join without depending on display text.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def stable_run_id(prefix: str, payload: Any) -> str:
    """Return a deterministic identifier for one run-scoped entity."""

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


class SourceHuntInstrumentation:
    """Append-only session instrumentation plus a materialized summary."""

    schema_version = 1

    def __init__(self, session_dir: str | Path, run_id: str):
        self.root = Path(session_dir).expanduser().resolve() / "instrumentation"
        self.root.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.events_path = self.root / "events.jsonl"
        self.reporting_failures_path = self.root / "reporting-failures.jsonl"
        self.summary_path = self.root / "summary.json"
        self._lock = threading.RLock()
        self._repair_truncated_tail(self.events_path)
        self._repair_truncated_tail(self.reporting_failures_path)
        self._sequence = self._existing_event_count()

    def record(
        self,
        event: str,
        *,
        stage: str = "",
        status: str = "",
        files: Iterable[str] = (),
        symbols: Iterable[str] = (),
        work_item_id: str | None = None,
        model_call_id: str | None = None,
        tool_action_id: str | None = None,
        finding_ids: Iterable[str] = (),
        detail: str = "",
        error: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one event and refresh the crash-safe materialized summary."""

        with self._lock:
            self._sequence += 1
            sequence = self._sequence
            normalized_files = sorted({str(item) for item in files if str(item)})
            normalized_symbols = sorted({str(item) for item in symbols if str(item)})
            normalized_findings = sorted({str(item) for item in finding_ids if str(item)})
            identifier = stable_run_id(
                "instrument",
                {
                    "run_id": self.run_id,
                    "sequence": sequence,
                    "event": event,
                    "stage": stage,
                    "work_item_id": work_item_id,
                    "model_call_id": model_call_id,
                    "tool_action_id": tool_action_id,
                },
            )
            record = {
                "schema_version": self.schema_version,
                "id": identifier,
                "run_id": self.run_id,
                "sequence": sequence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "stage": stage,
                "status": status,
                "files": normalized_files,
                "symbols": normalized_symbols,
                "work_item_id": work_item_id,
                "model_call_id": model_call_id,
                "tool_action_id": tool_action_id,
                "finding_ids": normalized_findings,
                "detail": detail,
                "error": error,
                "metadata": metadata or {},
            }
            self._append_jsonl(self.events_path, record)
            if event == "reporting_failure":
                self._append_jsonl(self.reporting_failures_path, record)
            self._write_summary_locked()
            return record

    def stage(
        self,
        stage: str,
        status: str,
        *,
        files: Iterable[str] = (),
        symbols: Iterable[str] = (),
        finding_ids: Iterable[str] = (),
        detail: str = "",
        error: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.record(
            "stage",
            stage=stage,
            status=status,
            files=files,
            symbols=symbols,
            finding_ids=finding_ids,
            detail=detail,
            error=error,
            metadata=metadata,
        )

    def reporting_failure(
        self,
        message: str,
        *,
        error_type: str,
        finding_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        return self.record(
            "reporting_failure",
            stage="report",
            status="failed",
            finding_ids=finding_ids,
            detail=message,
            error={"type": error_type, "message": message},
        )

    def ingest_spend_ledger(self, ledger_path: str | Path) -> int:
        """Join every settled provider call into the stage instrumentation."""

        source = Path(ledger_path).expanduser()
        if not source.is_file():
            return 0
        existing_call_ids = {
            str((event.get("metadata") or {}).get("ledger_call_id"))
            for event in self.read_events()
            if (event.get("metadata") or {}).get("ledger_call_id")
        }
        recorded = 0
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict) or payload.get("event") != "call_settled":
                continue
            ledger_call_id = str(payload.get("call_id") or "")
            if not ledger_call_id or ledger_call_id in existing_call_ids:
                continue
            metadata = payload.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            model_call_id = str(metadata.get("model_call_id") or "") or stable_run_id(
                "modelcall",
                {"run_id": self.run_id, "ledger_call_id": ledger_call_id},
            )
            target = str(metadata.get("target") or "")
            entry_point = str(metadata.get("entry_point") or "")
            self.record(
                "model_call",
                stage=str(payload.get("stage") or ""),
                status=str(payload.get("status") or "completed"),
                files=[target] if target else [],
                symbols=[entry_point] if entry_point else [],
                work_item_id=(
                    str(metadata["work_item_id"]) if metadata.get("work_item_id") else None
                ),
                model_call_id=model_call_id,
                detail=str(payload.get("error") or ""),
                metadata={
                    "ledger_call_id": ledger_call_id,
                    "model": payload.get("model"),
                    "provider": payload.get("provider"),
                    "cost_usd": payload.get("cost_usd", 0.0),
                    "input_tokens": payload.get("input_tokens", 0),
                    "cached_input_tokens": payload.get("cached_input_tokens", 0),
                    "output_tokens": payload.get("output_tokens", 0),
                    "ledger_metadata": metadata,
                },
            )
            existing_call_ids.add(ledger_call_id)
            recorded += 1
        return recorded

    def read_events(self) -> list[dict[str, Any]]:
        if not self.events_path.is_file():
            return []
        events: list[dict[str, Any]] = []
        lines = self.events_path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                if index == len(lines) - 1:
                    break
                raise
            if isinstance(payload, dict):
                events.append(payload)
        return events

    def finalize(self, status: str) -> Path:
        with self._lock:
            self.record("run", stage="run", status=status)
            return self.summary_path

    def _existing_event_count(self) -> int:
        if not self.events_path.is_file():
            return 0
        return sum(
            1 for line in self.events_path.read_text(encoding="utf-8").splitlines() if line.strip()
        )

    def _write_summary_locked(self) -> None:
        events = self.read_events()
        stage_latest: dict[str, dict[str, Any]] = {}
        files_by_stage: dict[str, set[str]] = {}
        symbols_by_stage: dict[str, set[str]] = {}
        work_items: set[str] = set()
        model_calls: set[str] = set()
        tool_actions: set[str] = set()
        findings: set[str] = set()
        reporting_failures = 0
        statuses: Counter[str] = Counter()
        for event in events:
            stage = str(event.get("stage") or "")
            status = str(event.get("status") or "")
            if stage and event.get("event") in {"stage", "run"}:
                stage_latest[stage] = {
                    "status": status,
                    "event_id": event.get("id"),
                    "detail": event.get("detail", ""),
                    "sequence": event.get("sequence", 0),
                }
            if stage:
                files_by_stage.setdefault(stage, set()).update(event.get("files") or [])
                symbols_by_stage.setdefault(stage, set()).update(event.get("symbols") or [])
            if status:
                statuses[status] += 1
            if event.get("work_item_id"):
                work_items.add(str(event["work_item_id"]))
            if event.get("model_call_id"):
                model_calls.add(str(event["model_call_id"]))
            if event.get("tool_action_id"):
                tool_actions.add(str(event["tool_action_id"]))
            findings.update(str(item) for item in event.get("finding_ids") or [])
            reporting_failures += int(event.get("event") == "reporting_failure")
        payload = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "event_count": len(events),
            "status_counts": dict(sorted(statuses.items())),
            "stages": dict(sorted(stage_latest.items())),
            "files_by_stage": {
                stage: sorted(values) for stage, values in sorted(files_by_stage.items())
            },
            "symbols_by_stage": {
                stage: sorted(values) for stage, values in sorted(symbols_by_stage.items())
            },
            "work_item_ids": sorted(work_items),
            "model_call_ids": sorted(model_calls),
            "tool_action_ids": sorted(tool_actions),
            "finding_ids": sorted(findings),
            "reporting_failure_count": reporting_failures,
            "events_path": str(self.events_path),
            "reporting_failures_path": str(self.reporting_failures_path),
        }
        self._atomic_json(self.summary_path, payload)

    @staticmethod
    def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str) + "\n"
        ).encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _repair_truncated_tail(path: Path) -> None:
        """Discard only an incomplete final JSONL record after a process crash."""

        if not path.is_file():
            return
        payload = path.read_bytes()
        if not payload:
            return
        lines = payload.splitlines(keepends=True)
        final = lines[-1]
        try:
            json.loads(final.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            valid_prefix = b"".join(lines[:-1])
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{path.name}.",
                dir=path.parent,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(valid_prefix)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
