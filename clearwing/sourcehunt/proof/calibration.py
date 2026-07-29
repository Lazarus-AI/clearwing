"""Empirical action-yield calibration for the proof scheduler."""

from __future__ import annotations

import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import Field

from .models import Action, ActionStatus, StrictModel
from .store import ProofStore


def profile_key(template: str, model_route: str | None) -> str:
    return f"{template}::{model_route or 'deterministic'}"


class ActionUtilityProfile(StrictModel):
    template: str = Field(min_length=1)
    model_route: str | None = None
    attempts: int = Field(ge=1)
    completed: int = Field(ge=0)
    informative: int = Field(ge=0)
    mean_information_gain: float = Field(ge=0.0, le=1.0)
    mean_cost_usd: float = Field(ge=0.0)
    mean_duration_seconds: float = Field(ge=0.0)


class SchedulerCalibration(StrictModel):
    """Portable, versioned scheduler calibration artifact."""

    schema_version: Literal[1] = 1
    source_sessions: list[str] = Field(default_factory=list)
    profiles: dict[str, ActionUtilityProfile] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> SchedulerCalibration:
        source = Path(path).expanduser()
        return cls.model_validate_json(source.read_text(encoding="utf-8"))

    def write(self, path: str | Path) -> Path:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return target

    def get(self, template: str, model_route: str | None) -> ActionUtilityProfile | None:
        return self.profiles.get(profile_key(template, model_route))

    def calibrated_information_gain(
        self,
        template: str,
        model_route: str | None,
        default: float,
    ) -> float:
        profile = self.get(template, model_route)
        if profile is None:
            return default
        weight = min(0.85, profile.attempts / (profile.attempts + 5.0))
        return max(
            0.0,
            min(1.0, default * (1.0 - weight) + profile.mean_information_gain * weight),
        )


class SchedulerCalibrationCompiler:
    """Compile action-level information yield without using model confidence."""

    def compile(self, session_dirs: list[str | Path]) -> SchedulerCalibration:
        aggregates: dict[str, dict[str, object]] = defaultdict(
            lambda: {
                "template": "",
                "model_route": None,
                "attempts": 0,
                "completed": 0,
                "informative": 0,
                "information": 0.0,
                "cost": 0.0,
                "seconds": 0.0,
            }
        )
        sources: list[str] = []
        for raw_dir in session_dirs:
            root = Path(raw_dir).expanduser().resolve()
            if not root.is_dir():
                raise ValueError(f"Calibration session does not exist: {root}")
            sources.append(str(root))
            store = ProofStore(root)
            actions = list(store.latest(Action).values())
            calls = _calls_by_action(root / "spend-ledger.jsonl")
            for action in actions:
                key = profile_key(action.template, action.model_route)
                aggregate = aggregates[key]
                aggregate["template"] = action.template
                aggregate["model_route"] = action.model_route
                aggregate["attempts"] = int(aggregate["attempts"]) + 1
                completed = action.status == ActionStatus.COMPLETED
                aggregate["completed"] = int(aggregate["completed"]) + int(completed)
                information = _observed_information(action)
                aggregate["information"] = float(aggregate["information"]) + information
                aggregate["informative"] = int(aggregate["informative"]) + int(information > 0)
                observed_seconds = (
                    action.observed_seconds
                    if action.observed_seconds is not None
                    else action.estimated_seconds
                )
                aggregate["seconds"] = float(aggregate["seconds"]) + float(observed_seconds)
                aggregate["cost"] = float(aggregate["cost"]) + sum(
                    float(call.get("cost_usd") or 0.0)
                    for identifier in (action.logical_id, action.id, action.attempt_id)
                    for call in calls.get(identifier, [])
                )

        profiles: dict[str, ActionUtilityProfile] = {}
        for key, aggregate in sorted(aggregates.items()):
            attempts = int(aggregate["attempts"])
            # A weak Beta prior keeps tiny samples from producing 0/1 utility.
            information = (float(aggregate["information"]) + 1.0) / (attempts + 2.0)
            profiles[key] = ActionUtilityProfile(
                template=str(aggregate["template"]),
                model_route=(
                    str(aggregate["model_route"]) if aggregate["model_route"] is not None else None
                ),
                attempts=attempts,
                completed=int(aggregate["completed"]),
                informative=int(aggregate["informative"]),
                mean_information_gain=information,
                mean_cost_usd=float(aggregate["cost"]) / attempts,
                mean_duration_seconds=float(aggregate["seconds"]) / attempts,
            )
        if not profiles:
            raise ValueError("Calibration requires at least one proof action")
        return SchedulerCalibration(
            source_sessions=sorted(set(sources)),
            profiles=profiles,
        )


def _observed_information(action: Action) -> float:
    if action.status != ActionStatus.COMPLETED:
        return 0.0
    if action.output_claim_ids:
        return 1.0
    if action.output_evidence_ids:
        return 0.5
    return 0.0


def _calls_by_action(path: Path) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = defaultdict(list)
    if not path.is_file():
        return result
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if index == len(lines) - 1:
                break
            raise
        if not isinstance(event, dict) or event.get("event") != "call_settled":
            continue
        metadata = event.get("metadata")
        if not isinstance(metadata, dict):
            continue
        action_id = str(metadata.get("proof_action_id") or "")
        if action_id:
            result[action_id].append(event)
    return result
