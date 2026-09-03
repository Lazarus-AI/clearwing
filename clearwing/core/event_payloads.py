"""Typed payloads for EventBus events."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class CampaignProgressPayload:
    campaign_name: str
    projects_completed: int
    projects_total: int
    current_project: str
    status: str
    cost_usd: float
    findings_total: int
    verified_total: int


@dataclass(slots=True, frozen=True)
class SourcehuntStagePayload:
    session_id: str
    repo: str
    stage: str
    status: str
    findings_so_far: int
    cost_usd: float
    detail: str
    progress: float | None = None


@dataclass(slots=True, frozen=True)
class HuntProgressPayload:
    session_id: str
    tier: str
    band: str
    files_completed: int
    files_total: int
    findings_this_tier: int
    cost_usd: float
    budget_remaining: float


@dataclass(slots=True, frozen=True)
class ValidationResultPayload:
    finding_id: str
    axes: dict[str, bool]
    advance: bool
    severity: str | None
    evidence_level: str


@dataclass(slots=True, frozen=True)
class DisclosureUpdatePayload:
    finding_id: str
    action: str
    reviewer: str | None
    days_remaining: int | None
    detail: str


@dataclass(slots=True, frozen=True)
class BenchmarkProgressPayload:
    mode: str
    targets_completed: int
    targets_total: int
    current_project: str
    tier_distribution: dict[str, int]
    cost_usd: float


@dataclass(slots=True, frozen=True)
class EvalProgressPayload:
    project: str
    config_name: str
    run_index: int
    runs_total: int
    configs_completed: int
    configs_total: int
    status: str
    cost_usd: float
