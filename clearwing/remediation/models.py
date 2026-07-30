"""Strict data contracts for the standalone remediation lifecycle."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RemediationMode = Literal["report-only", "apply"]
RemediationStatus = Literal[
    "pending",
    "proposed",
    "blocked",
    "applied",
    "validated",
    "validation_failed",
    "needs_review",
    "rolled_back",
    "error",
]
ValidationStatus = Literal["validated", "validation_failed", "needs_review"]
Confidence = Literal["high", "medium", "low"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingSnapshot(StrictModel):
    """The bounded finding context owned by a remediation DTO."""

    id: str
    file: str
    line_number: int | None = None
    cwe: str = ""
    severity: str = "info"
    evidence_level: str = "suspicion"
    verified: bool = False
    description: str = ""
    code_snippet: str = ""
    crash_evidence: str = ""
    poc: str = ""
    patch_oracle_passed: bool | None = None

    @classmethod
    def from_finding(cls, finding: Any) -> FindingSnapshot:
        getter = finding.get
        return cls(
            id=str(getter("id", "") or "unknown"),
            file=str(getter("file", "") or ""),
            line_number=getter("line_number"),
            cwe=str(getter("cwe", "") or ""),
            severity=str(
                getter("severity_verified") or getter("severity", "info") or "info"
            ).lower(),
            evidence_level=str(getter("evidence_level", "suspicion") or "suspicion"),
            verified=bool(getter("verified", False)),
            description=str(getter("description", "") or ""),
            code_snippet=str(getter("code_snippet", "") or ""),
            crash_evidence=str(getter("crash_evidence", "") or ""),
            poc=str(getter("poc", "") or ""),
            patch_oracle_passed=getter("patch_oracle_passed"),
        )


class ProposedFix(StrictModel):
    diff: str
    commit_message: str = ""
    explanation: str = ""
    confidence: Confidence = "low"
    touched_files: list[str] = Field(default_factory=list)
    diff_sha256: str = ""
    encrypted_diff_path: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.diff_sha256:
            self.diff_sha256 = hashlib.sha256(self.diff.encode("utf-8")).hexdigest()


class PolicyDecision(StrictModel):
    phase: Literal["pre-generation", "post-diff"]
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    touched_files: list[str] = Field(default_factory=list)
    kill_switch_active: bool = False
    policy_sha256: str = ""


class ApplicationRecord(StrictModel):
    attempted: bool = False
    applied: bool = False
    rolled_back: bool = False
    base_git_sha: str | None = None
    touched_files: list[str] = Field(default_factory=list)
    before_sha256: dict[str, str] = Field(default_factory=dict)
    after_sha256: dict[str, str] = Field(default_factory=dict)
    encrypted_backup_paths: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class DynamicValidation(StrictModel):
    attempted: bool = False
    passed: bool | None = None
    compiled: bool | None = None
    ran: bool | None = None
    still_crashes: bool | None = None
    notes: str = ""


class GateSignal(StrictModel):
    passed: bool
    confidence: Confidence
    rationale: str = Field(default="", max_length=1000)


class PanelOpinion(StrictModel):
    persona: Literal["security_architect", "penetration_tester", "regression_reviewer"]
    root_cause: GateSignal
    bypass_resistance: GateSignal
    regression_safety: GateSignal
    minimality: GateSignal
    recommendation: Literal["pass", "fail", "needs_review"]


class GateVerdict(StrictModel):
    name: Literal["root_cause", "bypass_resistance", "regression_safety", "minimality"]
    weight: float
    passed: bool
    votes_for: int
    votes_against: int
    rationale: str = ""


class ValidationVerdict(StrictModel):
    status: ValidationStatus
    score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    gates: list[GateVerdict] = Field(default_factory=list)
    opinions: list[PanelOpinion] = Field(default_factory=list)
    dynamic: DynamicValidation = Field(default_factory=DynamicValidation)
    host_reasons: list[str] = Field(default_factory=list)
    validated_at: str = Field(default_factory=utc_now)


class RemediationDTO(StrictModel):
    """Canonical, resumable record for one finding and proposed fix."""

    schema_version: int = 1
    remediation_id: str
    run_id: str
    mode: RemediationMode
    status: RemediationStatus = "pending"
    repository: str
    base_git_sha: str | None = None
    fingerprint: str
    finding: FindingSnapshot
    proposed_fix: ProposedFix | None = None
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    application: ApplicationRecord = Field(default_factory=ApplicationRecord)
    validation: ValidationVerdict | None = None
    error: str | None = None
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)

    def touch(self) -> None:
        self.updated_at = utc_now()

    def canonical_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"updated_at"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
