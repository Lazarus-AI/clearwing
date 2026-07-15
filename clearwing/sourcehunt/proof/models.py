"""Strict data contracts for proof-carrying sourcehunt investigations."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, payload: Any) -> str:
    """Return a short deterministic identifier for JSON-compatible data."""

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


def event_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


class ObligationStatus(str, Enum):
    PROVEN = "proven"
    DISPROVEN = "disproven"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    STALE = "stale"
    NOT_APPLICABLE = "not_applicable"


class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"


class CompletenessStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"
    NOT_AVAILABLE = "not_available"
    NOT_APPLICABLE = "not_applicable"


class CertificateKind(str, Enum):
    FINDING = "finding"
    REJECTION = "rejection"
    INCOMPLETE = "incomplete"


class StrictModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )


class SourceLocation(StrictModel):
    file: str
    line: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    function: str = ""
    column: int | None = Field(default=None, ge=1)


class Provenance(StrictModel):
    producer: str
    producer_version: str = ""
    source_digest: str = ""
    command: list[str] = Field(default_factory=list)
    environment_digest: str = ""
    context_packet_id: str | None = None
    model: str | None = None
    provider: str | None = None


class VersionedRecord(StrictModel):
    """Append-only record revision.

    `id` identifies this immutable revision. `logical_id` remains stable
    across revisions; `supersedes` points at the prior revision.
    """

    id_prefix: ClassVar[str] = "record"

    id: str = ""
    logical_id: str = ""
    revision: int = Field(default=1, ge=1)
    supersedes: str | None = None
    snapshot_id: str
    created_at: str = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _assign_ids(self) -> VersionedRecord:
        payload = self.model_dump(
            mode="json",
            exclude={"id", "logical_id", "created_at", "supersedes"},
        )
        if not self.logical_id:
            identity = {
                "snapshot_id": self.snapshot_id,
                "type": type(self).__name__,
                "identity": self.identity_payload(),
            }
            object.__setattr__(
                self,
                "logical_id",
                stable_id(f"{self.id_prefix}l", identity),
            )
        if not self.id:
            payload["logical_id"] = self.logical_id
            object.__setattr__(self, "id", stable_id(self.id_prefix, payload))
        return self

    def identity_payload(self) -> Any:
        """Fields defining the logical entity across revisions."""

        return self.model_dump(
            mode="json",
            exclude={
                "id",
                "logical_id",
                "revision",
                "supersedes",
                "created_at",
            },
        )


class RepositorySnapshot(StrictModel):
    id: str = ""
    repo_path: str
    repo_url: str = ""
    commit: str = ""
    dirty_tree_digest: str | None = None
    build_configuration: str = "default"
    compiler: str = ""
    feature_flags: dict[str, Any] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _assign_id(self) -> RepositorySnapshot:
        if not self.id:
            payload = self.model_dump(mode="json", exclude={"id", "created_at"})
            object.__setattr__(self, "id", stable_id("snapshot", payload))
        return self


class Fact(VersionedRecord):
    id_prefix: ClassVar[str] = "fact"

    kind: str
    subject: str
    predicate: str = ""
    object: Any = None
    properties: dict[str, Any] = Field(default_factory=dict)
    location: SourceLocation | None = None
    provenance: Provenance

    def identity_payload(self) -> Any:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "predicate": self.predicate,
            "object": self.object,
            "location": (self.location.model_dump(mode="json") if self.location else None),
            "producer": self.provenance.producer,
        }


class Evidence(VersionedRecord):
    id_prefix: ClassVar[str] = "evidence"

    kind: str
    artifact_uri: str | None = None
    artifact_digest: str | None = None
    observations: list[dict[str, Any]] = Field(default_factory=list)
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    provenance: Provenance
    reliability: dict[str, Any] = Field(default_factory=dict)

    def identity_payload(self) -> Any:
        return {
            "kind": self.kind,
            "artifact_digest": self.artifact_digest,
            "observations": self.observations,
            "provenance": self.provenance.model_dump(mode="json"),
        }


class Claim(VersionedRecord):
    id_prefix: ClassVar[str] = "claim"

    predicate: str
    subject: str
    object: Any = None
    status: ObligationStatus = ObligationStatus.UNKNOWN
    scope: dict[str, Any] = Field(default_factory=dict)
    assumption_ids: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    derivation_id: str | None = None

    def identity_payload(self) -> Any:
        return {
            "predicate": self.predicate,
            "subject": self.subject,
            "object": self.object,
            "scope": self.scope,
        }


class Assumption(VersionedRecord):
    id_prefix: ClassVar[str] = "assumption"

    kind: str
    statement: str
    status: ObligationStatus = ObligationStatus.UNKNOWN
    scope: dict[str, Any] = Field(default_factory=dict)
    required_by: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    def identity_payload(self) -> Any:
        return {
            "kind": self.kind,
            "statement": self.statement,
            "scope": self.scope,
        }


class ThreatModel(VersionedRecord):
    id_prefix: ClassVar[str] = "threat"

    attacker_principal: str = "unknown"
    attacker_capabilities: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    protected_assets: list[str] = Field(default_factory=list)
    required_privileges: list[str] = Field(default_factory=list)
    deployment_assumptions: list[str] = Field(default_factory=list)
    capability_gained: list[str] = Field(default_factory=list)
    security_properties_violated: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    def identity_payload(self) -> Any:
        return {
            "attacker_principal": self.attacker_principal,
            "trust_boundaries": self.trust_boundaries,
            "protected_assets": self.protected_assets,
        }


class Candidate(VersionedRecord):
    id_prefix: ClassVar[str] = "candidate"

    title: str
    invariant_families: list[str]
    suspected_mechanism: str
    source_symbols: list[str] = Field(default_factory=list)
    transformations: list[str] = Field(default_factory=list)
    state_sinks: list[str] = Field(default_factory=list)
    impact_sinks: list[str] = Field(default_factory=list)
    suspected_invariants: list[str] = Field(default_factory=list)
    fact_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    assumption_ids: list[str] = Field(default_factory=list)
    threat_model_id: str | None = None
    proof_plan_ids: list[str] = Field(default_factory=list)
    obligation_ids: list[str] = Field(default_factory=list)
    generator: str
    generator_version: str = "1"
    experimental: bool = False

    def identity_payload(self) -> Any:
        return {
            "invariant_families": sorted(self.invariant_families),
            "mechanism": self.suspected_mechanism,
            "sources": sorted(self.source_symbols),
            "state_sinks": sorted(self.state_sinks),
            "impact_sinks": sorted(self.impact_sinks),
        }


class Obligation(VersionedRecord):
    id_prefix: ClassVar[str] = "obligation"

    candidate_id: str
    proof_plan_id: str
    predicate: str
    subject: str = ""
    object: Any = None
    description: str = ""
    dependencies: list[str] = Field(default_factory=list)
    required_any_of: list[list[str]] = Field(default_factory=list)
    mandatory: bool = True
    decisive_rejection: bool = False
    status: ObligationStatus = ObligationStatus.UNKNOWN
    supporting_claim_ids: list[str] = Field(default_factory=list)
    contradicting_claim_ids: list[str] = Field(default_factory=list)
    blocked_reason: str | None = None
    available_actions: list[str] = Field(default_factory=list)

    def identity_payload(self) -> Any:
        return {
            "candidate_id": self.candidate_id,
            "proof_plan_id": self.proof_plan_id,
            "predicate": self.predicate,
            "subject": self.subject,
            "object": self.object,
        }


class Action(VersionedRecord):
    id_prefix: ClassVar[str] = "action"

    candidate_id: str
    obligation_ids: list[str]
    template: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    preconditions: list[str] = Field(default_factory=list)
    permitted_tools: list[str] = Field(default_factory=list)
    model_route: str | None = None
    status: ActionStatus = ActionStatus.PENDING
    estimated_cost_usd: float = Field(default=0.0, ge=0.0)
    estimated_seconds: float = Field(default=0.0, ge=0.0)
    started_at: str | None = None
    completed_at: str | None = None
    observed_seconds: float | None = Field(default=None, ge=0.0)
    expected_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    output_evidence_ids: list[str] = Field(default_factory=list)
    output_claim_ids: list[str] = Field(default_factory=list)
    error: str | None = None
    attempt_id: str = Field(default_factory=lambda: event_id("attempt"))

    def identity_payload(self) -> Any:
        return {
            "candidate_id": self.candidate_id,
            "obligation_ids": sorted(self.obligation_ids),
            "template": self.template,
            "inputs": self.inputs,
            "attempt_id": self.attempt_id,
        }


class Derivation(VersionedRecord):
    id_prefix: ClassVar[str] = "derivation"

    rule: str
    premise_ids: list[str]
    conclusion_claim_ids: list[str]
    limitations: list[str] = Field(default_factory=list)
    validator: Literal["deterministic", "model", "human", "hybrid"]
    context_packet_id: str | None = None

    def identity_payload(self) -> Any:
        return {
            "rule": self.rule,
            "premises": sorted(self.premise_ids),
            "conclusions": sorted(self.conclusion_claim_ids),
            "validator": self.validator,
        }


class CompletenessItem(StrictModel):
    status: CompletenessStatus
    basis: str = ""
    scope: str = ""
    limitations: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)


class CompletenessManifest(StrictModel):
    snapshot_id: str
    items: dict[str, CompletenessItem]

    @property
    def has_unknowns(self) -> bool:
        return any(
            item.status
            in {
                CompletenessStatus.PARTIAL,
                CompletenessStatus.UNRESOLVED,
                CompletenessStatus.NOT_AVAILABLE,
            }
            for item in self.items.values()
        )


class ContextPacket(VersionedRecord):
    id_prefix: ClassVar[str] = "packet"

    candidate_id: str
    obligation_id: str
    question: str
    fact_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    claim_ids: list[str] = Field(default_factory=list)
    assumption_ids: list[str] = Field(default_factory=list)
    evidence_summaries: list[dict[str, Any]] = Field(default_factory=list)
    claim_summaries: list[dict[str, Any]] = Field(default_factory=list)
    assumption_summaries: list[dict[str, Any]] = Field(default_factory=list)
    evaluation_hints: dict[str, Any] = Field(default_factory=dict)
    threat_model: dict[str, Any] | None = None
    excerpts: list[dict[str, Any]] = Field(default_factory=list)
    permitted_outputs: list[str] = Field(default_factory=list)
    token_count: int = Field(default=0, ge=0)
    completeness: CompletenessManifest

    def identity_payload(self) -> Any:
        return {
            "candidate_id": self.candidate_id,
            "obligation_id": self.obligation_id,
            "question": self.question,
            "facts": sorted(self.fact_ids),
            "evidence": sorted(self.evidence_ids),
            "claims": sorted(self.claim_ids),
            "assumptions": sorted(self.assumption_ids),
            "evaluation_hints": self.evaluation_hints,
            "threat_model": self.threat_model,
            "completeness": self.completeness.model_dump(mode="json"),
        }


class Certificate(VersionedRecord):
    id_prefix: ClassVar[str] = "certificate"

    kind: CertificateKind
    candidate_id: str
    proof_plan_ids: list[str]
    decision: str
    reason: str
    threat_model_id: str | None = None
    claim_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    assumption_ids: list[str] = Field(default_factory=list)
    unresolved_obligation_ids: list[str] = Field(default_factory=list)
    blocked_obligation_ids: list[str] = Field(default_factory=list)
    falsification_action_ids: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    dependency_symbols: list[str] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    cwe: str | None = None
    report_claims: list[dict[str, Any]] = Field(default_factory=list)
    validity: Literal["current", "stale"] = "current"
    invalidated_by: list[str] = Field(default_factory=list)
    stale_reason: str | None = None

    def identity_payload(self) -> Any:
        return {
            "kind": self.kind,
            "candidate_id": self.candidate_id,
            "proof_plans": sorted(self.proof_plan_ids),
            "decision": self.decision,
        }
