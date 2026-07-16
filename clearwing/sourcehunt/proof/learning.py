"""Typed exploration retrospectives and an explicit learning flywheel.

Exploratory model output never becomes executable policy directly.  A novel
candidate must first earn a finding certificate and complete falsification.
This module then emits a reviewable retrospective.  An explicit promotion
step turns eligible retrospectives into a portable registry consumed by a
mechanical candidate generator on later runs.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .models import (
    Action,
    ActionStatus,
    Candidate,
    Certificate,
    CertificateKind,
    Evidence,
    Fact,
    Obligation,
    ObligationStatus,
    StrictModel,
    stable_id,
)
from .store import ProofStore

_STRUCTURAL_FACT_KINDS = {
    "allocation",
    "assignment",
    "authorization_policy",
    "call",
    "call_edge",
    "cast",
    "concurrency_violation",
    "crypto_contract",
    "crypto_precondition",
    "encoding",
    "guard",
    "lifetime_relation",
    "loop",
    "memory_access",
    "memory_write",
    "parser_boundary",
    "range_violation",
    "reachability",
    "resource_limit",
    "resource_violation",
    "sentinel_use",
    "state_model",
    "state_transition",
    "synchronization",
    "taint_path",
}
_DECISIVE_EVIDENCE_KINDS = {
    "authorization_differential",
    "bounded_resource_exhaustion",
    "cryptographic_differential",
    "debugger_memory_violation",
    "fault_injection_violation",
    "configuration_differential",
    "injection_differential",
    "protocol_transition_violation",
    "patch_differential",
    "race_detector_violation",
    "sanitizer_crash",
    "sanitizer_uaf",
    "symbolic_memory_violation",
}


class RegressionSpecification(StrictModel):
    name: str = Field(min_length=1)
    transformation: Literal[
        "original",
        "add_guard_or_policy",
        "rename_symbols",
        "move_scope",
        "remove_reachability",
        "add_decoy",
    ]
    expected_relation: Literal[
        "finding_present",
        "rejection_added",
        "mechanism_preserved",
        "finding_removed",
        "no_extra_finding",
    ]


class GeneratorSeed(StrictModel):
    mechanism: str = Field(min_length=1)
    invariant_families: list[str] = Field(min_length=1)
    suspected_invariants: list[str] = Field(default_factory=list)
    required_fact_kinds: list[str] = Field(min_length=1)
    operation_markers: list[str] = Field(default_factory=list)
    proof_plan_ids: list[str] = Field(min_length=1)


class ProofPlanProfile(StrictModel):
    proof_plan_ids: list[str] = Field(min_length=1)
    mandatory_predicates: list[str] = Field(min_length=1)
    decisive_rejection_predicates: list[str] = Field(default_factory=list)
    decisive_evidence_kinds: list[str] = Field(default_factory=list)


class DiscoveryRetrospective(StrictModel):
    schema_version: Literal[1] = 1
    id: str = ""
    snapshot_id: str
    candidate_id: str
    certificate_id: str
    mechanism: str
    invariant_families: list[str]
    source_generator: str
    source_fact_ids: list[str]
    source_evidence_ids: list[str]
    falsification_action_ids: list[str]
    falsification_complete: bool
    generator_seed: GeneratorSeed
    proof_plan_profile: ProofPlanProfile
    regressions: list[RegressionSpecification]
    eligible_for_promotion: bool
    promotion_blockers: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _assign_id(self) -> DiscoveryRetrospective:
        expected = stable_id(
            "retrospective",
            {
                "snapshot_id": self.snapshot_id,
                "candidate_id": self.candidate_id,
                "certificate_id": self.certificate_id,
                "mechanism": self.mechanism,
            },
        )
        if self.id and self.id != expected:
            raise ValueError("Retrospective ID does not match its source proof")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self


class RetrospectiveBundle(StrictModel):
    schema_version: Literal[1] = 1
    snapshot_id: str
    retrospectives: list[DiscoveryRetrospective] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> RetrospectiveBundle:
        return cls.model_validate_json(Path(path).expanduser().read_text(encoding="utf-8"))

    def write(self, path: str | Path) -> Path:
        return _atomic_model_write(self, path)


class PromotedMechanism(StrictModel):
    id: str
    source_retrospective_id: str
    generator_seed: GeneratorSeed
    proof_plan_profile: ProofPlanProfile
    regressions: list[RegressionSpecification]

    @model_validator(mode="after")
    def _validate_id_and_regressions(self) -> PromotedMechanism:
        if set(self.generator_seed.proof_plan_ids) != set(self.proof_plan_profile.proof_plan_ids):
            raise ValueError("Generator seed and proof-plan profile bindings differ")
        expected = _promoted_id(
            self.source_retrospective_id,
            self.generator_seed,
            self.proof_plan_profile,
            self.regressions,
        )
        if self.id != expected:
            raise ValueError("Promoted mechanism ID does not match its reviewed content")
        required = {
            "original",
            "add_guard_or_policy",
            "rename_symbols",
            "move_scope",
            "remove_reachability",
            "add_decoy",
        }
        present = {item.transformation for item in self.regressions}
        if not required <= present:
            raise ValueError("Promoted mechanism lacks the required regression matrix")
        return self

    @classmethod
    def from_retrospective(cls, item: DiscoveryRetrospective) -> PromotedMechanism:
        if not item.eligible_for_promotion:
            raise ValueError(
                f"Retrospective {item.id} is not eligible: " + ", ".join(item.promotion_blockers)
            )
        return cls(
            id=_promoted_id(
                item.id,
                item.generator_seed,
                item.proof_plan_profile,
                item.regressions,
            ),
            source_retrospective_id=item.id,
            generator_seed=item.generator_seed,
            proof_plan_profile=item.proof_plan_profile,
            regressions=item.regressions,
        )


class LearningRegistry(StrictModel):
    schema_version: Literal[1] = 1
    mechanisms: list[PromotedMechanism] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_sources(self) -> LearningRegistry:
        identifiers = [item.id for item in self.mechanisms]
        sources = [item.source_retrospective_id for item in self.mechanisms]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Learning registry contains duplicate mechanism IDs")
        if len(sources) != len(set(sources)):
            raise ValueError("Learning registry promotes one retrospective more than once")
        return self

    @classmethod
    def load(cls, path: str | Path) -> LearningRegistry:
        source = Path(path).expanduser()
        return cls.model_validate_json(source.read_text(encoding="utf-8"))

    @classmethod
    def promote(
        cls,
        bundles: list[RetrospectiveBundle],
        *,
        existing: LearningRegistry | None = None,
    ) -> LearningRegistry:
        promoted = {
            item.source_retrospective_id: item for item in (existing.mechanisms if existing else [])
        }
        for bundle in bundles:
            for retrospective in bundle.retrospectives:
                if not retrospective.eligible_for_promotion:
                    continue
                item = PromotedMechanism.from_retrospective(retrospective)
                promoted[item.source_retrospective_id] = item
        if not promoted:
            raise ValueError("No eligible exploratory retrospectives were supplied")
        return cls(mechanisms=sorted(promoted.values(), key=lambda item: item.id))

    def write(self, path: str | Path) -> Path:
        return _atomic_model_write(self, path)


class RetrospectiveCompiler:
    """Distill only proof-carrying exploratory findings into proposals."""

    def compile_bundle(
        self,
        snapshot_id: str,
        candidates: list[Candidate],
        certificates: list[Certificate],
        facts: list[Fact],
        obligations: list[Obligation],
        actions: list[Action],
        evidence: list[Evidence],
    ) -> RetrospectiveBundle:
        certificates_by_candidate = {
            certificate.candidate_id: certificate
            for certificate in certificates
            if certificate.kind == CertificateKind.FINDING
        }
        fact_by_id = {
            identifier: fact for fact in facts for identifier in (fact.id, fact.logical_id)
        }
        evidence_by_id = {
            identifier: item for item in evidence for identifier in (item.id, item.logical_id)
        }
        obligations_by_candidate: dict[str, list[Obligation]] = defaultdict(list)
        for obligation in obligations:
            obligations_by_candidate[obligation.candidate_id].append(obligation)
        action_by_id = {
            identifier: action
            for action in actions
            for identifier in (action.id, action.logical_id)
        }
        retrospectives: list[DiscoveryRetrospective] = []
        for candidate in candidates:
            if candidate.generator != "bounded-exploratory-lane":
                continue
            certificate = certificates_by_candidate.get(candidate.logical_id)
            if certificate is None:
                continue
            candidate_facts = [
                fact_by_id[fact_id] for fact_id in candidate.fact_ids if fact_id in fact_by_id
            ]
            candidate_evidence = [
                evidence_by_id[evidence_id]
                for evidence_id in certificate.evidence_ids
                if evidence_id in evidence_by_id
            ]
            candidate_obligations = obligations_by_candidate.get(candidate.logical_id, [])
            falsification_actions = [
                action_by_id[action_id]
                for action_id in certificate.falsification_action_ids
                if action_id in action_by_id
            ]
            falsification_complete = bool(falsification_actions) and all(
                action.status == ActionStatus.COMPLETED for action in falsification_actions
            )
            blockers: list[str] = []
            if not candidate.proof_plan_ids:
                blockers.append("no proof plan")
            if not candidate_facts:
                blockers.append("no source facts")
            if not candidate_evidence:
                blockers.append("no audited evidence")
            if not falsification_complete:
                blockers.append("falsification incomplete")
            if not certificate.report_claims:
                blockers.append("no reportable evidence-linked claims")
            required_fact_kinds = _required_fact_kinds(candidate_facts)
            if not required_fact_kinds:
                blockers.append("no reusable structural fact signature")
            seed = GeneratorSeed(
                mechanism=candidate.suspected_mechanism,
                invariant_families=sorted(set(candidate.invariant_families)),
                suspected_invariants=sorted(set(candidate.suspected_invariants)),
                required_fact_kinds=required_fact_kinds or ["unclassified"],
                operation_markers=_operation_markers(candidate_facts),
                proof_plan_ids=sorted(set(candidate.proof_plan_ids)),
            )
            profile = ProofPlanProfile(
                proof_plan_ids=sorted(set(candidate.proof_plan_ids)),
                mandatory_predicates=sorted(
                    {item.predicate for item in candidate_obligations if item.mandatory}
                ),
                decisive_rejection_predicates=sorted(
                    {item.predicate for item in candidate_obligations if item.decisive_rejection}
                ),
                decisive_evidence_kinds=sorted(
                    {
                        item.kind
                        for item in candidate_evidence
                        if item.kind in _DECISIVE_EVIDENCE_KINDS
                    }
                ),
            )
            retrospectives.append(
                DiscoveryRetrospective(
                    snapshot_id=snapshot_id,
                    candidate_id=candidate.logical_id,
                    certificate_id=certificate.id,
                    mechanism=candidate.suspected_mechanism,
                    invariant_families=sorted(set(candidate.invariant_families)),
                    source_generator=candidate.generator,
                    source_fact_ids=sorted(set(candidate.fact_ids)),
                    source_evidence_ids=sorted(set(certificate.evidence_ids)),
                    falsification_action_ids=sorted(set(certificate.falsification_action_ids)),
                    falsification_complete=falsification_complete,
                    generator_seed=seed,
                    proof_plan_profile=profile,
                    regressions=_regression_specs(candidate),
                    eligible_for_promotion=not blockers,
                    promotion_blockers=blockers,
                )
            )
        return RetrospectiveBundle(
            snapshot_id=snapshot_id,
            retrospectives=sorted(retrospectives, key=lambda item: item.id),
        )


class LearnedMechanismGenerator:
    """Apply explicitly promoted structural seeds to later snapshots."""

    name = "promoted-mechanism-registry"
    version = "1"

    def __init__(self, registry: LearningRegistry):
        self.registry = registry

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        scopes: dict[tuple[str, str], list[Fact]] = defaultdict(list)
        for fact in facts:
            if fact.location is None:
                continue
            scopes[(fact.location.file, fact.location.function)].append(fact)
        candidates: list[Candidate] = []
        for promoted in self.registry.mechanisms:
            seed = promoted.generator_seed
            required = set(seed.required_fact_kinds)
            for scope_facts in scopes.values():
                kinds = {fact.kind for fact in scope_facts}
                if not required <= kinds:
                    continue
                if seed.operation_markers and not (
                    set(seed.operation_markers) & set(_operation_markers(scope_facts))
                ):
                    continue
                matched = [fact for fact in scope_facts if fact.kind in required]
                candidates.append(
                    Candidate(
                        snapshot_id=snapshot_id,
                        title=f"Promoted mechanism requires proof: {seed.mechanism}",
                        invariant_families=seed.invariant_families,
                        suspected_mechanism=seed.mechanism,
                        source_symbols=_source_symbols(matched),
                        transformations=[
                            _fact_expression(fact)
                            for fact in matched
                            if fact.kind in {"assignment", "cast", "call"}
                        ],
                        state_sinks=[
                            fact.subject
                            for fact in matched
                            if fact.kind in {"assignment", "state_transition"}
                        ],
                        impact_sinks=[
                            _fact_expression(fact)
                            for fact in matched
                            if fact.kind
                            in {
                                "call",
                                "memory_access",
                                "memory_write",
                                "resource_violation",
                            }
                        ],
                        suspected_invariants=seed.suspected_invariants,
                        fact_ids=sorted(fact.id for fact in matched),
                        proof_plan_ids=seed.proof_plan_ids,
                        generator=f"promoted:{promoted.id}",
                        generator_version=self.version,
                        experimental=False,
                    )
                )
        by_id = {candidate.logical_id: candidate for candidate in candidates}
        return sorted(by_id.values(), key=lambda candidate: candidate.logical_id)


class LearningCoverageSnapshot(StrictModel):
    sessions: list[str]
    promoted_mechanism_count: int = Field(ge=0)
    covered_mechanisms: list[str]
    structured_rediscoveries: list[str]
    model_resolved_obligations: int = Field(ge=0)
    local_only_resolved_obligations: int = Field(ge=0)
    local_only_completion_rate: float = Field(ge=0.0, le=1.0)
    frontier_actions: int = Field(ge=0)


class LearningCoverageReport(StrictModel):
    schema_version: Literal[1] = 1
    before: LearningCoverageSnapshot
    after: LearningCoverageSnapshot
    structured_rediscovery_delta: int
    local_only_resolved_obligation_delta: int
    local_only_completion_rate_delta: float
    frontier_action_delta: int
    improved: bool

    def write(self, path: str | Path) -> Path:
        return _atomic_model_write(self, path)


class LearningCoverageCompiler:
    def compare(
        self,
        registry: LearningRegistry,
        before_sessions: list[str | Path],
        after_sessions: list[str | Path],
    ) -> LearningCoverageReport:
        before = self._snapshot(registry, before_sessions)
        after = self._snapshot(registry, after_sessions)
        rediscovery_delta = len(after.structured_rediscoveries) - len(
            before.structured_rediscoveries
        )
        local_resolved_delta = (
            after.local_only_resolved_obligations - before.local_only_resolved_obligations
        )
        local_delta = after.local_only_completion_rate - before.local_only_completion_rate
        frontier_delta = after.frontier_actions - before.frontier_actions
        return LearningCoverageReport(
            before=before,
            after=after,
            structured_rediscovery_delta=rediscovery_delta,
            local_only_resolved_obligation_delta=local_resolved_delta,
            local_only_completion_rate_delta=local_delta,
            frontier_action_delta=frontier_delta,
            improved=(rediscovery_delta > 0 and local_resolved_delta > 0 and local_delta >= 0),
        )

    @staticmethod
    def _snapshot(
        registry: LearningRegistry,
        session_dirs: list[str | Path],
    ) -> LearningCoverageSnapshot:
        if not session_dirs:
            raise ValueError("Learning coverage requires at least one session per side")
        target_mechanisms = {item.generator_seed.mechanism for item in registry.mechanisms}
        target_mechanism_ids = {item.id for item in registry.mechanisms}
        covered: set[str] = set()
        rediscovered: set[str] = set()
        resolved: set[tuple[str, str, str]] = set()
        local_resolved: set[tuple[str, str, str]] = set()
        frontier_seen: set[tuple[str, str, str]] = set()
        frontier_actions = 0
        sessions: list[str] = []
        for raw in session_dirs:
            root = Path(raw).expanduser().resolve()
            if not root.is_dir():
                raise ValueError(f"Learning-coverage session does not exist: {root}")
            sessions.append(str(root))
            store = ProofStore(root)
            target_candidate_ids: set[str] = set()
            for candidate in store.latest(Candidate).values():
                if candidate.suspected_mechanism in target_mechanisms:
                    covered.add(candidate.suspected_mechanism)
                    target_candidate_ids.add(candidate.logical_id)
                    promoted_id = candidate.generator.removeprefix("promoted:")
                    if (
                        candidate.generator.startswith("promoted:")
                        and promoted_id in target_mechanism_ids
                    ):
                        rediscovered.add(promoted_id)
            terminal_obligations = {
                obligation.logical_id
                for obligation in store.latest(Obligation).values()
                if obligation.candidate_id in target_candidate_ids
                and obligation.status
                in {
                    ObligationStatus.PROVEN,
                    ObligationStatus.DISPROVEN,
                    ObligationStatus.NOT_APPLICABLE,
                }
            }
            actions = list(store.latest(Action).values())
            for action in actions:
                if action.candidate_id not in target_candidate_ids:
                    continue
                if action.model_route == "proof_frontier":
                    frontier_actions += 1
                for obligation_id in action.obligation_ids:
                    if obligation_id not in terminal_obligations:
                        continue
                    key = (str(root), action.candidate_id, obligation_id)
                    if action.model_route == "proof_frontier":
                        frontier_seen.add(key)
                    if (
                        action.model_route in {"proof_local", "proof_frontier"}
                        and action.output_claim_ids
                        and action.status == ActionStatus.COMPLETED
                    ):
                        resolved.add(key)
                        if action.model_route == "proof_local":
                            local_resolved.add(key)
        local_only = local_resolved - frontier_seen
        return LearningCoverageSnapshot(
            sessions=sorted(sessions),
            promoted_mechanism_count=len(registry.mechanisms),
            covered_mechanisms=sorted(covered),
            structured_rediscoveries=sorted(rediscovered),
            model_resolved_obligations=len(resolved),
            local_only_resolved_obligations=len(local_only),
            local_only_completion_rate=(len(local_only) / len(resolved) if resolved else 0.0),
            frontier_actions=frontier_actions,
        )


def _required_fact_kinds(facts: list[Fact]) -> list[str]:
    kinds = sorted({fact.kind for fact in facts if fact.kind in _STRUCTURAL_FACT_KINDS})
    return kinds[:6]


def _operation_markers(facts: list[Fact]) -> list[str]:
    markers: set[str] = set()
    for fact in facts:
        for key in ("operation", "callee"):
            value = str(fact.properties.get(key) or "").lower().split(".")[-1]
            if re.fullmatch(r"[a-z_][a-z0-9_]{1,63}", value):
                markers.add(value)
    return sorted(markers)[:8]


def _source_symbols(facts: list[Fact]) -> list[str]:
    symbols: set[str] = set()
    for fact in facts:
        if fact.kind in {"length", "taint_path"}:
            symbols.add(str(fact.properties.get("variable") or fact.subject))
        symbols.update(str(value) for value in fact.properties.get("extent_symbols", []))
        symbols.update(str(value) for value in fact.properties.get("offset_symbols", []))
    return sorted(symbol for symbol in symbols if symbol)


def _fact_expression(fact: Fact) -> str:
    return str(
        fact.properties.get("expression")
        or fact.properties.get("excerpt")
        or fact.properties.get("rhs")
        or fact.object
        or fact.subject
    )


def _regression_specs(candidate: Candidate) -> list[RegressionSpecification]:
    if "authority_safety" in candidate.invariant_families:
        negative_name = "policy-enforced"
    elif "temporal_safety" in candidate.invariant_families:
        negative_name = "lifetime-restored"
    elif "concurrency_safety" in candidate.invariant_families:
        negative_name = "synchronization-added"
    else:
        negative_name = "guarded"
    return [
        RegressionSpecification(
            name="vulnerable",
            transformation="original",
            expected_relation="finding_present",
        ),
        RegressionSpecification(
            name=negative_name,
            transformation="add_guard_or_policy",
            expected_relation="rejection_added",
        ),
        RegressionSpecification(
            name="renamed",
            transformation="rename_symbols",
            expected_relation="mechanism_preserved",
        ),
        RegressionSpecification(
            name="moved",
            transformation="move_scope",
            expected_relation="mechanism_preserved",
        ),
        RegressionSpecification(
            name="unreachable",
            transformation="remove_reachability",
            expected_relation="finding_removed",
        ),
        RegressionSpecification(
            name="decoy",
            transformation="add_decoy",
            expected_relation="no_extra_finding",
        ),
    ]


def _atomic_model_write(model: StrictModel, path: str | Path) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
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


def _promoted_id(
    retrospective_id: str,
    seed: GeneratorSeed,
    profile: ProofPlanProfile,
    regressions: list[RegressionSpecification],
) -> str:
    return stable_id(
        "promoted-mechanism",
        {
            "retrospective": retrospective_id,
            "seed": seed.model_dump(mode="json"),
            "profile": profile.model_dump(mode="json"),
            "regressions": [item.model_dump(mode="json") for item in regressions],
        },
    )
