"""Bounded deterministic and model-backed obligation resolvers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field

from clearwing.llm.native import response_text

from .graph import ProofGraph
from .models import (
    Candidate,
    Claim,
    CompletenessManifest,
    CompletenessStatus,
    ContextPacket,
    Derivation,
    Evidence,
    Fact,
    Obligation,
    ObligationStatus,
    Provenance,
    StrictModel,
)
from .store import ProofStore


@dataclass
class Resolution:
    status: ObligationStatus
    claims: list[Claim] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    derivations: list[Derivation] = field(default_factory=list)
    blocked_reason: str | None = None


class BoundedJudgment(StrictModel):
    status: Literal[
        "proven",
        "disproven",
        "unknown",
        "blocked",
        "conflicting_evidence",
    ]
    conclusion: str
    cited_fact_ids: list[str] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    cited_claim_ids: list[str] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MechanicalResolver:
    """Resolve only predicates with conservative, auditable rules."""

    def resolve(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        relevant = [fact for fact in facts if fact.id in set(candidate.fact_ids)]
        handlers = {
            "reserved_sentinel_established": self._reserved_sentinel,
            "live_identifier_domain_established": self._live_domain,
            "live_domain_overlaps_reserved_value": self._domain_overlap,
            "no_effective_upper_bound_guard": self._guard,
            "incorrect_state_reaches_memory_access": self._memory_access,
            "object_bounds_established": self._object_bounds,
            "attacker_controls_identifier_progression": self._taint_path,
            "attacker_controls_requested_extent": self._taint_path,
            "attacker_data_reaches_interpreter_boundary": self._taint_path,
            "attacker_observes_or_controls_relevant_values": self._taint_path,
            "attacker_influences_schedule_or_resource_consumption": self._taint_path,
        }
        handler = handlers.get(obligation.predicate)
        if handler is None:
            return None
        return handler(candidate, obligation, relevant, completeness)

    def _reserved_sentinel(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        matches = [fact for fact in facts if fact.kind == "sentinel_use"]
        if not matches:
            return None
        return self._supported(
            candidate,
            obligation,
            matches,
            conclusion="A reserved sentinel representation is present.",
            evidence_kind="static_sentinel_definition",
        )

    def _live_domain(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        assignments = [
            fact
            for fact in facts
            if fact.kind == "assignment"
            and any(
                sink in str(fact.properties.get("lhs", ""))
                for sink in candidate.state_sinks
            )
        ]
        if not assignments:
            return None
        return self._supported(
            candidate,
            obligation,
            assignments,
            conclusion=(
                "A live identifier is represented in the same storage used by "
                "the reserved value."
            ),
            evidence_kind="static_representation_assignment",
        )

    def _domain_overlap(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        assignments = [fact for fact in facts if fact.kind == "assignment"]
        sentinel_facts = [fact for fact in facts if fact.kind == "sentinel_use"]
        counters = [fact for fact in facts if fact.kind == "counter_update"]
        typed_sources = [
            fact
            for fact in facts
            if fact.kind in {"variable", "field", "parameter"}
            and any(source in fact.subject for source in candidate.source_symbols)
        ]
        if not assignments or not sentinel_facts:
            return None
        if not counters and not typed_sources:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason=(
                    "The representation assignment is known, but the live "
                    "identifier range is unresolved."
                ),
            )
        if (
            completeness.items.get("types")
            and completeness.items["types"].status
            in {
                "unresolved",
                "not_available",
            }
        ):
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Type-domain completeness is insufficient.",
            )
        return self._supported(
            candidate,
            obligation,
            [*assignments, *sentinel_facts, *counters, *typed_sources],
            conclusion=(
                "The extracted identifier range includes the reserved "
                "representation value."
            ),
            evidence_kind="static_domain_overlap",
        )

    def _guard(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        assignments = [
            fact
            for fact in facts
            if fact.kind == "assignment"
            and any(
                sink in str(fact.properties.get("lhs", ""))
                for sink in candidate.state_sinks
            )
        ]
        effective: list[Fact] = []
        for guard in (fact for fact in facts if fact.kind == "guard"):
            expression = _fact_text(guard)
            if not any(source in expression for source in candidate.source_symbols):
                continue
            if not re.search(r"(?:0x[fF]{4}|65535|UINT16_MAX)", expression):
                continue
            if not re.search(r"(?:>=|==|>)", expression):
                continue
            control_effect = str(guard.properties.get("control_effect", ""))
            if not (
                control_effect
                or re.search(r"\b(?:return|raise|throw|goto|break)\b", expression)
            ):
                continue
            for assignment in assignments:
                if _same_function(guard, assignment) and _line(guard) < _line(assignment):
                    effective.append(guard)
                    break
        if effective:
            return self._contradicted(
                candidate,
                obligation,
                effective,
                conclusion=(
                    "An earlier same-function rejecting guard prevents the "
                    "reserved value before the state-table assignment."
                ),
                evidence_kind="dominating_rejecting_guard",
            )
        dominators = completeness.items.get("control_dominators")
        if dominators is None or dominators.status != "complete":
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason=(
                    "No effective guard was found in the slice, but control "
                    "dominator coverage is incomplete."
                ),
            )
        return self._supported(
            candidate,
            obligation,
            assignments,
            conclusion="Complete dominator analysis found no effective upper-bound guard.",
            evidence_kind="complete_guard_enumeration",
        )

    def _memory_access(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        accesses = [
            fact
            for fact in facts
            if fact.kind in {"memory_access", "memory_write"}
        ]
        if not accesses:
            return None
        return self._supported(
            candidate,
            obligation,
            accesses,
            conclusion="The candidate state reaches a syntactic memory access.",
            evidence_kind="static_memory_access",
        )

    def _object_bounds(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        allocations = [fact for fact in facts if fact.kind == "allocation"]
        if not allocations:
            return None
        return self._supported(
            candidate,
            obligation,
            allocations,
            conclusion="An allocation expression establishes the candidate object extent.",
            evidence_kind="static_allocation_extent",
        )

    def _taint_path(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        paths = [fact for fact in facts if fact.kind == "taint_path"]
        if paths:
            return self._supported(
                candidate,
                obligation,
                paths,
                conclusion=(
                    "A language-aware intraprocedural source-to-sink path "
                    "carries an explicit candidate endpoint."
                ),
                evidence_kind="taint_path",
            )
        coverage = completeness.items.get("taint_paths")
        if coverage is None or coverage.status != CompletenessStatus.COMPLETE:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason=(
                    "No matching taint path was extracted, and taint coverage "
                    "is not complete enough to disprove attacker influence."
                ),
            )
        return None

    def _supported(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        *,
        conclusion: str,
        evidence_kind: str,
    ) -> Resolution:
        return self._resolution(
            candidate,
            obligation,
            facts,
            conclusion=conclusion,
            evidence_kind=evidence_kind,
            obligation_status=ObligationStatus.PROVEN,
            claim_status=ObligationStatus.PROVEN,
            supports=True,
        )

    def _contradicted(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        *,
        conclusion: str,
        evidence_kind: str,
    ) -> Resolution:
        return self._resolution(
            candidate,
            obligation,
            facts,
            conclusion=conclusion,
            evidence_kind=evidence_kind,
            obligation_status=ObligationStatus.DISPROVEN,
            claim_status=ObligationStatus.PROVEN,
            supports=False,
        )

    def _resolution(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        *,
        conclusion: str,
        evidence_kind: str,
        obligation_status: ObligationStatus,
        claim_status: ObligationStatus,
        supports: bool,
    ) -> Resolution:
        claim_predicate = (
            obligation.predicate
            if supports
            else f"counterexample_to:{obligation.predicate}"
        )
        claim = Claim(
            snapshot_id=candidate.snapshot_id,
            predicate=claim_predicate,
            subject=candidate.logical_id,
            object=conclusion,
            status=claim_status,
            scope={"obligation_id": obligation.logical_id},
        )
        evidence = Evidence(
            snapshot_id=candidate.snapshot_id,
            kind=evidence_kind,
            observations=[
                {
                    "fact_id": fact.id,
                    "location": (
                        fact.location.model_dump(mode="json")
                        if fact.location
                        else None
                    ),
                    "observation": _fact_text(fact),
                }
                for fact in facts
            ],
            supports=[claim.logical_id] if supports else [],
            contradicts=[] if supports else [obligation.logical_id],
            provenance=Provenance(
                producer="mechanical-obligation-resolver",
                producer_version="1",
            ),
            reliability={"method": "deterministic_rule", "scope": "included facts"},
        )
        claim_payload = claim.model_dump(mode="python")
        claim_payload.update(
            {
                "id": "",
                "supporting_evidence_ids": [evidence.id],
            }
        )
        claim = Claim.model_validate(claim_payload)
        derivation = Derivation(
            snapshot_id=candidate.snapshot_id,
            rule=f"mechanical:{evidence_kind}",
            premise_ids=[fact.id for fact in facts],
            conclusion_claim_ids=[claim.logical_id],
            validator="deterministic",
        )
        return Resolution(
            status=obligation_status,
            claims=[claim],
            evidence=[evidence],
            derivations=[derivation],
        )


class BoundedModelResolver:
    """Resolve one context packet using constrained model output."""

    SYSTEM_PROMPT = """You resolve one atomic vulnerability proof obligation.
Use only the supplied packet. Unknown or missing edges remain unknown. Cite
every fact used. Do not infer remote reachability, exploitability, or memory
corruption from a crash alone. Return §blocked§ when named missing context is
required, and §conflicting_evidence§ when supplied facts conflict."""

    def __init__(self, llm: Any):
        self.llm = llm

    async def resolve(
        self,
        candidate: Candidate,
        obligation: Obligation,
        packet: ContextPacket,
    ) -> Resolution:
        response = await self.llm.aask_text(
            system=self.SYSTEM_PROMPT,
            user=json.dumps(packet.model_dump(mode="json"), indent=2),
            response_schema=BoundedJudgment,
            response_schema_name="BoundedProofJudgment",
        )
        raw = response_text(response)
        judgment = BoundedJudgment.model_validate_json(raw)
        allowed_facts = set(packet.fact_ids)
        allowed_evidence = set(packet.evidence_ids)
        allowed_claims = set(packet.claim_ids)
        if not set(judgment.cited_fact_ids) <= allowed_facts:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Model cited facts outside its context packet.",
            )
        if not set(judgment.cited_evidence_ids) <= allowed_evidence:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Model cited evidence outside its context packet.",
            )
        if not set(judgment.cited_claim_ids) <= allowed_claims:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Model cited claims outside its context packet.",
            )
        status = ObligationStatus(judgment.status)
        if status in {ObligationStatus.PROVEN, ObligationStatus.DISPROVEN} and not (
            judgment.cited_fact_ids
            or judgment.cited_evidence_ids
            or judgment.cited_claim_ids
        ):
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Model conclusion has no cited packet evidence.",
            )
        if status in {ObligationStatus.UNKNOWN, ObligationStatus.BLOCKED}:
            return Resolution(
                status=status,
                blocked_reason="; ".join(judgment.missing_context) or judgment.conclusion,
            )
        supports = status == ObligationStatus.PROVEN
        claim = Claim(
            snapshot_id=candidate.snapshot_id,
            predicate=(
                obligation.predicate
                if supports
                else f"counterexample_to:{obligation.predicate}"
            ),
            subject=candidate.logical_id,
            object=judgment.conclusion,
            status=ObligationStatus.PROVEN,
            scope={"obligation_id": obligation.logical_id},
        )
        evidence = Evidence(
            snapshot_id=candidate.snapshot_id,
            kind="bounded_model_judgment",
            observations=[
                {
                    "conclusion": judgment.conclusion,
                    "cited_fact_ids": judgment.cited_fact_ids,
                    "cited_evidence_ids": judgment.cited_evidence_ids,
                    "cited_claim_ids": judgment.cited_claim_ids,
                    "limitations": judgment.limitations,
                }
            ],
            supports=[claim.logical_id] if supports else [],
            contradicts=[] if supports else [obligation.logical_id],
            provenance=Provenance(
                producer="bounded-model-resolver",
                model=str(getattr(self.llm, "model_name", "")),
                provider=str(getattr(self.llm, "provider_name", "")),
                context_packet_id=packet.id,
            ),
            reliability={
                "method": "constrained_model_judgment",
                "packet_completeness_unknowns": packet.completeness.has_unknowns,
            },
        )
        claim_payload = claim.model_dump(mode="python")
        claim_payload.update({"id": "", "supporting_evidence_ids": [evidence.id]})
        claim = Claim.model_validate(claim_payload)
        derivation = Derivation(
            snapshot_id=candidate.snapshot_id,
            rule="bounded-model-adjudication",
            premise_ids=[
                *judgment.cited_fact_ids,
                *judgment.cited_evidence_ids,
                *judgment.cited_claim_ids,
            ],
            conclusion_claim_ids=[claim.logical_id],
            limitations=judgment.limitations,
            validator="model",
            context_packet_id=packet.id,
        )
        return Resolution(
            status=status,
            claims=[claim],
            evidence=[evidence],
            derivations=[derivation],
        )


def apply_resolution(
    graph: ProofGraph,
    store: ProofStore,
    obligation: Obligation,
    resolution: Resolution,
) -> Obligation:
    """Persist a resolver result and update the authoritative obligation."""

    for evidence in resolution.evidence:
        graph.add_evidence(evidence)
    for claim in resolution.claims:
        graph.add_claim(claim)
    for derivation in resolution.derivations:
        store.append(derivation)
    supporting = (
        [claim.logical_id for claim in resolution.claims]
        if resolution.status == ObligationStatus.PROVEN
        else []
    )
    contradicting = (
        [claim.logical_id for claim in resolution.claims]
        if resolution.status == ObligationStatus.DISPROVEN
        else []
    )
    return graph.resolve_obligation(
        obligation.logical_id,
        resolution.status,
        supporting_claim_ids=supporting,
        contradicting_claim_ids=contradicting,
        blocked_reason=resolution.blocked_reason,
    )


def _fact_text(fact: Fact) -> str:
    return str(
        fact.properties.get("expression")
        or fact.properties.get("excerpt")
        or fact.properties.get("rhs")
        or fact.object
        or ""
    )


def _same_function(left: Fact, right: Fact) -> bool:
    if left.location is None or right.location is None:
        return False
    return (
        left.location.file == right.location.file
        and bool(left.location.function)
        and left.location.function == right.location.function
    )


def _line(fact: Fact) -> int:
    return fact.location.line if fact.location else 0
