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
    cited_assumption_ids: list[str] = Field(default_factory=list)
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
            "attacker_reaches_memory_operation": self._reachability,
            "incorrect_state_reaches_memory_access": self._memory_access,
            "object_bounds_established": self._object_bounds,
            "access_exceeds_live_object_bounds": self._bounds_violation,
            "parser_boundary_is_established": self._parser_boundary,
            "cursor_plus_length_exceeds_validated_boundary": self._parser_violation,
            "actual_enforcement_path_established": self._authorization_enforcement,
            "unauthorized_operation_is_permitted": self._authorization_bypass,
            "object_lifetime_established": self._object_lifetime,
            "attacker_reaches_stale_use": self._reachability,
            "dereference_occurs_outside_live_interval": self._stale_use,
            "expected_transition_graph_established": self._state_graph,
            "attacker_reaches_illegal_transition": self._illegal_transition,
            "required_cryptographic_property_established": self._crypto_property,
            "cryptographic_precondition_is_violated": self._crypto_precondition,
            "required_structural_encoding_is_absent": self._encoding_absent,
            "shared_state_or_resource_limit_established": self._shared_invariant,
            "bounded_execution_violates_shared_or_resource_invariant": (self._shared_violation),
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
            and any(sink in str(fact.properties.get("lhs", "")) for sink in candidate.state_sinks)
        ]
        if not assignments:
            return None
        return self._supported(
            candidate,
            obligation,
            assignments,
            conclusion=(
                "A live identifier is represented in the same storage used by the reserved value."
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
        if completeness.items.get("types") and completeness.items["types"].status in {
            "unresolved",
            "not_available",
        }:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Type-domain completeness is insufficient.",
            )
        return self._supported(
            candidate,
            obligation,
            [*assignments, *sentinel_facts, *counters, *typed_sources],
            conclusion=(
                "The extracted identifier range includes the reserved representation value."
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
            and any(sink in str(fact.properties.get("lhs", "")) for sink in candidate.state_sinks)
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
                control_effect or re.search(r"\b(?:return|raise|throw|goto|break)\b", expression)
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
        accesses = [fact for fact in facts if fact.kind in {"memory_access", "memory_write"}]
        if not accesses:
            return None
        return self._supported(
            candidate,
            obligation,
            accesses,
            conclusion="The candidate state reaches a syntactic memory access.",
            evidence_kind="static_memory_access",
        )

    def _reachability(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        explicit = [fact for fact in facts if fact.kind == "reachability"]
        reachable = [
            fact
            for fact in explicit
            if fact.object is True or fact.properties.get("reachable") is True
        ]
        if reachable:
            return self._supported(
                candidate,
                obligation,
                reachable,
                conclusion="An extracted entry-to-operation path is reachable.",
                evidence_kind="static_reachability_path",
            )
        unreachable = [
            fact
            for fact in explicit
            if fact.object is False or fact.properties.get("reachable") is False
        ]
        if unreachable:
            indirect = completeness.items.get("indirect_calls")
            direct = completeness.items.get("direct_calls")
            if (
                indirect is not None
                and direct is not None
                and indirect.status == CompletenessStatus.COMPLETE
                and direct.status == CompletenessStatus.COMPLETE
            ):
                return self._contradicted(
                    candidate,
                    obligation,
                    unreachable,
                    conclusion="Complete callgraph coverage proves the operation unreachable.",
                    evidence_kind="complete_unreachability_proof",
                )
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason=(
                    "A direct path was not found, but unresolved indirect calls prevent an "
                    "unreachability conclusion."
                ),
            )
        paths = [fact for fact in facts if fact.kind == "taint_path"]
        if paths:
            return self._supported(
                candidate,
                obligation,
                paths,
                conclusion="An extracted attacker-controlled path reaches the operation.",
                evidence_kind="taint_reachability_path",
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="No attacker entry-to-memory-operation path is present in the packet.",
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
            conclusion="A normalized allocation fact establishes the candidate object extent.",
            evidence_kind="static_allocation_extent",
        )

    def _bounds_violation(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        allocations = [fact for fact in facts if fact.kind == "allocation"]
        accesses = [fact for fact in facts if fact.kind == "memory_write"]
        guards = [fact for fact in facts if fact.kind == "guard"]
        if not allocations or not accesses:
            return None
        for allocation in allocations:
            for access in accesses:
                if not _same_target(allocation, access) or not _same_function(allocation, access):
                    continue
                preventing = [
                    guard
                    for guard in guards
                    if _same_function(guard, access)
                    and _line(guard) < _line(access)
                    and _guard_prevents_extent(guard, allocation, access)
                ]
                if preventing:
                    return self._contradicted(
                        candidate,
                        obligation,
                        preventing,
                        conclusion=(
                            "A preceding rejecting guard constrains the access extent to the "
                            "allocation extent."
                        ),
                        evidence_kind="dominating_spatial_guard",
                    )
                allocation_extent = _constant_extent(str(allocation.properties.get("extent") or ""))
                access_extent = _constant_extent(str(access.properties.get("extent") or ""))
                access_offset = _constant_extent(str(access.properties.get("offset") or "0"))
                if (
                    allocation_extent is not None
                    and access_extent is not None
                    and access_offset is not None
                ):
                    if access_offset + access_extent > allocation_extent:
                        return self._supported(
                            candidate,
                            obligation,
                            [allocation, access],
                            conclusion=(
                                "The normalized constant access interval exceeds the allocation "
                                "extent."
                            ),
                            evidence_kind="static_extent_violation",
                        )
                    return self._contradicted(
                        candidate,
                        obligation,
                        [allocation, access],
                        conclusion=(
                            "The normalized constant access interval is contained in the "
                            "allocation extent."
                        ),
                        evidence_kind="static_extent_containment",
                    )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason=(
                "Allocation and access extents are normalized, but a range proof is still required."
            ),
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

    def _parser_boundary(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        explicit = [fact for fact in facts if fact.kind == "parser_boundary"]
        if explicit:
            return self._supported(
                candidate,
                obligation,
                explicit,
                conclusion="An analyzer fact identifies the parser's validated boundary.",
                evidence_kind="static_parser_boundary",
            )
        guards = [
            fact
            for fact in facts
            if fact.kind == "guard"
            and (
                set(fact.properties.get("guarded_symbols") or []) & set(candidate.source_symbols)
                or any(symbol in _fact_text(fact) for symbol in candidate.source_symbols)
            )
        ]
        if not guards:
            return None
        return self._supported(
            candidate,
            obligation,
            guards,
            conclusion="A parser guard names the candidate cursor or extent boundary.",
            evidence_kind="static_parser_boundary",
        )

    def _parser_violation(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        explicit = [fact for fact in facts if fact.kind == "range_violation"]
        violating = [fact for fact in explicit if fact.properties.get("violated") is True]
        safe = [fact for fact in explicit if fact.properties.get("violated") is False]
        if violating:
            return self._supported(
                candidate,
                obligation,
                violating,
                conclusion="Analyzer range evidence proves the parser interval exceeds its boundary.",
                evidence_kind="static_parser_range_violation",
            )
        if safe:
            return self._contradicted(
                candidate,
                obligation,
                safe,
                conclusion="Analyzer range evidence proves the parser interval is contained.",
                evidence_kind="static_parser_range_containment",
            )
        accesses = [fact for fact in facts if fact.kind in {"memory_access", "memory_write"}]
        guards = [
            fact
            for fact in facts
            if fact.kind == "guard"
            and bool(fact.properties.get("rejecting"))
            and (
                fact.properties.get("range_complete") is True
                or fact.properties.get("effective") is True
            )
            and any(symbol in _fact_text(fact) for symbol in candidate.source_symbols)
            and any(
                _same_function(fact, access) and _line(fact) < _line(access) for access in accesses
            )
        ]
        dominators = completeness.items.get("control_dominators")
        if guards and dominators and dominators.status == CompletenessStatus.COMPLETE:
            return self._contradicted(
                candidate,
                obligation,
                guards,
                conclusion="A dominating rejecting parser guard contains the candidate interval.",
                evidence_kind="dominating_parser_boundary_guard",
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="A parser boundary is present, but no complete range proof is available.",
        )

    def _authorization_enforcement(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        guards = _authorization_guards(facts)
        if not guards:
            return None
        authorization_paths = completeness.items.get("authorization_paths")
        explicit_complete = any(
            fact.kind == "authorization_policy"
            and fact.properties.get("enforcement_complete") is True
            for fact in guards
        )
        if explicit_complete or (
            authorization_paths and authorization_paths.status == CompletenessStatus.COMPLETE
        ):
            return self._supported(
                candidate,
                obligation,
                guards,
                conclusion="Complete enforcement coverage identifies the applicable policy checks.",
                evidence_kind="complete_authorization_enforcement",
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="Policy checks exist, but indirect enforcement paths remain incomplete.",
        )

    def _authorization_bypass(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        results = [fact for fact in facts if fact.kind == "authorization_result"]
        permitted = [fact for fact in results if fact.properties.get("unauthorized") is True]
        denied = [fact for fact in results if fact.properties.get("unauthorized") is False]
        if permitted:
            return self._supported(
                candidate,
                obligation,
                permitted,
                conclusion="A policy differential permits an out-of-policy principal.",
                evidence_kind="static_authorization_bypass",
            )
        if denied:
            return self._contradicted(
                candidate,
                obligation,
                denied,
                conclusion="A policy differential denies the out-of-policy principal.",
                evidence_kind="static_authorization_denial",
            )
        operations = [fact for fact in facts if fact.kind == "call"]
        guards = [
            guard
            for guard in _authorization_guards(facts)
            if any(
                _same_function(guard, operation) and _line(guard) < _line(operation)
                for operation in operations
            )
        ]
        dominators = completeness.items.get("control_dominators")
        effective_policy = any(
            fact.kind == "authorization_policy"
            and fact.properties.get("dominates") is True
            and fact.properties.get("denies_unauthorized") is True
            for fact in guards
        )
        rejecting_guards = [
            fact
            for fact in guards
            if fact.kind == "guard" and fact.properties.get("rejecting") is True
        ]
        if effective_policy or (
            rejecting_guards and dominators and dominators.status == CompletenessStatus.COMPLETE
        ):
            return self._contradicted(
                candidate,
                obligation,
                guards if effective_policy else rejecting_guards,
                conclusion="A dominating authorization check denies the suspected bypass.",
                evidence_kind="dominating_authorization_guard",
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="No allowed-versus-denied authorization differential is available.",
        )

    def _object_lifetime(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        explicit = [fact for fact in facts if fact.kind == "lifetime_relation"]
        releases = [fact for fact in facts if _is_release(fact)]
        accesses = [
            fact
            for fact in facts
            if fact.kind in {"memory_access", "memory_write", "call"} and not _is_release(fact)
        ]
        if explicit or (releases and accesses):
            return self._supported(
                candidate,
                obligation,
                [*explicit, *releases, *accesses],
                conclusion="Release and subsequent-use events establish the candidate lifetime.",
                evidence_kind="static_lifetime_events",
            )
        return None

    def _stale_use(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        explicit = [fact for fact in facts if fact.kind == "lifetime_relation"]
        outside = [
            fact for fact in explicit if fact.properties.get("outside_live_interval") is True
        ]
        live = [fact for fact in explicit if fact.properties.get("outside_live_interval") is False]
        if outside:
            return self._supported(
                candidate,
                obligation,
                outside,
                conclusion="Lifetime analysis proves a dereference outside the live interval.",
                evidence_kind="static_stale_use",
            )
        if live:
            return self._contradicted(
                candidate,
                obligation,
                live,
                conclusion="Lifetime analysis proves the object is live at the dereference.",
                evidence_kind="static_live_interval",
            )
        releases = [fact for fact in facts if _is_release(fact)]
        reacquires = [fact for fact in facts if _is_reacquire(fact)]
        accesses = [
            fact
            for fact in facts
            if fact.kind in {"memory_access", "memory_write", "call"}
            and not _is_release(fact)
            and not _is_reacquire(fact)
        ]
        for release in releases:
            for access in accesses:
                if not _same_function(release, access) or _line(release) >= _line(access):
                    continue
                restored = [
                    fact
                    for fact in reacquires
                    if _same_function(release, fact)
                    and _line(release) < _line(fact) < _line(access)
                    and _same_object_event(release, fact, access)
                ]
                lifetime = completeness.items.get("lifetime_analysis")
                if restored and lifetime and lifetime.status == CompletenessStatus.COMPLETE:
                    return self._contradicted(
                        candidate,
                        obligation,
                        restored,
                        conclusion="Complete lifetime analysis finds a reacquisition before use.",
                        evidence_kind="static_lifetime_reacquisition",
                    )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="The release/use order is suspicious, but alias-aware lifetime proof is incomplete.",
        )

    def _state_graph(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        models = [fact for fact in facts if fact.kind == "state_model"]
        if not models:
            return None
        return self._supported(
            candidate,
            obligation,
            models,
            conclusion="A bounded state model enumerates permitted transitions.",
            evidence_kind="static_state_model",
        )

    def _illegal_transition(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        transitions = [fact for fact in facts if fact.kind == "state_transition"]
        illegal = [fact for fact in transitions if fact.properties.get("permitted") is False]
        permitted = [fact for fact in transitions if fact.properties.get("permitted") is True]
        if illegal:
            return self._supported(
                candidate,
                obligation,
                illegal,
                conclusion="The bounded state model reaches a transition marked prohibited.",
                evidence_kind="static_illegal_transition",
            )
        state_models = completeness.items.get("state_models")
        permitted_analysis_complete = any(
            fact.properties.get("analysis_complete") is True for fact in permitted
        ) or (
            permitted
            and state_models is not None
            and state_models.status == CompletenessStatus.COMPLETE
        )
        if permitted_analysis_complete:
            return self._contradicted(
                candidate,
                obligation,
                permitted,
                conclusion="The bounded state model permits the candidate transition.",
                evidence_kind="static_permitted_transition",
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="No bounded transition result is available.",
        )

    def _crypto_property(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        contracts = [fact for fact in facts if fact.kind == "crypto_contract"]
        if not contracts:
            return None
        return self._supported(
            candidate,
            obligation,
            contracts,
            conclusion="An API or construction contract names the required cryptographic property.",
            evidence_kind="static_cryptographic_contract",
        )

    def _crypto_precondition(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        conditions = [fact for fact in facts if fact.kind == "crypto_precondition"]
        violated = [fact for fact in conditions if fact.properties.get("violated") is True]
        satisfied = [fact for fact in conditions if fact.properties.get("violated") is False]
        if violated:
            return self._supported(
                candidate,
                obligation,
                violated,
                conclusion="Contract analysis identifies a violated cryptographic precondition.",
                evidence_kind="static_cryptographic_precondition_violation",
            )
        if satisfied:
            return self._contradicted(
                candidate,
                obligation,
                satisfied,
                conclusion="Contract analysis proves the cryptographic precondition is satisfied.",
                evidence_kind="static_cryptographic_precondition_satisfied",
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="A cryptographic API marker alone does not prove a property violation.",
        )

    def _encoding_absent(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        explicit = [fact for fact in facts if fact.kind == "encoding"]
        effective = [fact for fact in explicit if fact.properties.get("effective") is True]
        absent = [fact for fact in explicit if fact.properties.get("effective") is False]
        encoder_calls = [fact for fact in facts if _is_encoder(fact)]
        if effective:
            return self._contradicted(
                candidate,
                obligation,
                effective,
                conclusion="Context-correct encoding or parameterization protects the boundary.",
                evidence_kind="static_structural_encoding",
            )
        if absent:
            return self._supported(
                candidate,
                obligation,
                absent,
                conclusion="Boundary analysis explicitly reports missing structural encoding.",
                evidence_kind="static_missing_structural_encoding",
            )
        dependencies = completeness.items.get("data_dependencies")
        if dependencies is None or dependencies.status != CompletenessStatus.COMPLETE:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Encoding absence cannot be inferred from incomplete data dependencies.",
            )
        marker_note = (
            " An encoder-like call exists but its context effectiveness is unproven."
            if encoder_calls
            else ""
        )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="No explicit context-correct encoding result is available."
            + marker_note,
        )

    def _shared_invariant(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        del completeness
        relevant = [
            fact
            for fact in facts
            if fact.kind
            in {"resource_limit", "synchronization", "allocation", "loop", "memory_write"}
            or (fact.kind == "call" and _is_thread_or_sync(fact))
        ]
        if not relevant:
            return None
        return self._supported(
            candidate,
            obligation,
            relevant,
            conclusion="Extracted facts identify the shared state or resource under analysis.",
            evidence_kind="static_shared_or_resource_invariant",
        )

    def _shared_violation(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> Resolution | None:
        results = [
            fact for fact in facts if fact.kind in {"concurrency_violation", "resource_violation"}
        ]
        violated = [fact for fact in results if fact.properties.get("violated") is True]
        safe = [fact for fact in results if fact.properties.get("violated") is False]
        protections = [
            fact
            for fact in facts
            if fact.kind in {"resource_limit", "synchronization"}
            and fact.properties.get("effective") is True
        ]
        if violated:
            return self._supported(
                candidate,
                obligation,
                violated,
                conclusion="A bounded schedule or load violates the shared/resource invariant.",
                evidence_kind="static_shared_or_resource_violation",
            )
        if safe or protections:
            return self._contradicted(
                candidate,
                obligation,
                [*safe, *protections],
                conclusion="A synchronization or resource bound prevents the suspected violation.",
                evidence_kind="static_shared_or_resource_protection",
            )
        analysis_keys = (
            "concurrency_analysis"
            if "concurrency_safety" in candidate.invariant_families
            else "resource_bounds"
        )
        analysis = completeness.items.get(analysis_keys)
        if analysis is None or analysis.status != CompletenessStatus.COMPLETE:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason=(
                    "A synchronization call or declared limit is not proof that it covers "
                    "the suspected violation; complete effectiveness analysis is required."
                ),
            )
        return Resolution(
            status=ObligationStatus.BLOCKED,
            blocked_reason="A race detector, schedule perturbation, or bounded load result is required.",
        )

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
            obligation.predicate if supports else f"counterexample_to:{obligation.predicate}"
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
                    "location": (fact.location.model_dump(mode="json") if fact.location else None),
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
every fact, evidence item, prior claim, and assumption used by its supplied
ID. Assumptions remain labeled assumptions and cannot prove themselves. Do
not infer remote reachability, exploitability, or memory corruption from a
crash alone. Return §blocked§ when named missing context is required, and
§conflicting_evidence§ when supplied facts conflict."""

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
        allowed_assumptions = set(packet.assumption_ids)
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
        if not set(judgment.cited_assumption_ids) <= allowed_assumptions:
            return Resolution(
                status=ObligationStatus.BLOCKED,
                blocked_reason="Model cited assumptions outside its context packet.",
            )
        status = ObligationStatus(judgment.status)
        if status in {ObligationStatus.PROVEN, ObligationStatus.DISPROVEN}:
            has_support = bool(
                judgment.cited_fact_ids or judgment.cited_evidence_ids or judgment.cited_claim_ids
            )
            if not has_support:
                reason = (
                    "Assumptions alone cannot resolve a proof obligation."
                    if judgment.cited_assumption_ids
                    else "Model conclusion has no cited packet evidence."
                )
                return Resolution(
                    status=ObligationStatus.BLOCKED,
                    blocked_reason=reason,
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
                obligation.predicate if supports else f"counterexample_to:{obligation.predicate}"
            ),
            subject=candidate.logical_id,
            object=judgment.conclusion,
            status=ObligationStatus.PROVEN,
            scope={"obligation_id": obligation.logical_id},
            assumption_ids=judgment.cited_assumption_ids,
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
                    "cited_assumption_ids": judgment.cited_assumption_ids,
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
                *judgment.cited_assumption_ids,
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


def _same_target(allocation: Fact, access: Fact) -> bool:
    allocated = re.sub(r"\s+", "", str(allocation.properties.get("target") or ""))
    accessed = re.sub(r"\s+", "", str(access.properties.get("target") or ""))
    return bool(allocated and accessed and allocated.lstrip("&") == accessed.lstrip("&"))


def _guard_prevents_extent(guard: Fact, allocation: Fact, access: Fact) -> bool:
    if not bool(guard.properties.get("rejecting")):
        return False
    allocation_symbols = set(allocation.properties.get("extent_symbols") or [])
    access_symbols = set(access.properties.get("extent_symbols") or [])
    if not allocation_symbols or not access_symbols:
        return False
    comparisons = guard.properties.get("comparisons")
    if not isinstance(comparisons, list):
        return False
    for raw in comparisons:
        if not isinstance(raw, dict):
            continue
        left = str(raw.get("left") or "")
        right = str(raw.get("right") or "")
        operator = str(raw.get("operator") or "")
        if left in access_symbols and right in allocation_symbols and operator in {">", ">="}:
            return True
        if right in access_symbols and left in allocation_symbols and operator in {"<", "<="}:
            return True
    return False


def _constant_extent(expression: str) -> int | None:
    value = expression.strip()
    if not value:
        return None
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+", value):
        return int(value, 0)
    product = re.fullmatch(
        r"\(?\s*(0[xX][0-9A-Fa-f]+|\d+)\s*\)?\s*\*\s*"
        r"\(?\s*(0[xX][0-9A-Fa-f]+|\d+)\s*\)?",
        value,
    )
    if product:
        return int(product.group(1), 0) * int(product.group(2), 0)
    return None


def _authorization_guards(facts: list[Fact]) -> list[Fact]:
    markers = ("auth", "permit", "policy", "role", "owner", "principal", "tenant")
    return [
        fact
        for fact in facts
        if fact.kind == "authorization_policy"
        or (fact.kind == "guard" and any(marker in _fact_text(fact).lower() for marker in markers))
    ]


def _callee(fact: Fact) -> str:
    return str(fact.properties.get("callee") or "").lower().split(".")[-1]


def _is_release(fact: Fact) -> bool:
    return fact.kind == "call" and _callee(fact) in {
        "close",
        "delete",
        "drop",
        "free",
        "release",
        "unref",
    }


def _is_reacquire(fact: Fact) -> bool:
    if fact.kind == "call" and _callee(fact) in {
        "acquire",
        "alloc",
        "clone",
        "malloc",
        "realloc",
        "ref",
        "retain",
    }:
        return True
    return fact.kind == "assignment" and bool(
        re.search(r"\b(?:new|malloc|calloc|realloc|clone|retain|acquire)\b", _fact_text(fact))
    )


def _event_symbols(fact: Fact) -> set[str]:
    values = fact.properties.get("arguments")
    arguments = values if isinstance(values, list) else []
    text = " ".join(
        [
            *[str(value) for value in arguments],
            str(fact.properties.get("target") or ""),
            str(fact.properties.get("lhs") or ""),
            _fact_text(fact),
        ]
    )
    symbols = set(re.findall(r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*", text))
    return {
        symbol
        for symbol in symbols
        if symbol.lower()
        not in {
            "acquire",
            "alloc",
            "calloc",
            "clone",
            "close",
            "delete",
            "drop",
            "free",
            "malloc",
            "realloc",
            "ref",
            "release",
            "retain",
            "unref",
        }
    }


def _same_object_event(release: Fact, reacquire: Fact, access: Fact) -> bool:
    released = _event_symbols(release)
    return bool(released & _event_symbols(reacquire) & _event_symbols(access))


def _is_encoder(fact: Fact) -> bool:
    return fact.kind == "call" and any(
        marker in _callee(fact)
        for marker in ("escape", "parameter", "quote", "sanitize", "shellescape")
    )


def _is_synchronization(fact: Fact) -> bool:
    return fact.kind == "call" and any(
        marker in _callee(fact)
        for marker in ("atomic", "lock", "mutex", "semaphore", "synchronized")
    )


def _is_thread_or_sync(fact: Fact) -> bool:
    return fact.kind == "call" and (
        _is_synchronization(fact)
        or any(marker in _callee(fact) for marker in ("pthread_create", "spawn", "thread"))
    )
