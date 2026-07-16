"""Versioned, composable vulnerability proof plans."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Candidate, Obligation


@dataclass(frozen=True)
class ObligationTemplate:
    key: str
    predicate: str
    description: str
    dependencies: tuple[str, ...] = ()
    available_actions: tuple[str, ...] = ()
    mandatory: bool = True
    decisive_rejection: bool = False


@dataclass(frozen=True)
class ProofPlan:
    id: str
    invariant_families: frozenset[str]
    obligations: tuple[ObligationTemplate, ...]
    decisive_evidence_kinds: frozenset[str] = frozenset()


REPRESENTATION_DOMAIN_PLAN = ProofPlan(
    id="representation-domain-collision-v1",
    invariant_families=frozenset({"representation_domain_safety"}),
    obligations=(
        ObligationTemplate(
            "reserved_value",
            "reserved_sentinel_established",
            "A value has a distinct reserved sentinel meaning.",
            available_actions=("fact_query", "bounded_model_judgment"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "live_domain",
            "live_identifier_domain_established",
            "Live identifiers use the same representation domain.",
            available_actions=("type_query", "range_analysis"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "domain_overlap",
            "live_domain_overlaps_reserved_value",
            "A reachable live identifier can equal the sentinel value.",
            dependencies=("reserved_value", "live_domain"),
            available_actions=("range_analysis", "symbolic_execution"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "attacker_influence",
            "attacker_controls_identifier_progression",
            "Untrusted input can influence progression into the overlap.",
            available_actions=("reachability_query", "taint_query"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "no_guard",
            "no_effective_upper_bound_guard",
            "No dominating guard prevents the reserved value.",
            dependencies=("domain_overlap",),
            available_actions=("guard_enumeration", "bounded_model_judgment"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "consumer_ambiguity",
            "consumer_cannot_distinguish_live_id_from_sentinel",
            "At least one consumer gives the colliding values the same meaning.",
            dependencies=("domain_overlap", "no_guard"),
            available_actions=("comparison_query", "bounded_model_judgment"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "semantic_decision",
            "collision_changes_security_relevant_state",
            "The ambiguity changes a security-relevant state decision.",
            dependencies=("consumer_ambiguity",),
            available_actions=("slice_query", "bounded_model_judgment"),
            decisive_rejection=True,
        ),
    ),
)

MEMORY_WRITE_PLAN = ProofPlan(
    id="memory-write-v1",
    invariant_families=frozenset({"spatial_safety"}),
    obligations=(
        ObligationTemplate(
            "attacker_reachability",
            "attacker_reaches_memory_operation",
            "An attacker-controlled entry path reaches the candidate memory operation.",
            available_actions=("reachability_query", "taint_query"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "access_reached",
            "incorrect_state_reaches_memory_access",
            "The suspected state or extent reaches a memory access.",
            dependencies=(
                "attacker_reachability",
                "representation-domain-collision-v1:semantic_decision",
            ),
            available_actions=("slice_query", "reachability_query"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "object_bounds",
            "object_bounds_established",
            "The live object's valid address or extent bounds are known.",
            available_actions=("type_query", "allocation_query"),
        ),
        ObligationTemplate(
            "bounds_violation",
            "access_exceeds_live_object_bounds",
            "The selected address or extent is outside the live object.",
            dependencies=("access_reached", "object_bounds"),
            available_actions=("range_analysis", "symbolic_execution"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "trigger",
            "concrete_trigger_satisfies_path",
            "A concrete or symbolic witness satisfies the path constraints.",
            dependencies=("bounds_violation",),
            available_actions=("harness", "fuzz", "symbolic_execution"),
        ),
        ObligationTemplate(
            "realistic_configuration",
            "behavior_occurs_in_realistic_configuration",
            "The affected path exists in a realistic build and deployment.",
            available_actions=("configuration_query", "integration_test"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "runtime_confirmation",
            "runtime_confirms_unsafe_memory_access",
            "Sanitizer or equivalently strong evidence confirms the access.",
            dependencies=("trigger", "realistic_configuration"),
            available_actions=("sanitizer_run", "integration_test"),
        ),
        ObligationTemplate(
            "security_boundary",
            "unsafe_access_crosses_security_boundary",
            "The behavior violates a protected property in the threat model.",
            dependencies=("runtime_confirmation",),
            available_actions=("threat_model_query", "bounded_model_judgment"),
        ),
    ),
    decisive_evidence_kinds=frozenset(
        {"sanitizer_crash", "symbolic_memory_violation", "debugger_memory_violation"}
    ),
)

PARSER_INTEGER_PLAN = ProofPlan(
    id="parser-integer-domain-v2",
    invariant_families=frozenset({"parser_safety"}),
    obligations=(
        ObligationTemplate(
            "validated_boundary",
            "parser_boundary_is_established",
            "The parser's validated boundary is known.",
            available_actions=("fact_query", "range_analysis"),
        ),
        ObligationTemplate(
            "requested_extent",
            "attacker_controls_requested_extent",
            "Untrusted input controls the cursor or requested length.",
            available_actions=("taint_query", "reachability_query"),
        ),
        ObligationTemplate(
            "boundary_violation",
            "cursor_plus_length_exceeds_validated_boundary",
            "The parser can operate beyond its validated boundary.",
            dependencies=("validated_boundary", "requested_extent"),
            available_actions=("range_analysis", "symbolic_execution"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "trigger",
            "concrete_parser_input_satisfies_boundary_violation",
            "A concrete or symbolic parser input satisfies the violating path.",
            dependencies=("boundary_violation",),
            available_actions=("fuzz", "symbolic_execution", "protocol_replay"),
        ),
        ObligationTemplate(
            "runtime",
            "runtime_confirms_parser_boundary_violation",
            "A bounded runtime or symbolic backend confirms the parser violation.",
            dependencies=("trigger",),
            available_actions=("sanitizer_run", "symbolic_execution", "protocol_replay"),
        ),
        ObligationTemplate(
            "security_boundary",
            "parser_violation_crosses_security_boundary",
            "The parser violation breaks a protected property in the threat model.",
            dependencies=("runtime",),
            available_actions=("threat_model_query", "bounded_model_judgment"),
        ),
    ),
    decisive_evidence_kinds=frozenset(
        {"sanitizer_crash", "symbolic_memory_violation", "protocol_transition_violation"}
    ),
)

AUTHORIZATION_PLAN = ProofPlan(
    id="authorization-boundary-v2",
    invariant_families=frozenset({"authority_safety"}),
    obligations=(
        ObligationTemplate(
            "principal",
            "attacker_principal_established",
            "The requesting principal and credentials are known.",
            available_actions=("threat_model_query",),
        ),
        ObligationTemplate(
            "policy",
            "expected_authorization_policy_established",
            "The expected policy for the protected operation is explicit.",
            available_actions=("policy_query", "bounded_model_judgment"),
        ),
        ObligationTemplate(
            "enforcement",
            "actual_enforcement_path_established",
            "Every applicable enforcement path is enumerated.",
            available_actions=("reachability_query", "guard_enumeration"),
        ),
        ObligationTemplate(
            "bypass",
            "unauthorized_operation_is_permitted",
            "A principal outside policy can perform the protected operation.",
            dependencies=("principal", "policy", "enforcement"),
            available_actions=("differential_test",),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "capability",
            "unauthorized_capability_is_gained",
            "The policy bypass grants a capability over a protected asset.",
            dependencies=("bypass",),
            available_actions=("differential_test", "threat_model_query"),
        ),
    ),
    decisive_evidence_kinds=frozenset({"authorization_differential"}),
)

TEMPORAL_MEMORY_PLAN = ProofPlan(
    id="temporal-memory-safety-v2",
    invariant_families=frozenset({"temporal_safety"}),
    obligations=(
        ObligationTemplate(
            "lifetime",
            "object_lifetime_established",
            "Allocation, ownership, release, and alias lifetime are known.",
            available_actions=("lifetime_query",),
        ),
        ObligationTemplate(
            "attacker_reachability",
            "attacker_reaches_stale_use",
            "An attacker-controlled path reaches the suspected stale use.",
            available_actions=("taint_query", "reachability_query"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "stale_use",
            "dereference_occurs_outside_live_interval",
            "A reachable dereference occurs after release or before initialization.",
            dependencies=("lifetime", "attacker_reachability"),
            available_actions=("race_detector", "symbolic_execution"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "runtime",
            "runtime_confirms_temporal_violation",
            "A memory tool confirms the temporal violation.",
            dependencies=("stale_use",),
            available_actions=("sanitizer_run", "race_detector"),
        ),
        ObligationTemplate(
            "security_boundary",
            "temporal_violation_crosses_security_boundary",
            "The temporal violation breaks a protected property in the threat model.",
            dependencies=("runtime",),
            available_actions=("threat_model_query", "bounded_model_judgment"),
        ),
    ),
    decisive_evidence_kinds=frozenset({"sanitizer_uaf", "race_detector_violation"}),
)

STATE_MACHINE_PLAN = ProofPlan(
    id="state-machine-safety-v2",
    invariant_families=frozenset({"state_machine_safety"}),
    obligations=(
        ObligationTemplate(
            "expected_graph",
            "expected_transition_graph_established",
            "Permitted transitions and authenticated states are known.",
            available_actions=("state_model_query",),
        ),
        ObligationTemplate(
            "illegal_transition",
            "attacker_reaches_illegal_transition",
            "A bounded input sequence reaches a prohibited transition.",
            dependencies=("expected_graph",),
            available_actions=("model_check", "protocol_replay"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "consequence",
            "illegal_transition_has_security_consequence",
            "The inconsistent state crosses a security boundary.",
            dependencies=("illegal_transition",),
            available_actions=("differential_test", "bounded_model_judgment"),
        ),
    ),
    decisive_evidence_kinds=frozenset({"protocol_transition_violation"}),
)

CRYPTOGRAPHIC_PLAN = ProofPlan(
    id="cryptographic-property-v2",
    invariant_families=frozenset({"cryptographic_safety"}),
    obligations=(
        ObligationTemplate(
            "property",
            "required_cryptographic_property_established",
            "The required secrecy, authenticity, uniqueness, or separation is known.",
            available_actions=("api_contract_query",),
        ),
        ObligationTemplate(
            "precondition",
            "cryptographic_precondition_is_violated",
            "A construction or API precondition is violated.",
            dependencies=("property",),
            available_actions=("fact_query", "bounded_model_judgment"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "attacker_observation",
            "attacker_observes_or_controls_relevant_values",
            "The threat model exposes the violation to an attacker.",
            available_actions=("taint_query", "threat_model_query"),
        ),
        ObligationTemplate(
            "consequence",
            "cryptographic_violation_has_concrete_consequence",
            "A distinguishing, forgery, reuse, or disclosure consequence exists.",
            dependencies=("precondition", "attacker_observation"),
            available_actions=("differential_test", "symbolic_execution"),
        ),
    ),
    decisive_evidence_kinds=frozenset({"cryptographic_differential"}),
)

INJECTION_BOUNDARY_PLAN = ProofPlan(
    id="injection-boundary-v2",
    invariant_families=frozenset({"injection_safety"}),
    obligations=(
        ObligationTemplate(
            "taint",
            "attacker_data_reaches_interpreter_boundary",
            "Untrusted data reaches a command, query, path, or deserializer.",
            available_actions=("taint_query",),
        ),
        ObligationTemplate(
            "encoding",
            "required_structural_encoding_is_absent",
            "The boundary lacks parameterization or context-correct encoding.",
            dependencies=("taint",),
            available_actions=("guard_enumeration", "bounded_model_judgment"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "differential",
            "input_changes_interpreted_structure",
            "A differential test proves that input changes interpreted structure.",
            dependencies=("encoding",),
            available_actions=("differential_test",),
        ),
        ObligationTemplate(
            "security_boundary",
            "interpreter_structure_change_crosses_security_boundary",
            "The interpreted-structure change grants an attacker capability.",
            dependencies=("differential",),
            available_actions=("threat_model_query", "bounded_model_judgment"),
        ),
    ),
    decisive_evidence_kinds=frozenset({"injection_differential"}),
)

CONCURRENCY_RESOURCE_PLAN = ProofPlan(
    id="concurrency-resource-v2",
    invariant_families=frozenset({"concurrency_safety", "resource_safety"}),
    obligations=(
        ObligationTemplate(
            "shared_state",
            "shared_state_or_resource_limit_established",
            "The shared invariant or bounded resource is known.",
            available_actions=("fact_query",),
        ),
        ObligationTemplate(
            "schedule_or_input",
            "attacker_influences_schedule_or_resource_consumption",
            "The attacker can trigger the relevant schedule or growth.",
            available_actions=("taint_query", "load_test"),
        ),
        ObligationTemplate(
            "violation",
            "bounded_execution_violates_shared_or_resource_invariant",
            "A perturbed schedule or bounded load violates the invariant.",
            dependencies=("shared_state", "schedule_or_input"),
            available_actions=("race_detector", "schedule_perturbation", "load_test"),
            decisive_rejection=True,
        ),
        ObligationTemplate(
            "security_boundary",
            "shared_or_resource_violation_crosses_security_boundary",
            "The race or bounded resource violation breaks a protected property.",
            dependencies=("violation",),
            available_actions=("threat_model_query", "bounded_model_judgment"),
        ),
    ),
    decisive_evidence_kinds=frozenset({"race_detector_violation", "bounded_resource_exhaustion"}),
)

DEFAULT_PLANS = (
    REPRESENTATION_DOMAIN_PLAN,
    MEMORY_WRITE_PLAN,
    PARSER_INTEGER_PLAN,
    AUTHORIZATION_PLAN,
    TEMPORAL_MEMORY_PLAN,
    STATE_MACHINE_PLAN,
    CRYPTOGRAPHIC_PLAN,
    INJECTION_BOUNDARY_PLAN,
    CONCURRENCY_RESOURCE_PLAN,
)


class ProofPlanRegistry:
    def __init__(self, plans: tuple[ProofPlan, ...] = DEFAULT_PLANS):
        self.plans = {plan.id: plan for plan in plans}

    def select(self, candidate: Candidate) -> list[ProofPlan]:
        families = set(candidate.invariant_families)
        if candidate.proof_plan_ids:
            unknown = sorted(set(candidate.proof_plan_ids) - set(self.plans))
            if unknown:
                raise KeyError("Candidate references unknown proof plans: " + ", ".join(unknown))
            return [self.plans[plan_id] for plan_id in candidate.proof_plan_ids]
        if candidate.suspected_mechanism == "live_identifier_aliases_reserved_sentinel":
            selected_ids = ["representation-domain-collision-v1"]
            if "spatial_safety" in families:
                selected_ids.append("memory-write-v1")
            return [self.plans[plan_id] for plan_id in selected_ids]
        if candidate.suspected_mechanism == "allocation_access_extent_contrast":
            return [self.plans["memory-write-v1"]]
        selected = [plan for plan in self.plans.values() if plan.invariant_families & families]
        return sorted(selected, key=lambda plan: plan.id)

    def instantiate(
        self,
        candidate: Candidate,
        plans: list[ProofPlan],
    ) -> list[Obligation]:
        placeholders: dict[str, Obligation] = {}
        for plan in plans:
            for template in plan.obligations:
                qualified = f"{plan.id}:{template.key}"
                placeholders[qualified] = Obligation(
                    snapshot_id=candidate.snapshot_id,
                    candidate_id=candidate.logical_id,
                    proof_plan_id=plan.id,
                    predicate=template.predicate,
                    description=template.description,
                    mandatory=template.mandatory,
                    decisive_rejection=template.decisive_rejection,
                    available_actions=list(template.available_actions),
                )

        obligations: list[Obligation] = []
        for plan in plans:
            for template in plan.obligations:
                qualified = f"{plan.id}:{template.key}"
                dependencies: list[str] = []
                for dependency in template.dependencies:
                    dependency_key = dependency if ":" in dependency else f"{plan.id}:{dependency}"
                    target = placeholders.get(dependency_key)
                    if target is not None:
                        dependencies.append(target.logical_id)
                payload = placeholders[qualified].model_dump(mode="python")
                payload.update(
                    {
                        "id": "",
                        "dependencies": dependencies,
                    }
                )
                obligations.append(Obligation.model_validate(payload))
        return obligations

    def get(self, plan_id: str) -> ProofPlan:
        return self.plans[plan_id]
