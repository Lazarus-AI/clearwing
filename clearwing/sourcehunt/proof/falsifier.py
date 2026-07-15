"""Finite, atomic falsification plans."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field

from clearwing.llm.native import response_text

from .models import (
    Action,
    ActionStatus,
    Candidate,
    Claim,
    CompletenessManifest,
    Derivation,
    Evidence,
    Fact,
    Obligation,
    ObligationStatus,
    Provenance,
    StrictModel,
    ThreatModel,
)
from .resolvers import Resolution
from .store import ProofStore


@dataclass(frozen=True)
class FalsificationTask:
    key: str
    objective: str
    permitted_tools: tuple[str, ...]


class FalsificationJudgment(StrictModel):
    status: Literal["counterexample_found", "no_counterexample", "blocked"]
    conclusion: str
    contradicted_obligation_id: str | None = None
    cited_fact_ids: list[str] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)


@dataclass
class FalsificationExecution:
    completed: bool
    evidence: list[Evidence]
    resolution: Resolution | None = None
    error: str | None = None


_COMMON_TASKS = (
    FalsificationTask(
        "unreachable",
        "Find a concrete reason the suspected entry-to-sink path is unreachable.",
        ("reachability_query", "configuration_query"),
    ),
    FalsificationTask(
        "effective_guard",
        "Find a local, caller-side, or type-level guard that prevents the trigger.",
        ("guard_enumeration", "type_query"),
    ),
    FalsificationTask(
        "threat_boundary",
        "Show that the behavior cannot cross the stated security boundary.",
        ("threat_model_query",),
    ),
)

_FAMILY_TASKS = {
    "spatial_safety": (
        FalsificationTask(
            "valid_extent",
            "Prove that padding, allocation, or alias semantics make the access valid.",
            ("allocation_query", "range_analysis"),
        ),
        FalsificationTask(
            "harness_artifact",
            "Show that dynamic behavior is introduced by the harness or build.",
            ("integration_test", "sanitizer_run"),
        ),
    ),
    "representation_domain_safety": (
        FalsificationTask(
            "domain_disjoint",
            "Prove that live values cannot occupy the reserved representation.",
            ("range_analysis", "guard_enumeration"),
        ),
        FalsificationTask(
            "consumer_distinguishes",
            "Find additional state that lets every consumer distinguish the values.",
            ("comparison_query", "slice_query"),
        ),
    ),
    "authority_safety": (
        FalsificationTask(
            "equivalent_enforcement",
            "Find equivalent authorization enforcement on every reachable path.",
            ("policy_query", "guard_enumeration"),
        ),
    ),
}


class FalsificationPlanner:
    def plan(
        self,
        store: ProofStore,
        candidate: Candidate,
        obligations: list[Obligation],
        claims: list[Claim],
        *,
        max_actions: int | None = None,
    ) -> list[Action]:
        tasks = list(_COMMON_TASKS)
        for family in candidate.invariant_families:
            tasks.extend(_FAMILY_TASKS.get(family, ()))
        unique = {task.key: task for task in tasks}
        atomic_claims = [
            {
                "claim_id": claim.logical_id,
                "predicate": claim.predicate,
                "object": claim.object,
            }
            for claim in claims
            if claim.status == "proven" and claim.subject in {candidate.id, candidate.logical_id}
        ]
        actions: list[Action] = []
        tasks_to_run = list(unique.values())
        if max_actions is not None:
            tasks_to_run = tasks_to_run[: max(0, max_actions)]
        for task in tasks_to_run:
            action = Action(
                snapshot_id=candidate.snapshot_id,
                candidate_id=candidate.logical_id,
                obligation_ids=[obligation.logical_id for obligation in obligations],
                template=f"falsify:{task.key}",
                inputs={
                    "objective": task.objective,
                    "atomic_claims": atomic_claims,
                    "falsification": True,
                },
                permitted_tools=list(task.permitted_tools),
                model_route="proof_falsifier",
                estimated_cost_usd=0.05,
                estimated_seconds=30.0,
                expected_information_gain=0.65,
            )
            store.append(action)
            actions.append(action)
        self.materialize(store, candidate)
        return actions

    @staticmethod
    def materialize(store: ProofStore, candidate: Candidate) -> None:
        """Write a current, reproducible view of the finite falsifier run."""

        actions = sorted(
            (
                action
                for action in store.latest(Action).values()
                if action.candidate_id == candidate.logical_id
                and action.template.startswith("falsify:")
            ),
            key=lambda action: action.logical_id,
        )
        statuses = Counter(action.status.value for action in actions)
        complete = bool(actions) and all(
            action.status == ActionStatus.COMPLETED for action in actions
        )
        counterexample_found = any(action.output_claim_ids for action in actions)
        if counterexample_found:
            outcome = "counterexample_found"
        elif complete:
            outcome = "no_counterexample_within_bounded_scope"
        else:
            outcome = "incomplete"
        store.write_falsification(
            candidate.logical_id,
            {
                "candidate_id": candidate.logical_id,
                "finite": True,
                "complete": complete,
                "outcome": outcome,
                "status_counts": dict(sorted(statuses.items())),
                "actions": [
                    {
                        "action_id": action.logical_id,
                        "attempt_id": action.attempt_id,
                        "template": action.template,
                        "objective": action.inputs["objective"],
                        "status": action.status.value,
                        "evidence_ids": action.output_evidence_ids,
                        "claim_ids": action.output_claim_ids,
                        "error": action.error,
                    }
                    for action in actions
                ],
            },
        )


class BoundedFalsifier:
    """Seek a concrete counterexample to atomic claims, never a narrative."""

    SYSTEM_PROMPT = """You are an independent falsifier. Try only the finite
objective supplied. A counterexample must name one supplied obligation and
cite concrete supplied facts. `no_counterexample` means only that this bounded
attempt found none; it does not add support to the vulnerability. Return
`blocked` when required context is absent."""

    def __init__(self, llm: Any):
        self.llm = llm

    async def execute(
        self,
        action: Action,
        candidate: Candidate,
        obligations: list[Obligation],
        facts: list[Fact],
        completeness: CompletenessManifest,
        threat_model: ThreatModel | None = None,
    ) -> FalsificationExecution:
        candidate_fact_ids = set(candidate.fact_ids)
        included_facts = [fact for fact in facts if fact.id in candidate_fact_ids]
        packet = {
            "objective": action.inputs.get("objective"),
            "atomic_claims": action.inputs.get("atomic_claims", []),
            "obligations": [
                {
                    "id": obligation.logical_id,
                    "predicate": obligation.predicate,
                    "status": obligation.status,
                }
                for obligation in obligations
            ],
            "facts": [
                {
                    "id": fact.id,
                    "kind": fact.kind,
                    "subject": fact.subject,
                    "location": (fact.location.model_dump(mode="json") if fact.location else None),
                    "properties": fact.properties,
                }
                for fact in included_facts
            ],
            "completeness": completeness.model_dump(mode="json"),
            "threat_model": (
                threat_model.model_dump(mode="json") if threat_model is not None else None
            ),
        }
        response = await self.llm.aask_text(
            system=self.SYSTEM_PROMPT,
            user=json.dumps(packet, indent=2, default=str),
            response_schema=FalsificationJudgment,
            response_schema_name="FalsificationJudgment",
        )
        judgment = FalsificationJudgment.model_validate_json(response_text(response))
        allowed_facts = {fact.id for fact in included_facts}
        if not set(judgment.cited_fact_ids) <= allowed_facts:
            return FalsificationExecution(
                completed=False,
                evidence=[],
                error="falsifier cited facts outside its packet",
            )
        if judgment.status == "blocked":
            return FalsificationExecution(
                completed=False,
                evidence=[],
                error="; ".join(judgment.missing_context) or judgment.conclusion,
            )
        evidence = Evidence(
            snapshot_id=candidate.snapshot_id,
            kind=(
                "falsification_counterexample"
                if judgment.status == "counterexample_found"
                else "bounded_falsification_no_counterexample"
            ),
            observations=[
                {
                    "objective": action.inputs.get("objective"),
                    "conclusion": judgment.conclusion,
                    "cited_fact_ids": judgment.cited_fact_ids,
                    "scope": "finite bounded falsification attempt",
                }
            ],
            contradicts=(
                [judgment.contradicted_obligation_id] if judgment.contradicted_obligation_id else []
            ),
            provenance=Provenance(
                producer="bounded-falsifier",
                producer_version="1",
                model=str(getattr(self.llm, "model_name", "")),
                provider=str(getattr(self.llm, "provider_name", "")),
            ),
            reliability={
                "independent_role": True,
                "no_counterexample_is_not_confirmation": True,
            },
        )
        if judgment.status == "no_counterexample":
            return FalsificationExecution(
                completed=True,
                evidence=[evidence],
            )
        obligation_by_id = {obligation.logical_id: obligation for obligation in obligations}
        contradicted = obligation_by_id.get(judgment.contradicted_obligation_id or "")
        if contradicted is None or not judgment.cited_fact_ids:
            return FalsificationExecution(
                completed=False,
                evidence=[],
                error=(
                    "counterexample must name an included obligation and cite at least one fact"
                ),
            )
        claim = Claim(
            snapshot_id=candidate.snapshot_id,
            predicate=f"counterexample_to:{contradicted.predicate}",
            subject=candidate.logical_id,
            object=judgment.conclusion,
            status=ObligationStatus.PROVEN,
            scope={"obligation_id": contradicted.logical_id},
            supporting_evidence_ids=[evidence.id],
        )
        derivation = Derivation(
            snapshot_id=candidate.snapshot_id,
            rule="independent-bounded-falsification",
            premise_ids=judgment.cited_fact_ids,
            conclusion_claim_ids=[claim.logical_id],
            validator="model",
        )
        return FalsificationExecution(
            completed=True,
            evidence=[evidence],
            resolution=Resolution(
                status=ObligationStatus.DISPROVEN,
                claims=[claim],
                evidence=[evidence],
                derivations=[derivation],
            ),
        )
