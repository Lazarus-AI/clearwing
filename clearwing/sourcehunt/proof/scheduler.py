"""Value-of-information scheduling and explicit model routing."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .graph import ProofGraph, revise
from .models import Action, ActionStatus, Candidate, Obligation, ObligationStatus
from .store import ProofStore

_MECHANICAL_ACTIONS = {
    "fact_query",
    "type_query",
    "range_analysis",
    "guard_enumeration",
    "reachability_query",
    "taint_query",
    "comparison_query",
    "slice_query",
    "allocation_query",
    "configuration_query",
    "threat_model_query",
    "policy_query",
    "lifetime_query",
    "state_model_query",
    "api_contract_query",
}

_DYNAMIC_ACTIONS = {
    "harness",
    "fuzz",
    "sanitizer_run",
    "integration_test",
    "differential_test",
    "symbolic_execution",
    "model_check",
    "protocol_replay",
    "race_detector",
    "schedule_perturbation",
    "load_test",
}


def is_dynamic_action(template: str) -> bool:
    """Return whether an action executes target-controlled code or a harness."""

    return template in _DYNAMIC_ACTIONS


@dataclass(frozen=True)
class InvestigationBudget:
    max_actions: int = 200
    max_model_calls: int = 40
    max_dynamic_actions: int = 20
    exploration_fraction: float = 0.10
    structured_fraction: float = 0.90

    def __post_init__(self) -> None:
        if self.max_actions < 1:
            raise ValueError("max_actions must be positive")
        if self.max_model_calls < 0 or self.max_dynamic_actions < 0:
            raise ValueError("action sub-budgets cannot be negative")
        if not 0 <= self.exploration_fraction <= 1:
            raise ValueError("exploration_fraction must be between 0 and 1")
        if not 0 <= self.structured_fraction <= 1:
            raise ValueError("structured_fraction must be between 0 and 1")
        if self.exploration_fraction + self.structured_fraction > 1.000001:
            raise ValueError("structured and exploration fractions exceed 100%")


@dataclass(frozen=True)
class SchedulerState:
    actions_total: int
    model_calls: int
    dynamic_actions: int
    exploration_actions: int


class ModelRoutePolicy:
    """Local-first routing with explicit escalation and independent falsification."""

    def route(
        self,
        template: str,
        *,
        prior_attempts: int = 0,
        falsification: bool = False,
        exploration: bool = False,
    ) -> str | None:
        if template in _MECHANICAL_ACTIONS or template in _DYNAMIC_ACTIONS:
            return None
        if falsification:
            return "proof_falsifier"
        if exploration:
            return "proof_exploration"
        return "proof_local" if prior_attempts == 0 else "proof_frontier"


class ActionScheduler:
    def __init__(
        self,
        store: ProofStore,
        graph: ProofGraph,
        *,
        budget: InvestigationBudget | None = None,
        route_policy: ModelRoutePolicy | None = None,
    ):
        self.store = store
        self.graph = graph
        self.budget = budget or InvestigationBudget()
        self.route_policy = route_policy or ModelRoutePolicy()

    def state(self) -> SchedulerState:
        actions = [
            action
            for action in self.store.latest(Action).values()
            if action.snapshot_id == self.graph.snapshot_id
        ]
        return SchedulerState(
            actions_total=len(actions),
            model_calls=sum(1 for action in actions if action.model_route),
            dynamic_actions=sum(
                1 for action in actions if action.template in _DYNAMIC_ACTIONS
            ),
            exploration_actions=sum(
                1
                for action in actions
                if bool(action.inputs.get("exploration"))
            ),
        )

    def next_action(
        self,
        candidate: Candidate | list[Candidate],
    ) -> Action | None:
        state = self.state()
        if state.actions_total >= self.budget.max_actions:
            return None
        candidate_pool = candidate if isinstance(candidate, list) else [candidate]
        all_previous = [
            action
            for action in self.store.latest(Action).values()
            if action.snapshot_id == self.graph.snapshot_id
        ]
        choices: list[
            tuple[float, Candidate, Obligation, str, str | None]
        ] = []
        for current_candidate in candidate_pool:
            previous = [
                action
                for action in all_previous
                if action.candidate_id
                in {current_candidate.id, current_candidate.logical_id}
            ]
            attempted = Counter(
                (obligation_id, action.template)
                for action in previous
                for obligation_id in action.obligation_ids
            )
            for obligation in self.graph.candidate_obligations(
                current_candidate.logical_id
            ):
                if obligation.status not in {
                    ObligationStatus.UNKNOWN,
                    ObligationStatus.BLOCKED,
                    ObligationStatus.STALE,
                }:
                    continue
                if not self._dependencies_satisfied(obligation):
                    continue
                templates = list(obligation.available_actions)
                if "bounded_model_judgment" not in templates:
                    templates.append("bounded_model_judgment")
                for template in templates:
                    attempt_count = attempted[
                        (obligation.logical_id, template)
                    ]
                    max_attempts = (
                        2 if template == "bounded_model_judgment" else 1
                    )
                    if attempt_count >= max_attempts:
                        continue
                    if template in _DYNAMIC_ACTIONS and (
                        state.dynamic_actions
                        >= self.budget.max_dynamic_actions
                    ):
                        continue
                    prior_model_attempts = sum(
                        1
                        for action in previous
                        if obligation.logical_id in action.obligation_ids
                        and action.template == template
                        and action.model_route is not None
                    )
                    route = self.route_policy.route(
                        template,
                        prior_attempts=prior_model_attempts,
                    )
                    if route and state.model_calls >= self.budget.max_model_calls:
                        continue
                    score = self._score(
                        current_candidate,
                        obligation,
                        template,
                        len(previous),
                    )
                    choices.append(
                        (
                            score,
                            current_candidate,
                            obligation,
                            template,
                            route,
                        )
                    )
                    break
        if not choices:
            return None
        _, selected_candidate, obligation, template, route = max(
            choices,
            key=lambda item: (
                item[0],
                item[1].logical_id,
                item[2].logical_id,
                item[3],
            ),
        )
        action = Action(
            snapshot_id=self.graph.snapshot_id,
            candidate_id=selected_candidate.logical_id,
            obligation_ids=[obligation.logical_id],
            template=template,
            inputs={
                "predicate": obligation.predicate,
                "exploration": False,
            },
            permitted_tools=[template],
            model_route=route,
            estimated_cost_usd=0.0 if route is None else 0.05,
            estimated_seconds=(
                2.0
                if template in _MECHANICAL_ACTIONS
                else 300.0
                if template in _DYNAMIC_ACTIONS
                else 30.0
            ),
            expected_information_gain=self._information_gain(obligation, template),
        )
        self.store.append(action)
        return action

    def exploration_action(
        self,
        candidate: Candidate,
        *,
        objective: str,
    ) -> Action | None:
        state = self.state()
        exploration_cap = int(self.budget.max_actions * self.budget.exploration_fraction)
        if (
            state.actions_total >= self.budget.max_actions
            or state.exploration_actions >= exploration_cap
            or state.model_calls >= self.budget.max_model_calls
        ):
            return None
        action = Action(
            snapshot_id=self.graph.snapshot_id,
            candidate_id=candidate.logical_id,
            obligation_ids=[],
            template="bounded_exploration",
            inputs={"objective": objective, "exploration": True},
            permitted_tools=["read_source", "query_facts", "propose_candidate"],
            model_route=self.route_policy.route(
                "bounded_exploration",
                exploration=True,
            ),
            estimated_cost_usd=0.10,
            estimated_seconds=60.0,
            expected_information_gain=0.25,
        )
        self.store.append(action)
        return action

    def complete(
        self,
        action: Action,
        *,
        status: ActionStatus,
        evidence_ids: list[str] | None = None,
        claim_ids: list[str] | None = None,
        error: str | None = None,
    ) -> Action:
        successor = revise(
            action,
            status=status,
            output_evidence_ids=evidence_ids or [],
            output_claim_ids=claim_ids or [],
            error=error,
        )
        self.store.append(successor)
        return successor

    def _dependencies_satisfied(self, obligation: Obligation) -> bool:
        for dependency_id in obligation.dependencies:
            dependency = self.graph.obligations.get(dependency_id)
            if dependency is None or dependency.status not in {
                ObligationStatus.PROVEN,
                ObligationStatus.NOT_APPLICABLE,
            }:
                return False
        return True

    @staticmethod
    def _score(
        candidate: Candidate,
        obligation: Obligation,
        template: str,
        age: int,
    ) -> float:
        impact = 1.0
        if "spatial_safety" in candidate.invariant_families:
            impact += 0.4
        if "authority_safety" in candidate.invariant_families:
            impact += 0.3
        rejection_value = 1.35 if obligation.decisive_rejection else 1.0
        information = ActionScheduler._information_gain(obligation, template)
        cost = (
            1.0
            if template in _MECHANICAL_ACTIONS
            else 8.0
            if template in _DYNAMIC_ACTIONS
            else 3.0
        )
        starvation_bonus = 0.05 / (1 + age)
        return impact * rejection_value * information / cost + starvation_bonus

    @staticmethod
    def _information_gain(obligation: Obligation, template: str) -> float:
        base = 0.70 if obligation.decisive_rejection else 0.50
        if template in _MECHANICAL_ACTIONS:
            return min(1.0, base + 0.20)
        if template in _DYNAMIC_ACTIONS:
            return min(1.0, base + 0.15)
        return base
