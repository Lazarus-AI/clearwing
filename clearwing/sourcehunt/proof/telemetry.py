"""Action-level telemetry for proof-flow evaluation and scheduler calibration."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .models import Action, ActionStatus, Candidate, Obligation, ObligationStatus
from .scheduler import is_dynamic_action
from .store import ProofStore

_TERMINAL_PROOF_STATES = {
    ObligationStatus.PROVEN,
    ObligationStatus.DISPROVEN,
    ObligationStatus.NOT_APPLICABLE,
}


class ProofTelemetryCompiler:
    """Join proof actions to physical provider calls from the spend ledger.

    Provider requests retain their globally unique ledger call IDs.  The
    proof engine adds stable action, candidate, and obligation identifiers as
    spend metadata, allowing this compiler to calculate cost and information
    yield without treating model self-confidence as calibration data.
    """

    def __init__(self, store: ProofStore):
        self.store = store

    def compile(self) -> dict[str, Any]:
        actions = list(self.store.latest(Action).values())
        candidates = list(self.store.latest(Candidate).values())
        obligations = list(self.store.latest(Obligation).values())
        calls = _read_settled_calls(self.store.root / "spend-ledger.jsonl")
        calls_by_action: dict[str, list[dict[str, Any]]] = defaultdict(list)
        unlinked_calls: list[str] = []
        action_ids = {
            identifier
            for action in actions
            for identifier in (action.id, action.logical_id, action.attempt_id)
        }
        for call in calls:
            metadata = call.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            action_id = str(metadata.get("proof_action_id") or "")
            if action_id and action_id in action_ids:
                calls_by_action[action_id].append(call)
            else:
                unlinked_calls.append(str(call.get("call_id") or "unknown"))

        action_statuses = Counter(action.status.value for action in actions)
        obligation_statuses = Counter(obligation.status.value for obligation in obligations)
        resolved_ids = {
            obligation.logical_id
            for obligation in obligations
            if obligation.status in _TERMINAL_PROOF_STATES
        }
        action_groups = _group_actions(
            actions,
            calls_by_action,
            key=lambda action: action.template,
        )
        route_groups = _group_actions(
            actions,
            calls_by_action,
            key=lambda action: action.model_route or "deterministic",
        )
        predicate_groups = self._predicate_groups(
            actions,
            obligations,
            calls_by_action,
        )
        total_cost = sum(float(call.get("cost_usd") or 0.0) for call in calls)
        input_tokens = sum(int(call.get("input_tokens") or 0) for call in calls)
        cached_tokens = sum(int(call.get("cached_input_tokens") or 0) for call in calls)
        output_tokens = sum(int(call.get("output_tokens") or 0) for call in calls)
        evidence_outputs = {
            evidence_id for action in actions for evidence_id in action.output_evidence_ids
        }
        claim_outputs = {claim_id for action in actions for claim_id in action.output_claim_ids}
        model_actions = [action for action in actions if action.model_route]
        frontier_actions = [
            action for action in model_actions if action.model_route == "proof_frontier"
        ]
        valid_frontier_escalations = [
            action for action in frontier_actions if _has_prior_local_ambiguity(action, actions)
        ]
        resolved_frontier_escalations = [
            action
            for action in valid_frontier_escalations
            if action.status == ActionStatus.COMPLETED and action.output_claim_ids
        ]
        local_actions = [action for action in model_actions if action.model_route == "proof_local"]
        candidate_generators = Counter(candidate.generator for candidate in candidates)
        exploratory_candidates = [
            candidate
            for candidate in candidates
            if candidate.generator == "bounded-exploratory-lane"
        ]
        promoted_candidates = [
            candidate for candidate in candidates if candidate.generator.startswith("promoted:")
        ]
        linked_call_ids = {
            str(call.get("call_id") or "unknown")
            for linked in calls_by_action.values()
            for call in linked
        }
        return {
            "schema_version": 1,
            "session_dir": str(self.store.root),
            "totals": {
                "actions": len(actions),
                "candidates": len(candidates),
                "model_actions": len(model_actions),
                "dynamic_actions": sum(is_dynamic_action(action.template) for action in actions),
                "physical_model_calls": len(calls),
                "linked_model_calls": len(linked_call_ids),
                "unlinked_model_calls": len(unlinked_calls),
                "model_actions_without_ledger_call": sum(
                    not _calls_for_action(action, calls_by_action) for action in model_actions
                ),
                "obligations": len(obligations),
                "obligations_resolved": len(resolved_ids),
                "evidence_outputs": len(evidence_outputs),
                "claim_outputs": len(claim_outputs),
                "cost_usd": total_cost,
                "input_tokens": input_tokens,
                "cached_input_tokens": cached_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            },
            "action_statuses": dict(sorted(action_statuses.items())),
            "obligation_statuses": dict(sorted(obligation_statuses.items())),
            "by_action_template": action_groups,
            "by_candidate_generator": dict(sorted(candidate_generators.items())),
            "by_model_route": route_groups,
            "by_obligation_predicate": predicate_groups,
            "model_call_linkage": {
                "linked_call_ids": sorted(linked_call_ids),
                "unlinked_call_ids": sorted(unlinked_calls),
            },
            "routing": {
                "local_actions": len(local_actions),
                "frontier_actions": len(frontier_actions),
                "frontier_with_prior_local_ambiguity": len(valid_frontier_escalations),
                "frontier_without_prior_local_ambiguity": (
                    len(frontier_actions) - len(valid_frontier_escalations)
                ),
                "frontier_resolved_explicit_ambiguity": len(resolved_frontier_escalations),
                "explicit_frontier_escalation_rate": _ratio(
                    len(valid_frontier_escalations),
                    len(frontier_actions),
                ),
                "frontier_ambiguity_resolution_rate": _ratio(
                    len(resolved_frontier_escalations),
                    len(valid_frontier_escalations),
                ),
            },
            "learning": {
                "exploratory_candidates": len(exploratory_candidates),
                "promoted_candidates": len(promoted_candidates),
                "structured_candidates": (
                    len(candidates) - len(exploratory_candidates) - len(promoted_candidates)
                ),
                "promoted_mechanism_ids": sorted(
                    {
                        candidate.generator.removeprefix("promoted:")
                        for candidate in promoted_candidates
                    }
                ),
            },
            "efficiency": {
                "evidence_per_1000_tokens": _per_thousand(
                    len(evidence_outputs),
                    input_tokens + output_tokens,
                ),
                "resolved_obligations_per_model_call": _ratio(
                    len(resolved_ids),
                    len(calls),
                ),
                "cost_per_resolved_obligation_usd": _ratio(
                    total_cost,
                    len(resolved_ids),
                ),
            },
        }

    def write(self) -> tuple[Path, dict[str, Any]]:
        payload = self.compile()
        path = self.store.write_json("metrics/run-metrics.json", payload)
        return path, payload

    @staticmethod
    def _predicate_groups(
        actions: list[Action],
        obligations: list[Obligation],
        calls_by_action: dict[str, list[dict[str, Any]]],
    ) -> dict[str, dict[str, Any]]:
        obligation_by_id = {
            identifier: obligation
            for obligation in obligations
            for identifier in (obligation.id, obligation.logical_id)
        }
        grouped: dict[str, list[Action]] = defaultdict(list)
        for action in actions:
            predicates = {
                obligation.predicate
                for obligation_id in action.obligation_ids
                if (obligation := obligation_by_id.get(obligation_id)) is not None
            }
            for predicate in predicates or {"session_level"}:
                grouped[predicate].append(action)
        return {
            key: _summarize_actions(group, calls_by_action)
            for key, group in sorted(grouped.items())
        }


def _group_actions(
    actions: list[Action],
    calls_by_action: dict[str, list[dict[str, Any]]],
    *,
    key: Any,
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[Action]] = defaultdict(list)
    for action in actions:
        grouped[str(key(action))].append(action)
    return {
        label: _summarize_actions(group, calls_by_action)
        for label, group in sorted(grouped.items())
    }


def _summarize_actions(
    actions: list[Action],
    calls_by_action: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    calls = [call for action in actions for call in _calls_for_action(action, calls_by_action)]
    evidence = {evidence_id for action in actions for evidence_id in action.output_evidence_ids}
    claims = {claim_id for action in actions for claim_id in action.output_claim_ids}
    return {
        "actions": len(actions),
        "completed": sum(action.status == ActionStatus.COMPLETED for action in actions),
        "failed": sum(
            action.status
            in {
                ActionStatus.FAILED,
                ActionStatus.TIMED_OUT,
                ActionStatus.BUDGET_EXHAUSTED,
                ActionStatus.CANCELLED,
            }
            for action in actions
        ),
        "evidence_outputs": len(evidence),
        "claim_outputs": len(claims),
        "physical_model_calls": len(calls),
        "cost_usd": sum(float(call.get("cost_usd") or 0.0) for call in calls),
        "input_tokens": sum(int(call.get("input_tokens") or 0) for call in calls),
        "output_tokens": sum(int(call.get("output_tokens") or 0) for call in calls),
    }


def _calls_for_action(
    action: Action,
    calls_by_action: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    for identifier in (action.logical_id, action.id, action.attempt_id):
        if identifier in calls_by_action:
            return calls_by_action[identifier]
    return []


def _has_prior_local_ambiguity(frontier: Action, actions: list[Action]) -> bool:
    frontier_obligations = set(frontier.obligation_ids)
    return any(
        action.model_route == "proof_local"
        and action.candidate_id == frontier.candidate_id
        and bool(frontier_obligations & set(action.obligation_ids))
        and action.template == frontier.template
        and action.created_at <= frontier.created_at
        and (action.status != ActionStatus.COMPLETED or not action.output_claim_ids)
        for action in actions
    )


def _read_settled_calls(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    calls: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if index == len(lines) - 1:
                break
            raise
        if isinstance(event, dict) and event.get("event") == "call_settled":
            calls.append(event)
    return calls


def _ratio(numerator: int | float, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return float(numerator) / denominator


def _per_thousand(count: int, tokens: int) -> float | None:
    if tokens <= 0:
        return None
    return count * 1000.0 / tokens
