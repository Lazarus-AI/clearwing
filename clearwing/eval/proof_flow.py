"""Stage-aware and counterfactual evaluation for proof-flow sourcehunt."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.sourcehunt.proof import (
    Action,
    Candidate,
    Certificate,
    CertificateKind,
    ContextPacket,
    Evidence,
    Fact,
    Obligation,
    ProofStore,
)


@dataclass(frozen=True)
class GroundTruth:
    expected_mechanisms: frozenset[str] = frozenset()
    expected_predicates: frozenset[str] = frozenset()
    expected_decision: str = ""
    expected_files: frozenset[str] = frozenset()


@dataclass
class ProofFunnel:
    facts_extracted: bool = False
    candidate_generated: bool = False
    correct_plan_selected: bool = False
    obligations_instantiated: bool = False
    bounded_packets_created: bool = False
    dynamic_evidence_acquired: bool = False
    falsification_completed: bool = False
    correct_certificate_emitted: bool = False

    def first_failure(self) -> str | None:
        stages = (
            ("facts_extracted", self.facts_extracted),
            ("candidate_generated", self.candidate_generated),
            ("correct_plan_selected", self.correct_plan_selected),
            ("obligations_instantiated", self.obligations_instantiated),
            ("bounded_packets_created", self.bounded_packets_created),
            ("dynamic_evidence_acquired", self.dynamic_evidence_acquired),
            ("falsification_completed", self.falsification_completed),
            ("correct_certificate_emitted", self.correct_certificate_emitted),
        )
        return next((name for name, passed in stages if not passed), None)


@dataclass
class ProofEvalObservation:
    name: str
    session_dir: str
    funnel: ProofFunnel
    candidate_mechanisms: set[str] = field(default_factory=set)
    decisions: set[str] = field(default_factory=set)
    finding_count: int = 0
    rejection_count: int = 0
    incomplete_count: int = 0
    model_calls: int = 0
    model_actions: int = 0
    linked_model_calls: int = 0
    unlinked_model_calls: int = 0
    action_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass(frozen=True)
class CounterfactualExpectation:
    name: str
    relation: str
    expected: bool


@dataclass
class CounterfactualScore:
    passed: int
    total: int
    failures: list[str] = field(default_factory=list)

    @property
    def consistency(self) -> float:
        return self.passed / self.total if self.total else 0.0


@dataclass(frozen=True)
class CutoverMetrics:
    frontier_recall: float
    legacy_frontier_recall: float
    local_recall: float
    legacy_local_recall: float
    precision: float
    legacy_precision: float
    mean_cost: float
    legacy_mean_cost: float


@dataclass
class CutoverDecision:
    passed: bool
    checks: dict[str, bool]


def inspect_proof_session(
    name: str,
    session_dir: str | Path,
    truth: GroundTruth,
    *,
    cost_usd: float | None = None,
) -> ProofEvalObservation:
    store = ProofStore(session_dir)
    facts = store.read_all(Fact)
    candidates = list(store.latest(Candidate).values())
    obligations = list(store.latest(Obligation).values())
    packets = store.read_all(ContextPacket)
    evidence = list(store.latest(Evidence).values())
    actions = list(store.latest(Action).values())
    certificates = list(store.latest(Certificate).values())
    metrics = _load_metrics(store.root / "metrics" / "run-metrics.json")
    raw_metric_totals = metrics.get("totals")
    metric_totals = raw_metric_totals if isinstance(raw_metric_totals, dict) else {}
    model_actions = sum(bool(action.model_route) for action in actions)
    physical_model_calls = int(metric_totals.get("physical_model_calls", model_actions))

    mechanisms = {candidate.suspected_mechanism for candidate in candidates}
    selected_predicates = {obligation.predicate for obligation in obligations}
    correct_candidates = not truth.expected_mechanisms or bool(
        truth.expected_mechanisms & mechanisms
    )
    correct_plans = (
        not truth.expected_predicates or truth.expected_predicates <= selected_predicates
    )
    dynamic = any(
        item.kind
        in {
            "sanitizer_crash",
            "sanitizer_uaf",
            "authorization_differential",
            "cryptographic_differential",
            "injection_differential",
            "race_detector_violation",
        }
        for item in evidence
    )
    falsification_actions = [action for action in actions if action.template.startswith("falsify:")]
    falsification_complete = bool(falsification_actions) and all(
        action.status == "completed" for action in falsification_actions
    )
    decisions = {certificate.decision for certificate in certificates}
    correct_decision = not truth.expected_decision or truth.expected_decision in decisions
    return ProofEvalObservation(
        name=name,
        session_dir=str(Path(session_dir)),
        funnel=ProofFunnel(
            facts_extracted=bool(facts),
            candidate_generated=correct_candidates,
            correct_plan_selected=correct_plans and bool(candidates),
            obligations_instantiated=bool(obligations),
            bounded_packets_created=bool(packets),
            dynamic_evidence_acquired=dynamic,
            falsification_completed=falsification_complete,
            correct_certificate_emitted=correct_decision,
        ),
        candidate_mechanisms=mechanisms,
        decisions=decisions,
        finding_count=sum(
            certificate.kind == CertificateKind.FINDING for certificate in certificates
        ),
        rejection_count=sum(
            certificate.kind == CertificateKind.REJECTION for certificate in certificates
        ),
        incomplete_count=sum(
            certificate.kind == CertificateKind.INCOMPLETE for certificate in certificates
        ),
        model_calls=physical_model_calls,
        model_actions=model_actions,
        linked_model_calls=int(metric_totals.get("linked_model_calls", 0)),
        unlinked_model_calls=int(metric_totals.get("unlinked_model_calls", 0)),
        action_count=len(actions),
        input_tokens=int(metric_totals.get("input_tokens", 0)),
        output_tokens=int(metric_totals.get("output_tokens", 0)),
        cost_usd=(float(metric_totals.get("cost_usd", 0.0)) if cost_usd is None else cost_usd),
    )


def score_counterfactuals(
    vulnerable: ProofEvalObservation,
    variants: dict[str, ProofEvalObservation],
    expectations: list[CounterfactualExpectation],
) -> CounterfactualScore:
    failures: list[str] = []
    for expectation in expectations:
        variant = variants[expectation.name]
        relation_passed = _relation_holds(
            vulnerable,
            variant,
            expectation.relation,
        )
        if relation_passed != expectation.expected:
            failures.append(f"{expectation.name}:{expectation.relation}")
    return CounterfactualScore(
        passed=len(expectations) - len(failures),
        total=len(expectations),
        failures=failures,
    )


def evaluate_cutover(metrics: CutoverMetrics) -> CutoverDecision:
    checks = {
        "frontier_recall_not_worse": (metrics.frontier_recall >= metrics.legacy_frontier_recall),
        "local_recall_plus_10pp": (metrics.local_recall >= metrics.legacy_local_recall + 0.10),
        "precision_not_worse": metrics.precision >= metrics.legacy_precision,
        "cost_within_1_25x": (
            metrics.mean_cost <= metrics.legacy_mean_cost * 1.25
            if metrics.legacy_mean_cost > 0
            else metrics.mean_cost == 0
        ),
    }
    return CutoverDecision(passed=all(checks.values()), checks=checks)


def _relation_holds(
    vulnerable: ProofEvalObservation,
    variant: ProofEvalObservation,
    relation: str,
) -> bool:
    if relation == "mechanism_preserved":
        return bool(vulnerable.candidate_mechanisms & variant.candidate_mechanisms)
    if relation == "finding_removed":
        return vulnerable.finding_count > 0 and variant.finding_count == 0
    if relation == "rejection_added":
        return variant.rejection_count > vulnerable.rejection_count
    if relation == "no_extra_finding":
        return variant.finding_count <= vulnerable.finding_count
    if relation == "decision_preserved":
        return vulnerable.decisions == variant.decisions
    raise ValueError(f"Unknown counterfactual relation: {relation}")


def _load_metrics(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}
