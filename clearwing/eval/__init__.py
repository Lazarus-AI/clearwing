"""Evaluation and A/B testing framework for Clearwing (spec 018)."""

from .proof_flow import (
    CounterfactualExpectation,
    CounterfactualScore,
    CutoverDecision,
    CutoverMetrics,
    GroundTruth,
    ProofEvalObservation,
    ProofFunnel,
    evaluate_cutover,
    inspect_proof_session,
    score_counterfactuals,
)

__all__ = [
    "CounterfactualExpectation",
    "CounterfactualScore",
    "CutoverDecision",
    "CutoverMetrics",
    "GroundTruth",
    "ProofEvalObservation",
    "ProofFunnel",
    "evaluate_cutover",
    "inspect_proof_session",
    "score_counterfactuals",
]
