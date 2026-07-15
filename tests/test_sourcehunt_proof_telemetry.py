"""Proof action, model-call linkage, and calibration telemetry tests."""

from __future__ import annotations

import json

import pytest

from clearwing.eval.proof_flow import GroundTruth, inspect_proof_session
from clearwing.sourcehunt.proof import (
    Action,
    ActionStatus,
    Obligation,
    ObligationStatus,
    ProofStore,
    ProofTelemetryCompiler,
)


def test_telemetry_joins_provider_calls_to_actions_and_obligations(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id="candidate-1",
        proof_plan_id="memory-write-v1",
        predicate="attacker_input_reaches_sink",
        status=ObligationStatus.PROVEN,
    )
    action = Action(
        snapshot_id="snapshot-1",
        candidate_id="candidate-1",
        obligation_ids=[obligation.logical_id],
        template="bounded_model_judgment",
        model_route="proof_local",
        status=ActionStatus.COMPLETED,
        output_evidence_ids=["evidence-1"],
        output_claim_ids=["claim-1"],
    )
    store.append_many([obligation, action])
    events = [
        {
            "event": "call_settled",
            "call_id": "linked-call",
            "cost_usd": 0.25,
            "input_tokens": 800,
            "cached_input_tokens": 200,
            "output_tokens": 200,
            "metadata": {
                "proof_action_id": action.logical_id,
                "obligation_id": obligation.logical_id,
            },
        },
        {
            "event": "call_settled",
            "call_id": "unlinked-call",
            "cost_usd": 0.05,
            "input_tokens": 100,
            "cached_input_tokens": 0,
            "output_tokens": 50,
            "metadata": {},
        },
    ]
    (store.root / "spend-ledger.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    path, metrics = ProofTelemetryCompiler(store).write()

    assert path == store.root / "metrics" / "run-metrics.json"
    assert metrics["totals"]["physical_model_calls"] == 2
    assert metrics["totals"]["linked_model_calls"] == 1
    assert metrics["totals"]["unlinked_model_calls"] == 1
    assert metrics["totals"]["cost_usd"] == pytest.approx(0.30)
    assert metrics["totals"]["total_tokens"] == 1150
    assert metrics["by_model_route"]["proof_local"]["cost_usd"] == 0.25
    assert (
        metrics["by_obligation_predicate"]["attacker_input_reaches_sink"]["evidence_outputs"] == 1
    )
    assert json.loads(path.read_text(encoding="utf-8")) == metrics

    observation = inspect_proof_session(
        "telemetry",
        store.root,
        GroundTruth(),
    )
    assert observation.model_calls == 2
    assert observation.model_actions == 1
    assert observation.linked_model_calls == 1
    assert observation.unlinked_model_calls == 1
    assert observation.input_tokens == 900
    assert observation.output_tokens == 250
    assert observation.cost_usd == pytest.approx(0.30)
