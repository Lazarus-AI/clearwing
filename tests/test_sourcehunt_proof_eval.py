"""Proof-flow evaluation funnel and cutover gate tests."""

from __future__ import annotations

from clearwing.eval.proof_flow import (
    CounterfactualExpectation,
    CounterfactualManifest,
    CutoverMetrics,
    GroundTruth,
    ProofEvalObservation,
    ProofFunnel,
    evaluate_counterfactual_sessions,
    evaluate_cutover,
    inspect_proof_session,
    score_counterfactuals,
)
from clearwing.sourcehunt.proof import (
    Candidate,
    Certificate,
    CertificateKind,
    Evidence,
    Fact,
    Obligation,
    ProofStore,
    Provenance,
)


def test_stage_funnel_identifies_the_first_missing_mechanism(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    fact = Fact(
        snapshot_id="snapshot-1",
        kind="sentinel_use",
        subject="owner_table",
        provenance=Provenance(producer="test"),
    )
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="sentinel collision",
        invariant_families=["representation_domain_safety"],
        suspected_mechanism="live_identifier_aliases_reserved_sentinel",
        fact_ids=[fact.id],
        generator="test",
        proof_plan_ids=["representation-domain-collision-v1"],
    )
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="representation-domain-collision-v1",
        predicate="reserved_sentinel_established",
    )
    certificate = Certificate(
        snapshot_id="snapshot-1",
        kind=CertificateKind.INCOMPLETE,
        candidate_id=candidate.logical_id,
        proof_plan_ids=candidate.proof_plan_ids,
        decision="incomplete",
        reason="runtime missing",
    )
    store.append_many([fact, candidate, obligation, certificate])

    observation = inspect_proof_session(
        "vulnerable",
        store.root,
        GroundTruth(
            expected_mechanisms=frozenset({"live_identifier_aliases_reserved_sentinel"}),
            expected_predicates=frozenset({"reserved_sentinel_established"}),
            expected_decision="incomplete",
        ),
    )

    assert observation.funnel.candidate_generated
    assert observation.funnel.correct_plan_selected
    assert observation.funnel.first_failure() == "bounded_packets_created"


def test_counterfactual_consistency_scores_relations() -> None:
    vulnerable = ProofEvalObservation(
        name="vulnerable",
        session_dir="v",
        funnel=ProofFunnel(),
        candidate_mechanisms={"sentinel"},
        decisions={"confirmed"},
        finding_count=1,
    )
    fixed = ProofEvalObservation(
        name="fixed",
        session_dir="f",
        funnel=ProofFunnel(),
        candidate_mechanisms={"sentinel"},
        decisions={"disproven"},
        rejection_count=1,
    )
    renamed = ProofEvalObservation(
        name="renamed",
        session_dir="r",
        funnel=ProofFunnel(),
        candidate_mechanisms={"sentinel"},
        decisions={"confirmed"},
        finding_count=1,
    )

    score = score_counterfactuals(
        vulnerable,
        {"fixed": fixed, "renamed": renamed},
        [
            CounterfactualExpectation("fixed", "finding_removed", True),
            CounterfactualExpectation("fixed", "rejection_added", True),
            CounterfactualExpectation("renamed", "mechanism_preserved", True),
            CounterfactualExpectation("renamed", "decision_preserved", True),
        ],
    )

    assert score.consistency == 1.0
    assert score.failures == []


def test_cutover_gate_enforces_recall_precision_and_cost_thresholds() -> None:
    passing = evaluate_cutover(
        CutoverMetrics(
            frontier_recall=0.62,
            legacy_frontier_recall=0.60,
            local_recall=0.43,
            legacy_local_recall=0.30,
            precision=0.80,
            legacy_precision=0.80,
            mean_cost=12.0,
            legacy_mean_cost=10.0,
        )
    )
    expensive = evaluate_cutover(
        CutoverMetrics(
            frontier_recall=0.62,
            legacy_frontier_recall=0.60,
            local_recall=0.43,
            legacy_local_recall=0.30,
            precision=0.80,
            legacy_precision=0.80,
            mean_cost=13.0,
            legacy_mean_cost=10.0,
        )
    )

    assert passing.passed
    assert not expensive.passed
    assert expensive.checks["cost_within_1_25x"] is False


def test_manifest_driven_counterfactual_matrix_is_complete_and_operational(
    tmp_path,
) -> None:
    def session(name, kind, *, evidence_kind=None):
        store = ProofStore(tmp_path / name)
        candidate = Candidate(
            snapshot_id=f"snapshot-{name}",
            title=name,
            invariant_families=["representation_domain_safety"],
            suspected_mechanism="live_identifier_aliases_reserved_sentinel",
            generator="test",
        )
        certificate = Certificate(
            snapshot_id=f"snapshot-{name}",
            kind=kind,
            candidate_id=candidate.logical_id,
            proof_plan_ids=["representation-domain-collision-v1"],
            decision=(
                "confirmed"
                if kind == CertificateKind.FINDING
                else "disproven"
                if kind == CertificateKind.REJECTION
                else "incomplete"
            ),
            reason="fixture",
        )
        records = [candidate, certificate]
        if evidence_kind is not None:
            records.append(
                Evidence(
                    snapshot_id=f"snapshot-{name}",
                    kind=evidence_kind,
                    provenance=Provenance(producer="test"),
                )
            )
        store.append_many(records)
        return store.root

    manifest = CounterfactualManifest.load("evaluations/ffmpeg_proof.yaml")
    report = evaluate_counterfactual_sessions(
        manifest,
        {
            "vulnerable": session("vulnerable", CertificateKind.FINDING),
            "fixed": session(
                "fixed",
                CertificateKind.REJECTION,
                evidence_kind="dominating_rejecting_guard",
            ),
            "renamed": session("renamed", CertificateKind.FINDING),
            "moved": session("moved", CertificateKind.FINDING),
            "guarded": session("guarded", CertificateKind.REJECTION),
            "unreachable": session("unreachable", CertificateKind.INCOMPLETE),
            "decoy": session("decoy", CertificateKind.FINDING),
            "widened-domain": session("widened", CertificateKind.INCOMPLETE),
        },
    )

    assert report.score.consistency == 1.0
    assert report.score.total == len(manifest.expectations)
    target = report.write(tmp_path / "counterfactual-report.json")
    assert target.is_file()
    assert report.payload()["manifest"] == "ffmpeg-h264-slice-sentinel"
