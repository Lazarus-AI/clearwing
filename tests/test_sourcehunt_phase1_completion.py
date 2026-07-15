"""Assumption and persistent invalidation coverage completing Phase 1."""

from __future__ import annotations

import json

import pytest

from clearwing.sourcehunt.proof import (
    Assumption,
    BoundedModelResolver,
    Candidate,
    Certificate,
    CertificateCompiler,
    CertificateKind,
    Claim,
    CompletenessItem,
    CompletenessManifest,
    CompletenessStatus,
    ContextPacketBuilder,
    Evidence,
    Fact,
    Obligation,
    ObligationStatus,
    ProofFlowRunner,
    ProofGraph,
    ProofReporter,
    ProofRunConfig,
    ProofStore,
    Provenance,
    ThreatModel,
    invalidate_certificates,
)


def _candidate(snapshot_id: str, assumption_id: str = "") -> Candidate:
    return Candidate(
        snapshot_id=snapshot_id,
        title="attacker-controlled extent reaches copy",
        invariant_families=["spatial_safety"],
        suspected_mechanism="allocation_access_extent_contrast",
        source_symbols=["length"],
        impact_sinks=["copy"],
        assumption_ids=[assumption_id] if assumption_id else [],
        generator="test",
        proof_plan_ids=["memory-write-v1"],
    )


def test_assumption_revision_stales_claim_obligation_and_dependents(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    assumption = graph.add_assumption(
        Assumption(
            snapshot_id="snapshot-1",
            kind="deployment",
            statement="the parser is remotely reachable",
            required_by=[],
        )
    )
    candidate = graph.add_candidate(_candidate("snapshot-1", assumption.logical_id))
    first = graph.add_obligation(
        Obligation(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            proof_plan_id="memory-write-v1",
            predicate="attacker_input_reaches_sink",
        )
    )
    dependent = graph.add_obligation(
        Obligation(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            proof_plan_id="memory-write-v1",
            predicate="runtime_confirms_spatial_violation",
            dependencies=[first.logical_id],
        )
    )
    claim = graph.add_claim(
        Claim(
            snapshot_id="snapshot-1",
            predicate=first.predicate,
            subject=candidate.logical_id,
            status=ObligationStatus.PROVEN,
            assumption_ids=[assumption.logical_id],
        )
    )
    graph.resolve_obligation(
        first.logical_id,
        ObligationStatus.PROVEN,
        supporting_claim_ids=[claim.logical_id],
    )
    dependent_claim = graph.add_claim(
        Claim(
            snapshot_id="snapshot-1",
            predicate=dependent.predicate,
            subject=candidate.logical_id,
        )
    )
    graph.resolve_obligation(
        dependent.logical_id,
        ObligationStatus.PROVEN,
        supporting_claim_ids=[dependent_claim.logical_id],
    )
    current_certificate = Certificate(
        snapshot_id="snapshot-1",
        kind=CertificateKind.FINDING,
        candidate_id=candidate.logical_id,
        proof_plan_ids=["memory-write-v1"],
        decision="confirmed",
        reason="test",
        assumption_ids=[assumption.logical_id],
    )
    store.append(current_certificate)

    graph.update_assumption(
        assumption.logical_id,
        status=ObligationStatus.DISPROVEN,
    )

    assert graph.claims[claim.logical_id].status == ObligationStatus.STALE
    assert graph.obligations[first.logical_id].status == ObligationStatus.STALE
    assert graph.obligations[dependent.logical_id].status == ObligationStatus.STALE
    assert store.get(Certificate, current_certificate.logical_id).validity == "stale"
    materialized = graph.materialize(candidate.logical_id)
    assert materialized["assumptions"][0]["status"] == "disproven"
    assert any(edge["kind"] == "assumed_by" for edge in materialized["edges"])


def test_assumptions_flow_through_packet_certificate_and_report(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    assumption = graph.add_assumption(
        Assumption(
            snapshot_id="snapshot-1",
            kind="deployment",
            statement="the affected component is enabled",
            required_by=[],
        )
    )
    candidate = graph.add_candidate(_candidate("snapshot-1", assumption.logical_id))
    obligation = graph.add_obligation(
        Obligation(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            proof_plan_id="memory-write-v1",
            predicate="attacker_controls_requested_extent",
            description="Determine whether the requested extent is attacker controlled.",
        )
    )
    fact = Fact(
        snapshot_id="snapshot-1",
        kind="parameter",
        subject="length",
        provenance=Provenance(producer="test"),
    )
    completeness = CompletenessManifest(
        snapshot_id="snapshot-1",
        items={
            "types": CompletenessItem(status=CompletenessStatus.COMPLETE),
        },
    )
    packet = ContextPacketBuilder().build(
        candidate,
        obligation,
        [fact],
        [],
        [],
        completeness,
        threat_model=ThreatModel(snapshot_id="snapshot-1"),
        assumptions=[assumption],
        evaluation_hints={"target_functions": ["decode"]},
    )

    certificate = CertificateCompiler(store, graph).compile(
        candidate,
        threat_model=ThreatModel(snapshot_id="snapshot-1"),
        facts=[fact],
    )
    store.append(certificate)
    markdown = ProofReporter(store)._markdown(
        [certificate],
        {candidate.logical_id: candidate},
    )

    assert packet.assumption_ids == [assumption.id]
    assert packet.assumption_summaries[0]["statement"] == assumption.statement
    assert packet.evaluation_hints == {"target_functions": ["decode"]}
    assert certificate.assumption_ids == [assumption.logical_id]
    assert "the affected component is enabled" in markdown
    assert "[unknown]" in markdown


def test_certificate_invalidation_persists_a_stale_successor(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    evidence = Evidence(
        snapshot_id="snapshot-1",
        kind="static_reachability",
        provenance=Provenance(producer="test"),
    )
    certificate = Certificate(
        snapshot_id="snapshot-1",
        kind=CertificateKind.FINDING,
        candidate_id="candidate-1",
        proof_plan_ids=["memory-write-v1"],
        decision="confirmed",
        reason="all obligations proven",
        dependency_files=["decoder.c"],
        dependency_symbols=["decode"],
        assumption_ids=["assumption-1"],
        evidence_ids=[evidence.logical_id],
    )
    store.append(certificate)

    successors = invalidate_certificates(
        store,
        changed_files=["decoder.c"],
        changed_assumptions=["assumption-1"],
        reason="guard added and deployment assumption changed",
    )

    assert len(successors) == 1
    stale = successors[0]
    assert stale.validity == "stale"
    assert stale.revision == 2
    assert stale.supersedes == certificate.id
    assert stale.invalidated_by == [
        "assumption:assumption-1",
        "file:decoder.c",
    ]
    latest = store.get(Certificate, certificate.logical_id)
    assert latest == stale
    assert len(store.read_all(Certificate)) == 2

    repeated = invalidate_certificates(
        store,
        [certificate],
        changed_files=["decoder.c"],
    )
    assert repeated == []
    assert len(store.read_all(Certificate)) == 2


@pytest.mark.asyncio
async def test_assumption_alone_cannot_resolve_an_obligation(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    assumption = graph.add_assumption(
        Assumption(
            snapshot_id="snapshot-1",
            kind="deployment",
            statement="the parser is remotely reachable",
        )
    )
    candidate = graph.add_candidate(_candidate("snapshot-1", assumption.logical_id))
    obligation = graph.add_obligation(
        Obligation(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            proof_plan_id="memory-write-v1",
            predicate="attacker_input_reaches_sink",
        )
    )
    packet = ContextPacketBuilder().build(
        candidate,
        obligation,
        [],
        [],
        [],
        CompletenessManifest(
            snapshot_id="snapshot-1",
            items={"types": CompletenessItem(status=CompletenessStatus.COMPLETE)},
        ),
        threat_model=ThreatModel(snapshot_id="snapshot-1"),
        assumptions=[assumption],
    )

    class AssumptionOnlyLLM:
        model_name = "test-model"
        provider_name = "test-provider"

        async def aask_text(self, **_kwargs):
            return type(
                "Response",
                (),
                {
                    "first_text": json.dumps(
                        {
                            "status": "proven",
                            "conclusion": "Reachability is assumed.",
                            "cited_fact_ids": [],
                            "cited_evidence_ids": [],
                            "cited_claim_ids": [],
                            "cited_assumption_ids": [assumption.id],
                            "missing_context": [],
                            "limitations": [],
                        }
                    ),
                    "texts": [],
                },
            )()

    resolution = await BoundedModelResolver(AssumptionOnlyLLM()).resolve(
        candidate,
        obligation,
        packet,
    )

    assert resolution.status == ObligationStatus.BLOCKED
    assert resolution.blocked_reason == "Assumptions alone cannot resolve a proof obligation."


@pytest.mark.asyncio
async def test_engine_instantiates_assumptions_for_every_live_candidate(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "decoder.py").write_text(
        "def decode(slice_num, index):\n"
        "    owner_table = [0xFFFF] * 8\n"
        "    slice_num += 1\n"
        "    owner_table[index] = slice_num\n"
        "    return owner_table[index]\n",
        encoding="utf-8",
    )
    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(tmp_path / "results"),
            max_actions=20,
            max_model_calls=0,
            exploration_fraction=0.0,
            falsify=False,
            evaluation_hints={"target_functions": ["decode"]},
        ),
    ).arun()
    store = ProofStore(tmp_path / "results" / result.session_id)
    assumptions = list(store.latest(Assumption).values())
    manifest = json.loads(
        (tmp_path / "results" / result.session_id / "manifest.json").read_text(encoding="utf-8")
    )

    assert result.candidates
    assert assumptions
    assert all(candidate.assumption_ids for candidate in result.candidates)
    assert all(
        assumption.logical_id
        in {
            assumption_id
            for candidate in result.candidates
            for assumption_id in candidate.assumption_ids
        }
        for assumption in assumptions
    )
    assert manifest["evaluation_ablation"] == {
        "assisted": True,
        "hints": {"target_functions": ["decode"]},
    }
    assert manifest["blind_boundary"]["sealed"] is False
    assert manifest["blind_boundary"]["oracle_evidence_permitted"] is False
