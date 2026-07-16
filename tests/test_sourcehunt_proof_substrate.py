"""Tests for the proof-carrying sourcehunt substrate."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from clearwing.sourcehunt.proof import (
    Candidate,
    Certificate,
    CertificateKind,
    Claim,
    Evidence,
    Obligation,
    ObligationStatus,
    ProofGraph,
    ProofStore,
    Provenance,
    RepositorySnapshot,
)


def _candidate(snapshot_id: str) -> Candidate:
    return Candidate(
        snapshot_id=snapshot_id,
        title="length narrowing reaches copy",
        invariant_families=["spatial_safety", "representation_domain_safety"],
        suspected_mechanism="allocation_length_narrowed_but_copy_length_not_narrowed",
        source_symbols=["payload_len"],
        state_sinks=["allocation"],
        impact_sinks=["memcpy"],
        suspected_invariants=["copied region is within allocated region"],
        generator="test",
    )


def _claim(snapshot_id: str, subject: str) -> Claim:
    return Claim(
        snapshot_id=snapshot_id,
        predicate="test_predicate",
        subject=subject,
    )


def test_models_are_strict_frozen_and_deterministically_identified() -> None:
    provenance = Provenance(producer="unit-test")
    left = Evidence(
        snapshot_id="snapshot-1",
        kind="source_excerpt",
        observations=[{"value": 42}],
        provenance=provenance,
    )
    right = Evidence(
        snapshot_id="snapshot-1",
        kind="source_excerpt",
        observations=[{"value": 42}],
        provenance=provenance,
    )

    assert left.id == right.id
    assert left.logical_id == right.logical_id
    with pytest.raises(ValidationError):
        Evidence.model_validate(
            {
                **left.model_dump(mode="json"),
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        left.kind = "changed"  # type: ignore[misc]


def test_store_is_append_only_and_content_addressed(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    snapshot = RepositorySnapshot(repo_path="/repo", commit="abc")
    store.append(snapshot)
    candidate = _candidate(snapshot.id)
    store.append(candidate)

    uri, digest = store.store_artifact(
        "sanitizer output",
        media_type="text/plain",
        name="asan.txt",
    )
    duplicate_uri, duplicate_digest = store.store_artifact("sanitizer output")

    assert uri == duplicate_uri == f"sha256:{digest}"
    assert digest == duplicate_digest
    assert store.read_artifact(uri) == b"sanitizer output"
    assert store.get(Candidate, candidate.id) == candidate
    assert len(store.read_all(Candidate)) == 1

    path = store.path_for(Candidate)
    path.write_text(path.read_text() + '{"truncated":', encoding="utf-8")
    assert store.read_all(Candidate) == [candidate]


def test_graph_propagates_stale_state_when_a_dependency_changes(tmp_path) -> None:
    snapshot = RepositorySnapshot(repo_path="/repo", commit="abc")
    store = ProofStore(tmp_path / "session")
    store.append(snapshot)
    graph = ProofGraph(store, snapshot.id)
    candidate = graph.add_candidate(_candidate(snapshot.id))

    reachability = graph.add_obligation(
        Obligation(
            snapshot_id=snapshot.id,
            candidate_id=candidate.id,
            proof_plan_id="memory-write-v1",
            predicate="attacker_input_reaches_sink",
        )
    )
    bounds = graph.add_obligation(
        Obligation(
            snapshot_id=snapshot.id,
            candidate_id=candidate.id,
            proof_plan_id="memory-write-v1",
            predicate="access_exceeds_object_bounds",
            dependencies=[reachability.logical_id],
        )
    )

    assert graph.ready_obligations(candidate.id) == [reachability]

    reachable_claim = graph.add_claim(_claim(snapshot.id, "copy"))
    graph.resolve_obligation(
        reachability.logical_id,
        ObligationStatus.PROVEN,
        supporting_claim_ids=[reachable_claim.id],
    )
    assert graph.ready_obligations(candidate.id) == [bounds]

    bounds_claim = graph.add_claim(_claim(snapshot.id, "allocation"))
    proven_bounds = graph.resolve_obligation(
        bounds.logical_id,
        ObligationStatus.PROVEN,
        supporting_claim_ids=[bounds_claim.id],
    )
    not_reachable_claim = graph.add_claim(_claim(snapshot.id, "entry"))
    graph.resolve_obligation(
        reachability.logical_id,
        ObligationStatus.DISPROVEN,
        contradicting_claim_ids=[not_reachable_claim.id],
    )

    assert graph.obligations[bounds.logical_id].status == ObligationStatus.STALE
    assert graph.obligations[bounds.logical_id].revision == 3
    assert graph.obligations[bounds.logical_id].supersedes == proven_bounds.id

    materialized = graph.materialize(candidate.id)
    assert materialized["edges"] == [
        {
            "from": reachability.logical_id,
            "to": bounds.logical_id,
            "kind": "requires",
        }
    ]


def test_graph_rejects_dangling_dependencies_without_persisting_them(tmp_path) -> None:
    snapshot = RepositorySnapshot(repo_path="/repo")
    store = ProofStore(tmp_path / "session")
    store.append(snapshot)
    graph = ProofGraph(store, snapshot.id)
    candidate = graph.add_candidate(_candidate(snapshot.id))
    invalid = Obligation(
        snapshot_id=snapshot.id,
        candidate_id=candidate.id,
        proof_plan_id="memory-write-v1",
        predicate="unsafe_access",
        dependencies=["missing-obligation"],
    )

    with pytest.raises(ValueError, match="missing dependency"):
        graph.add_obligation(invalid)

    assert store.read_all(Obligation) == []


def test_certificates_get_queryable_json_views(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    certificate = Certificate(
        snapshot_id="snapshot-1",
        kind=CertificateKind.INCOMPLETE,
        candidate_id="candidate-1",
        proof_plan_ids=["memory-write-v1"],
        decision="incomplete",
        reason="runtime evidence unavailable",
        unresolved_obligation_ids=["obligation-1"],
    )
    store.append(certificate)

    view = (
        tmp_path
        / "session"
        / "certificates"
        / "incomplete"
        / f"{certificate.id}.json"
    )
    assert json.loads(view.read_text())["candidate_id"] == "candidate-1"
