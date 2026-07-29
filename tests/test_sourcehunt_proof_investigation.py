"""End-to-end proof investigation component tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clearwing.sourcehunt.proof import (
    Action,
    ActionScheduler,
    ActionStatus,
    BoundedFalsifier,
    BoundedModelResolver,
    Candidate,
    CandidatePipeline,
    CertificateCompiler,
    CertificateKind,
    Claim,
    CompletenessItem,
    CompletenessManifest,
    CompletenessStatus,
    ContextPacketBuilder,
    Evidence,
    ExploratoryLane,
    Fact,
    FactExtractor,
    FalsificationPlanner,
    InvestigationBudget,
    MechanicalResolver,
    Obligation,
    ObligationStatus,
    ProofFlowRunner,
    ProofGraph,
    ProofPlanRegistry,
    ProofReporter,
    ProofStore,
    Provenance,
    SanitizerValidationBackend,
    SourceLocation,
    ThreatModelBuilder,
    ValidationManifest,
    ValidationRequest,
    apply_resolution,
    invalidated_certificates,
)
from clearwing.sourcehunt.proof.extractors import CommandResult


def _fact(kind: str, line: int, **properties) -> Fact:
    return Fact(
        snapshot_id="snapshot-1",
        kind=kind,
        subject=str(properties.pop("subject", "codec.c")),
        properties=properties,
        location=SourceLocation(
            file="codec.c",
            line=line,
            function="decode_slice",
        ),
        provenance=Provenance(producer="test"),
    )


def _ffmpeg_style_facts(*, fixed: bool) -> list[Fact]:
    facts = [
        _fact(
            "sentinel_use",
            10,
            expression="memset(h->slice_table, -1, table_size);",
            values=["-1"],
        ),
        _fact(
            "field",
            11,
            subject="slice_table",
            type="uint16_t *",
            integer_width=16,
            excerpt="uint16_t *slice_table;",
        ),
        _fact(
            "variable",
            20,
            subject="slice_num",
            type="unsigned int",
            integer_width=32,
            excerpt="unsigned int slice_num;",
        ),
        _fact(
            "counter_update",
            30,
            expression="sl->slice_num++;",
        ),
        _fact(
            "assignment",
            40,
            lhs="h->slice_table[mb_xy]",
            rhs="sl->slice_num",
            excerpt="h->slice_table[mb_xy] = sl->slice_num;",
        ),
        _fact(
            "memory_access",
            70,
            expression="h->slice_table[neighbor_xy]",
        ),
    ]
    if fixed:
        facts.append(
            _fact(
                "guard",
                35,
                expression=("if (sl->slice_num >= 0xFFFF) return AVERROR_INVALIDDATA;"),
            )
        )
    return facts


def _completeness() -> CompletenessManifest:
    return CompletenessManifest(
        snapshot_id="snapshot-1",
        items={
            "types": CompletenessItem(
                status=CompletenessStatus.COMPLETE,
                basis="clang-ast",
            ),
            "control_dominators": CompletenessItem(
                status=CompletenessStatus.PARTIAL,
                basis="syntax slice",
            ),
            "indirect_calls": CompletenessItem(
                status=CompletenessStatus.UNRESOLVED,
                unresolved=["callback"],
            ),
        },
    )


def _build_graph(tmp_path, *, fixed: bool):
    facts = _ffmpeg_style_facts(fixed=fixed)
    candidate = CandidatePipeline().generate("snapshot-1", facts).candidates[0]
    threat = ThreatModelBuilder().build(candidate, facts)
    registry = ProofPlanRegistry()
    plans = registry.select(candidate)
    obligations = registry.instantiate(candidate, plans)
    payload = candidate.model_dump(mode="python")
    payload.update(
        {
            "id": "",
            "threat_model_id": threat.logical_id,
            "proof_plan_ids": [plan.id for plan in plans],
            "obligation_ids": [obligation.logical_id for obligation in obligations],
        }
    )
    candidate = Candidate.model_validate(payload)
    store = ProofStore(tmp_path / "session")
    store.append(threat)
    graph = ProofGraph(store, "snapshot-1")
    graph.add_candidate(candidate)
    for obligation in obligations:
        graph.add_obligation(obligation)
    return store, graph, candidate, threat, facts


def test_context_packets_are_bounded_and_preserve_unknown_completeness(tmp_path) -> None:
    store, graph, candidate, threat, facts = _build_graph(tmp_path, fixed=False)
    obligation = next(
        item
        for item in graph.candidate_obligations(candidate.logical_id)
        if item.predicate == "reserved_sentinel_established"
    )
    prior_evidence = Evidence(
        snapshot_id="snapshot-1",
        kind="static_test",
        observations=[{"value": "0xFFFF"}],
        provenance=Provenance(producer="test"),
    )
    prior_claim = Claim(
        snapshot_id="snapshot-1",
        predicate="prior_atomic_claim",
        subject=candidate.logical_id,
        object="The table uses an all-ones sentinel.",
        status=ObligationStatus.PROVEN,
        supporting_evidence_ids=[prior_evidence.id],
    )
    packet = ContextPacketBuilder(max_tokens=1000).build(
        candidate,
        obligation,
        facts,
        [prior_evidence],
        [prior_claim],
        _completeness(),
        threat_model=threat,
    )
    store.append(packet)

    assert packet.token_count <= 1000
    assert packet.completeness.has_unknowns
    assert packet.permitted_outputs == [
        "proven",
        "disproven",
        "unknown",
        "blocked",
        "conflicting_evidence",
    ]
    assert packet.excerpts
    assert packet.threat_model is not None
    assert packet.threat_model["attacker_principal"] == "unknown"
    assert packet.claim_ids == [prior_claim.id]
    assert packet.evidence_ids == [prior_evidence.id]
    assert packet.claim_summaries[0]["object"] == prior_claim.object


def test_mechanical_guard_counterexample_emits_rejection_certificate(tmp_path) -> None:
    store, graph, candidate, threat, facts = _build_graph(tmp_path, fixed=True)
    resolver = MechanicalResolver()
    completeness = _completeness()
    predicates = [
        "reserved_sentinel_established",
        "live_identifier_domain_established",
        "live_domain_overlaps_reserved_value",
        "no_effective_upper_bound_guard",
    ]
    for predicate in predicates:
        obligation = next(
            item
            for item in graph.candidate_obligations(candidate.logical_id)
            if item.predicate == predicate
        )
        resolution = resolver.resolve(
            candidate,
            obligation,
            facts,
            completeness,
        )
        assert resolution is not None
        apply_resolution(graph, store, obligation, resolution)

    guard_obligation = next(
        item
        for item in graph.candidate_obligations(candidate.logical_id)
        if item.predicate == "no_effective_upper_bound_guard"
    )
    assert guard_obligation.status == ObligationStatus.DISPROVEN

    certificate = CertificateCompiler(store, graph).compile(
        candidate,
        threat_model=threat,
        facts=facts,
    )
    assert certificate.kind == CertificateKind.REJECTION
    assert certificate.decision == "disproven"
    assert certificate.evidence_ids
    assert invalidated_certificates(
        [certificate],
        changed_files=["codec.c"],
    ) == [certificate.logical_id]


def test_taint_fact_mechanically_resolves_injection_reachability(
    tmp_path,
) -> None:
    (tmp_path / "handler.py").write_text(
        "import os\ndef handle():\n    user_input = input()\n    os.system(user_input)\n"
    )
    extraction = FactExtractor(tmp_path, "snapshot-1").extract()
    candidate = next(
        item
        for item in CandidatePipeline()
        .generate(
            "snapshot-1",
            extraction.facts,
        )
        .candidates
        if item.suspected_mechanism == "untrusted_data_reaches_interpreter_boundary"
    )
    taint = next(fact for fact in extraction.facts if fact.kind == "taint_path")
    assert taint.id in candidate.fact_ids
    registry = ProofPlanRegistry()
    obligation = next(
        item
        for item in registry.instantiate(candidate, registry.select(candidate))
        if item.predicate == "attacker_data_reaches_interpreter_boundary"
    )

    resolution = MechanicalResolver().resolve(
        candidate,
        obligation,
        extraction.facts,
        extraction.completeness,
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.PROVEN
    assert resolution.evidence[0].kind == "taint_path"


def test_scheduler_uses_mechanical_actions_before_model_routes(tmp_path) -> None:
    store, graph, candidate, _threat, _facts = _build_graph(
        tmp_path,
        fixed=False,
    )
    scheduler = ActionScheduler(
        store,
        graph,
        budget=InvestigationBudget(max_actions=10, max_model_calls=2),
    )

    action = scheduler.next_action(candidate)

    assert action is not None
    assert action.template in {
        "fact_query",
        "type_query",
        "reachability_query",
    }
    assert action.model_route is None
    completed = scheduler.complete(action, status=ActionStatus.COMPLETED)
    assert completed.revision == 2
    assert scheduler.state().actions_total == 1


def test_scheduler_escalates_a_bounded_judgment_local_then_frontier(
    tmp_path,
) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="bounded question",
        invariant_families=["state_machine_safety"],
        suspected_mechanism="test",
        generator="test",
    )
    graph.add_candidate(candidate)
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="test-v1",
        predicate="atomic_security_question",
        available_actions=["bounded_model_judgment"],
    )
    graph.add_obligation(obligation)
    scheduler = ActionScheduler(store, graph)

    local = scheduler.next_action(candidate)
    assert local is not None
    assert local.model_route == "proof_local"
    scheduler.complete(local, status=ActionStatus.FAILED, error="unknown")

    frontier = scheduler.next_action(candidate)
    assert frontier is not None
    assert frontier.model_route == "proof_frontier"


def test_global_scheduler_does_not_let_one_candidate_monopolize_budget(
    tmp_path,
) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    candidates = [
        Candidate(
            snapshot_id="snapshot-1",
            title=f"candidate {index}",
            invariant_families=["state_machine_safety"],
            suspected_mechanism=f"test-{index}",
            generator="test",
        )
        for index in range(2)
    ]
    for candidate in candidates:
        graph.add_candidate(candidate)
        graph.add_obligation(
            Obligation(
                snapshot_id="snapshot-1",
                candidate_id=candidate.logical_id,
                proof_plan_id="test-v1",
                predicate="atomic_question",
                available_actions=["fact_query"],
            )
        )
    scheduler = ActionScheduler(store, graph)

    first = scheduler.next_action(candidates)
    assert first is not None
    scheduler.complete(first, status=ActionStatus.FAILED, error="unknown")
    second = scheduler.next_action(candidates)

    assert second is not None
    assert second.candidate_id != first.candidate_id


def test_falsifier_is_finite_and_receives_atomic_claims(tmp_path) -> None:
    store, graph, candidate, _threat, _facts = _build_graph(
        tmp_path,
        fixed=False,
    )
    claim = Claim(
        snapshot_id="snapshot-1",
        predicate="reserved_sentinel_established",
        subject=candidate.logical_id,
        object="0xFFFF is reserved",
        status=ObligationStatus.PROVEN,
        supporting_evidence_ids=["evidence-1"],
    )
    actions = FalsificationPlanner().plan(
        store,
        candidate,
        graph.candidate_obligations(candidate.logical_id),
        [claim],
    )

    assert 1 <= len(actions) <= 10
    assert all(action.model_route == "proof_falsifier" for action in actions)
    assert all(
        action.inputs["atomic_claims"][0]["claim_id"] == claim.logical_id for action in actions
    )
    plan = json.loads((store.root / "falsification" / f"{candidate.logical_id}.json").read_text())
    assert plan["finite"] is True


def test_falsifier_respects_remaining_budget_and_candidate_scope(tmp_path) -> None:
    store, graph, candidate, _threat, _facts = _build_graph(
        tmp_path,
        fixed=False,
    )
    own_claim = Claim(
        snapshot_id="snapshot-1",
        predicate="own_claim",
        subject=candidate.logical_id,
        object=True,
        status=ObligationStatus.PROVEN,
        supporting_evidence_ids=["evidence-1"],
    )
    foreign_claim = Claim(
        snapshot_id="snapshot-1",
        predicate="foreign_claim",
        subject="candidate-other",
        object=True,
        status=ObligationStatus.PROVEN,
        supporting_evidence_ids=["evidence-2"],
    )

    actions = FalsificationPlanner().plan(
        store,
        candidate,
        graph.candidate_obligations(candidate.logical_id),
        [own_claim, foreign_claim],
        max_actions=2,
    )

    assert len(actions) == 2
    assert all(
        [claim["predicate"] for claim in action.inputs["atomic_claims"]] == ["own_claim"]
        for action in actions
    )


class _SanitizerRunner:
    sandboxed = True
    identity = "test-sandbox"

    def map_path(self, path: Path) -> str:
        return str(path)

    def run(self, arguments, *, cwd: Path, timeout: int) -> CommandResult:
        del arguments, cwd, timeout
        return CommandResult(
            1,
            "",
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
        )


def test_dynamic_backend_keeps_runtime_scope_narrow(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    backend = SanitizerValidationBackend(_SanitizerRunner(), store)
    result = backend.validate(
        ValidationRequest(
            snapshot_id="snapshot-1",
            candidate_id="candidate-1",
            command=("./decoder", "trigger.h264"),
            cwd=tmp_path,
            repeats=2,
        )
    )

    assert result.evidence.kind == "sanitizer_crash"
    assert result.reproductions == 2
    assert "does not establish attacker reachability" in str(result.evidence.reliability["scope"])
    assert store.read_artifact(result.evidence.artifact_uri or "")


def test_manifest_driven_dynamic_action_resolves_only_its_predicate(
    tmp_path,
) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="runtime memory check",
        invariant_families=["spatial_safety"],
        suspected_mechanism="allocation_access_extent_contrast",
        generator="test",
    )
    graph.add_candidate(candidate)
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="memory-write-v1",
        predicate="runtime_confirms_unsafe_memory_access",
        available_actions=["sanitizer_run"],
    )
    graph.add_obligation(obligation)
    action = Action(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        obligation_ids=[obligation.logical_id],
        template="sanitizer_run",
    )
    manifest = ValidationManifest.model_validate(
        {
            "schema_version": 1,
            "commands": [
                {
                    "name": "decoder-asan",
                    "action_template": "sanitizer_run",
                    "obligation_predicate": ("runtime_confirms_unsafe_memory_access"),
                    "candidate_mechanism": ("allocation_access_extent_contrast"),
                    "command": ["./decoder", "trigger.bin"],
                    "repeats": 2,
                    "success_condition": "sanitizer",
                }
            ],
        }
    )

    resolution, evidence_ids = ProofFlowRunner._run_validation_action(
        store,
        graph,
        candidate,
        obligation,
        action,
        _SanitizerRunner(),
        manifest,
        tmp_path,
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.PROVEN
    assert evidence_ids
    apply_resolution(graph, store, obligation, resolution)
    resolved = graph.obligations[obligation.logical_id]
    assert resolved.status == ObligationStatus.PROVEN
    claim = graph.claims[resolved.supporting_claim_ids[0]]
    assert claim.predicate == obligation.predicate
    assert claim.supporting_evidence_ids == evidence_ids


class _JudgmentLLM:
    model_name = "test-model"
    provider_name = "test-provider"

    def __init__(self, payload):
        self.payload = payload

    async def aask_text(self, **kwargs):
        del kwargs
        return type(
            "Response",
            (),
            {"first_text": json.dumps(self.payload), "texts": []},
        )()


@pytest.mark.asyncio
async def test_bounded_model_can_only_cite_packet_records(tmp_path) -> None:
    _store, graph, candidate, threat, facts = _build_graph(
        tmp_path,
        fixed=False,
    )
    obligation = next(
        item
        for item in graph.candidate_obligations(candidate.logical_id)
        if item.predicate == "consumer_cannot_distinguish_live_id_from_sentinel"
    )
    packet = ContextPacketBuilder(max_tokens=1000).build(
        candidate,
        obligation,
        facts,
        [],
        [],
        _completeness(),
        threat_model=threat,
    )
    resolver = BoundedModelResolver(
        _JudgmentLLM(
            {
                "status": "proven",
                "conclusion": "The comparison uses only the stored table value.",
                "cited_fact_ids": [packet.fact_ids[0]],
                "cited_evidence_ids": [],
                "cited_claim_ids": [],
                "missing_context": [],
                "limitations": ["bounded to the supplied consumer slice"],
            }
        )
    )

    resolution = await resolver.resolve(candidate, obligation, packet)

    assert resolution.status == ObligationStatus.PROVEN
    assert resolution.evidence[0].provenance.context_packet_id == packet.id

    invalid = await BoundedModelResolver(
        _JudgmentLLM(
            {
                "status": "proven",
                "conclusion": "Unsupported.",
                "cited_fact_ids": ["fact-outside-packet"],
                "cited_evidence_ids": [],
                "cited_claim_ids": [],
                "missing_context": [],
                "limitations": [],
            }
        )
    ).resolve(candidate, obligation, packet)
    assert invalid.status == ObligationStatus.BLOCKED


@pytest.mark.asyncio
async def test_bounded_falsifier_requires_a_concrete_cited_counterexample(
    tmp_path,
) -> None:
    store, graph, candidate, _threat, facts = _build_graph(
        tmp_path,
        fixed=False,
    )
    obligation = graph.candidate_obligations(candidate.logical_id)[0]
    action = FalsificationPlanner().plan(
        store,
        candidate,
        [obligation],
        [],
        max_actions=1,
    )[0]
    falsifier = BoundedFalsifier(
        _JudgmentLLM(
            {
                "status": "counterexample_found",
                "conclusion": "A rejecting guard prevents the candidate path.",
                "contradicted_obligation_id": obligation.logical_id,
                "cited_fact_ids": [facts[0].id],
                "missing_context": [],
            }
        )
    )

    execution = await falsifier.execute(
        action,
        candidate,
        [obligation],
        facts,
        _completeness(),
    )

    assert execution.completed
    assert execution.resolution is not None
    assert execution.resolution.status == ObligationStatus.DISPROVEN
    assert execution.evidence[0].kind == "falsification_counterexample"
    apply_resolution(graph, store, obligation, execution.resolution)
    ActionScheduler(store, graph).complete(
        action,
        status=ActionStatus.COMPLETED,
        evidence_ids=[execution.evidence[0].logical_id],
        claim_ids=[execution.resolution.claims[0].logical_id],
    )
    FalsificationPlanner.materialize(store, candidate)
    falsification = json.loads(
        (store.root / "falsification" / f"{candidate.logical_id}.json").read_text(encoding="utf-8")
    )
    assert falsification["complete"] is True
    assert falsification["outcome"] == "counterexample_found"
    assert falsification["actions"][0]["status"] == "completed"


def test_reporter_emits_incomplete_state_without_unsupported_findings(tmp_path) -> None:
    store, graph, candidate, threat, facts = _build_graph(
        tmp_path,
        fixed=False,
    )
    certificate = CertificateCompiler(store, graph).compile(
        candidate,
        threat_model=threat,
        facts=facts,
        budget_exhausted=True,
    )

    paths = ProofReporter(store).write(
        [certificate],
        [candidate],
        facts,
    )

    assert certificate.kind == CertificateKind.INCOMPLETE
    assert json.loads(paths["json"].read_text()) == []
    report = paths["markdown"].read_text()
    assert "run budget exhausted" in report
    assert "Unknown and blocked obligations are preserved" in report


def test_sanitizer_evidence_cannot_prove_attacker_reachability(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="untrusted reachability",
        invariant_families=["spatial_safety"],
        suspected_mechanism="test",
        generator="test",
        proof_plan_ids=["memory-write-v1"],
    )
    graph.add_candidate(candidate)
    evidence = Evidence(
        snapshot_id="snapshot-1",
        kind="sanitizer_crash",
        observations=[{"crash": True}],
        provenance=Provenance(producer="test"),
    )
    graph.add_evidence(evidence)
    claim = Claim(
        snapshot_id="snapshot-1",
        predicate="attacker_controls_identifier_progression",
        subject=candidate.logical_id,
        object=True,
        status=ObligationStatus.PROVEN,
        supporting_evidence_ids=[evidence.logical_id],
    )
    graph.add_claim(claim)
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="memory-write-v1",
        predicate="attacker_controls_identifier_progression",
        decisive_rejection=True,
    )
    graph.add_obligation(obligation)
    graph.resolve_obligation(
        obligation.logical_id,
        ObligationStatus.PROVEN,
        supporting_claim_ids=[claim.logical_id],
    )

    certificate = CertificateCompiler(store, graph).compile(
        candidate,
        threat_model=None,
        facts=[],
    )

    assert certificate.kind == CertificateKind.INCOMPLETE
    assert obligation.logical_id in certificate.unresolved_obligation_ids
    assert certificate.report_claims == []


class _ExplorationLLM:
    model_name = "local-test"
    provider_name = "test"

    async def aask_text(self, **kwargs):
        packet = json.loads(kwargs["user"])
        fact_id = packet["facts"][0]["id"]
        payload = {
            "proposals": [
                {
                    "title": "Cross-component state confusion",
                    "suspected_mechanism": "state_value_reused_across_boundary",
                    "invariant_families": ["state_machine_safety"],
                    "cited_fact_ids": [fact_id],
                    "source_symbols": [],
                    "transformations": [],
                    "state_sinks": [],
                    "impact_sinks": [],
                    "suspected_invariants": ["state transitions preserve principal identity"],
                    "unresolved_questions": ["is the transition reachable?"],
                },
                {
                    "title": "Unsupported ontology",
                    "suspected_mechanism": "made_up",
                    "invariant_families": ["made_up_family"],
                    "cited_fact_ids": [fact_id],
                },
            ],
            "ignored_areas": [],
            "proposed_new_invariant_families": [],
        }
        return type(
            "Response",
            (),
            {"first_text": json.dumps(payload), "texts": []},
        )()


@pytest.mark.asyncio
async def test_exploration_can_only_emit_evidence_cited_candidates() -> None:
    facts = [_fact("call", 1, callee="transition")]
    candidates, output, packet = await ExploratoryLane(_ExplorationLLM()).explore(
        "snapshot-1",
        facts,
        _completeness(),
    )

    assert len(output.proposals) == 2
    assert len(candidates) == 1
    assert candidates[0].experimental
    assert candidates[0].generator == "bounded-exploratory-lane"
    assert candidates[0].fact_ids == [packet["facts"][0]["id"]]
