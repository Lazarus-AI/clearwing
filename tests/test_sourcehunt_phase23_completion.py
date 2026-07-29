"""Repository-complete Phase-2 and Phase-3 acceptance tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from clearwing.sourcehunt.proof import (
    Action,
    ActionScheduler,
    ActionStatus,
    Candidate,
    CandidatePipeline,
    CertificateCompiler,
    CertificateKind,
    CompletenessItem,
    CompletenessManifest,
    CompletenessStatus,
    Evidence,
    Fact,
    FactNormalizer,
    InvestigationBudget,
    MechanicalResolver,
    Obligation,
    ObligationStatus,
    ProofFlowRunner,
    ProofGraph,
    ProofPlanRegistry,
    ProofStore,
    ProofTelemetryCompiler,
    Provenance,
    SchedulerCalibrationCompiler,
    SourceLocation,
    ValidationManifest,
    apply_resolution,
)
from clearwing.sourcehunt.proof.extractors import CommandResult
from clearwing.ui.commands import eval as eval_command
from clearwing.ui.commands import sourcehunt as sourcehunt_command


def _fact(
    kind: str,
    line: int,
    expression: str = "",
    *,
    subject: str = "codec.c",
    object: object = None,
    file: str = "codec.c",
    function: str = "decode",
    **properties,
) -> Fact:
    if expression:
        properties["expression"] = expression
    return Fact(
        snapshot_id="snapshot-1",
        kind=kind,
        subject=subject,
        object=object,
        properties=properties,
        location=SourceLocation(file=file, line=line, function=function),
        provenance=Provenance(producer="test"),
    )


def _memory_facts(
    *,
    renamed: bool = False,
    moved: bool = False,
    guarded: bool = False,
    reachable: bool = True,
) -> list[Fact]:
    target = "storage" if renamed else "buffer"
    capacity = "room" if renamed else "capacity"
    requested = "demand" if renamed else "requested"
    file = "lib/moved_codec.c" if moved else "codec.c"
    function = "consume" if moved else "decode"
    facts = [
        _fact(
            "allocation",
            10,
            f"uint8_t *{target} = malloc({capacity});",
            file=file,
            function=function,
        ),
        _fact(
            "memory_write",
            30,
            f"memcpy({target}, input, {requested});",
            file=file,
            function=function,
        ),
        _fact(
            "cast",
            20,
            f"uint16_t narrowed = (uint16_t){requested};",
            file=file,
            function=function,
        ),
        _fact(
            "reachability",
            1,
            f"network_input -> {function}",
            object=reachable,
            file=file,
            function=function,
            reachable=reachable,
        ),
        _fact(
            "call",
            2,
            f"{function}(input, {requested});",
            file=file,
            function=function,
            callee=function,
        ),
    ]
    if guarded:
        facts.append(
            _fact(
                "guard",
                25,
                f"if ({requested} > {capacity}) return -1;",
                file=file,
                function=function,
                control_effect="return",
            )
        )
    return FactNormalizer().normalize(facts)


def _complete_callgraph() -> CompletenessManifest:
    return CompletenessManifest(
        snapshot_id="snapshot-1",
        items={
            "direct_calls": CompletenessItem(
                status=CompletenessStatus.COMPLETE,
                basis="fixture callgraph",
            ),
            "indirect_calls": CompletenessItem(
                status=CompletenessStatus.COMPLETE,
                basis="fixture has no indirect calls",
            ),
            "types": CompletenessItem(
                status=CompletenessStatus.COMPLETE,
                basis="fixture types",
            ),
            "control_dominators": CompletenessItem(
                status=CompletenessStatus.COMPLETE,
                basis="fixture CFG",
            ),
        },
    )


def _spatial_candidate(facts: list[Fact]) -> Candidate:
    return next(
        candidate
        for candidate in CandidatePipeline().generate("snapshot-1", facts).candidates
        if candidate.suspected_mechanism == "allocation_access_extent_contrast"
    )


def test_memory_facts_are_normalized_into_explicit_roles() -> None:
    facts = _memory_facts(guarded=True)
    allocation = next(fact for fact in facts if fact.kind == "allocation")
    write = next(fact for fact in facts if fact.kind == "memory_write")
    guard = next(fact for fact in facts if fact.kind == "guard")
    lengths = {fact.subject: fact for fact in facts if fact.kind == "length"}

    assert allocation.properties["target"] == "buffer"
    assert allocation.properties["extent"] == "capacity"
    assert write.properties["target"] == "buffer"
    assert write.properties["extent"] == "requested"
    assert guard.properties["comparisons"] == [
        {"left": "requested", "operator": ">", "right": "capacity"}
    ]
    assert guard.properties["rejecting"] is True
    assert lengths["capacity"].properties["roles"] == ["allocation_extent"]
    assert lengths["requested"].properties["roles"] == ["access_extent"]


def test_spatial_generator_is_stable_under_rename_and_move_and_ignores_decoy() -> None:
    original = _memory_facts()
    decoy = FactNormalizer().normalize(
        [
            _fact("allocation", 40, "uint8_t *other = malloc(64);"),
            _fact("memory_write", 41, "memcpy(other, constant, 8);"),
        ]
    )
    renamed = _memory_facts(renamed=True)
    moved = _memory_facts(moved=True)

    original_candidates = CandidatePipeline().generate("snapshot-1", [*original, *decoy]).candidates
    mechanisms = {candidate.suspected_mechanism for candidate in original_candidates}

    assert "allocation_access_extent_contrast" in mechanisms
    assert (
        len(
            [
                candidate
                for candidate in original_candidates
                if candidate.suspected_mechanism == "allocation_access_extent_contrast"
            ]
        )
        == 2
    )
    decoy_candidate = next(
        candidate for candidate in original_candidates if "other" in candidate.state_sinks
    )
    decoy_bounds = next(
        obligation
        for obligation in ProofPlanRegistry().instantiate(
            decoy_candidate,
            ProofPlanRegistry().select(decoy_candidate),
        )
        if obligation.predicate == "access_exceeds_live_object_bounds"
    )
    decoy_resolution = MechanicalResolver().resolve(
        decoy_candidate,
        decoy_bounds,
        [*original, *decoy],
        _complete_callgraph(),
    )
    assert decoy_resolution is not None
    assert decoy_resolution.status == ObligationStatus.DISPROVEN
    assert decoy_resolution.evidence[0].kind == "static_extent_containment"
    assert _spatial_candidate(renamed).suspected_mechanism == (
        _spatial_candidate(original).suspected_mechanism
    )
    assert _spatial_candidate(moved).proof_plan_ids == []
    assert ProofPlanRegistry().select(_spatial_candidate(moved))[0].id == "memory-write-v1"


def test_spatial_guard_and_unreachability_are_decisive_counterexamples(tmp_path) -> None:
    resolver = MechanicalResolver()
    fixed_facts = _memory_facts(guarded=True)
    fixed = _spatial_candidate(fixed_facts)
    obligations = ProofPlanRegistry().instantiate(
        fixed,
        ProofPlanRegistry().select(fixed),
    )
    bounds = next(
        obligation
        for obligation in obligations
        if obligation.predicate == "access_exceeds_live_object_bounds"
    )

    guard_resolution = resolver.resolve(
        fixed,
        bounds,
        fixed_facts,
        _complete_callgraph(),
    )

    assert guard_resolution is not None
    assert guard_resolution.status == ObligationStatus.DISPROVEN
    assert guard_resolution.evidence[0].kind == "dominating_spatial_guard"

    unreachable_facts = _memory_facts(reachable=False)
    unreachable = _spatial_candidate(unreachable_facts)
    reachability = next(
        obligation
        for obligation in ProofPlanRegistry().instantiate(
            unreachable,
            ProofPlanRegistry().select(unreachable),
        )
        if obligation.predicate == "attacker_reaches_memory_operation"
    )
    unreachable_resolution = resolver.resolve(
        unreachable,
        reachability,
        unreachable_facts,
        _complete_callgraph(),
    )

    assert unreachable_resolution is not None
    assert unreachable_resolution.status == ObligationStatus.DISPROVEN
    assert unreachable_resolution.evidence[0].kind == "complete_unreachability_proof"

    store = ProofStore(tmp_path / "unreachable-session")
    graph = ProofGraph(store, "snapshot-1")
    graph.add_candidate(unreachable)
    for item in ProofPlanRegistry().instantiate(
        unreachable,
        ProofPlanRegistry().select(unreachable),
    ):
        graph.add_obligation(item)
    graph_reachability = next(
        item
        for item in graph.candidate_obligations(unreachable.logical_id)
        if item.predicate == "attacker_reaches_memory_operation"
    )
    apply_resolution(
        graph,
        store,
        graph_reachability,
        unreachable_resolution,
    )
    certificate = CertificateCompiler(store, graph).compile(
        unreachable,
        threat_model=None,
        facts=unreachable_facts,
    )
    assert certificate.kind == CertificateKind.REJECTION


def test_unresolved_indirect_calls_block_unreachability_rejection() -> None:
    facts = _memory_facts(reachable=False)
    candidate = _spatial_candidate(facts)
    reachability = next(
        obligation
        for obligation in ProofPlanRegistry().instantiate(
            candidate,
            ProofPlanRegistry().select(candidate),
        )
        if obligation.predicate == "attacker_reaches_memory_operation"
    )
    incomplete_callgraph = CompletenessManifest(
        snapshot_id="snapshot-1",
        items={
            "direct_calls": CompletenessItem(
                status=CompletenessStatus.COMPLETE,
                basis="fixture direct callgraph",
            ),
            "indirect_calls": CompletenessItem(
                status=CompletenessStatus.PARTIAL,
                basis="unresolved callback",
                unresolved=["decoder->write"],
            ),
        },
    )

    resolution = MechanicalResolver().resolve(
        candidate,
        reachability,
        facts,
        incomplete_callgraph,
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.BLOCKED
    assert resolution.evidence == []
    assert "indirect calls" in (resolution.blocked_reason or "")


class _TemplateHarnessRunner:
    sandboxed = True
    identity = "phase2-test-sandbox"

    def __init__(self, root: Path):
        self.root = root
        self.writes: dict[str, bytes] = {}
        self.commands: list[list[str]] = []

    def map_path(self, path: Path) -> str:
        return "/workspace/" + path.resolve().relative_to(self.root).as_posix()

    def write_file(self, path: str, content: bytes) -> None:
        self.writes[path] = content

    def run(self, arguments, *, cwd: Path, timeout: int) -> CommandResult:
        del cwd, timeout
        command = list(arguments)
        self.commands.append(command)
        if command[0] == "clang":
            return CommandResult(0, "compiled", "")
        return CommandResult(
            77,
            "",
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
        )


def test_proof_flow_reuses_a_sandboxed_libfuzzer_template(tmp_path) -> None:
    (tmp_path / "codec.c").write_text(
        "int decode(const unsigned char *data, size_t size) { return data[size]; }\n"
    )
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="template harness",
        invariant_families=["spatial_safety"],
        suspected_mechanism="allocation_access_extent_contrast",
        generator="test",
    )
    graph.add_candidate(candidate)
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="memory-write-v1",
        predicate="concrete_trigger_satisfies_path",
        available_actions=["harness"],
    )
    graph.add_obligation(obligation)
    action = Action(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        obligation_ids=[obligation.logical_id],
        template="harness",
    )
    manifest = ValidationManifest.model_validate(
        {
            "commands": [
                {
                    "name": "decode-template",
                    "action_template": "harness",
                    "obligation_predicate": "concrete_trigger_satisfies_path",
                    "candidate_mechanism": "allocation_access_extent_contrast",
                    "harness_template": {
                        "target_function": "decode",
                        "signature": "int decode(const uint8_t *, size_t)",
                        "source_files": ["codec.c"],
                        "duration_seconds": 5,
                    },
                    "success_condition": "sanitizer",
                }
            ]
        }
    )
    runner = _TemplateHarnessRunner(tmp_path)

    resolution, evidence_ids = ProofFlowRunner._run_validation_action(
        store,
        graph,
        candidate,
        obligation,
        action,
        runner,
        manifest,
        tmp_path,
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.PROVEN
    assert len(evidence_ids) == 2
    assert any(path.endswith(".c") for path in runner.writes)
    assert runner.commands[0][0] == "clang"
    kinds = {evidence.kind for evidence in store.latest(Evidence).values()}
    assert {"harness_build", "sanitizer_crash"} <= kinds


def test_scheduler_calibration_is_compiled_and_consumed(tmp_path) -> None:
    calibration_store = ProofStore(tmp_path / "calibration-session")
    successful = Action(
        snapshot_id="snapshot-1",
        candidate_id="candidate-1",
        obligation_ids=["obligation-1"],
        template="bounded_model_judgment",
        model_route="proof_local",
        status=ActionStatus.COMPLETED,
        output_claim_ids=["claim-1"],
        estimated_seconds=12,
        observed_seconds=3,
    )
    calibration_store.append(successful)
    (calibration_store.root / "spend-ledger.jsonl").write_text(
        json.dumps(
            {
                "event": "call_settled",
                "cost_usd": 0.02,
                "metadata": {"proof_action_id": successful.logical_id},
            }
        )
        + "\n"
    )
    calibration = SchedulerCalibrationCompiler().compile([calibration_store.root])
    profile = calibration.get("bounded_model_judgment", "proof_local")

    assert profile is not None
    assert profile.attempts == 1
    assert profile.informative == 1
    assert profile.mean_cost_usd == pytest.approx(0.02)
    assert profile.mean_duration_seconds == pytest.approx(3)

    store = ProofStore(tmp_path / "scheduled-session")
    graph = ProofGraph(store, "snapshot-1")
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="calibrated question",
        invariant_families=["state_machine_safety"],
        suspected_mechanism="test",
        generator="test",
    )
    graph.add_candidate(candidate)
    graph.add_obligation(
        Obligation(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            proof_plan_id="test-v1",
            predicate="atomic_question",
            available_actions=["bounded_model_judgment"],
        )
    )
    action = ActionScheduler(store, graph, calibration=calibration).next_action(candidate)

    assert action is not None
    assert action.model_route == "proof_local"
    assert action.estimated_cost_usd == pytest.approx(0.02)
    assert action.inputs["calibration_profile"] == ("bounded_model_judgment::proof_local")
    assert 0 < action.expected_information_gain <= 1


def test_scheduler_records_observed_action_time(tmp_path) -> None:
    store = ProofStore(tmp_path / "timing-session")
    graph = ProofGraph(store, "snapshot-1")
    scheduler = ActionScheduler(store, graph)
    action = Action(
        snapshot_id="snapshot-1",
        candidate_id="candidate-1",
        obligation_ids=["obligation-1"],
        template="fact_query",
    )

    running = scheduler.complete(action, status=ActionStatus.RUNNING)
    completed = scheduler.complete(running, status=ActionStatus.COMPLETED)

    assert running.started_at is not None
    assert completed.completed_at is not None
    assert completed.observed_seconds is not None
    assert completed.observed_seconds >= 0


def test_structured_budget_is_enforced_and_unattempted_candidates_are_aged(
    tmp_path,
) -> None:
    store = ProofStore(tmp_path / "session")
    graph = ProofGraph(store, "snapshot-1")
    candidates = [
        Candidate(
            snapshot_id="snapshot-1",
            title=f"candidate {index}",
            invariant_families=["spatial_safety"],
            suspected_mechanism=f"test-{index}",
            generator="test",
        )
        for index in range(3)
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
    scheduler = ActionScheduler(
        store,
        graph,
        budget=InvestigationBudget(
            max_actions=4,
            max_model_calls=0,
            structured_fraction=0.5,
            exploration_fraction=0.5,
        ),
    )

    first = scheduler.next_action(candidates)
    assert first is not None
    scheduler.complete(first, status=ActionStatus.FAILED)
    second = scheduler.next_action(candidates)
    assert second is not None
    assert second.candidate_id != first.candidate_id
    scheduler.complete(second, status=ActionStatus.FAILED)

    assert scheduler.state().structured_actions == 2
    assert scheduler.next_action(candidates) is None


def test_frontier_routing_is_audited_as_an_explicit_local_escalation(tmp_path) -> None:
    store = ProofStore(tmp_path / "session")
    local = Action(
        snapshot_id="snapshot-1",
        candidate_id="candidate-1",
        obligation_ids=["obligation-1"],
        template="bounded_model_judgment",
        model_route="proof_local",
        status=ActionStatus.FAILED,
        error="insufficient context",
    )
    frontier = Action(
        snapshot_id="snapshot-1",
        candidate_id="candidate-1",
        obligation_ids=["obligation-1"],
        template="bounded_model_judgment",
        model_route="proof_frontier",
        status=ActionStatus.COMPLETED,
        output_claim_ids=["claim-1"],
    )
    store.append_many([local, frontier])

    metrics = ProofTelemetryCompiler(store).compile()

    assert metrics["routing"]["frontier_actions"] == 1
    assert metrics["routing"]["frontier_with_prior_local_ambiguity"] == 1
    assert metrics["routing"]["explicit_frontier_escalation_rate"] == 1.0
    assert metrics["routing"]["frontier_ambiguity_resolution_rate"] == 1.0


def test_phase23_cli_help_exposes_operational_controls(capsys) -> None:
    parser = argparse.ArgumentParser(prog="clearwing")
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)
    eval_command.add_parser(subparsers)

    with pytest.raises(SystemExit) as sourcehunt_exit:
        parser.parse_args(["sourcehunt", "--help"])
    assert sourcehunt_exit.value.code == 0
    sourcehunt_help = capsys.readouterr().out
    assert "--scheduler-calibration" in sourcehunt_help
    assert "--proof-local-model" in sourcehunt_help
    assert "--proof-frontier-model" in sourcehunt_help

    with pytest.raises(SystemExit) as eval_exit:
        parser.parse_args(["eval", "--help"])
    assert eval_exit.value.code == 0
    eval_help = capsys.readouterr().out
    assert "sourcehunt-calibrate" in eval_help
    assert "sourcehunt-counterfactual" in eval_help
