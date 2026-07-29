"""Repository-complete Phase-4 and Phase-5 acceptance tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from clearwing.sourcehunt.proof import (
    Action,
    ActionStatus,
    AuthorizationBoundaryGenerator,
    Candidate,
    Certificate,
    CertificateKind,
    CompletenessItem,
    CompletenessManifest,
    CompletenessStatus,
    ConcurrencyResourceGenerator,
    CryptographicPropertyGenerator,
    Evidence,
    Fact,
    FactNormalizer,
    InjectionBoundaryGenerator,
    LearnedMechanismGenerator,
    LearningCoverageCompiler,
    LearningRegistry,
    MechanicalResolver,
    Obligation,
    ObligationStatus,
    ParserBoundaryGenerator,
    ProofFlowRunner,
    ProofGraph,
    ProofPlanRegistry,
    ProofRunConfig,
    ProofStore,
    ProofTelemetryCompiler,
    Provenance,
    RetrospectiveBundle,
    RetrospectiveCompiler,
    SourceLocation,
    StateMachineGenerator,
    TemporalSafetyGenerator,
    ValidationManifest,
)
from clearwing.sourcehunt.proof.extractors import CommandResult
from clearwing.ui.commands import eval as eval_command
from clearwing.ui.commands import sourcehunt as sourcehunt_command


def _fact(
    kind: str,
    line: int,
    expression: str = "",
    *,
    subject: str = "fixture",
    object: object = None,
    file: str = "service.c",
    function: str = "handle",
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
        provenance=Provenance(producer="phase45-test"),
    )


def _complete_analysis() -> CompletenessManifest:
    complete = lambda basis: CompletenessItem(  # noqa: E731
        status=CompletenessStatus.COMPLETE,
        basis=basis,
    )
    return CompletenessManifest(
        snapshot_id="snapshot-1",
        items={
            "direct_calls": complete("fixture direct calls"),
            "indirect_calls": complete("fixture indirect calls"),
            "control_dominators": complete("fixture CFG"),
            "data_dependencies": complete("fixture dataflow"),
            "lifetime_analysis": complete("fixture ownership"),
        },
    )


_PHASE4_PLANS = {
    "parser-integer-domain-v2": "symbolic_memory_violation",
    "authorization-boundary-v2": "authorization_differential",
    "temporal-memory-safety-v2": "sanitizer_uaf",
    "state-machine-safety-v2": "protocol_transition_violation",
    "cryptographic-property-v2": "cryptographic_differential",
    "injection-boundary-v2": "injection_differential",
    "concurrency-resource-v2": "race_detector_violation",
}


def test_every_phase4_plan_has_rejection_and_hard_evidence_gates() -> None:
    registry = ProofPlanRegistry()

    for plan_id, evidence_kind in _PHASE4_PLANS.items():
        plan = registry.get(plan_id)
        assert plan.obligations
        assert any(item.decisive_rejection for item in plan.obligations)
        assert plan.decisive_evidence_kinds
        assert evidence_kind in plan.decisive_evidence_kinds


class _Phase4Runner:
    sandboxed = True
    identity = "phase4-validation-sandbox"

    def __init__(self, root: Path):
        self.root = root

    def map_path(self, path: Path) -> str:
        return "/workspace/" + path.resolve().relative_to(self.root).as_posix()

    def write_file(self, path: str, content: bytes) -> None:
        del path, content

    def run(self, arguments, *, cwd: Path, timeout: int) -> CommandResult:
        del cwd, timeout
        if arguments[0] == "race":
            return CommandResult(66, "", "WARNING: ThreadSanitizer: data race")
        return CommandResult(0, "VIOLATION CONFIRMED", "")


@pytest.mark.parametrize(
    ("label", "action_template", "predicate", "evidence_kind", "sanitizer"),
    [
        (
            "parser",
            "symbolic_execution",
            "runtime_confirms_parser_boundary_violation",
            "symbolic_memory_violation",
            False,
        ),
        (
            "authorization",
            "differential_test",
            "unauthorized_operation_is_permitted",
            "authorization_differential",
            False,
        ),
        (
            "temporal",
            "race_detector",
            "runtime_confirms_temporal_violation",
            "race_detector_violation",
            True,
        ),
        (
            "state",
            "protocol_replay",
            "attacker_reaches_illegal_transition",
            "protocol_transition_violation",
            False,
        ),
        (
            "state-model-check",
            "model_check",
            "attacker_reaches_illegal_transition",
            "protocol_transition_violation",
            False,
        ),
        (
            "crypto",
            "differential_test",
            "cryptographic_violation_has_concrete_consequence",
            "cryptographic_differential",
            False,
        ),
        (
            "injection",
            "differential_test",
            "input_changes_interpreted_structure",
            "injection_differential",
            False,
        ),
        (
            "concurrency",
            "race_detector",
            "bounded_execution_violates_shared_or_resource_invariant",
            "race_detector_violation",
            True,
        ),
        (
            "schedule",
            "schedule_perturbation",
            "bounded_execution_violates_shared_or_resource_invariant",
            "race_detector_violation",
            False,
        ),
        (
            "resource",
            "load_test",
            "bounded_execution_violates_shared_or_resource_invariant",
            "bounded_resource_exhaustion",
            False,
        ),
        (
            "fault",
            "fault_injection",
            "error_path_violates_security_invariant",
            "fault_injection_violation",
            False,
        ),
        (
            "configuration",
            "configuration_matrix",
            "violation_occurs_in_realistic_configuration",
            "configuration_differential",
            False,
        ),
        (
            "patch",
            "patch_differential",
            "fix_removes_security_violation",
            "patch_differential",
            False,
        ),
    ],
)
def test_phase4_validation_matrix_produces_typed_positive_evidence(
    tmp_path,
    label,
    action_template,
    predicate,
    evidence_kind,
    sanitizer,
) -> None:
    store = ProofStore(tmp_path / label)
    graph = ProofGraph(store, "snapshot-1")
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title=label,
        invariant_families=["resource_safety"],
        suspected_mechanism=f"phase4:{label}",
        generator="test",
    )
    graph.add_candidate(candidate)
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="phase4-test-v1",
        predicate=predicate,
        available_actions=[action_template],
    )
    graph.add_obligation(obligation)
    command = "race" if sanitizer else label
    spec = {
        "name": label,
        "action_template": action_template,
        "obligation_predicate": predicate,
        "candidate_mechanism": candidate.suspected_mechanism,
        "command": [command],
        "success_condition": "sanitizer" if sanitizer else "output_regex",
    }
    if sanitizer:
        spec["repeats"] = 1
    else:
        spec["output_regex"] = "VIOLATION CONFIRMED"
        spec["evidence_kind"] = evidence_kind
    manifest = ValidationManifest.model_validate({"commands": [spec]})
    action = Action(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        obligation_ids=[obligation.logical_id],
        template=action_template,
    )

    resolution, evidence_ids = ProofFlowRunner._run_validation_action(
        store,
        graph,
        candidate,
        obligation,
        action,
        _Phase4Runner(tmp_path),
        manifest,
        tmp_path,
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.PROVEN
    assert evidence_ids
    assert store.latest(Evidence)[evidence_ids[-1]].kind == evidence_kind


@pytest.mark.parametrize(
    ("family", "plan_id", "predicate", "facts", "sources", "evidence_kind"),
    [
        (
            "parser_safety",
            "parser-integer-domain-v2",
            "cursor_plus_length_exceeds_validated_boundary",
            [
                _fact(
                    "guard",
                    10,
                    "if (offset >= packet_size) return error;",
                    control_effect="return",
                    range_complete=True,
                ),
                _fact("memory_access", 12, "packet[offset]"),
            ],
            ["offset", "packet_size"],
            "dominating_parser_boundary_guard",
        ),
        (
            "authority_safety",
            "authorization-boundary-v2",
            "unauthorized_operation_is_permitted",
            [
                _fact(
                    "guard", 10, "if (!principal.is_owner) return denied;", control_effect="return"
                ),
                _fact("call", 12, "delete_account(id)", callee="delete_account"),
            ],
            [],
            "dominating_authorization_guard",
        ),
        (
            "temporal_safety",
            "temporal-memory-safety-v2",
            "dereference_occurs_outside_live_interval",
            [
                _fact("call", 10, "free(packet)", callee="free"),
                _fact("call", 11, "retain(packet)", callee="retain"),
                _fact("memory_access", 12, "packet[index]"),
            ],
            ["packet"],
            "static_lifetime_reacquisition",
        ),
        (
            "state_machine_safety",
            "state-machine-safety-v2",
            "attacker_reaches_illegal_transition",
            [_fact("state_transition", 10, permitted=True, analysis_complete=True)],
            [],
            "static_permitted_transition",
        ),
        (
            "cryptographic_safety",
            "cryptographic-property-v2",
            "cryptographic_precondition_is_violated",
            [_fact("crypto_precondition", 10, violated=False)],
            [],
            "static_cryptographic_precondition_satisfied",
        ),
        (
            "injection_safety",
            "injection-boundary-v2",
            "required_structural_encoding_is_absent",
            [_fact("encoding", 10, effective=True)],
            [],
            "static_structural_encoding",
        ),
        (
            "concurrency_safety",
            "concurrency-resource-v2",
            "bounded_execution_violates_shared_or_resource_invariant",
            [_fact("synchronization", 10, primitive="mutex", effective=True)],
            [],
            "static_shared_or_resource_protection",
        ),
        (
            "resource_safety",
            "concurrency-resource-v2",
            "bounded_execution_violates_shared_or_resource_invariant",
            [_fact("resource_limit", 10, bound=100, effective=True)],
            [],
            "static_shared_or_resource_protection",
        ),
    ],
)
def test_phase4_safe_counterfactuals_resolve_as_decisive_rejections(
    family,
    plan_id,
    predicate,
    facts,
    sources,
    evidence_kind,
) -> None:
    normalized = FactNormalizer().normalize(facts)
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title=family,
        invariant_families=[family],
        suspected_mechanism=f"phase4-safe:{family}",
        source_symbols=sources,
        fact_ids=[fact.id for fact in normalized],
        proof_plan_ids=[plan_id],
        generator="test",
    )
    registry = ProofPlanRegistry()
    obligation = next(
        item
        for item in registry.instantiate(candidate, registry.select(candidate))
        if item.predicate == predicate
    )

    resolution = MechanicalResolver().resolve(
        candidate,
        obligation,
        normalized,
        _complete_analysis(),
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.DISPROVEN
    assert resolution.evidence[0].kind == evidence_kind


@pytest.mark.parametrize(
    ("family", "predicate", "fact"),
    [
        (
            "parser_safety",
            "cursor_plus_length_exceeds_validated_boundary",
            _fact(
                "guard",
                10,
                "if (offset >= packet_size) return error;",
                control_effect="return",
            ),
        ),
        (
            "injection_safety",
            "required_structural_encoding_is_absent",
            _fact("call", 10, "escape(user_input)", callee="escape"),
        ),
        (
            "concurrency_safety",
            "bounded_execution_violates_shared_or_resource_invariant",
            _fact("call", 10, "pthread_mutex_lock(&lock)", callee="pthread_mutex_lock"),
        ),
        (
            "resource_safety",
            "bounded_execution_violates_shared_or_resource_invariant",
            _fact("resource_limit", 10, bound=100),
        ),
        (
            "state_machine_safety",
            "attacker_reaches_illegal_transition",
            _fact("state_transition", 10, permitted=True),
        ),
    ],
)
def test_phase4_incidental_protection_markers_do_not_prove_safety(
    family,
    predicate,
    fact,
) -> None:
    normalized = FactNormalizer().normalize([fact])
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title=family,
        invariant_families=[family],
        suspected_mechanism=f"phase4-ambiguous:{family}",
        fact_ids=[item.id for item in normalized],
        generator="test",
    )
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="phase4-test-v1",
        predicate=predicate,
    )

    resolution = MechanicalResolver().resolve(
        candidate,
        obligation,
        normalized,
        _complete_analysis(),
    )

    assert resolution is not None
    assert resolution.status == ObligationStatus.BLOCKED


def _counterfactual_facts(kind: str, name: str, *, moved: bool) -> list[Fact]:
    file = "moved/component.c" if moved else "component.c"
    function = "relocated" if moved else "handle"
    factory = lambda fact_kind, line, expression="", **properties: _fact(  # noqa: E731
        fact_kind,
        line,
        expression,
        file=file,
        function=function,
        **properties,
    )
    if kind == "parser":
        extent = "offset" if name == "request" else "cursor"
        return [
            factory("guard", 10, f"if ({extent} >= packet_size) return error"),
            factory("memory_access", 12, f"packet[{extent}]"),
        ]
    if kind == "authorization":
        return [factory("call", 10, f"delete_account({name})", callee="delete_account")]
    if kind == "temporal":
        return [
            factory("call", 10, f"free({name})", callee="free"),
            factory("memory_access", 12, f"{name}[index]"),
        ]
    if kind == "crypto":
        return [factory("call", 10, f"sha1({name})", callee="sha1")]
    if kind == "injection":
        return [factory("call", 10, f"execute({name})", callee="execute")]
    if kind == "state":
        return [factory("assignment", 10, f"{name}.state = AUTHENTICATED", lhs=f"{name}.state")]
    if kind == "resource":
        return [
            factory("loop", 10, f"while ({name}.more)"),
            factory("allocation", 12, f"malloc({name}.size)"),
        ]
    if kind == "concurrency":
        return [
            factory("call", 10, "pthread_create(...) ", callee="pthread_create"),
            factory("memory_write", 12, f"{name}[index] = value"),
        ]
    raise AssertionError(kind)


@pytest.mark.parametrize(
    ("kind", "generator"),
    [
        ("parser", ParserBoundaryGenerator()),
        ("authorization", AuthorizationBoundaryGenerator()),
        ("temporal", TemporalSafetyGenerator()),
        ("crypto", CryptographicPropertyGenerator()),
        ("injection", InjectionBoundaryGenerator()),
        ("state", StateMachineGenerator()),
        ("resource", ConcurrencyResourceGenerator()),
        ("concurrency", ConcurrencyResourceGenerator()),
    ],
)
def test_phase4_generators_preserve_mechanism_under_rename_and_move(kind, generator) -> None:
    original = generator.generate("snapshot-1", _counterfactual_facts(kind, "request", moved=False))
    renamed = generator.generate("snapshot-1", _counterfactual_facts(kind, "payload", moved=False))
    moved = generator.generate("snapshot-1", _counterfactual_facts(kind, "request", moved=True))

    assert original and renamed and moved
    assert original[0].suspected_mechanism == renamed[0].suspected_mechanism
    assert original[0].suspected_mechanism == moved[0].suspected_mechanism
    registry = ProofPlanRegistry()
    assert {plan.id for plan in registry.select(original[0])} == {
        plan.id for plan in registry.select(moved[0])
    }


def _exploratory_proof_fixture(tmp_path, *, falsification_complete=True):
    facts = FactNormalizer().normalize(
        [
            _fact("call", 10, "execute(user_input)", callee="execute"),
            _fact(
                "taint_path",
                9,
                "input -> execute via user_input",
                subject="user_input",
                variable="user_input",
            ),
        ]
    )
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="novel interpreter boundary",
        invariant_families=["injection_safety"],
        suspected_mechanism="novel_structured_interpreter_confusion",
        source_symbols=["user_input"],
        impact_sinks=["execute"],
        suspected_invariants=["untrusted input cannot alter interpreter structure"],
        fact_ids=[fact.id for fact in facts],
        proof_plan_ids=["injection-boundary-v2"],
        generator="bounded-exploratory-lane",
        experimental=True,
    )
    obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="injection-boundary-v2",
        predicate="input_changes_interpreted_structure",
        status=ObligationStatus.PROVEN,
    )
    evidence = Evidence(
        snapshot_id="snapshot-1",
        kind="injection_differential",
        provenance=Provenance(producer="fixture-validator"),
    )
    falsification = Action(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        obligation_ids=[obligation.logical_id],
        template="falsify:context_correct_encoding",
        model_route="proof_falsifier",
        status=(ActionStatus.COMPLETED if falsification_complete else ActionStatus.FAILED),
    )
    certificate = Certificate(
        snapshot_id="snapshot-1",
        kind=CertificateKind.FINDING,
        candidate_id=candidate.logical_id,
        proof_plan_ids=candidate.proof_plan_ids,
        decision="confirmed",
        reason="fixture proof complete",
        evidence_ids=[evidence.logical_id],
        falsification_action_ids=[falsification.logical_id],
        report_claims=[
            {
                "claim_id": "claim-1",
                "predicate": obligation.predicate,
                "statement": "input changes interpreted structure",
                "evidence_ids": [evidence.logical_id],
            }
        ],
    )
    bundle = RetrospectiveCompiler().compile_bundle(
        "snapshot-1",
        [candidate],
        [certificate],
        facts,
        [obligation],
        [falsification],
        [evidence],
    )
    return bundle, facts, candidate


def test_phase5_retrospective_promotes_only_complete_proof_carrying_discoveries(
    tmp_path,
) -> None:
    bundle, facts, candidate = _exploratory_proof_fixture(tmp_path)

    assert len(bundle.retrospectives) == 1
    retrospective = bundle.retrospectives[0]
    assert retrospective.eligible_for_promotion
    assert retrospective.falsification_complete
    assert {case.transformation for case in retrospective.regressions} == {
        "original",
        "add_guard_or_policy",
        "rename_symbols",
        "move_scope",
        "remove_reachability",
        "add_decoy",
    }

    target = bundle.write(tmp_path / "retrospectives.json")
    registry = LearningRegistry.promote([RetrospectiveBundle.load(target)])
    registry_path = registry.write(tmp_path / "learning-registry.json")
    loaded = LearningRegistry.load(registry_path)
    generated = LearnedMechanismGenerator(loaded).generate(
        "snapshot-2",
        [
            Fact.model_validate(
                {
                    **fact.model_dump(mode="python"),
                    "id": "",
                    "logical_id": "",
                    "snapshot_id": "snapshot-2",
                    "location": {
                        "file": "moved/service.c",
                        "line": fact.location.line,
                        "function": "renamed_handler",
                    },
                }
            )
            for fact in facts
        ],
    )

    assert generated
    assert generated[0].suspected_mechanism == candidate.suspected_mechanism
    assert generated[0].proof_plan_ids == ["injection-boundary-v2"]
    assert generated[0].generator.startswith("promoted:")


def test_phase5_refuses_to_promote_incomplete_falsification(tmp_path) -> None:
    bundle, _facts, _candidate = _exploratory_proof_fixture(
        tmp_path,
        falsification_complete=False,
    )

    assert not bundle.retrospectives[0].eligible_for_promotion
    assert "falsification incomplete" in bundle.retrospectives[0].promotion_blockers
    with pytest.raises(ValueError, match="No eligible"):
        LearningRegistry.promote([bundle])


def test_phase5_coverage_report_measures_structured_local_rediscovery(tmp_path) -> None:
    bundle, _facts, candidate = _exploratory_proof_fixture(tmp_path)
    registry = LearningRegistry.promote([bundle])
    before = ProofStore(tmp_path / "before")
    after = ProofStore(tmp_path / "after")
    before.append(candidate)
    learned_payload = candidate.model_dump(mode="python")
    learned_payload.update(
        {
            "id": "",
            "logical_id": "",
            "snapshot_id": "snapshot-2",
            "generator": f"promoted:{registry.mechanisms[0].id}",
            "experimental": False,
        }
    )
    learned = Candidate.model_validate(learned_payload)
    after.append(learned)
    before_local = Action(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        obligation_ids=["obligation-1"],
        template="bounded_model_judgment",
        model_route="proof_local",
        status=ActionStatus.COMPLETED,
        output_claim_ids=["claim-local"],
    )
    before_frontier = Action(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        obligation_ids=["obligation-1"],
        template="bounded_model_judgment",
        model_route="proof_frontier",
        status=ActionStatus.COMPLETED,
        output_claim_ids=["claim-frontier"],
    )
    after_local = Action(
        snapshot_id="snapshot-2",
        candidate_id=learned.logical_id,
        obligation_ids=["obligation-2"],
        template="bounded_model_judgment",
        model_route="proof_local",
        status=ActionStatus.COMPLETED,
        output_claim_ids=["claim-after"],
    )
    before_obligation = Obligation(
        snapshot_id="snapshot-1",
        candidate_id=candidate.logical_id,
        proof_plan_id="injection-boundary-v2",
        predicate="input_changes_interpreted_structure",
        status=ObligationStatus.PROVEN,
    )
    after_obligation = Obligation(
        snapshot_id="snapshot-2",
        candidate_id=learned.logical_id,
        proof_plan_id="injection-boundary-v2",
        predicate="input_changes_interpreted_structure",
        status=ObligationStatus.PROVEN,
    )
    before_local = before_local.model_copy(
        update={"obligation_ids": [before_obligation.logical_id]}
    )
    before_frontier = before_frontier.model_copy(
        update={"obligation_ids": [before_obligation.logical_id]}
    )
    after_local = after_local.model_copy(update={"obligation_ids": [after_obligation.logical_id]})
    before.append_many([before_obligation, before_local, before_frontier])
    after.append_many([after_obligation, after_local])

    report = LearningCoverageCompiler().compare(
        registry,
        [before.root],
        [after.root],
    )

    assert report.structured_rediscovery_delta == 1
    assert report.local_only_resolved_obligation_delta == 1
    assert report.local_only_completion_rate_delta == 1.0
    assert report.frontier_action_delta == -1
    assert report.improved
    assert report.write(tmp_path / "coverage.json").is_file()

    metrics = ProofTelemetryCompiler(after).compile()
    assert metrics["by_candidate_generator"] == {learned.generator: 1}
    assert metrics["learning"]["promoted_candidates"] == 1
    assert metrics["learning"]["promoted_mechanism_ids"] == [registry.mechanisms[0].id]


def test_phase5_cli_exposes_registry_promotion_and_coverage(capsys) -> None:
    parser = argparse.ArgumentParser(prog="clearwing")
    subparsers = parser.add_subparsers(dest="command")
    sourcehunt_command.add_parser(subparsers)
    eval_command.add_parser(subparsers)

    with pytest.raises(SystemExit) as sourcehunt_exit:
        parser.parse_args(["sourcehunt", "--help"])
    assert sourcehunt_exit.value.code == 0
    sourcehunt_help = capsys.readouterr().out
    assert "--proof-learning-registry" in sourcehunt_help

    with pytest.raises(SystemExit) as eval_exit:
        parser.parse_args(["eval", "--help"])
    assert eval_exit.value.code == 0
    eval_help = capsys.readouterr().out
    assert "sourcehunt-promote" in eval_help
    assert "sourcehunt-learning-coverage" in eval_help


@pytest.mark.asyncio
async def test_phase5_registry_is_provenance_tracked_and_marks_run_assisted(
    tmp_path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text("def add(left, right):\n    return left + right\n")
    registry_path = LearningRegistry().write(tmp_path / "registry.json")

    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(tmp_path / "results"),
            learning_registry=str(registry_path),
            max_actions=5,
            max_model_calls=0,
            exploration_fraction=0.0,
            falsify=False,
        ),
    ).arun()

    manifest = json.loads(
        (tmp_path / "results" / result.session_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["learning_registry"]["mechanism_count"] == 0
    assert manifest["blind_boundary"]["sealed"] is False
    assert result.output_paths["retrospectives"].endswith("retrospectives.json")


@pytest.mark.asyncio
async def test_phase5_registry_with_unknown_proof_plan_fails_preflight(tmp_path) -> None:
    bundle, _facts, _candidate = _exploratory_proof_fixture(tmp_path)
    retrospective = bundle.retrospectives[0]
    unknown_plan = "not-installed-proof-plan-v1"
    bad_retrospective = retrospective.model_copy(
        update={
            "generator_seed": retrospective.generator_seed.model_copy(
                update={"proof_plan_ids": [unknown_plan]}
            ),
            "proof_plan_profile": retrospective.proof_plan_profile.model_copy(
                update={"proof_plan_ids": [unknown_plan]}
            ),
        }
    )
    registry_path = LearningRegistry.promote(
        [bundle.model_copy(update={"retrospectives": [bad_retrospective]})]
    ).write(tmp_path / "bad-registry.json")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text("def add(left, right):\n    return left + right\n")

    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(tmp_path / "results"),
            learning_registry=str(registry_path),
            exploration_fraction=0.0,
        ),
    ).arun()

    assert result.status == "incomplete"
    assert result.errors[0]["stage"] == "preflight"
    assert result.errors[0]["missing"] == [unknown_plan]
