"""Complete Phase-0 ground-truth, ablation, and baseline tests."""

from __future__ import annotations

import json
import subprocess

import pytest

from clearwing.eval.sourcehunt import (
    AblationArm,
    AblationLevel,
    GroundTruthManifest,
    RunObservation,
    StageFunnel,
    ablation_hints,
    aggregate_baseline,
    build_ablation_plan,
    execute_sourcehunt_run,
    inspect_ablation_session,
    run_ablation_campaign,
)


@pytest.fixture
def manifest() -> GroundTruthManifest:
    return GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")


def _arms(flow: str = "proof") -> list[AblationArm]:
    return [
        AblationArm(flow=flow, model_tier="local", model="local-test"),
        AblationArm(flow=flow, model_tier="frontier", model="frontier-test"),
    ]


def _observation(run, *, found: bool) -> RunObservation:
    funnel = StageFunnel(
        target_in_working_set=True,
        relevant_facts_extracted=True,
        true_candidate_generated=found,
        correct_proof_plan_selected=found,
        reachability_dataflow_resolved=found,
        guards_counterevidence_handled=found,
        validation_plan_constructed=found,
        expected_evidence_acquired=found,
        threat_model_classified=found,
        correct_certificate_compiled=found,
    )
    return RunObservation(
        run_id=run.id,
        context_id=run.context_id,
        case_id=run.case_id,
        flow=run.flow,
        model_tier=run.model_tier,
        model=run.model,
        level=run.level,
        replicate=run.replicate,
        session_dir=f"sessions/{run.id}",
        status="completed",
        funnel=funnel,
        true_positives=int(found),
        false_negatives=int(not found),
        finding_count=int(found),
        cost_usd=0.5 if run.model_tier == "local" else 2.0,
        input_tokens=100,
        output_tokens=50,
    )


def test_representative_manifest_has_full_intermediate_ground_truth(
    manifest: GroundTruthManifest,
) -> None:
    from clearwing.sourcehunt.proof.plans import ProofPlanRegistry

    registry = ProofPlanRegistry()
    assert len(manifest.cases) >= 5
    for case in manifest.cases:
        truth = case.ground_truth
        assert truth.target_files
        assert truth.target_functions
        assert truth.expected_fact_symbols
        assert truth.entry_points
        assert truth.sources and truth.sinks
        assert truth.transformations and truth.invariants
        assert truth.trigger_constraints and truth.reproduction_behavior
        assert truth.threat_model.trust_boundary
        assert truth.threat_model.security_property_violated
        plans = [registry.get(plan_id) for plan_id in truth.expected_proof_plans]
        predicates = {obligation.predicate for plan in plans for obligation in plan.obligations}
        assert set(truth.expected_predicates) <= predicates


def test_ablation_levels_never_leak_later_hints(
    manifest: GroundTruthManifest,
) -> None:
    case = manifest.cases[0]

    assert ablation_hints(case, AblationLevel.REPOSITORY) == {}
    assert set(ablation_hints(case, AblationLevel.TARGET_FILE)) == {"target_files"}
    assert "target_functions" in ablation_hints(case, AblationLevel.TARGET_FUNCTION)
    assert "sources" in ablation_hints(case, AblationLevel.SOURCE_SINK)
    assert "invariants" in ablation_hints(case, AblationLevel.INVARIANT_PATH)
    assert "trigger_constraints" not in ablation_hints(case, AblationLevel.COMPLETE_TRACE)
    assert "trigger_constraints" in ablation_hints(case, AblationLevel.TRIGGER)


def test_local_and_frontier_arms_receive_identical_contexts(
    manifest: GroundTruthManifest,
) -> None:
    plan = build_ablation_plan(
        manifest,
        _arms(),
        levels=[AblationLevel.REPOSITORY, AblationLevel.INVARIANT_PATH],
        replicates=2,
    )

    cells: dict[tuple[str, int, int], set[str]] = {}
    for run in plan.runs:
        cell = (run.case_id, int(run.level), run.replicate)
        cells.setdefault(cell, set()).add(run.context_id)
    assert all(len(contexts) == 1 for contexts in cells.values())
    assert len(plan.runs) == len(manifest.cases) * 2 * 2 * 2

    blind = next(run for run in plan.runs if run.level == AblationLevel.REPOSITORY)
    assisted_runs = [run for run in plan.runs if run.level == AblationLevel.INVARIANT_PATH]
    assisted = assisted_runs[0]
    assert blind.campaign_hint() is None
    hint = json.loads(assisted.campaign_hint() or "{}")
    assert hint["context_id"] == assisted.context_id
    assert hint["ablation_level"] == int(AblationLevel.INVARIANT_PATH)
    assert "trigger_constraints" not in hint
    packets_by_cell: dict[tuple[str, int], set[str | None]] = {}
    for run in assisted_runs:
        packets_by_cell.setdefault((run.case_id, run.replicate), set()).add(run.campaign_hint())
    assert all(len(packets) == 1 for packets in packets_by_cell.values())


def test_baseline_requires_complete_matrix_and_reports_failure_stage(
    manifest: GroundTruthManifest,
) -> None:
    plan = build_ablation_plan(
        manifest,
        _arms(),
        levels=[AblationLevel.REPOSITORY],
    )
    observations = [_observation(run, found=(run.model_tier == "frontier")) for run in plan.runs]

    report = aggregate_baseline(plan, observations)

    assert report.complete
    local = next(group for group in report.groups if group.model_tier == "local")
    frontier = next(group for group in report.groups if group.model_tier == "frontier")
    assert local.recall == 0.0
    assert local.failure_stage_counts == {"true_candidate_generated": len(manifest.cases)}
    assert frontier.recall == 1.0
    assert frontier.precision == 1.0
    assert frontier.mean_cost_usd == 2.0
    with pytest.raises(ValueError, match="matrix is incomplete"):
        aggregate_baseline(plan, observations[:-1])
    partial = aggregate_baseline(plan, observations[:-1], require_complete=False)
    assert not partial.complete
    assert len(partial.missing_run_ids) == 1

    tampered = list(observations)
    tampered[0] = tampered[0].model_copy(update={"model": "different-model"})
    with pytest.raises(ValueError, match="disagrees with its plan"):
        aggregate_baseline(plan, tampered)


def test_plan_ids_fail_closed_when_pinned_inputs_are_tampered(
    manifest: GroundTruthManifest,
    tmp_path,
) -> None:
    plan = build_ablation_plan(
        GroundTruthManifest(cases=[manifest.cases[0]]),
        _arms(),
        levels=[AblationLevel.REPOSITORY],
    )
    payload = plan.model_dump(mode="json")
    payload["runs"][0]["model"] = "tampered-model"
    path = tmp_path / "tampered-plan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="run ID does not match"):
        type(plan).load(path)


@pytest.mark.asyncio
async def test_campaign_runner_is_resumable_and_checkpoints_by_run_id(
    manifest: GroundTruthManifest,
    tmp_path,
) -> None:
    plan = build_ablation_plan(
        GroundTruthManifest(cases=[manifest.cases[0]]),
        _arms(),
        levels=[AblationLevel.REPOSITORY],
    )
    calls: list[str] = []

    async def execute(spec, _case):
        calls.append(spec.id)
        return _observation(spec, found=True)

    existing = [_observation(plan.runs[0], found=True)]
    observations = await run_ablation_campaign(
        plan,
        manifest,
        execute,
        existing=existing,
        checkpoint_path=tmp_path / "observations.json",
    )

    assert calls == [plan.runs[1].id]
    assert [item.run_id for item in observations] == [run.id for run in plan.runs]
    assert (tmp_path / "observations.json").is_file()


@pytest.mark.asyncio
async def test_concrete_executor_pins_checkout_and_wires_exact_hint_packet(
    manifest: GroundTruthManifest,
    tmp_path,
    monkeypatch,
) -> None:
    import clearwing.eval.sourcehunt as sourcehunt_eval
    import clearwing.sourcehunt.runner as sourcehunt_runner

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    (checkout / "app.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=SourceHunt Test",
            "-c",
            "user.email=sourcehunt@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    base_case = manifest.cases[-1]
    case = base_case.model_copy(update={"repository": str(checkout), "vulnerable_commit": head})
    plan = build_ablation_plan(
        GroundTruthManifest(cases=[case]),
        _arms(flow="proof"),
        levels=[AblationLevel.INVARIANT_PATH],
    )
    spec = plan.runs[0]
    captured: dict = {}

    class FakeRunner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def arun(self):
            return None

    monkeypatch.setattr(sourcehunt_runner, "SourceHuntRunner", FakeRunner)
    monkeypatch.setattr(
        sourcehunt_eval,
        "inspect_ablation_session",
        lambda run, _case, _session: _observation(run, found=True),
    )

    observation = await execute_sourcehunt_run(
        spec,
        case,
        checkout=checkout,
        output_dir=tmp_path / "results",
        provider_manager=object(),
        budget_usd=1.0,
    )

    assert observation.run_id == spec.id
    assert captured["parent_session_id"] == spec.id
    assert captured["campaign_hint"] == spec.campaign_hint()
    assert captured["flow"] == "proof"
    assert captured["model_override"] == spec.model

    (checkout / "app.py").write_text("print('changed')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="tracked modifications"):
        await execute_sourcehunt_run(
            spec,
            case,
            checkout=checkout,
            output_dir=tmp_path / "results",
            provider_manager=object(),
            budget_usd=1.0,
        )


def test_proof_session_scorer_uses_target_linked_artifacts(
    manifest: GroundTruthManifest,
    tmp_path,
) -> None:
    from clearwing.sourcehunt.proof import (
        Action,
        ActionStatus,
        Candidate,
        Certificate,
        CertificateKind,
        Evidence,
        Fact,
        Obligation,
        ObligationStatus,
        ProofStore,
        Provenance,
        SourceLocation,
        ThreatModel,
    )

    case = manifest.cases[0]
    spec = build_ablation_plan(
        GroundTruthManifest(cases=[case]),
        _arms(),
        levels=[AblationLevel.REPOSITORY],
    ).runs[0]
    store = ProofStore(tmp_path / spec.id)
    facts = [
        Fact(
            snapshot_id="snapshot-1",
            kind="variable",
            subject=symbol,
            location=SourceLocation(file=case.ground_truth.target_files[0]),
            provenance=Provenance(producer="test"),
        )
        for symbol in case.ground_truth.expected_fact_symbols
    ]
    store.append_many(facts)
    threat_truth = case.ground_truth.threat_model
    threat = ThreatModel(
        snapshot_id="snapshot-1",
        attacker_principal=threat_truth.attacker_principal,
        attacker_capabilities=threat_truth.attacker_capabilities,
        trust_boundaries=[threat_truth.trust_boundary],
        protected_assets=[threat_truth.protected_asset],
        capability_gained=[threat_truth.capability_gained],
        security_properties_violated=[threat_truth.security_property_violated],
    )
    store.append(threat)
    candidate = Candidate(
        snapshot_id="snapshot-1",
        title="sentinel collision",
        invariant_families=["representation_domain_safety", "spatial_safety"],
        suspected_mechanism=case.ground_truth.expected_mechanisms[0],
        fact_ids=[fact.id for fact in facts],
        threat_model_id=threat.logical_id,
        proof_plan_ids=case.ground_truth.expected_proof_plans,
        generator="test",
    )
    store.append(candidate)
    predicates = [
        *case.ground_truth.expected_predicates,
        "attacker_controls_identifier_progression",
    ]
    obligations = [
        Obligation(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            proof_plan_id=case.ground_truth.expected_proof_plans[0],
            predicate=predicate,
            status=ObligationStatus.PROVEN,
            decisive_rejection=("guard" in predicate),
        )
        for predicate in predicates
    ]
    store.append_many(obligations)
    evidence = Evidence(
        snapshot_id="snapshot-1",
        kind=case.ground_truth.expected_evidence_kinds[0],
        provenance=Provenance(producer="test"),
    )
    store.append(evidence)
    store.append(
        Action(
            snapshot_id="snapshot-1",
            candidate_id=candidate.logical_id,
            obligation_ids=[obligation.logical_id for obligation in obligations],
            template="sanitizer_run",
            status=ActionStatus.COMPLETED,
            output_evidence_ids=[evidence.logical_id],
        )
    )
    store.append(
        Certificate(
            snapshot_id="snapshot-1",
            kind=CertificateKind.FINDING,
            candidate_id=candidate.logical_id,
            proof_plan_ids=candidate.proof_plan_ids,
            decision="confirmed",
            reason="test",
            evidence_ids=[evidence.logical_id],
            dependency_files=case.ground_truth.target_files,
            cwe=case.ground_truth.expected_cwes[0],
            report_claims=[
                {
                    "predicate": "runtime_confirms_unsafe_memory_access",
                    "statement": "the runtime confirms an unsafe access",
                    "evidence_ids": [evidence.logical_id],
                }
            ],
        )
    )
    store.write_manifest({"status": "completed"})
    store.write_json(
        "metrics/run-metrics.json",
        {"totals": {"cost_usd": 1.0, "input_tokens": 100, "output_tokens": 20}},
    )

    observation = inspect_ablation_session(spec, case, store.root)

    assert all(value is True for value in observation.funnel.model_dump().values())
    assert observation.true_positives == 1
    assert observation.false_positives == 0
    assert observation.report_claim_count == 1
    assert observation.unsupported_claims == 0


def test_legacy_session_scorer_uses_instrumented_working_set(
    manifest: GroundTruthManifest,
    tmp_path,
) -> None:
    case = manifest.cases[0]
    spec = build_ablation_plan(
        GroundTruthManifest(cases=[case]),
        _arms(flow="legacy"),
        levels=[AblationLevel.REPOSITORY],
    ).runs[0]
    session = tmp_path / spec.id
    (session / "instrumentation").mkdir(parents=True)
    (session / "instrumentation" / "summary.json").write_text(
        json.dumps(
            {
                "files_by_stage": {"rank": case.ground_truth.target_files},
                "reporting_failure_count": 1,
            }
        ),
        encoding="utf-8",
    )
    (session / "findings.json").write_text(
        json.dumps(
            [
                {
                    "file": case.ground_truth.target_files[0],
                    "cwe": case.ground_truth.expected_cwes[0],
                    "evidence_level": "root_cause_explained",
                    "vulnerability_trace": {"steps": [{"file": "target.c"}]},
                    "poc": "trigger",
                }
            ]
        ),
        encoding="utf-8",
    )
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "total_spent": 0.5,
                "input_tokens": 40,
                "output_tokens": 10,
                "total_tokens": 50,
            }
        ),
        encoding="utf-8",
    )

    observation = inspect_ablation_session(spec, case, session)

    assert observation.true_positives == 1
    assert observation.false_negatives == 0
    assert observation.report_claim_count == 1
    assert observation.unsupported_claims == 0
    assert observation.report_failures == 1
    assert observation.input_tokens == 40
    assert observation.output_tokens == 10
