"""End-to-end proof-carrying sourcehunt orchestration."""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.llm.budget import spend_metadata
from clearwing.sandbox.hunter_sandbox import HunterSandbox

from ..preprocessor import Preprocessor
from .calibration import SchedulerCalibration
from .candidates import AssumptionBuilder, CandidatePipeline, ThreatModelBuilder
from .certificates import CertificateCompiler
from .context import ContextPacketBuilder
from .exploration import ExploratoryLane
from .extractors import (
    LANGUAGE_BY_EXTENSION,
    SUPPORTED_LANGUAGES,
    CommandRunner,
    ExtractionConfig,
    FactExtractor,
    ProofPreflightError,
    SandboxCommandRunner,
)
from .falsifier import BoundedFalsifier, FalsificationPlanner
from .graph import ProofGraph, revise
from .learning import LearnedMechanismGenerator, LearningRegistry, RetrospectiveCompiler
from .models import (
    Action,
    ActionStatus,
    Candidate,
    Certificate,
    CertificateKind,
    Claim,
    Derivation,
    Evidence,
    Obligation,
    ObligationStatus,
    RepositorySnapshot,
)
from .plans import ProofPlanRegistry
from .reporter import ProofReporter
from .resolvers import (
    BoundedModelResolver,
    MechanicalResolver,
    Resolution,
    apply_resolution,
)
from .scheduler import ActionScheduler, InvestigationBudget, is_dynamic_action
from .snapshot import capture_snapshot
from .store import ProofStore
from .telemetry import ProofTelemetryCompiler
from .validation import (
    CommandValidationBackend,
    SanitizerValidationBackend,
    TemplateHarnessBackend,
    ValidationManifest,
    ValidationRequest,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProofRunConfig:
    output_dir: str
    session_id: str = ""
    compile_commands: str | None = None
    validation_manifest: str | None = None
    scheduler_calibration: str | None = None
    learning_registry: str | None = None
    build_configuration: str = "default"
    clang_binary: str = "clang"
    max_actions: int = 200
    max_model_calls: int = 40
    max_dynamic_actions: int = 20
    structured_fraction: float = 0.90
    exploration_fraction: float = 0.10
    retain_incomplete_certificates: bool = True
    emit_rejection_certificates: bool = True
    falsify: bool = True
    gvisor_runtime: str | None = None
    sandbox_cpus: float | None = None
    evaluation_hints: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProofFlowResult:
    session_id: str
    repo_path: str
    snapshot: RepositorySnapshot | None
    candidates: list[Candidate]
    certificates: list[Certificate]
    findings: list[dict[str, Any]]
    output_paths: dict[str, str]
    files_analyzed: int
    duration_seconds: float
    status: str
    errors: list[dict[str, Any]] = field(default_factory=list)

    @property
    def incomplete(self) -> bool:
        return self.status != "completed" or any(
            certificate.kind == CertificateKind.INCOMPLETE for certificate in self.certificates
        )


class ProofFlowRunner:
    """Run the repository as facts → candidates → obligations → certificates."""

    def __init__(
        self,
        *,
        repo_url: str,
        branch: str = "main",
        local_path: str | None = None,
        config: ProofRunConfig,
        command_runner: CommandRunner | None = None,
        model_client_factory: Callable[[str], Any | None] | None = None,
    ):
        self.repo_url = repo_url
        self.branch = branch
        self.local_path = local_path
        self.config = config
        self.command_runner = command_runner
        self.model_client_factory = model_client_factory
        self._sandbox: HunterSandbox | None = None

    async def arun(self) -> ProofFlowResult:  # noqa: C901
        started = time.monotonic()
        session_id = self.config.session_id or f"proof-{uuid.uuid4().hex[:8]}"
        session_dir = Path(self.config.output_dir).expanduser() / session_id
        store = ProofStore(session_dir)
        snapshot: RepositorySnapshot | None = None
        candidates: list[Candidate] = []
        certificates: list[Certificate] = []
        compiled_certificates: list[Certificate] = []
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        files_analyzed = 0
        repo_path = ""
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "engine": "proof",
            "session_id": session_id,
            "status": "starting",
            "blind_boundary": {
                "sealed": not bool(self.config.evaluation_hints or self.config.learning_registry),
                "oracle_evidence_permitted": False,
                "learning_registry_supplied": bool(self.config.learning_registry),
            },
            "evaluation_ablation": {
                "assisted": bool(self.config.evaluation_hints or self.config.learning_registry),
                "hints": self.config.evaluation_hints,
            },
            "budget": {
                "max_actions": self.config.max_actions,
                "max_model_calls": self.config.max_model_calls,
                "max_dynamic_actions": self.config.max_dynamic_actions,
                "structured_fraction": self.config.structured_fraction,
                "exploration_fraction": self.config.exploration_fraction,
            },
            "supported_languages": sorted(SUPPORTED_LANGUAGES),
        }
        store.write_manifest(manifest)
        try:
            repo_path = self._resolve_repository()
            languages = self._language_inventory(Path(repo_path))
            validation_manifest = (
                ValidationManifest.load(self.config.validation_manifest)
                if self.config.validation_manifest
                else None
            )
            scheduler_calibration = (
                SchedulerCalibration.load(self.config.scheduler_calibration)
                if self.config.scheduler_calibration
                else None
            )
            try:
                learning_registry = (
                    LearningRegistry.load(self.config.learning_registry)
                    if self.config.learning_registry
                    else None
                )
            except (OSError, ValueError) as exc:
                raise ProofPreflightError(
                    f"Invalid learning registry: {exc}",
                    missing=("valid_learning_registry",),
                ) from exc
            plan_registry = ProofPlanRegistry()
            if learning_registry is not None:
                referenced_plan_ids = {
                    plan_id
                    for mechanism in learning_registry.mechanisms
                    for plan_id in mechanism.generator_seed.proof_plan_ids
                }
                unknown_plan_ids = sorted(referenced_plan_ids - set(plan_registry.plans))
                if unknown_plan_ids:
                    raise ProofPreflightError(
                        "Learning registry references unknown proof plans: "
                        + ", ".join(unknown_plan_ids),
                        missing=tuple(unknown_plan_ids),
                    )
            command_runner = self.command_runner
            if {"c", "cpp"} & set(languages):
                compile_commands = self._compile_commands_path(Path(repo_path))
                if not compile_commands.is_file():
                    raise ProofPreflightError(
                        "C/C++ proof flow requires compile_commands.json before sandbox startup",
                        missing=("compile_commands.json",),
                    )
                if command_runner is None:
                    command_runner = self._build_sandbox_runner(
                        repo_path,
                        sorted(languages),
                    )
            if validation_manifest is not None:
                if command_runner is None:
                    command_runner = self._build_sandbox_runner(
                        repo_path,
                        sorted(languages),
                    )
                if not command_runner.sandboxed:
                    raise ProofPreflightError(
                        "Validation manifests require a sandboxed command runner",
                        missing=("sandboxed_validation_runner",),
                    )
            snapshot = capture_snapshot(
                repo_path,
                repo_url=self.repo_url,
                build_configuration=self.config.build_configuration,
                compiler=self.config.clang_binary if {"c", "cpp"} & set(languages) else "",
                feature_flags={
                    "flow": "proof",
                    "falsification": self.config.falsify,
                    "exploration_fraction": self.config.exploration_fraction,
                    "validation_manifest": bool(validation_manifest),
                    "learning_registry": bool(learning_registry),
                },
                tool_versions={
                    "command_runner": (
                        command_runner.identity if command_runner else "not_required"
                    )
                },
            )
            store.append(snapshot)
            if self.config.validation_manifest:
                assert validation_manifest is not None
                validation_source = Path(self.config.validation_manifest).expanduser().resolve()
                validation_uri, validation_digest = store.store_artifact(
                    validation_source.read_bytes(),
                    media_type="application/json",
                    name="validation-manifest.json",
                )
                manifest["validation_manifest"] = {
                    "artifact_uri": validation_uri,
                    "digest": validation_digest,
                    "command_count": len(validation_manifest.commands),
                }
            if self.config.scheduler_calibration:
                calibration_source = Path(self.config.scheduler_calibration).expanduser().resolve()
                calibration_uri, calibration_digest = store.store_artifact(
                    calibration_source.read_bytes(),
                    media_type="application/json",
                    name="scheduler-calibration.json",
                )
                manifest["scheduler_calibration"] = {
                    "artifact_uri": calibration_uri,
                    "digest": calibration_digest,
                    "profile_count": len(scheduler_calibration.profiles),
                    "source_sessions": scheduler_calibration.source_sessions,
                }
            if self.config.learning_registry:
                assert learning_registry is not None
                learning_source = Path(self.config.learning_registry).expanduser().resolve()
                learning_uri, learning_digest = store.store_artifact(
                    learning_source.read_bytes(),
                    media_type="application/json",
                    name="proof-learning-registry.json",
                )
                manifest["learning_registry"] = {
                    "artifact_uri": learning_uri,
                    "digest": learning_digest,
                    "mechanism_count": len(learning_registry.mechanisms),
                    "strict_blind_baseline": False,
                }
            manifest.update(
                {
                    "snapshot_id": snapshot.id,
                    "repository": {
                        "path": repo_path,
                        "url": self.repo_url,
                        "commit": snapshot.commit,
                        "dirty_tree_digest": snapshot.dirty_tree_digest,
                    },
                    "languages": languages,
                    "blind_boundary": {
                        "sealed": not bool(
                            self.config.evaluation_hints or self.config.learning_registry
                        ),
                        "oracle_evidence_permitted": False,
                        "learning_registry_supplied": bool(self.config.learning_registry),
                        "snapshot_id": snapshot.id,
                    },
                    "status": "extracting",
                }
            )
            store.write_manifest(manifest)
            extraction = FactExtractor(
                repo_path,
                snapshot.id,
                store=store,
                config=ExtractionConfig(
                    compile_commands=self._compile_commands_path(Path(repo_path)),
                    clang_binary=self.config.clang_binary,
                    build_configuration=self.config.build_configuration,
                ),
                command_runner=command_runner,
            ).extract()
            files_analyzed = extraction.files_analyzed
            errors.extend(extraction.errors)

            candidate_pipeline = CandidatePipeline()
            if learning_registry is not None:
                candidate_pipeline.generators.append(LearnedMechanismGenerator(learning_registry))
            generation = candidate_pipeline.generate(
                snapshot.id,
                extraction.facts,
            )
            generated_candidates = list(generation.candidates)
            exploration_client = self._model_client("proof_exploration")
            exploration_cap = int(self.config.max_actions * self.config.exploration_fraction)
            if (
                exploration_client is not None
                and exploration_cap > 0
                and self.config.max_model_calls > 0
            ):
                exploration_action = Action(
                    snapshot_id=snapshot.id,
                    candidate_id="session-exploration",
                    obligation_ids=[],
                    template="bounded_exploration",
                    inputs={
                        "objective": (
                            "find unmodeled trust transitions and architectural interactions"
                        ),
                        "exploration": True,
                    },
                    permitted_tools=["query_facts", "propose_candidate"],
                    model_route="proof_exploration",
                    estimated_cost_usd=0.10,
                    estimated_seconds=60.0,
                    expected_information_gain=0.25,
                )
                store.append(exploration_action)
                running_exploration = revise(
                    exploration_action,
                    status=ActionStatus.RUNNING,
                )
                store.append(running_exploration)
                try:
                    with spend_metadata(
                        proof_action_id=running_exploration.logical_id,
                        proof_attempt_id=running_exploration.attempt_id,
                        proof_role="exploration",
                        candidate_id=running_exploration.candidate_id,
                        action_template=running_exploration.template,
                        model_route=running_exploration.model_route,
                    ):
                        proposed, exploration_output, exploration_packet = await ExploratoryLane(
                            exploration_client
                        ).explore(
                            snapshot.id,
                            extraction.facts,
                            extraction.completeness,
                        )
                    known = {candidate.logical_id for candidate in generated_candidates}
                    generated_candidates.extend(
                        candidate for candidate in proposed if candidate.logical_id not in known
                    )
                    packet_uri, packet_digest = store.store_artifact(
                        json.dumps(
                            exploration_packet,
                            sort_keys=True,
                            default=str,
                        ),
                        media_type="application/json",
                        name="exploration-context.json",
                    )
                    store.write_json(
                        "exploration/result.json",
                        {
                            "action_id": exploration_action.logical_id,
                            "packet_uri": packet_uri,
                            "packet_digest": packet_digest,
                            "output": exploration_output.model_dump(mode="json"),
                            "accepted_candidate_ids": [
                                candidate.logical_id for candidate in proposed
                            ],
                        },
                    )
                    store.append(
                        revise(
                            running_exploration,
                            status=ActionStatus.COMPLETED,
                        )
                    )
                except Exception as exc:
                    logger.warning("Bounded exploratory lane failed", exc_info=True)
                    store.append(
                        revise(
                            running_exploration,
                            status=ActionStatus.FAILED,
                            error=str(exc),
                        )
                    )
            store.write_json(
                "candidates/duplicates.json",
                {
                    "snapshot_id": snapshot.id,
                    "duplicates": generation.duplicates,
                },
            )
            graph = ProofGraph(store, snapshot.id)
            threat_builder = ThreatModelBuilder()
            assumption_builder = AssumptionBuilder()
            for draft in generated_candidates:
                candidate_threat = threat_builder.build(draft, extraction.facts)
                assumptions = assumption_builder.build(draft, candidate_threat)
                plans = plan_registry.select(draft)
                obligations = plan_registry.instantiate(draft, plans)
                payload = draft.model_dump(mode="python")
                payload.update(
                    {
                        "id": "",
                        "threat_model_id": candidate_threat.logical_id,
                        "assumption_ids": [assumption.logical_id for assumption in assumptions],
                        "proof_plan_ids": [plan.id for plan in plans],
                        "obligation_ids": [obligation.logical_id for obligation in obligations],
                    }
                )
                candidate = Candidate.model_validate(payload)
                store.append(candidate_threat)
                graph.add_candidate(candidate)
                for assumption in assumptions:
                    graph.add_assumption(assumption)
                for obligation in obligations:
                    graph.add_obligation(obligation)
                candidates.append(candidate)

            scheduler = ActionScheduler(
                store,
                graph,
                budget=InvestigationBudget(
                    max_actions=self.config.max_actions,
                    max_model_calls=self.config.max_model_calls,
                    max_dynamic_actions=self.config.max_dynamic_actions,
                    structured_fraction=self.config.structured_fraction,
                    exploration_fraction=self.config.exploration_fraction,
                ),
                calibration=scheduler_calibration,
            )
            threats = store.latest_threats(snapshot.id)
            await self._investigate_candidates(
                store,
                graph,
                scheduler,
                candidates,
                extraction.facts,
                extraction.completeness,
                command_runner=command_runner,
                validation_manifest=validation_manifest,
                repo_path=Path(repo_path),
                threat_models={
                    candidate.logical_id: threats.get(candidate.threat_model_id or "")
                    for candidate in candidates
                },
            )
            for candidate in candidates:
                graph.materialize(candidate.logical_id)

            compiler = CertificateCompiler(
                store,
                graph,
                plan_registry=plan_registry,
            )
            for candidate in candidates:
                threat = threats.get(candidate.threat_model_id or "")
                falsification_ids: list[str] = []
                decisive_rejection = any(
                    obligation.decisive_rejection
                    and obligation.status == ObligationStatus.DISPROVEN
                    for obligation in graph.candidate_obligations(candidate.logical_id)
                )
                if self.config.falsify and not decisive_rejection:
                    falsification_planner = FalsificationPlanner()
                    scheduler_state = scheduler.state()
                    falsification_capacity = min(
                        self.config.max_actions - scheduler_state.actions_total,
                        self.config.max_model_calls - scheduler_state.model_calls,
                    )
                    actions = falsification_planner.plan(
                        store,
                        candidate,
                        graph.candidate_obligations(candidate.logical_id),
                        list(graph.claims.values()),
                        max_actions=falsification_capacity,
                    )
                    falsification_ids = [action.logical_id for action in actions]
                    falsifier_client = self._model_client("proof_falsifier")
                    for action in actions:
                        if falsifier_client is None:
                            scheduler.complete(
                                action,
                                status=ActionStatus.FAILED,
                                error="no independent falsifier model route",
                            )
                            continue
                        running = scheduler.complete(
                            action,
                            status=ActionStatus.RUNNING,
                        )
                        try:
                            with spend_metadata(
                                proof_action_id=running.logical_id,
                                proof_attempt_id=running.attempt_id,
                                proof_role="falsification",
                                candidate_id=candidate.logical_id,
                                obligation_ids=running.obligation_ids,
                                action_template=running.template,
                                model_route=running.model_route,
                            ):
                                execution = await BoundedFalsifier(falsifier_client).execute(
                                    running,
                                    candidate,
                                    graph.candidate_obligations(candidate.logical_id),
                                    extraction.facts,
                                    extraction.completeness,
                                    threat_model=threat,
                                    assumptions=list(graph.assumptions.values()),
                                )
                            if not execution.completed:
                                scheduler.complete(
                                    running,
                                    status=ActionStatus.FAILED,
                                    error=execution.error,
                                )
                                continue
                            if execution.resolution is not None:
                                target_id = execution.resolution.evidence[0].contradicts[0]
                                target = graph.obligations[target_id]
                                apply_resolution(
                                    graph,
                                    store,
                                    target,
                                    execution.resolution,
                                )
                            else:
                                for evidence in execution.evidence:
                                    graph.add_evidence(evidence)
                            scheduler.complete(
                                running,
                                status=ActionStatus.COMPLETED,
                                evidence_ids=[
                                    evidence.logical_id for evidence in execution.evidence
                                ],
                                claim_ids=(
                                    [claim.logical_id for claim in execution.resolution.claims]
                                    if execution.resolution
                                    else []
                                ),
                            )
                        except Exception as exc:
                            logger.warning(
                                "Bounded falsification action failed",
                                exc_info=True,
                            )
                            scheduler.complete(
                                running,
                                status=ActionStatus.FAILED,
                                error=str(exc),
                            )
                    falsification_planner.materialize(store, candidate)
                certificate = compiler.compile(
                    candidate,
                    threat_model=threat,
                    facts=extraction.facts,
                    falsification_action_ids=falsification_ids,
                    budget_exhausted=(scheduler.state().actions_total >= self.config.max_actions),
                    persist=False,
                )
                compiled_certificates.append(certificate)
                if (
                    certificate.kind == CertificateKind.INCOMPLETE
                    and not self.config.retain_incomplete_certificates
                ):
                    continue
                if (
                    certificate.kind == CertificateKind.REJECTION
                    and not self.config.emit_rejection_certificates
                ):
                    continue
                store.append(certificate)
                certificates.append(certificate)

            paths = ProofReporter(store).write(
                certificates,
                candidates,
                extraction.facts,
            )
            metrics_path, metrics = ProofTelemetryCompiler(store).write()
            paths["metrics"] = metrics_path
            finding_payloads = [
                ProofReporter(store).to_finding(
                    certificate,
                    next(
                        (
                            candidate
                            for candidate in candidates
                            if candidate.logical_id == certificate.candidate_id
                        ),
                        None,
                    ),
                    extraction.facts,
                )
                for certificate in certificates
                if certificate.kind == CertificateKind.FINDING
            ]
            findings = finding_payloads
            retrospective_bundle = RetrospectiveCompiler().compile_bundle(
                snapshot.id,
                candidates,
                certificates,
                extraction.facts,
                list(store.latest(Obligation).values()),
                list(store.latest(Action).values()),
                list(store.latest(Evidence).values()),
            )
            retrospective_path = retrospective_bundle.write(
                store.root / "learning" / "retrospectives.json"
            )
            paths["retrospectives"] = retrospective_path
            status = (
                "incomplete"
                if any(
                    certificate.kind == CertificateKind.INCOMPLETE
                    for certificate in compiled_certificates
                )
                else "completed"
            )
            manifest.update(
                {
                    "status": status,
                    "candidate_count": len(candidates),
                    "learning": {
                        "retrospective_count": len(retrospective_bundle.retrospectives),
                        "promotion_eligible_count": sum(
                            item.eligible_for_promotion
                            for item in retrospective_bundle.retrospectives
                        ),
                        "registry_mechanism_count": (
                            len(learning_registry.mechanisms)
                            if learning_registry is not None
                            else 0
                        ),
                    },
                    "certificate_counts": {
                        kind.value: sum(
                            1 for certificate in certificates if certificate.kind == kind
                        )
                        for kind in CertificateKind
                    },
                    "compiled_certificate_counts": {
                        kind.value: sum(
                            1 for certificate in compiled_certificates if certificate.kind == kind
                        )
                        for kind in CertificateKind
                    },
                    "action_counts": scheduler.state().__dict__,
                    "metrics": {
                        "path": str(metrics_path),
                        "totals": metrics["totals"],
                        "efficiency": metrics["efficiency"],
                    },
                    "errors": errors,
                }
            )
            store.write_manifest(manifest)
            return ProofFlowResult(
                session_id=session_id,
                repo_path=repo_path,
                snapshot=snapshot,
                candidates=candidates,
                certificates=certificates,
                findings=findings,
                output_paths={name: str(path) for name, path in paths.items()},
                files_analyzed=files_analyzed,
                duration_seconds=time.monotonic() - started,
                status=status,
                errors=errors,
            )
        except ProofPreflightError as exc:
            error = {
                "stage": "preflight",
                "message": str(exc),
                "missing": list(exc.missing),
            }
            errors.append(error)
            manifest.update(
                {
                    "status": "incomplete",
                    "preflight_error": error,
                    "errors": errors,
                }
            )
            store.write_manifest(manifest)
            report_path = store.root / "report.md"
            report_path.write_text(
                "# Clearwing Sourcehunt Proof Report\n\n"
                "## Incomplete preflight\n\n"
                f"{exc}\n\n"
                "No legacy or heuristic fallback was used.\n",
                encoding="utf-8",
            )
            return ProofFlowResult(
                session_id=session_id,
                repo_path=repo_path,
                snapshot=snapshot,
                candidates=[],
                certificates=[],
                findings=[],
                output_paths={"markdown": str(report_path)},
                files_analyzed=0,
                duration_seconds=time.monotonic() - started,
                status="incomplete",
                errors=errors,
            )
        finally:
            if self._sandbox is not None:
                self._sandbox.cleanup()

    async def _investigate_candidates(
        self,
        store: ProofStore,
        graph: ProofGraph,
        scheduler: ActionScheduler,
        candidates: list[Candidate],
        facts: list[Any],
        completeness: Any,
        *,
        command_runner: CommandRunner | None,
        validation_manifest: ValidationManifest | None,
        repo_path: Path,
        threat_models: dict[str, Any | None],
    ) -> None:
        mechanical = MechanicalResolver()
        context_builder = ContextPacketBuilder()
        candidate_by_id = {
            identifier: candidate
            for candidate in candidates
            for identifier in (candidate.id, candidate.logical_id)
        }
        while True:
            action = scheduler.next_action(candidates)
            if action is None:
                return
            running = scheduler.complete(action, status=ActionStatus.RUNNING)
            candidate = candidate_by_id[running.candidate_id]
            threat_model = threat_models.get(candidate.logical_id)
            obligation_id = running.obligation_ids[0]
            obligation = graph.obligations[obligation_id]
            resolution = None
            output_evidence_ids: list[str] = []
            if is_dynamic_action(running.template):
                if command_runner is not None and validation_manifest is not None:
                    resolution, output_evidence_ids = self._run_validation_action(
                        store,
                        graph,
                        candidate,
                        obligation,
                        running,
                        command_runner,
                        validation_manifest,
                        repo_path,
                    )
            elif running.model_route is None:
                resolution = mechanical.resolve(
                    candidate,
                    obligation,
                    facts,
                    completeness,
                )
            if running.model_route:
                client = self._model_client(running.model_route)
                if client is not None:
                    packet = context_builder.build(
                        candidate,
                        obligation,
                        facts,
                        list(graph.evidence.values()),
                        list(graph.claims.values()),
                        completeness,
                        threat_model=threat_model,
                        assumptions=list(graph.assumptions.values()),
                        evaluation_hints=self.config.evaluation_hints,
                    )
                    store.append(packet)
                    try:
                        with spend_metadata(
                            proof_action_id=running.logical_id,
                            proof_attempt_id=running.attempt_id,
                            proof_role="obligation_resolution",
                            candidate_id=candidate.logical_id,
                            obligation_id=obligation.logical_id,
                            proof_plan_id=obligation.proof_plan_id,
                            obligation_predicate=obligation.predicate,
                            action_template=running.template,
                            model_route=running.model_route,
                        ):
                            resolution = await BoundedModelResolver(client).resolve(
                                candidate,
                                obligation,
                                packet,
                            )
                    except Exception as exc:
                        logger.warning(
                            "Bounded proof resolver failed for %s",
                            obligation.logical_id,
                            exc_info=True,
                        )
                        scheduler.complete(
                            running,
                            status=ActionStatus.FAILED,
                            error=str(exc),
                        )
                        continue
            if resolution is None:
                reason = (
                    "no model route configured"
                    if running.model_route
                    else "mechanical action produced no conclusive evidence"
                )
                scheduler.complete(
                    running,
                    status=ActionStatus.FAILED,
                    error=reason,
                )
                continue
            apply_resolution(graph, store, obligation, resolution)
            scheduler.complete(
                running,
                status=ActionStatus.COMPLETED,
                evidence_ids=[evidence.logical_id for evidence in resolution.evidence]
                or output_evidence_ids,
                claim_ids=[claim.logical_id for claim in resolution.claims],
            )

    @staticmethod
    def _run_validation_action(
        store: ProofStore,
        graph: ProofGraph,
        candidate: Candidate,
        obligation: Any,
        action: Action,
        command_runner: CommandRunner,
        manifest: ValidationManifest,
        repo_path: Path,
    ) -> tuple[Resolution | None, list[str]]:
        spec = manifest.match(candidate, obligation, action.template)
        if spec is None:
            return None, []
        cwd = (repo_path / spec.cwd).resolve()
        try:
            cwd.relative_to(repo_path.resolve())
        except ValueError as exc:
            raise ProofPreflightError(f"Validation cwd escapes the repository: {spec.cwd}") from exc
        evidence_ids: list[str] = []
        command = tuple(spec.command)
        if spec.harness_template is not None:
            preparation = TemplateHarnessBackend(command_runner, store).prepare(
                snapshot_id=candidate.snapshot_id,
                candidate_id=candidate.logical_id,
                spec=spec.harness_template,
                repo_root=repo_path,
                timeout_seconds=spec.timeout_seconds,
            )
            graph.reload()
            evidence_ids.append(preparation.evidence.logical_id)
            if not preparation.succeeded:
                return (
                    Resolution(
                        status=ObligationStatus.BLOCKED,
                        blocked_reason=preparation.error,
                    ),
                    evidence_ids,
                )
            command = preparation.command
        request = ValidationRequest(
            snapshot_id=candidate.snapshot_id,
            candidate_id=candidate.logical_id,
            command=command,
            cwd=cwd,
            repeats=spec.repeats,
            timeout_seconds=spec.timeout_seconds,
            metadata={
                "validation_spec": spec.name,
                "action_template": action.template,
                "obligation_predicate": obligation.predicate,
                **spec.metadata,
            },
            success_condition=spec.success_condition,
            output_regex=spec.output_regex,
            evidence_kind=spec.evidence_kind,
            required_reproductions=spec.required_reproductions,
        )
        backend = (
            SanitizerValidationBackend(command_runner, store)
            if spec.success_condition == "sanitizer"
            else CommandValidationBackend(command_runner, store)
        )
        result = backend.validate(request)
        graph.reload()
        evidence_ids.append(result.evidence.logical_id)
        if result.reproductions < spec.required_reproductions:
            return (
                Resolution(
                    status=ObligationStatus.BLOCKED,
                    blocked_reason=(
                        f"Validation {spec.name!r} reproduced "
                        f"{result.reproductions}/{result.runs} times; "
                        f"{spec.required_reproductions} required"
                    ),
                ),
                evidence_ids,
            )
        claim = Claim(
            snapshot_id=candidate.snapshot_id,
            predicate=obligation.predicate,
            subject=candidate.logical_id,
            object=(
                f"Bounded validation {spec.name!r} satisfied its declared "
                f"success condition in {result.reproductions}/{result.runs} runs."
            ),
            status=ObligationStatus.PROVEN,
            scope={
                "obligation_id": obligation.logical_id,
                "validation_spec": spec.name,
            },
            supporting_evidence_ids=evidence_ids,
        )
        derivation = Derivation(
            snapshot_id=candidate.snapshot_id,
            rule=f"dynamic-validation:{spec.action_template}",
            premise_ids=evidence_ids,
            conclusion_claim_ids=[claim.logical_id],
            limitations=[
                "The command establishes only the scoped runtime predicate; "
                "reachability and threat-model claims require separate evidence."
            ],
            validator="deterministic",
        )
        return (
            Resolution(
                status=ObligationStatus.PROVEN,
                claims=[claim],
                derivations=[derivation],
            ),
            evidence_ids,
        )

    def _resolve_repository(self) -> str:
        preprocessor = Preprocessor(
            repo_url=self.repo_url,
            branch=self.branch,
            local_path=self.local_path,
            build_callgraph=False,
            run_semgrep=False,
            tag_files=False,
        )
        return str(preprocessor._clone_or_use_local())

    def _compile_commands_path(self, repo_path: Path) -> Path:
        if self.config.compile_commands:
            candidate = Path(self.config.compile_commands).expanduser()
            if not candidate.is_absolute():
                candidate = repo_path / candidate
            return candidate.resolve()
        return (repo_path / "compile_commands.json").resolve()

    def _build_sandbox_runner(
        self,
        repo_path: str,
        languages: list[str],
    ) -> SandboxCommandRunner:
        try:
            self._sandbox = HunterSandbox(
                repo_path,
                languages=languages,
                extra_packages=["clang"],
                default_cpus=self.config.sandbox_cpus,
            )
            self._sandbox.build_image()
            container = self._sandbox.spawn(
                session_id=self.config.session_id or None,
                runtime=self.config.gvisor_runtime,
            )
        except Exception as exc:
            raise ProofPreflightError(
                f"Unable to start the required C/C++ analysis sandbox: {exc}",
                missing=("analysis_sandbox",),
            ) from exc
        return SandboxCommandRunner(container, host_root=repo_path)

    def _model_client(self, route: str) -> Any | None:
        if self.model_client_factory is None:
            return None
        try:
            return self.model_client_factory(route)
        except Exception:
            logger.debug("Proof model route %s is unavailable", route, exc_info=True)
            return None

    @staticmethod
    def _language_inventory(repo_path: Path) -> dict[str, int]:
        counts: dict[str, int] = {}
        for path in repo_path.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
            if language:
                counts[language] = counts.get(language, 0) + 1
        return counts
