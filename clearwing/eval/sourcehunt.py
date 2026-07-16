"""Reproducible Phase-0 evaluation for sourcehunt.

The evaluation contract deliberately separates information used to execute a
known snapshot from information revealed to the hunter.  That lets the same
case and hint packet be replayed across model tiers without leaking later
ablation levels into earlier ones.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Awaitable, Callable, Iterable
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from clearwing.sourcehunt.instrumentation import stable_run_id

FUNNEL_STAGES: tuple[str, ...] = (
    "target_in_working_set",
    "relevant_facts_extracted",
    "true_candidate_generated",
    "correct_proof_plan_selected",
    "reachability_dataflow_resolved",
    "guards_counterevidence_handled",
    "validation_plan_constructed",
    "expected_evidence_acquired",
    "threat_model_classified",
    "correct_certificate_compiled",
)


class _EvalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ThreatGroundTruth(_EvalModel):
    attacker_principal: str
    attacker_capabilities: list[str] = Field(default_factory=list)
    trust_boundary: str
    protected_asset: str
    capability_gained: str
    security_property_violated: str
    deployment_assumptions: list[str] = Field(default_factory=list)


class IntermediateGroundTruth(_EvalModel):
    """Expected artifacts at every point where ground truth is knowable."""

    target_files: list[str]
    target_functions: list[str]
    expected_fact_symbols: list[str]
    entry_points: list[str]
    sources: list[str]
    sinks: list[str]
    transformations: list[str]
    invariants: list[str]
    guards: list[str]
    trigger_constraints: list[str]
    reproduction_behavior: list[str]
    trace: list[dict[str, Any]] = Field(default_factory=list)
    expected_mechanisms: list[str]
    expected_proof_plans: list[str]
    expected_predicates: list[str]
    expected_evidence_kinds: list[str]
    expected_decision: Literal["confirmed", "disproven", "incomplete"]
    expected_cwes: list[str] = Field(default_factory=list)
    threat_model: ThreatGroundTruth

    @model_validator(mode="after")
    def _require_intermediate_labels(self) -> IntermediateGroundTruth:
        required = {
            "target_files": self.target_files,
            "target_functions": self.target_functions,
            "expected_fact_symbols": self.expected_fact_symbols,
            "entry_points": self.entry_points,
            "sources": self.sources,
            "sinks": self.sinks,
            "transformations": self.transformations,
            "invariants": self.invariants,
            "trigger_constraints": self.trigger_constraints,
            "expected_mechanisms": self.expected_mechanisms,
            "expected_proof_plans": self.expected_proof_plans,
            "expected_predicates": self.expected_predicates,
        }
        missing = sorted(name for name, values in required.items() if not values)
        if missing:
            raise ValueError("Intermediate ground truth is incomplete: " + ", ".join(missing))
        return self


class SourceHuntCase(_EvalModel):
    id: str
    cves: list[str]
    repository: str
    vulnerable_commit: str
    fixed_commit: str | None = None
    language: str
    ground_truth: IntermediateGroundTruth

    @property
    def digest(self) -> str:
        """Pin plans and checkpoints to the complete case definition."""

        return stable_run_id("evalcase", self.model_dump(mode="json"))


class GroundTruthManifest(_EvalModel):
    schema_version: Literal[1] = 1
    cases: list[SourceHuntCase]

    @model_validator(mode="after")
    def _unique_cases(self) -> GroundTruthManifest:
        identifiers = [case.id for case in self.cases]
        duplicates = sorted(
            identifier for identifier, count in Counter(identifiers).items() if count > 1
        )
        if duplicates:
            raise ValueError("Duplicate sourcehunt cases: " + ", ".join(duplicates))
        if not self.cases:
            raise ValueError("A ground-truth manifest requires at least one case")
        return self

    @classmethod
    def load(cls, path: str | Path) -> GroundTruthManifest:
        source = Path(path).expanduser()
        text = source.read_text(encoding="utf-8")
        payload = json.loads(text) if source.suffix.lower() == ".json" else yaml.safe_load(text)
        return cls.model_validate(payload)

    def case(self, case_id: str) -> SourceHuntCase:
        for case in self.cases:
            if case.id == case_id:
                return case
        raise KeyError(case_id)


class AblationLevel(IntEnum):
    REPOSITORY = 1
    TARGET_FILE = 2
    TARGET_FUNCTION = 3
    SOURCE_SINK = 4
    INVARIANT_PATH = 5
    COMPLETE_TRACE = 6
    TRIGGER = 7


class AblationArm(_EvalModel):
    flow: Literal["legacy", "proof"]
    model_tier: Literal["local", "frontier"]
    model: str = Field(min_length=1)


class AblationRunSpec(_EvalModel):
    id: str = ""
    context_id: str = ""
    case_id: str
    repository: str
    vulnerable_commit: str
    case_digest: str = Field(min_length=1)
    flow: Literal["legacy", "proof"]
    model_tier: Literal["local", "frontier"]
    model: str = Field(min_length=1)
    level: AblationLevel
    replicate: int = Field(default=1, ge=1)
    hints: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _assign_ids(self) -> AblationRunSpec:
        context_payload = {
            "case_id": self.case_id,
            "case_digest": self.case_digest,
            "repository": self.repository,
            "vulnerable_commit": self.vulnerable_commit,
            "level": int(self.level),
            "hints": self.hints,
        }
        expected_context_id = stable_run_id("evalcontext", context_payload)
        if self.context_id and self.context_id != expected_context_id:
            raise ValueError("Ablation context_id does not match its pinned inputs")
        if not self.context_id:
            object.__setattr__(
                self,
                "context_id",
                expected_context_id,
            )
        expected_run_id = stable_run_id(
            "evalrun",
            {
                **context_payload,
                "flow": self.flow,
                "model_tier": self.model_tier,
                "model": self.model,
                "replicate": self.replicate,
            },
        )
        if self.id and self.id != expected_run_id:
            raise ValueError("Ablation run ID does not match its pinned inputs")
        if not self.id:
            object.__setattr__(
                self,
                "id",
                expected_run_id,
            )
        return self

    def campaign_hint(self) -> str | None:
        """Return the exact assisted context accepted by sourcehunt's CLI."""

        if not self.hints:
            return None
        return json.dumps(
            {
                "context_id": self.context_id,
                "ablation_level": int(self.level),
                **self.hints,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class AblationPlan(_EvalModel):
    schema_version: Literal[1] = 1
    id: str = ""
    ground_truth_path: str = ""
    required_model_tiers: list[Literal["local", "frontier"]] = Field(
        default_factory=lambda: ["local", "frontier"]
    )
    runs: list[AblationRunSpec]

    @model_validator(mode="after")
    def _validate_matrix(self) -> AblationPlan:
        if not self.runs:
            raise ValueError("An ablation plan requires at least one run")
        if (
            set(self.required_model_tiers) != {"local", "frontier"}
            or len(self.required_model_tiers) != 2
        ):
            raise ValueError("Ablation plans require exactly local and frontier model tiers")
        run_ids = [run.id for run in self.runs]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("Ablation plan contains duplicate run IDs")
        tiers_by_cell: dict[tuple[str, str, int, int], set[str]] = defaultdict(set)
        tier_counts_by_cell: dict[tuple[str, str, int, int], Counter[str]] = defaultdict(Counter)
        contexts_by_cell: dict[tuple[str, str, int, int], set[str]] = defaultdict(set)
        for run in self.runs:
            cell = (run.case_id, run.flow, int(run.level), run.replicate)
            tiers_by_cell[cell].add(run.model_tier)
            tier_counts_by_cell[cell][run.model_tier] += 1
            contexts_by_cell[cell].add(run.context_id)
        required = set(self.required_model_tiers)
        incomplete = sorted(cell for cell, tiers in tiers_by_cell.items() if not required <= tiers)
        if incomplete:
            raise ValueError(
                "Every ablation cell must contain local and frontier arms; "
                f"missing tier(s) in {incomplete[:3]}"
            )
        duplicates = sorted(
            cell
            for cell, counts in tier_counts_by_cell.items()
            if any(count != 1 for tier, count in counts.items() if tier in required)
        )
        if duplicates:
            raise ValueError(
                "Every ablation cell must contain exactly one run per model tier; "
                f"duplicate tier(s) in {duplicates[:3]}"
            )
        divergent = sorted(
            cell for cell, contexts in contexts_by_cell.items() if len(contexts) != 1
        )
        if divergent:
            raise ValueError(f"Model tiers received different context packets in {divergent[:3]}")
        expected_plan_id = stable_run_id("evalplan", sorted(run_ids))
        if self.id and self.id != expected_plan_id:
            raise ValueError("Ablation plan ID does not match its runs")
        if not self.id:
            object.__setattr__(
                self,
                "id",
                expected_plan_id,
            )
        return self

    @classmethod
    def load(cls, path: str | Path) -> AblationPlan:
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))

    def write(self, path: str | Path) -> Path:
        target = Path(path).expanduser()
        _atomic_write_text(
            target,
            json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        )
        return target


def ablation_hints(
    case: SourceHuntCase,
    level: AblationLevel,
) -> dict[str, Any]:
    """Reveal exactly the information permitted at one ablation level."""

    truth = case.ground_truth
    hints: dict[str, Any] = {}
    if level >= AblationLevel.TARGET_FILE:
        hints["target_files"] = truth.target_files
    if level >= AblationLevel.TARGET_FUNCTION:
        hints["target_functions"] = truth.target_functions
    if level >= AblationLevel.SOURCE_SINK:
        hints.update({"sources": truth.sources, "sinks": truth.sinks})
    if level >= AblationLevel.INVARIANT_PATH:
        hints.update(
            {
                "invariants": truth.invariants,
                "transformations": truth.transformations,
            }
        )
    if level >= AblationLevel.COMPLETE_TRACE:
        hints.update(
            {
                "entry_points": truth.entry_points,
                "trace": truth.trace,
                "guards": truth.guards,
            }
        )
    if level >= AblationLevel.TRIGGER:
        hints.update(
            {
                "trigger_constraints": truth.trigger_constraints,
                "reproduction_behavior": truth.reproduction_behavior,
            }
        )
    return hints


def build_ablation_plan(
    manifest: GroundTruthManifest,
    arms: Iterable[AblationArm],
    *,
    levels: Iterable[AblationLevel] = tuple(AblationLevel),
    replicates: int = 1,
    ground_truth_path: str = "",
) -> AblationPlan:
    if replicates < 1:
        raise ValueError("replicates must be at least one")
    selected_arms = list(arms)
    selected_levels = sorted(set(levels), key=int)
    runs = [
        AblationRunSpec(
            case_id=case.id,
            repository=case.repository,
            vulnerable_commit=case.vulnerable_commit,
            case_digest=case.digest,
            flow=arm.flow,
            model_tier=arm.model_tier,
            model=arm.model,
            level=level,
            replicate=replicate,
            hints=ablation_hints(case, level),
        )
        for case in manifest.cases
        for level in selected_levels
        for replicate in range(1, replicates + 1)
        for arm in selected_arms
    ]
    return AblationPlan(
        ground_truth_path=ground_truth_path,
        runs=runs,
    )


class StageFunnel(_EvalModel):
    target_in_working_set: bool | None = None
    relevant_facts_extracted: bool | None = None
    true_candidate_generated: bool | None = None
    correct_proof_plan_selected: bool | None = None
    reachability_dataflow_resolved: bool | None = None
    guards_counterevidence_handled: bool | None = None
    validation_plan_constructed: bool | None = None
    expected_evidence_acquired: bool | None = None
    threat_model_classified: bool | None = None
    correct_certificate_compiled: bool | None = None

    def first_failure(self) -> str | None:
        for stage in FUNNEL_STAGES:
            if getattr(self, stage) is False:
                return stage
        return None


class RunObservation(_EvalModel):
    schema_version: Literal[1] = 1
    run_id: str
    context_id: str
    case_id: str
    flow: Literal["legacy", "proof"]
    model_tier: Literal["local", "frontier"]
    model: str = ""
    level: AblationLevel
    replicate: int
    session_dir: str
    status: str
    funnel: StageFunnel
    first_failure: str | None = None
    true_positives: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    false_negatives: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    rejection_count: int = Field(default=0, ge=0)
    incomplete_count: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    report_claim_count: int = Field(default=0, ge=0)
    unsupported_claims: int = Field(default=0, ge=0)
    report_failures: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _derive_failure(self) -> RunObservation:
        expected = self.funnel.first_failure()
        if self.first_failure is None and expected is not None:
            object.__setattr__(self, "first_failure", expected)
        elif self.first_failure is not None and self.first_failure not in FUNNEL_STAGES:
            raise ValueError(f"Unknown funnel stage: {self.first_failure}")
        elif self.first_failure != expected:
            raise ValueError(
                f"first_failure must be derived from the funnel: expected {expected!r}, "
                f"received {self.first_failure!r}"
            )
        return self


class BaselineGroup(_EvalModel):
    flow: str
    model_tier: str
    model: str
    level: int
    runs: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    mean_cost_usd: float
    mean_tokens: float
    report_claims: int
    unsupported_claims: int
    unsupported_claim_rate: float
    report_failure_rate: float
    failure_stage_counts: dict[str, int]


class BaselineReport(_EvalModel):
    schema_version: Literal[1] = 1
    plan_id: str
    complete: bool
    expected_runs: int
    observed_runs: int
    missing_run_ids: list[str]
    unexpected_run_ids: list[str]
    groups: list[BaselineGroup]

    def write(self, path: str | Path) -> Path:
        target = Path(path).expanduser()
        _atomic_write_text(
            target,
            json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        )
        return target

    def markdown(self) -> str:
        lines = [
            "# Sourcehunt Phase 0 baseline",
            "",
            f"- Plan: `{self.plan_id}`",
            f"- Matrix complete: `{str(self.complete).lower()}`",
            f"- Runs: {self.observed_runs}/{self.expected_runs}",
            "",
            "| Flow | Tier | Model | Level | Runs | Precision | Recall | Mean cost | Mean tokens | Unsupported claims | Report failures | First failures |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
        for group in self.groups:
            failures = (
                ", ".join(f"{stage}={count}" for stage, count in group.failure_stage_counts.items())
                or "none"
            )
            lines.append(
                f"| {group.flow} | {group.model_tier} | {group.model or '-'} | "
                f"{group.level} | {group.runs} | {group.precision:.3f} | "
                f"{group.recall:.3f} | ${group.mean_cost_usd:.4f} | "
                f"{group.mean_tokens:.0f} | {group.unsupported_claims}/"
                f"{group.report_claims} ({group.unsupported_claim_rate:.3f}) | "
                f"{group.report_failure_rate:.3f} | {failures} |"
            )
        if self.missing_run_ids:
            lines.extend(
                ["", "## Missing runs", "", *[f"- `{item}`" for item in self.missing_run_ids]]
            )
        if self.unexpected_run_ids:
            lines.extend(
                [
                    "",
                    "## Unexpected runs",
                    "",
                    *[f"- `{item}`" for item in self.unexpected_run_ids],
                ]
            )
        return "\n".join(lines).rstrip() + "\n"


def aggregate_baseline(
    plan: AblationPlan,
    observations: Iterable[RunObservation],
    *,
    require_complete: bool = True,
) -> BaselineReport:
    observed = list(observations)
    by_id: dict[str, RunObservation] = {}
    for observation in observed:
        if observation.run_id in by_id:
            raise ValueError(f"Duplicate observation for {observation.run_id}")
        by_id[observation.run_id] = observation
    specs_by_id = {run.id: run for run in plan.runs}
    expected_ids = {run.id for run in plan.runs}
    observed_ids = set(by_id)
    missing = sorted(expected_ids - observed_ids)
    unexpected = sorted(observed_ids - expected_ids)
    complete = not missing and not unexpected
    if require_complete and not complete:
        raise ValueError(
            f"Ablation matrix is incomplete: {len(missing)} missing, {len(unexpected)} unexpected"
        )
    for run_id in sorted(expected_ids & observed_ids):
        _validate_observation_against_spec(by_id[run_id], specs_by_id[run_id])

    grouped: dict[tuple[str, str, str, int], list[RunObservation]] = defaultdict(list)
    for observation in observed:
        if observation.run_id not in expected_ids:
            continue
        grouped[
            (
                observation.flow,
                observation.model_tier,
                observation.model,
                int(observation.level),
            )
        ].append(observation)
    groups: list[BaselineGroup] = []
    for (flow, tier, model, level), values in sorted(grouped.items()):
        tp = sum(item.true_positives for item in values)
        fp = sum(item.false_positives for item in values)
        fn = sum(item.false_negatives for item in values)
        claims = tp + fp
        expected = tp + fn
        report_claims = sum(item.report_claim_count for item in values)
        unsupported_claims = sum(item.unsupported_claims for item in values)
        failures = Counter(item.first_failure for item in values if item.first_failure is not None)
        groups.append(
            BaselineGroup(
                flow=flow,
                model_tier=tier,
                model=model,
                level=level,
                runs=len(values),
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=(tp / claims if claims else 0.0),
                recall=(tp / expected if expected else 0.0),
                mean_cost_usd=sum(item.cost_usd for item in values) / len(values),
                mean_tokens=sum(item.input_tokens + item.output_tokens for item in values)
                / len(values),
                report_claims=report_claims,
                unsupported_claims=unsupported_claims,
                unsupported_claim_rate=(
                    unsupported_claims / report_claims if report_claims else 0.0
                ),
                report_failure_rate=sum(bool(item.report_failures) for item in values)
                / len(values),
                failure_stage_counts=dict(sorted(failures.items())),
            )
        )
    return BaselineReport(
        plan_id=plan.id,
        complete=complete,
        expected_runs=len(expected_ids),
        observed_runs=len(expected_ids & observed_ids),
        missing_run_ids=missing,
        unexpected_run_ids=unexpected,
        groups=groups,
    )


def load_observations(paths: Iterable[str | Path]) -> list[RunObservation]:
    observations: list[RunObservation] = []
    for path in paths:
        source = Path(path).expanduser()
        payload = json.loads(source.read_text(encoding="utf-8"))
        items = payload if isinstance(payload, list) else payload.get("observations", [])
        observations.extend(RunObservation.model_validate(item) for item in items)
    return observations


def write_observations(
    observations: Iterable[RunObservation],
    path: str | Path,
) -> Path:
    target = Path(path).expanduser()
    _atomic_write_text(
        target,
        json.dumps(
            {
                "schema_version": 1,
                "observations": [item.model_dump(mode="json") for item in observations],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return target


def _atomic_write_text(path: Path, payload: str) -> None:
    """Publish plan, checkpoint, and baseline JSON without partial files."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _validate_observation_against_spec(
    observation: RunObservation,
    spec: AblationRunSpec,
) -> None:
    expected = {
        "run_id": spec.id,
        "context_id": spec.context_id,
        "case_id": spec.case_id,
        "flow": spec.flow,
        "model_tier": spec.model_tier,
        "model": spec.model,
        "level": spec.level,
        "replicate": spec.replicate,
    }
    mismatches = [
        name
        for name, expected_value in expected.items()
        if getattr(observation, name) != expected_value
    ]
    if mismatches:
        raise ValueError(
            f"Observation {observation.run_id} disagrees with its plan for: "
            + ", ".join(mismatches)
        )


CampaignExecutor = Callable[
    [AblationRunSpec, SourceHuntCase],
    RunObservation | Awaitable[RunObservation],
]


async def execute_sourcehunt_run(
    spec: AblationRunSpec,
    case: SourceHuntCase,
    *,
    checkout: str | Path,
    output_dir: str | Path,
    provider_manager: Any,
    budget_usd: float,
    compile_commands: str | None = None,
    validation_manifest: str | None = None,
    scheduler_calibration: str | None = None,
    learning_registry: str | None = None,
    proof_max_actions: int = 200,
    proof_max_model_calls: int = 40,
    proof_max_dynamic_actions: int = 20,
) -> RunObservation:
    """Run one planned arm against a pre-positioned immutable checkout."""

    from clearwing.sourcehunt.runner import SourceHuntRunner

    checkout_path = Path(checkout).expanduser().resolve()
    if not checkout_path.is_dir():
        raise ValueError(f"Checkout does not exist for {case.id}: {checkout_path}")
    if spec.case_id != case.id or spec.case_digest != case.digest:
        raise ValueError(f"Plan and ground truth disagree for case {spec.case_id}")
    if spec.repository != case.repository or spec.vulnerable_commit != case.vulnerable_commit:
        raise ValueError(f"Plan snapshot and ground truth disagree for case {case.id}")
    head = subprocess.run(
        ["git", "-C", str(checkout_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != case.vulnerable_commit:
        raise ValueError(f"Checkout for {case.id} is at {head}, expected {case.vulnerable_commit}")
    if not spec.model:
        raise ValueError(f"Planned run {spec.id} has no model name")
    if budget_usd <= 0:
        raise ValueError("Ablation runs require a positive per-run budget")
    tracked_changes = subprocess.run(
        ["git", "-C", str(checkout_path), "status", "--porcelain", "--untracked-files=no"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if tracked_changes:
        raise ValueError(f"Checkout for {case.id} has tracked modifications")
    if case.language.lower() in {"c", "cpp", "c++"} and not compile_commands:
        raise ValueError(f"C/C++ case {case.id} requires compile_commands")
    for label, path in (
        ("compile_commands", compile_commands),
        ("validation_manifest", validation_manifest),
        ("scheduler_calibration", scheduler_calibration),
        ("learning_registry", learning_registry),
    ):
        if path and not Path(path).expanduser().is_file():
            raise ValueError(f"{label} does not exist for {case.id}: {path}")
    output_root = Path(output_dir).expanduser().resolve()
    runner = SourceHuntRunner(
        repo_url=case.repository,
        local_path=str(checkout_path),
        depth="deep",
        budget_usd=budget_usd,
        output_dir=str(output_root),
        output_formats=["sarif", "markdown", "json"],
        parent_session_id=spec.id,
        provider_manager=provider_manager,
        model_override=spec.model,
        campaign_hint=spec.campaign_hint(),
        flow=spec.flow,
        proof_compile_commands=compile_commands,
        proof_validation_manifest=validation_manifest,
        proof_scheduler_calibration=scheduler_calibration,
        proof_learning_registry=learning_registry,
        proof_max_actions=proof_max_actions,
        proof_max_model_calls=proof_max_model_calls,
        proof_max_dynamic_actions=proof_max_dynamic_actions,
        proof_exploration_fraction=0.0,
        falsify=True,
        no_exploit=True,
        enable_variant_loop=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
        enable_stability_verification=False,
        enable_knowledge_graph=False,
        enable_calibration=False,
        enable_findings_pool=False,
        enable_behavior_monitor=False,
    )
    await runner.arun()
    return inspect_ablation_session(spec, case, output_root / spec.id)


async def run_ablation_campaign(
    plan: AblationPlan,
    manifest: GroundTruthManifest,
    executor: CampaignExecutor,
    *,
    checkpoint_path: str | Path | None = None,
    existing: Iterable[RunObservation] = (),
) -> list[RunObservation]:
    """Execute a complete matrix with resumable, run-ID keyed checkpoints."""

    for spec in plan.runs:
        case = manifest.case(spec.case_id)
        if (
            spec.case_digest != case.digest
            or spec.repository != case.repository
            or spec.vulnerable_commit != case.vulnerable_commit
        ):
            raise ValueError(f"Plan and ground truth disagree for case {spec.case_id}")
    observations: dict[str, RunObservation] = {}
    for item in existing:
        previous = observations.get(item.run_id)
        if previous is not None and previous != item:
            raise ValueError(f"Conflicting checkpoint observations for {item.run_id}")
        observations[item.run_id] = item
    expected = {run.id for run in plan.runs}
    unknown = sorted(set(observations) - expected)
    if unknown:
        raise ValueError(f"Checkpoint contains unknown run IDs: {unknown[:3]}")
    specs_by_id = {run.id: run for run in plan.runs}
    for run_id, observation in observations.items():
        _validate_observation_against_spec(observation, specs_by_id[run_id])
    for spec in plan.runs:
        if spec.id in observations:
            continue
        outcome = executor(spec, manifest.case(spec.case_id))
        observation = await outcome if inspect.isawaitable(outcome) else outcome
        if observation.run_id != spec.id:
            raise ValueError(f"Executor returned {observation.run_id} for planned run {spec.id}")
        _validate_observation_against_spec(observation, spec)
        observations[spec.id] = observation
        if checkpoint_path is not None:
            write_observations(observations.values(), checkpoint_path)
    return [observations[run.id] for run in plan.runs]


def inspect_ablation_session(
    spec: AblationRunSpec,
    case: SourceHuntCase,
    session_dir: str | Path,
) -> RunObservation:
    """Score a proof or legacy session against intermediate ground truth."""

    root = Path(session_dir).expanduser()
    if not root.is_dir():
        raise ValueError(f"Sourcehunt session directory does not exist: {root}")
    if (
        spec.case_id != case.id
        or spec.case_digest != case.digest
        or spec.repository != case.repository
        or spec.vulnerable_commit != case.vulnerable_commit
    ):
        raise ValueError(f"Plan and ground truth disagree for case {spec.case_id}")
    return (
        _inspect_proof_session(spec, case, root)
        if spec.flow == "proof"
        else _inspect_legacy_session(spec, case, root)
    )


def _inspect_proof_session(
    spec: AblationRunSpec,
    case: SourceHuntCase,
    root: Path,
) -> RunObservation:
    from clearwing.sourcehunt.proof import (
        Action,
        Candidate,
        Certificate,
        CertificateKind,
        Evidence,
        EvidencePolicy,
        Fact,
        Obligation,
        ProofStore,
        ThreatModel,
    )

    store = ProofStore(root)
    truth = case.ground_truth
    facts = list(store.latest(Fact).values())
    candidates = list(store.latest(Candidate).values())
    obligations = list(store.latest(Obligation).values())
    evidence = list(store.latest(Evidence).values())
    actions = list(store.latest(Action).values())
    certificates = [
        item for item in store.latest(Certificate).values() if item.validity == "current"
    ]
    threats = list(store.latest(ThreatModel).values())
    facts_by_id = {identifier: fact for fact in facts for identifier in (fact.id, fact.logical_id)}
    fact_files = {fact.location.file for fact in facts if fact.location is not None}
    target_facts = [
        fact
        for fact in facts
        if fact.location is not None and fact.location.file in set(truth.target_files)
    ]
    fact_text = " ".join(
        f"{fact.subject} {fact.predicate} {fact.object} {fact.properties}" for fact in target_facts
    ).lower()
    target_candidates = [
        candidate
        for candidate in candidates
        if candidate.suspected_mechanism in set(truth.expected_mechanisms)
        and {
            fact.location.file
            for fact_id in candidate.fact_ids
            if (fact := facts_by_id.get(fact_id)) is not None and fact.location is not None
        }.intersection(truth.target_files)
    ]
    target_candidate_ids = {
        identifier
        for candidate in target_candidates
        for identifier in (candidate.id, candidate.logical_id)
    }
    mechanisms = {candidate.suspected_mechanism for candidate in target_candidates}
    plans = {plan for candidate in target_candidates for plan in candidate.proof_plan_ids}
    target_obligations = [
        obligation for obligation in obligations if obligation.candidate_id in target_candidate_ids
    ]
    predicates = {obligation.predicate for obligation in target_obligations}
    dataflow_obligations = [
        obligation
        for obligation in target_obligations
        if any(token in obligation.predicate for token in ("reach", "attacker", "flow"))
    ]
    guard_obligations = [
        obligation
        for obligation in target_obligations
        if obligation.decisive_rejection
        or any(token in obligation.predicate for token in ("guard", "bound", "counter"))
    ]
    evidence_by_id = {
        identifier: item for item in evidence for identifier in (item.id, item.logical_id)
    }
    target_actions = [action for action in actions if action.candidate_id in target_candidate_ids]
    evidence_policy = EvidencePolicy()
    report_claims = [claim for certificate in certificates for claim in certificate.report_claims]
    unsupported_report_claims = 0
    for claim in report_claims:
        cited_ids = [str(item) for item in claim.get("evidence_ids", [])]
        cited_evidence = [evidence_by_id[item] for item in cited_ids if item in evidence_by_id]
        predicate = str(claim.get("predicate") or "")
        if (
            not cited_ids
            or len(cited_evidence) != len(cited_ids)
            or not all(evidence_policy.accepts(predicate, item) for item in cited_evidence)
        ):
            unsupported_report_claims += 1
    dynamic_actions = [
        action
        for action in target_actions
        if any(
            token in action.template
            for token in ("validate", "harness", "fuzz", "differential", "sanitizer")
        )
    ]
    expected_decision = truth.expected_decision
    decision_matches = [
        certificate
        for certificate in certificates
        if certificate.decision == expected_decision
        and certificate.candidate_id in target_candidate_ids
        and (not truth.expected_cwes or certificate.cwe in set(truth.expected_cwes))
        and (
            not truth.target_files
            or bool(set(certificate.dependency_files).intersection(truth.target_files))
        )
    ]
    relevant_evidence_ids = {
        *(evidence_id for action in target_actions for evidence_id in action.output_evidence_ids),
        *(
            evidence_id
            for certificate in decision_matches
            for evidence_id in certificate.evidence_ids
        ),
    }
    evidence_kinds = {
        evidence.kind
        for evidence_id in relevant_evidence_ids
        if (evidence := evidence_by_id.get(evidence_id)) is not None
    }
    finding_count = sum(item.kind == CertificateKind.FINDING for item in certificates)
    rejection_count = sum(item.kind == CertificateKind.REJECTION for item in certificates)
    incomplete_count = sum(item.kind == CertificateKind.INCOMPLETE for item in certificates)
    expected_positive = expected_decision == "confirmed"
    true_positive = int(expected_positive and bool(decision_matches))
    false_positive = max(0, finding_count - true_positive)
    false_negative = int(expected_positive and not decision_matches)
    target_threat_ids = {
        candidate.threat_model_id for candidate in target_candidates if candidate.threat_model_id
    }
    target_threats = [
        threat
        for threat in threats
        if threat.id in target_threat_ids or threat.logical_id in target_threat_ids
    ]
    threat_text = " ".join(
        " ".join(
            [
                threat.attacker_principal,
                *threat.attacker_capabilities,
                *threat.trust_boundaries,
                *threat.protected_assets,
                *threat.capability_gained,
                *threat.security_properties_violated,
            ]
        )
        for threat in target_threats
    ).lower()
    expected_threat_terms = [
        truth.threat_model.attacker_principal,
        truth.threat_model.trust_boundary,
        truth.threat_model.protected_asset,
        truth.threat_model.security_property_violated,
    ]
    manifest_payload = _read_json(root / "manifest.json")
    metrics = _read_json(root / "metrics" / "run-metrics.json")
    totals = metrics.get("totals", {}) if isinstance(metrics.get("totals"), dict) else {}
    funnel = StageFunnel(
        target_in_working_set=bool(set(truth.target_files) & fact_files),
        relevant_facts_extracted=all(
            symbol.lower() in fact_text for symbol in truth.expected_fact_symbols
        ),
        true_candidate_generated=bool(set(truth.expected_mechanisms) & mechanisms),
        correct_proof_plan_selected=(
            set(truth.expected_proof_plans) <= plans
            and set(truth.expected_predicates) <= predicates
        ),
        reachability_dataflow_resolved=(
            bool(dataflow_obligations)
            and all(item.status in {"proven", "disproven"} for item in dataflow_obligations)
        ),
        guards_counterevidence_handled=(
            bool(guard_obligations)
            and all(item.status in {"proven", "disproven"} for item in guard_obligations)
        ),
        validation_plan_constructed=bool(dynamic_actions),
        expected_evidence_acquired=(
            not truth.expected_evidence_kinds
            or bool(set(truth.expected_evidence_kinds) & evidence_kinds)
        ),
        threat_model_classified=(
            bool(target_threats)
            and all(term.lower() in threat_text for term in expected_threat_terms if term)
        ),
        correct_certificate_compiled=bool(decision_matches),
    )
    return RunObservation(
        run_id=spec.id,
        context_id=spec.context_id,
        case_id=spec.case_id,
        flow=spec.flow,
        model_tier=spec.model_tier,
        model=spec.model,
        level=spec.level,
        replicate=spec.replicate,
        session_dir=str(root),
        status=str(manifest_payload.get("status", "unknown")),
        funnel=funnel,
        true_positives=true_positive,
        false_positives=false_positive,
        false_negatives=false_negative,
        finding_count=finding_count,
        rejection_count=rejection_count,
        incomplete_count=incomplete_count,
        cost_usd=float(totals.get("cost_usd", manifest_payload.get("total_spent", 0.0)) or 0.0),
        input_tokens=int(totals.get("input_tokens", 0) or 0),
        output_tokens=int(totals.get("output_tokens", 0) or 0),
        report_claim_count=len(report_claims),
        unsupported_claims=unsupported_report_claims,
        report_failures=0,
    )


def _inspect_legacy_session(
    spec: AblationRunSpec,
    case: SourceHuntCase,
    root: Path,
) -> RunObservation:
    truth = case.ground_truth
    instrumentation = _read_json(root / "instrumentation" / "summary.json")
    manifest = _read_json(root / "manifest.json")
    raw_findings = _read_json(root / "findings.json", default=[])
    findings = (
        raw_findings
        if isinstance(raw_findings, list)
        else raw_findings.get("findings", [])
        if isinstance(raw_findings, dict)
        else []
    )
    stage_files = instrumentation.get("files_by_stage", {})
    ranked = set(stage_files.get("rank", []))
    matched = [
        finding
        for finding in findings
        if (not truth.target_files or str(finding.get("file") or "") in set(truth.target_files))
        and (not truth.expected_cwes or str(finding.get("cwe") or "") in set(truth.expected_cwes))
    ]
    expected_positive = truth.expected_decision == "confirmed"
    true_positive = int(expected_positive and bool(matched))
    false_positive = max(0, len(findings) - true_positive)
    false_negative = int(expected_positive and not matched)
    report_failures = int(instrumentation.get("reporting_failure_count", 0) or 0)
    funnel = StageFunnel(
        target_in_working_set=bool(set(truth.target_files) & ranked),
        relevant_facts_extracted=None,
        true_candidate_generated=bool(matched),
        correct_proof_plan_selected=None,
        reachability_dataflow_resolved=bool(
            matched and all(item.get("vulnerability_trace") for item in matched)
        ),
        guards_counterevidence_handled=None,
        validation_plan_constructed=bool(
            matched and any(item.get("poc") or item.get("crash_evidence") for item in matched)
        ),
        expected_evidence_acquired=bool(
            matched and any(item.get("evidence_level") != "suspicion" for item in matched)
        ),
        threat_model_classified=None,
        correct_certificate_compiled=bool(matched) if expected_positive else not findings,
    )
    total_tokens = int(manifest.get("total_tokens", 0) or 0)
    output_tokens = int(manifest.get("output_tokens", 0) or 0)
    input_tokens = int(manifest.get("input_tokens", max(0, total_tokens - output_tokens)) or 0)
    unsupported_claims = sum(
        str(finding.get("evidence_level") or "suspicion") == "suspicion" for finding in findings
    )
    return RunObservation(
        run_id=spec.id,
        context_id=spec.context_id,
        case_id=spec.case_id,
        flow=spec.flow,
        model_tier=spec.model_tier,
        model=spec.model,
        level=spec.level,
        replicate=spec.replicate,
        session_dir=str(root),
        status=str(manifest.get("status", "unknown")),
        funnel=funnel,
        true_positives=true_positive,
        false_positives=false_positive,
        false_negatives=false_negative,
        finding_count=len(findings),
        cost_usd=float(manifest.get("total_spent", 0.0) or 0.0),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        report_claim_count=len(findings),
        unsupported_claims=unsupported_claims,
        report_failures=report_failures,
    )


def _read_json(path: Path, default: Any | None = None) -> Any:
    if not path.is_file():
        return {} if default is None else default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {} if default is None else default
