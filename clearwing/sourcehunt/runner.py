"""SourceHuntRunner — the public orchestrator for the sourcehunt pipeline.

Analog of clearwing/runners/cicd/runner.py::CICDRunner, but for source-code
hunting instead of network targets.

Pipeline:
    preprocess → sandbox build → rank → tiered hunt → verify → exploit → report
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import math
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from opentelemetry import trace as otel_trace

from clearwing.core.event_payloads import SourcehuntStagePayload
from clearwing.core.events import EventBus
from clearwing.llm.budget import BudgetExceeded, SpendLedger
from clearwing.llm.native import AsyncLLMClient
from clearwing.observability.otel import get_oi_tracer
from clearwing.providers import (
    ProviderManager,
    resolve_llm_endpoint,
)
from clearwing.reporting.safety import redact_tree

from ..sandbox.hunter_sandbox import HunterSandbox
from .checkpoints import (
    ExploitationCheckpoint,
    ExploitationResult,
    HuntCheckpoint,
    HuntResult,
    PreprocessCheckpoint,
    RankCheckpoint,
    SourceHuntCheckpoint,
    VerificationCheckpoint,
    VerificationResult,
)
from .config import SourceHuntConfig
from .disclosure import (
    DisclosureGenerator,
)
from .disclosure import (
    write_bundle as write_disclosure_bundle,
)
from .exploiter import AgenticExploiter, Exploiter, apply_exploiter_result
from .harness_generator import HarnessGenerator, HarnessGeneratorConfig, SeededCrash
from .hunt_work_cache import HuntWorkCache
from .instrumentation import SourceHuntInstrumentation, stable_run_id
from .manifest import build_run_metadata
from .mechanism_memory import (
    MechanismExtractor,
    MechanismStore,
    format_mechanisms_for_prompt,
)
from .patcher import AutoPatcher, apply_patch_attempt
from .paths import resolve_repo_file
from .poc_runner import build_rerun_poc_callback
from .pool import HunterPool, HuntPoolConfig, TierBudget
from .preprocessor import (
    _SOURCE_EXTS_TO_LANG,
    Preprocessor,
    PreprocessResult,
    _tag_file,
)
from .ranker import Ranker, RankerConfig
from .state import (
    EvidenceLevel,
    FileTarget,
    Finding,
    PipelineStatus,
    StageOutcome,
    evidence_at_or_above,
    filter_by_evidence,
)
from .target_windows import render_target_window_message, split_physical_source_lines
from .variant_loop import (
    VariantLoop,
    VariantPatternGenerator,
)
from .verifier import Verifier, apply_verifier_result

logger = logging.getLogger(__name__)
tracer = get_oi_tracer(__name__)

MAX_TARGET_FILES = 100
MAX_TARGET_PATH_LENGTH = 1024
MAX_TARGET_FILE_BYTES = 2 * 1024 * 1024
MAX_TARGET_TOTAL_BYTES = 16 * 1024 * 1024
MAX_TARGET_WINDOWS = 512
MAX_TARGET_WINDOW_BYTES = 512 * 1024


@dataclass
class SourceHuntResult:
    """Result of a complete sourcehunt run."""

    exit_code: int  # 0=clean, 1=medium, 2=critical/high, 3=incomplete/budget
    repo_url: str
    repo_path: str
    findings: list[Finding]
    verified_findings: list[Finding]
    exploited_findings: list[Finding]
    files_ranked: int
    files_hunted: int
    duration_seconds: float
    cost_usd: float
    spent_per_tier: dict[str, float]
    tokens_used: int
    output_paths: dict[str, str] = field(default_factory=dict)
    checkpoint: dict[str, Any] | None = None
    session_id: str = ""
    subsystems_hunted: int = 0
    subsystem_spent_usd: float = 0.0
    potentials: list[dict] = field(default_factory=list)
    elaborated_findings: list[Finding] = field(default_factory=list)
    pipeline_status: PipelineStatus = field(default_factory=PipelineStatus)
    status: str = "completed"
    budget_usd: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for f in self.verified_findings
            if (f.get("severity_verified") or f.get("severity")) == "critical"
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for f in self.verified_findings
            if (f.get("severity_verified") or f.get("severity")) == "high"
        )


@dataclass(frozen=True)
class SourceHuntProgress:
    """One semantic sourcehunt stage transition.

    Transports may persist and sequence these values for polling or streaming.
    """

    stage: str
    status: str
    findings_so_far: int = 0
    cost_usd: float = 0.0
    detail: str = ""
    files: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    error: dict[str, Any] | None = None
    type: Literal["stage"] = "stage"


SourceHuntProgressCallback = Callable[[SourceHuntProgress], None]


_IMPACT_TO_SEVERITY = {
    "code_execution": "critical",
    "remote_code_execution": "critical",
    "sandbox_escape": "critical",
    "privilege_escalation": "critical",
    "cross_origin_bypass": "high",
    "info_disclosure": "high",
    "denial_of_service": "medium",
}


def _apply_elaboration(finding: Finding, elab_result) -> Finding:
    """Create a new finding from a successful elaboration."""
    sev = _IMPACT_TO_SEVERITY.get(
        elab_result.upgraded_impact or "",
        "high",
    )
    stable_finding_id = stable_run_id(
        "elab",
        {
            "finding_id": finding.get("id", "unknown"),
            "upgrade_path": elab_result.upgrade_path,
            "upgraded_impact": elab_result.upgraded_impact,
            "upgraded_exploit_code": elab_result.upgraded_exploit_code,
            "chained_findings": sorted(elab_result.chained_findings or []),
        },
    )
    return {
        "id": f"elab-{uuid.uuid4().hex[:8]}",
        "stable_finding_id": stable_finding_id,
        "related_finding_id": finding.get("id", "unknown"),
        "file": finding.get("file", ""),
        "line_number": finding.get("line_number"),
        "end_line": finding.get("end_line"),
        "finding_type": finding.get("finding_type", "unknown"),
        "cwe": finding.get("cwe"),
        "severity": sev,
        "severity_verified": sev,
        "evidence_level": "exploit_demonstrated",
        "verified": True,
        "description": (f"Elaborated from {finding.get('id', '?')}: {elab_result.upgrade_path}"),
        "exploit": elab_result.upgraded_exploit_code or "",
        "exploit_success": True,
        "exploit_impact": elab_result.upgraded_impact or "",
        "discovered_by": "elaboration_agent",
        "elaboration_upgrade_path": elab_result.upgrade_path,
        "exploit_chained_findings": elab_result.chained_findings,
    }


class SourceHuntRunner:
    """Public entry point for the sourcehunt pipeline."""

    def __init__(
        self,
        repo_url: str = "",
        branch: str = "main",
        local_path: str | None = None,
        target_files: list[str] | tuple[str, ...] | None = None,
        target_window_lines: int | None = None,
        depth: str = "standard",  # quick | standard | deep
        budget_usd: float = 0.0,
        input_price_per_million: float | None = None,
        output_price_per_million: float | None = None,
        max_parallel: int = 8,
        tier_budget: TierBudget | None = None,
        output_dir: str | None = None,
        output_formats: list[str] | None = None,
        no_verify: bool = False,
        no_exploit: bool = False,
        exploit_budget: str | None = None,  # "standard" | "deep" | "campaign" | None (auto)
        enable_elaboration: bool = False,  # v0.4: Stage 1.5 exploit elaboration
        elaboration_cap: str = "10%",  # max findings to elaborate
        adversarial_verifier: bool = True,  # v0.2: on by default
        adversarial_threshold: EvidenceLevel | None = "static_corroboration",  # v0.4: budget gate
        validator_mode: str = "v2",  # "v1" (old Verifier) | "v2" (4-axis Validator)
        enable_calibration: bool = True,  # v0.5: severity calibration tracking
        enable_mechanism_memory: bool = True,  # v0.3: cross-run mechanism store
        mechanism_store_path: Any = None,  # override default store location
        enable_patch_oracle: bool = True,  # v0.3: patch oracle truth test
        enable_stability_verification: bool = True,  # v0.5: Stage 2.5 PoC stability
        enable_variant_loop: bool = True,  # v0.3: compound finding density
        enable_auto_patch: bool = False,  # v0.3: opt-in auto-patch mode
        auto_pr: bool = False,  # v0.3: open a draft PR via gh
        enable_knowledge_graph: bool = True,  # v0.3: populate source-hunt KG
        knowledge_graph: Any = None,  # inject a KG instance for tests
        export_disclosures: bool = False,  # v0.4: write MITRE/HackerOne templates
        disclosure_reporter_name: str = "(your name)",
        disclosure_reporter_affiliation: str = "(your affiliation)",
        disclosure_reporter_email: str = "(your email)",
        model_override: str | None = None,
        provider_manager: ProviderManager | None = None,
        ranker_llm: Any = None,  # injectable for tests
        hunter_llm: Any = None,
        verifier_llm: Any = None,
        exploiter_llm: Any = None,
        sandbox_factory: Any = None,  # callable[[], SandboxContainer]
        parent_session_id: str | None = None,
        resume_session_id: str | None = None,
        checkpoint: dict[str, Any] | str | None = None,
        checkpoint_path: str | Path | None = None,
        agent_mode: str = "auto",  # "auto" | "constrained" | "deep"
        prompt_mode: str = "unconstrained",  # "unconstrained" | "specialist"
        campaign_hint: str | None = None,
        exploit_mode: bool = False,
        starting_band: str | None = None,  # "fast" | "standard" | "deep" | None (auto)
        redundancy_override: int | None = None,
        shard_entry_points: bool | None = None,  # None = auto (deep depth)
        min_shard_rank: int = 4,
        min_project_loc: int = 50_000,
        seed_corpus_sources: list[str] | None = None,
        enable_findings_pool: bool = True,
        historical_db_path: Any = None,
        enable_subsystem_hunt: bool = False,
        subsystem_paths: list[str] | None = None,
        no_per_file_hunt: bool = False,
        no_rank: bool = False,
        subsystem_budget_usd: float = 0.0,
        subsystem_max_parallel: int = 4,
        subsystem_max_files: int | None = None,
        enable_behavior_monitor: bool = True,
        enable_artifact_store: bool = False,
        gvisor_runtime: str | None = None,
        preprocessing: bool = True,
        enable_semgrep: bool = False,
        seed_harness_crashes: bool = False,
        respect_gitignore: bool = False,
        live: bool = False,
        sandbox_cpus: float | None = None,
        *,
        config: SourceHuntConfig | None = None,
        flow: str = "legacy",
        proof_compile_commands: str | None = None,
        proof_validation_manifest: str | None = None,
        proof_scheduler_calibration: str | None = None,
        proof_learning_registry: str | None = None,
        proof_build_configuration: str = "default",
        proof_clang_binary: str = "clang",
        proof_max_actions: int = 200,
        proof_max_model_calls: int = 40,
        proof_max_dynamic_actions: int = 20,
        proof_structured_fraction: float = 0.90,
        proof_exploration_fraction: float = 0.10,
        retain_incomplete_certificates: bool = True,
        emit_rejection_certificates: bool = True,
        falsify: bool = True,
        stop_after: str | None = None,
        on_progress: SourceHuntProgressCallback | None = None,
    ):
        # --- Resolve from SourceHuntConfig when provided ----------------------
        if config is not None:
            t = config.target
            b = config.budget
            o = config.output
            f = config.features
            h = config.tuning
            # Target params — keyword args override config if explicitly given
            repo_url = repo_url or t.repo_url
            branch = branch if branch != "main" else t.branch
            local_path = local_path if local_path is not None else t.local_path
            target_files = target_files if target_files is not None else t.target_files
            target_window_lines = (
                target_window_lines
                if target_window_lines is not None
                else t.target_window_lines
            )
            depth = depth if depth != "standard" else t.depth
            # Budget params
            budget_usd = budget_usd if budget_usd != 0.0 else b.budget_usd
            input_price_per_million = (
                input_price_per_million
                if input_price_per_million is not None
                else b.input_price_per_million
            )
            output_price_per_million = (
                output_price_per_million
                if output_price_per_million is not None
                else b.output_price_per_million
            )
            max_parallel = max_parallel if max_parallel != 8 else b.max_parallel
            tier_budget = tier_budget if tier_budget is not None else b.tier_budget
            exploit_budget = exploit_budget if exploit_budget is not None else b.exploit_budget
            elaboration_cap = elaboration_cap if elaboration_cap != "10%" else b.elaboration_cap
            subsystem_budget_usd = (
                subsystem_budget_usd if subsystem_budget_usd != 0.0 else b.subsystem_budget_usd
            )
            subsystem_max_parallel = (
                subsystem_max_parallel if subsystem_max_parallel != 4 else b.subsystem_max_parallel
            )
            subsystem_max_files = (
                subsystem_max_files
                if subsystem_max_files is not None
                else getattr(b, "subsystem_max_files", None)
            )
            # Output params
            output_dir = output_dir if output_dir is not None else (o.output_dir or None)
            output_formats = output_formats if output_formats is not None else o.output_formats
            export_disclosures = export_disclosures or o.export_disclosures
            disclosure_reporter_name = (
                disclosure_reporter_name
                if disclosure_reporter_name != "(your name)"
                else o.disclosure_reporter_name
            )
            disclosure_reporter_affiliation = (
                disclosure_reporter_affiliation
                if disclosure_reporter_affiliation != "(your affiliation)"
                else o.disclosure_reporter_affiliation
            )
            disclosure_reporter_email = (
                disclosure_reporter_email
                if disclosure_reporter_email != "(your email)"
                else o.disclosure_reporter_email
            )
            # Feature flags
            no_verify = no_verify or f.no_verify
            no_exploit = no_exploit or f.no_exploit
            enable_elaboration = enable_elaboration or f.enable_elaboration
            enable_variant_loop = enable_variant_loop and f.enable_variant_loop
            enable_stability_verification = (
                enable_stability_verification and f.enable_stability_verification
            )
            enable_mechanism_memory = enable_mechanism_memory and f.enable_mechanism_memory
            enable_behavior_monitor = enable_behavior_monitor and f.enable_behavior_monitor
            enable_patch_oracle = enable_patch_oracle and f.enable_patch_oracle
            enable_findings_pool = enable_findings_pool and f.enable_findings_pool
            enable_subsystem_hunt = enable_subsystem_hunt or f.enable_subsystem_hunt
            enable_auto_patch = enable_auto_patch or f.enable_auto_patch
            auto_pr = auto_pr or f.auto_pr
            enable_knowledge_graph = enable_knowledge_graph and f.enable_knowledge_graph
            enable_calibration = enable_calibration and f.enable_calibration
            enable_artifact_store = enable_artifact_store or f.enable_artifact_store
            no_per_file_hunt = no_per_file_hunt or f.no_per_file_hunt
            no_rank = no_rank or f.no_rank
            seed_harness_crashes = seed_harness_crashes or f.seed_harness_crashes
            preprocessing = preprocessing and f.preprocessing
            enable_semgrep = enable_semgrep or f.enable_semgrep
            adversarial_verifier = adversarial_verifier and f.adversarial_verifier
            adversarial_threshold = (
                adversarial_threshold
                if adversarial_threshold != "static_corroboration"
                else f.adversarial_threshold
            )
            validator_mode = validator_mode if validator_mode != "v2" else f.validator_mode
            exploit_mode = exploit_mode or f.exploit_mode
            agent_mode = agent_mode if agent_mode != "auto" else f.agent_mode
            prompt_mode = prompt_mode if prompt_mode != "unconstrained" else f.prompt_mode
            # Hunt tuning
            starting_band = starting_band if starting_band is not None else h.starting_band
            redundancy_override = (
                redundancy_override if redundancy_override is not None else h.redundancy_override
            )
            shard_entry_points = (
                shard_entry_points if shard_entry_points is not None else h.shard_entry_points
            )
            min_shard_rank = min_shard_rank if min_shard_rank != 4 else h.min_shard_rank
            min_project_loc = min_project_loc if min_project_loc != 50_000 else h.min_project_loc
            seed_corpus_sources = (
                seed_corpus_sources if seed_corpus_sources is not None else h.seed_corpus_sources
            )
            subsystem_paths = subsystem_paths if subsystem_paths is not None else h.subsystem_paths
            campaign_hint = campaign_hint if campaign_hint is not None else h.campaign_hint
            gvisor_runtime = gvisor_runtime if gvisor_runtime is not None else h.gvisor_runtime
            sandbox_cpus = sandbox_cpus if sandbox_cpus is not None else h.sandbox_cpus
            p = config.proof
            flow = flow if flow != "legacy" else p.flow
            proof_compile_commands = (
                proof_compile_commands if proof_compile_commands is not None else p.compile_commands
            )
            proof_validation_manifest = (
                proof_validation_manifest
                if proof_validation_manifest is not None
                else p.validation_manifest
            )
            proof_scheduler_calibration = (
                proof_scheduler_calibration
                if proof_scheduler_calibration is not None
                else p.scheduler_calibration
            )
            proof_learning_registry = (
                proof_learning_registry
                if proof_learning_registry is not None
                else p.learning_registry
            )
            proof_build_configuration = (
                proof_build_configuration
                if proof_build_configuration != "default"
                else p.build_configuration
            )
            proof_clang_binary = (
                proof_clang_binary if proof_clang_binary != "clang" else p.clang_binary
            )
            proof_max_actions = proof_max_actions if proof_max_actions != 200 else p.max_actions
            proof_max_model_calls = (
                proof_max_model_calls if proof_max_model_calls != 40 else p.max_model_calls
            )
            proof_max_dynamic_actions = (
                proof_max_dynamic_actions
                if proof_max_dynamic_actions != 20
                else p.max_dynamic_actions
            )
            proof_structured_fraction = (
                proof_structured_fraction
                if proof_structured_fraction != 0.90
                else p.structured_fraction
            )
            proof_exploration_fraction = (
                proof_exploration_fraction
                if proof_exploration_fraction != 0.10
                else p.exploration_fraction
            )
            retain_incomplete_certificates = (
                retain_incomplete_certificates and p.retain_incomplete_certificates
            )
            emit_rejection_certificates = (
                emit_rejection_certificates and p.emit_rejection_certificates
            )
            falsify = falsify and p.falsify
            checkpoint = checkpoint if checkpoint is not None else config.checkpoint

        if not repo_url:
            raise ValueError(
                "repo_url is required — pass it directly or via "
                "config=SourceHuntConfig(target=TargetConfig(repo_url=...))"
            )
        if sandbox_cpus is not None and (not math.isfinite(sandbox_cpus) or sandbox_cpus < 0):
            raise ValueError("sandbox_cpus must be a finite number greater than or equal to 0")
        normalized_target_files = self._normalize_target_files(target_files or ())
        target_window_lines = 480 if target_window_lines is None else target_window_lines
        if type(target_window_lines) is not int or not 40 <= target_window_lines <= 500:
            raise ValueError("target_window_lines must be between 40 and 500")
        if normalized_target_files and flow != "legacy":
            raise ValueError("target_files is currently supported only by the legacy flow")
        if normalized_target_files and depth == "quick":
            raise ValueError("target_files requires standard or deep depth so hunters run")
        if normalized_target_files and no_per_file_hunt:
            raise ValueError("target_files cannot be combined with no_per_file_hunt")
        if normalized_target_files and shard_entry_points:
            raise ValueError("target_files cannot be combined with entry-point sharding")
        if normalized_target_files and (enable_subsystem_hunt or subsystem_paths):
            raise ValueError("target_files cannot be combined with subsystem hunting")
        if flow not in {"legacy", "proof"}:
            raise ValueError("flow must be 'legacy' or 'proof'")
        if checkpoint is not None and flow != "legacy":
            raise ValueError("checkpoint restoration is currently supported only for legacy flow")
        if stop_after is not None and flow != "legacy":
            raise ValueError("stop_after is currently supported only for legacy flow")
        if enable_semgrep and flow != "legacy":
            raise ValueError("Semgrep is currently supported only for legacy flow")
        if proof_max_actions < 1:
            raise ValueError("proof_max_actions must be positive")
        if proof_max_model_calls < 0 or proof_max_dynamic_actions < 0:
            raise ValueError("proof action sub-budgets cannot be negative")
        if not 0 <= proof_structured_fraction <= 1:
            raise ValueError("proof_structured_fraction must be between 0 and 1")
        if not 0 <= proof_exploration_fraction <= 1:
            raise ValueError("proof_exploration_fraction must be between 0 and 1")
        if proof_structured_fraction + proof_exploration_fraction > 1.000001:
            raise ValueError("proof structured and exploration budgets exceed 100%")

        # Store the config for introspection (None if constructed the old way)
        self._config = config

        self.repo_url = repo_url
        self.branch = branch
        self.local_path = local_path
        self._target_files = normalized_target_files
        self._target_window_lines = target_window_lines
        self._target_metadata: dict[str, dict[str, Any]] = {}
        self._target_plan_incomplete = False
        self.depth = depth
        self.budget_usd = budget_usd
        self.input_price_per_million = input_price_per_million
        self.output_price_per_million = output_price_per_million
        self.max_parallel = max_parallel
        self.tier_budget = tier_budget or TierBudget()
        if output_dir is None:
            from clearwing.core.config import default_results_dir

            output_dir = default_results_dir("sourcehunt")
        self.output_dir = output_dir
        self.output_formats = output_formats or ["sarif", "markdown", "json"]
        self.no_verify = no_verify
        self.no_exploit = no_exploit
        self._exploit_budget_override = exploit_budget
        self.enable_elaboration = enable_elaboration
        self._elaboration_cap = elaboration_cap
        self.adversarial_verifier = adversarial_verifier
        self.adversarial_threshold = adversarial_threshold
        self.validator_mode = validator_mode
        self._calibration_store = None
        if enable_calibration:
            try:
                from .calibration import CalibrationStore

                self._calibration_store = CalibrationStore()
            except Exception:
                logger.debug("CalibrationStore init failed", exc_info=True)
        self.enable_mechanism_memory = enable_mechanism_memory
        self._mechanism_store = (
            MechanismStore(path=mechanism_store_path) if enable_mechanism_memory else None
        )
        self.enable_patch_oracle = enable_patch_oracle
        self.enable_stability_verification = enable_stability_verification
        self.enable_variant_loop = enable_variant_loop
        self.enable_auto_patch = enable_auto_patch
        self.auto_pr = auto_pr
        self.enable_knowledge_graph = enable_knowledge_graph
        self._knowledge_graph = knowledge_graph
        self.export_disclosures = export_disclosures
        self.disclosure_reporter_name = disclosure_reporter_name
        self.disclosure_reporter_affiliation = disclosure_reporter_affiliation
        self.disclosure_reporter_email = disclosure_reporter_email
        self.model_override = model_override
        self.provider_manager: ProviderManager | None = provider_manager
        self.ranker_llm = ranker_llm
        self.hunter_llm = hunter_llm
        self.verifier_llm = verifier_llm
        self.exploiter_llm = exploiter_llm
        self.sandbox_factory = sandbox_factory
        self._sandbox_manager: HunterSandbox | None = None
        self._preprocessor: Preprocessor | None = None
        # --resume reuses a prior session directory in place: same session id,
        # so its checkpoint, spend ledger, findings pool, and hunt work cache
        # are all continued rather than started fresh. It routes entirely through
        # the checkpoint machinery below — there is no separate resume path.
        if resume_session_id is not None:
            if parent_session_id is not None:
                raise ValueError("resume_session_id cannot be combined with parent_session_id")
            session_dir = Path(self.output_dir) / resume_session_id
            if not session_dir.is_dir():
                raise ValueError(f"Sourcehunt session {resume_session_id!r} does not exist")
        self._resuming = resume_session_id is not None
        self._session_id = resume_session_id or parent_session_id or f"sh-{uuid.uuid4().hex[:8]}"
        self._checkpoint_path = (
            Path(checkpoint_path)
            if checkpoint_path is not None
            else Path(self.output_dir) / self._session_id / "checkpoint.json"
        )
        if checkpoint is not None:
            self._checkpoint = SourceHuntCheckpoint.from_input(checkpoint)
        elif self._checkpoint_path.is_file():
            self._checkpoint = SourceHuntCheckpoint.from_file(self._checkpoint_path)
        else:
            self._checkpoint = None
        self._agent_mode_override = agent_mode
        self._prompt_mode = prompt_mode
        self._campaign_hint = campaign_hint
        self._exploit_mode = exploit_mode
        self._starting_band_override = starting_band
        self._redundancy_override = redundancy_override
        self._shard_entry_points_override = shard_entry_points
        self._min_shard_rank = min_shard_rank
        self._min_project_loc = min_project_loc
        self._seed_corpus_sources = seed_corpus_sources
        self._enable_findings_pool = enable_findings_pool
        self._historical_db_path = historical_db_path
        self._enable_subsystem_hunt = enable_subsystem_hunt or bool(subsystem_paths)
        self._subsystem_paths = subsystem_paths
        self._no_per_file_hunt = no_per_file_hunt
        self._no_rank = no_rank or bool(self._target_files)
        self._stop_after = stop_after
        self._subsystem_budget_usd = subsystem_budget_usd
        self._subsystem_max_parallel = subsystem_max_parallel
        # None = library default (DEFAULT_MAX_FILES_PER_SUBSYSTEM for auto
        # detection; uncapped for an explicit --subsystem PATH). An operator
        # override raises/removes the per-subsystem file cap for both paths.
        self._subsystem_max_files = subsystem_max_files
        self._injected_findings_pool = None
        self._injected_historical_db = None
        self._enable_behavior_monitor = enable_behavior_monitor
        self._enable_artifact_store = enable_artifact_store
        self._sandbox_cpus = None if sandbox_cpus is None else float(sandbox_cpus)
        self._gvisor_runtime = self._check_runtime_available(gvisor_runtime)
        self._preprocessing = preprocessing
        self._enable_semgrep = enable_semgrep
        self._seed_harness_crashes = seed_harness_crashes
        self._respect_gitignore = respect_gitignore
        self._live = live
        self._spend_ledger: SpendLedger | None = None
        self._spend_instrumented = False
        self._metered_clients: dict[tuple[int, str], AsyncLLMClient] = {}
        self._flow = flow
        self._proof_compile_commands = proof_compile_commands
        self._proof_validation_manifest = proof_validation_manifest
        self._proof_scheduler_calibration = proof_scheduler_calibration
        self._proof_learning_registry = proof_learning_registry
        self._proof_build_configuration = proof_build_configuration
        self._proof_clang_binary = proof_clang_binary
        self._proof_max_actions = proof_max_actions
        self._proof_max_model_calls = proof_max_model_calls
        self._proof_max_dynamic_actions = proof_max_dynamic_actions
        self._proof_structured_fraction = proof_structured_fraction
        self._proof_exploration_fraction = proof_exploration_fraction
        self._retain_incomplete_certificates = retain_incomplete_certificates
        self._emit_rejection_certificates = emit_rejection_certificates
        self._falsify = falsify
        self._instrumentation = SourceHuntInstrumentation(
            Path(self.output_dir) / self._session_id,
            self._session_id,
        )
        self._instrumentation_finalized = False
        self._last_reporting_error: dict[str, str] | None = None
        self._on_progress = on_progress
        self._run_started_at: str | None = None
        self._run_started_monotonic: float | None = None
        self._resolved_model_roles: dict[str, dict[str, str]] = {}
        self._verification_incomplete = False

    @staticmethod
    def _normalize_target_files(paths: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        """Validate and normalize explicit repository-relative target files."""
        if len(paths) > MAX_TARGET_FILES:
            raise ValueError(f"target_files accepts at most {MAX_TARGET_FILES} paths")
        normalized: list[str] = []
        for raw_path in paths:
            if not isinstance(raw_path, str):
                raise ValueError("target_files entries must be strings")
            candidate = raw_path.strip().replace("\\", "/")
            if len(candidate) > MAX_TARGET_PATH_LENGTH:
                raise ValueError(
                    f"target_files entries must be at most {MAX_TARGET_PATH_LENGTH} characters"
                )
            path = PurePosixPath(candidate)
            windows_drive = len(candidate) >= 2 and candidate[0].isalpha() and candidate[1] == ":"
            if (
                not candidate
                or "\x00" in candidate
                or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
                or "\u2028" in candidate
                or "\u2029" in candidate
                or path.is_absolute()
                or windows_drive
                or ".." in path.parts
                or path.as_posix() == "."
            ):
                raise ValueError(
                    f"target_files entries must be repository-relative files: {raw_path!r}"
                )
            relative = path.as_posix()
            if relative not in normalized:
                normalized.append(relative)
        return tuple(normalized)

    def _inspect_target_files(self, repo_path: str) -> dict[str, dict[str, Any]]:
        """Validate, fingerprint, and size an explicit target plan."""
        if not self._target_files:
            return {}

        root = Path(repo_path).resolve()
        metadata: dict[str, dict[str, Any]] = {}
        total_bytes = 0
        total_windows = 0
        for relative in self._target_files:
            unresolved = root / relative
            cursor = root
            for part in PurePosixPath(relative).parts:
                cursor /= part
                if cursor.is_symlink():
                    raise ValueError(
                        f"invalid target file {relative}: symbolic links are not supported"
                    )
            try:
                absolute = unresolved.resolve(strict=True)
                absolute.relative_to(root)
            except (OSError, ValueError) as exc:
                raise ValueError(f"invalid target file {relative}: {exc}") from exc
            if not absolute.is_file():
                raise ValueError(f"target file is not a regular file: {relative}")

            language = _SOURCE_EXTS_TO_LANG.get(absolute.suffix.lower())
            if language is None:
                raise ValueError(f"unsupported source target: {relative}")
            try:
                source_bytes = absolute.read_bytes()
            except OSError as exc:
                raise ValueError(f"unable to read target file {relative}: {exc}") from exc
            if not source_bytes:
                raise ValueError(f"target file is empty: {relative}")
            if len(source_bytes) > MAX_TARGET_FILE_BYTES:
                raise ValueError(
                    f"target file exceeds {MAX_TARGET_FILE_BYTES} bytes: {relative}"
                )

            lines = split_physical_source_lines(source_bytes)
            line_count = len(lines)
            file_windows = 0
            for start in range(0, line_count, self._target_window_lines):
                window_lines = lines[start : start + self._target_window_lines]
                rendered = render_target_window_message(
                    file_path=relative,
                    language=language,
                    source_lines=window_lines,
                    start_line=start + 1,
                    total_lines=line_count,
                )
                window_size = len(rendered.encode("utf-8"))
                if window_size > MAX_TARGET_WINDOW_BYTES:
                    first_line = start + 1
                    last_line = min(line_count, start + self._target_window_lines)
                    raise ValueError(
                        f"target window {relative}:{first_line}-{last_line} exceeds "
                        f"{MAX_TARGET_WINDOW_BYTES} prompt bytes"
                    )
                file_windows += 1

            total_bytes += len(source_bytes)
            total_windows += file_windows
            metadata[relative] = {
                "absolute_path": str(absolute),
                "language": language,
                "line_count": line_count,
                "size_bytes": len(source_bytes),
                "sha256": hashlib.sha256(source_bytes).hexdigest(),
            }

        if total_bytes > MAX_TARGET_TOTAL_BYTES:
            raise ValueError(f"target files exceed {MAX_TARGET_TOTAL_BYTES} total bytes")
        if total_windows > MAX_TARGET_WINDOWS:
            raise ValueError(f"target plan exceeds {MAX_TARGET_WINDOWS} windows")
        return metadata

    def _filter_target_files(self, result: PreprocessResult) -> PreprocessResult:
        """Restrict preprocessing output to explicit files before ranking."""
        if not self._target_files:
            return result

        current_metadata = self._inspect_target_files(result.repo_path)
        if self._target_metadata and current_metadata != self._target_metadata:
            raise ValueError("target files changed while preprocessing; rerun the hunt")
        self._target_metadata = current_metadata
        targets_by_path = {target.get("path", ""): target for target in result.file_targets}

        selected: list[FileTarget] = []
        for path in self._target_files:
            item = current_metadata[path]
            target = dict(
                targets_by_path.get(path)
                or {
                    "path": path,
                    "absolute_path": item["absolute_path"],
                    "language": item["language"],
                    "tags": _tag_file(path, ""),
                    "surface": 0,
                    "influence": 0,
                    "reachability": 3,
                    "priority": 0.0,
                    "tier": "C",
                }
            )
            target["absolute_path"] = item["absolute_path"]
            target["language"] = item["language"]
            target["loc"] = item["line_count"]
            target["target_size_bytes"] = item["size_bytes"]
            target["target_sha256"] = item["sha256"]
            selected.append(target)

        selected_paths = set(self._target_files)
        repo_root = Path(result.repo_path).resolve()

        def _static_path(finding: Any) -> str:
            path = Path(str(getattr(finding, "file_path", "") or ""))
            if path.is_absolute():
                try:
                    path = path.resolve().relative_to(repo_root)
                except ValueError:
                    return ""
            return path.as_posix()

        result.file_targets = selected
        result.static_findings = [
            finding for finding in result.static_findings if _static_path(finding) in selected_paths
        ]
        result.semgrep_findings = [
            finding
            for finding in result.semgrep_findings
            if str(finding.get("file") or "") in selected_paths
        ]
        result.taint_paths = [
            path for path in result.taint_paths if str(path.file or "") in selected_paths
        ]
        return result

    def _expand_target_windows(self, files: list[FileTarget]) -> list[FileTarget]:
        """Create independently seeded windows for explicit target files."""
        if not self._target_files:
            return files

        windows: list[FileTarget] = []
        for file_target in files:
            total_lines = int(file_target.get("loc", 0) or 0)
            if total_lines == 0:
                windows.append(file_target)
                continue
            for start_line in range(1, total_lines + 1, self._target_window_lines):
                window = dict(file_target)
                window["target_start_line"] = start_line
                window["target_end_line"] = min(
                    total_lines, start_line + self._target_window_lines - 1
                )
                window["target_total_lines"] = total_lines
                windows.append(window)
        return windows

    def _dump_checkpoint(self) -> None:
        if self._checkpoint is None:
            return
        self._checkpoint.dump(self._checkpoint_path)

    @staticmethod
    def _check_runtime_available(runtime: str | None) -> str | None:
        if not runtime:
            return None
        try:
            import docker

            info = docker.from_env().info()
            runtimes = info.get("Runtimes") or {}
            if runtime in runtimes:
                return runtime
            logger.warning(
                "Docker runtime %r not installed (available: %s) — "
                "sandboxes will use the default runtime instead",
                runtime,
                ", ".join(runtimes) or "runc",
            )
        except Exception:
            logger.debug("Could not query Docker runtimes", exc_info=True)
        return None

    def _inject_campaign_pool(
        self,
        findings_pool: Any,
        historical_db: Any = None,
    ) -> None:
        """Allow campaign runner to inject a shared pool. Must be called before arun()."""
        self._injected_findings_pool = findings_pool
        self._injected_historical_db = historical_db

    @property
    def _agent_mode(self) -> str:
        if self._agent_mode_override != "auto":
            return self._agent_mode_override
        if self.depth in ("standard", "deep"):
            return "deep"
        return "constrained"

    @property
    def _effective_agent_mode(self) -> str:
        """Select tools that can actually access the checked-out source.

        Downgrades ``deep`` to ``constrained`` when no sandbox_factory is
        available — avoids crashing when Docker isn't installed.
        """
        requested = self._agent_mode
        if requested == "deep" and self.sandbox_factory is None:
            return "constrained"
        return requested

    @property
    def _starting_band(self) -> str:
        if self._starting_band_override:
            return self._starting_band_override
        return {"standard": "fast", "deep": "standard"}.get(self.depth, "fast")

    @property
    def _max_band(self) -> str:
        if self._starting_band_override:
            return self._starting_band_override
        return {"standard": "standard", "deep": "deep"}.get(self.depth, "standard")

    @property
    def _exploit_budget_band(self) -> str:
        if self._exploit_budget_override:
            return self._exploit_budget_override
        if self.depth == "deep":
            return "deep"
        return "standard"

    def _run_spent_usd(self) -> float:
        """Return spend recorded by this run's atomic ledger."""

        if self._spend_ledger is None:
            return 0.0
        return self._spend_ledger.spent_usd

    @property
    def _shard_entry_points(self) -> bool:
        if self._shard_entry_points_override is not None:
            return self._shard_entry_points_override
        return self.depth == "deep"

    # --- Public API ---------------------------------------------------------

    def _emit_stage(
        self,
        stage: str,
        status: str,
        findings_so_far: int = 0,
        cost_usd: float = 0.0,
        detail: str = "",
        *,
        files: list[str] | tuple[str, ...] = (),
        symbols: list[str] | tuple[str, ...] = (),
        finding_ids: list[str] | tuple[str, ...] = (),
        error: dict[str, Any] | None = None,
    ) -> None:
        progress = SourceHuntProgress(
            stage=stage,
            status=status,
            findings_so_far=findings_so_far,
            cost_usd=cost_usd,
            detail=detail,
            files=tuple(files),
            symbols=tuple(symbols),
            finding_ids=tuple(finding_ids),
            error=error,
        )
        EventBus().emit_sourcehunt_stage(
            SourcehuntStagePayload(
                session_id=self._session_id,
                repo=self.repo_url,
                stage=stage,
                status=status,
                findings_so_far=findings_so_far,
                cost_usd=cost_usd,
                detail=detail,
            )
        )
        if self._on_progress is not None:
            try:
                self._on_progress(progress)
            except Exception:  # pragma: no cover - observer isolation
                logger.warning("sourcehunt progress observer failed", exc_info=True)
        try:
            self._instrumentation.stage(
                stage,
                status,
                files=files,
                symbols=symbols,
                finding_ids=finding_ids,
                detail=detail,
                error=error,
                metadata={
                    "findings_so_far": findings_so_far,
                    "cost_usd": cost_usd,
                    "flow": self._flow,
                },
            )
        except Exception:
            logger.debug("Sourcehunt instrumentation write failed", exc_info=True)

    def _finalize_instrumentation(self, status: str) -> None:
        if self._instrumentation_finalized:
            return
        try:
            self._instrumentation.finalize(status)
            self._instrumentation_finalized = True
        except Exception:
            logger.debug("Sourcehunt instrumentation finalization failed", exc_info=True)

    def _ensure_spend_ledger(self) -> SpendLedger:
        if self._spend_ledger is None:
            self._spend_ledger = SpendLedger(
                limit_usd=self.budget_usd,
                session_id=self._session_id,
                repo_url=self.repo_url,
                output_dir=self.output_dir,
                input_price_per_million=self.input_price_per_million,
                output_price_per_million=self.output_price_per_million,
                manifest_filename=(
                    "spend-summary.json" if self._flow == "proof" else "manifest.json"
                ),
                resume=self._resuming,
            )
        return self._spend_ledger

    def _budget_exhausted(self) -> bool:
        return self._spend_ledger is not None and self._spend_ledger.exhausted

    def _preflight_budget_clients(self) -> None:
        """Validate every model this run may use before the first paid call."""

        if self._spend_ledger is None or not self._spend_ledger.enforcing:
            return
        roles: list[tuple[str, AsyncLLMClient | None, str]] = []
        if not self._no_rank:
            roles.append(("ranker", self.ranker_llm, "rank"))
        if self.depth != "quick":
            roles.append(("hunter", self.hunter_llm, "hunt"))
            if not self.no_verify:
                roles.append(("verifier", self.verifier_llm, "verify"))
            if not self.no_exploit or self.enable_auto_patch or self.enable_elaboration:
                roles.append(("sourcehunt_exploit", self.exploiter_llm, "exploit"))
        for task, override, stage in roles:
            self._get_native_client(task, override, budget_stage=stage)

    def _finalize_spend_ledger(self, status: str | None = None) -> dict[str, Any]:
        ledger = self._ensure_spend_ledger()
        summary = ledger.snapshot() if ledger.finalized else ledger.finalize(status)
        if not self._spend_instrumented:
            try:
                ledger_path = summary.get("ledger_path")
                if ledger_path:
                    self._instrumentation.ingest_spend_ledger(ledger_path)
                self._spend_instrumented = True
            except Exception:
                logger.debug("Could not join sourcehunt spend instrumentation", exc_info=True)
        return summary

    def run(self) -> SourceHuntResult:
        from clearwing.ui.llm_activity import llm_activity_panel

        self._ensure_spend_ledger()
        with llm_activity_panel(
            live=self._live,
            budget_usd=self.budget_usd or None,
            spend_ledger=self._spend_ledger,
            trace_context=lambda: (
                getattr(self, "_otel_trace_id", None),
                getattr(self, "_otel_span_id", None),
            ),
        ):
            return asyncio.run(self.arun())

    async def _arun_proof_flow(self) -> SourceHuntResult:
        """Run the proof-carrying engine and adapt its typed output."""

        from .proof.engine import ProofFlowRunner, ProofRunConfig

        ledger = self._ensure_spend_ledger()

        def model_client(route: str) -> AsyncLLMClient | None:
            override = self.verifier_llm if route == "proof_falsifier" else self.hunter_llm
            return self._get_native_client(
                route,
                override,
                budget_stage=route,
            )

        if ledger.enforcing and self._proof_max_model_calls > 0:
            routes = ["proof_local", "proof_frontier"]
            if self._proof_exploration_fraction > 0:
                routes.append("proof_exploration")
            if self._falsify:
                routes.append("proof_falsifier")
            for route in routes:
                model_client(route)

        evaluation_hints: dict[str, Any] = {}
        if self._campaign_hint:
            try:
                parsed_hint = json.loads(self._campaign_hint)
            except json.JSONDecodeError:
                parsed_hint = {"objective": self._campaign_hint}
            evaluation_hints = (
                parsed_hint if isinstance(parsed_hint, dict) else {"objective": self._campaign_hint}
            )

        proof_runner = ProofFlowRunner(
            repo_url=self.repo_url,
            branch=self.branch,
            local_path=self.local_path,
            config=ProofRunConfig(
                output_dir=self.output_dir,
                session_id=self._session_id,
                compile_commands=self._proof_compile_commands,
                validation_manifest=self._proof_validation_manifest,
                scheduler_calibration=self._proof_scheduler_calibration,
                learning_registry=self._proof_learning_registry,
                build_configuration=self._proof_build_configuration,
                clang_binary=self._proof_clang_binary,
                max_actions=self._proof_max_actions,
                max_model_calls=self._proof_max_model_calls,
                max_dynamic_actions=self._proof_max_dynamic_actions,
                structured_fraction=self._proof_structured_fraction,
                exploration_fraction=self._proof_exploration_fraction,
                retain_incomplete_certificates=(self._retain_incomplete_certificates),
                emit_rejection_certificates=(self._emit_rejection_certificates),
                falsify=self._falsify,
                gvisor_runtime=self._gvisor_runtime,
                sandbox_cpus=self._sandbox_cpus,
                evaluation_hints=evaluation_hints,
            ),
            model_client_factory=model_client,
        )
        self._instrumentation.record(
            "run",
            stage="run",
            status="started",
            metadata={"flow": self._flow, "repository": self.repo_url},
        )
        self._emit_stage("proof", "started")
        try:
            proof_result = await proof_runner.arun()
            run_status = "budget_exhausted" if ledger.exhausted else proof_result.status
            proof_manifest = self._read_proof_manifest(proof_result.session_id)
            budget_summary = self._finalize_spend_ledger(run_status)
            self._finalize_proof_manifest(
                proof_result,
                proof_manifest=proof_manifest,
                budget_summary=budget_summary,
                status=run_status,
            )
        except Exception as exc:
            self._finalize_spend_ledger("failed")
            self._emit_stage(
                "proof",
                "failed",
                error={"type": type(exc).__name__, "message": str(exc)},
            )
            self._finalize_instrumentation("failed")
            raise

        findings: list[Finding] = []
        known_fields = set(Finding.__dataclass_fields__)
        for payload in proof_result.findings:
            base = {
                key: value
                for key, value in payload.items()
                if key in known_fields and key != "extra"
            }
            base["cwe"] = base.get("cwe") or ""
            base["severity_verified"] = base.get("severity")
            base["hunter_session_id"] = proof_result.session_id
            extra = {key: value for key, value in payload.items() if key not in known_fields}
            findings.append(Finding(**base, extra=extra))

        pipeline_status = PipelineStatus()
        if proof_result.incomplete:
            pipeline_status.record_degraded(
                "proof",
                "Residual obligation graph and incomplete certificates were retained",
            )
            self._emit_stage(
                "proof",
                "incomplete",
                findings_so_far=len(findings),
                files=[str(finding.file or "") for finding in findings],
                finding_ids=[finding.id for finding in findings],
            )
        else:
            pipeline_status.record_succeeded("proof")
            self._emit_stage(
                "proof",
                "completed",
                findings_so_far=len(findings),
                files=[str(finding.file or "") for finding in findings],
                finding_ids=[finding.id for finding in findings],
            )

        has_high = any(finding.severity in {"critical", "high"} for finding in findings)
        has_medium = any(finding.severity == "medium" for finding in findings)
        exit_code = (
            3
            if proof_result.incomplete or ledger.exhausted
            else 2
            if has_high
            else 1
            if has_medium
            else 0
        )
        total_spent = float(budget_summary.get("total_spent", 0.0))
        self._finalize_instrumentation(run_status)
        proof_result.output_paths.update(
            {
                "instrumentation": str(self._instrumentation.summary_path),
                "instrumentation_events": str(self._instrumentation.events_path),
            }
        )
        return SourceHuntResult(
            exit_code=exit_code,
            repo_url=self.repo_url,
            repo_path=proof_result.repo_path,
            findings=findings,
            verified_findings=list(findings),
            exploited_findings=[],
            files_ranked=proof_result.files_analyzed,
            files_hunted=len(proof_result.candidates),
            duration_seconds=proof_result.duration_seconds,
            cost_usd=total_spent,
            spent_per_tier={"A": total_spent, "B": 0.0, "C": 0.0},
            tokens_used=int(budget_summary.get("total_tokens", 0)),
            output_paths=proof_result.output_paths,
            session_id=proof_result.session_id,
            pipeline_status=pipeline_status,
            status=run_status,
            budget_usd=self.budget_usd,
        )

    def _read_proof_manifest(self, session_id: str) -> dict[str, Any]:
        """Capture the proof manifest before final spend-ledger checkpointing."""

        path = Path(self.output_dir) / session_id / "manifest.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _finalize_proof_manifest(
        self,
        proof_result: Any,
        *,
        proof_manifest: dict[str, Any],
        budget_summary: dict[str, Any],
        status: str,
    ) -> None:
        """Atomically publish one combined proof, spend, and output index."""

        session_dir = Path(self.output_dir) / proof_result.session_id
        manifest_path = session_dir / "manifest.json"
        outputs = dict(proof_result.output_paths)
        ledger_path = budget_summary.get("ledger_path")
        if ledger_path:
            outputs["ledger"] = str(ledger_path)
        spend_summary_path = budget_summary.get("spend_summary_path")
        if spend_summary_path:
            outputs["spend_summary"] = str(spend_summary_path)
        outputs["instrumentation"] = str(self._instrumentation.summary_path)
        outputs["instrumentation_events"] = str(self._instrumentation.events_path)
        outputs["manifest"] = str(manifest_path)

        combined = dict(proof_manifest)
        combined.update(
            {
                "engine": "proof",
                "session_id": proof_result.session_id,
                "status": status,
                "proof_status": proof_result.status,
                "complete": status == "completed" and not proof_result.incomplete,
                "spend": budget_summary,
                "total_spent": float(budget_summary.get("total_spent", 0.0)),
                "input_tokens": int(budget_summary.get("input_tokens", 0)),
                "cached_input_tokens": int(budget_summary.get("cached_input_tokens", 0)),
                "output_tokens": int(budget_summary.get("output_tokens", 0)),
                "total_tokens": int(budget_summary.get("total_tokens", 0)),
                "model_call_count": int(budget_summary.get("call_count", 0)),
                "outputs": outputs,
            }
        )
        temporary = manifest_path.with_suffix(".json.tmp")
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(redact_tree(combined), stream, indent=2, sort_keys=True, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest_path)
        proof_result.output_paths.update(outputs)

    @tracer.chain(name="SourceHunt")
    async def arun(self) -> SourceHuntResult:
        self._run_started_at = datetime.now(timezone.utc).isoformat()
        self._run_started_monotonic = time.monotonic()
        span_context = otel_trace.get_current_span().get_span_context()
        self._otel_trace_id = (
            f"{span_context.trace_id:032x}" if span_context.is_valid else None
        )
        self._otel_span_id = (
            f"{span_context.span_id:016x}" if span_context.is_valid else None
        )
        if self._flow == "proof":
            try:
                return await self._arun_proof_flow()
            finally:
                self._finalize_instrumentation("failed")
        start_time = time.monotonic()
        self._ensure_output_dir_layout()
        self._ensure_spend_ledger()
        pipeline_status = PipelineStatus()
        logger.info("Sourcehunt session %s starting on %s", self._session_id, self.repo_url)
        self._instrumentation.record(
            "run",
            stage="run",
            status="started",
            metadata={"flow": self._flow, "repository": self.repo_url},
        )
        try:
            self._preflight_budget_clients()
            # 1. Preprocess
            self._emit_stage("preprocess", "started")
            preprocess_result = self._filter_target_files(self._preprocess())
            repo_path = preprocess_result.repo_path
            files = preprocess_result.file_targets
            files_ranked = len(files)
            logger.info("Preprocessor enumerated %d files", files_ranked)
            if preprocess_result.callgraph is not None and not preprocess_result.callgraph.empty:
                logger.info(
                    "Callgraph ready  functions=%d",
                    sum(len(v) for v in preprocess_result.callgraph.functions.values()),
                )
            stage_files = [str(file_target.get("path") or "") for file_target in files]
            self._emit_stage(
                "preprocess",
                "completed",
                detail=(
                    f"Restored {files_ranked} files from checkpoint"
                    if self._preprocess_restored
                    else f"Enumerated {files_ranked} files"
                ),
                files=stage_files,
            )

            if self._stop_after == "preprocess":
                logger.info("--stop-after preprocess: exiting early")
                return self._build_quick_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    preprocess_result=preprocess_result,
                    files_ranked=files_ranked,
                    pipeline_status=pipeline_status,
                )

            _t = time.monotonic()
            self._ensure_sandbox_factory(repo_path, files)
            logger.info("Sandbox factory ready in %.2fs", time.monotonic() - _t)

            # 2. Rank
            if self._no_rank:
                skip_reason = "--target-files" if self._target_files else "--no-rank"
                logger.info("Ranker skipped (%s); assigning default priority scores", skip_reason)
                self._emit_stage(
                    "rank",
                    "started",
                    detail=f"{len(files)} files",
                    files=stage_files,
                )
                if self._target_files:
                    pipeline_status.record(
                        "ranker",
                        StageOutcome.SKIPPED,
                        fallback_description="Explicit target files bypass ranking",
                    )
                else:
                    pipeline_status.record_degraded(
                        "ranker", f"All files assigned default priority scores ({skip_reason})"
                    )
                self._emit_stage(
                    "rank",
                    "skipped" if self._target_files else "degraded",
                    detail=f"Skipped ({skip_reason})",
                    files=stage_files,
                )
                self._apply_rank_fallbacks(files)
            else:
                files = await self._rank(files, pipeline_status, stage_files)
            preprocess_result.file_targets = files

            if self._stop_after == "rank":
                logger.info("--stop-after rank: exiting early")
                return self._build_quick_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    preprocess_result=preprocess_result,
                    files_ranked=files_ranked,
                    pipeline_status=pipeline_status,
                )

            # depth=quick exits here with the static_findings as-is
            if self.depth == "quick":
                return self._build_quick_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    preprocess_result=preprocess_result,
                    files_ranked=files_ranked,
                    pipeline_status=pipeline_status,
                )

            # 2.5. Harness Generator (crash-first ordering) — at depth=deep or
            #      when seed_harness_crashes is explicitly enabled (spec 018).
            seeded_crashes: list[SeededCrash] = []
            if (
                self.depth == "deep" or self._seed_harness_crashes
            ) and not self._budget_exhausted():
                harness_llm = self._get_native_client(
                    "hunter",
                    self.hunter_llm,
                    budget_stage="harness",
                )
                harness_sandbox = self._sandbox_manager or self.sandbox_factory
                if harness_llm is not None and harness_sandbox is not None:
                    try:
                        hg = HarnessGenerator(
                            llm=harness_llm,
                            sandbox_factory=harness_sandbox,
                            config=HarnessGeneratorConfig(),
                        )
                        hg_result = hg.run(files, repo_path)
                        seeded_crashes = hg_result.seeded_crashes
                        logger.info(
                            "Harness generator produced %d crashes from %d harnesses",
                            len(seeded_crashes),
                            hg_result.harnesses_generated,
                        )
                    except BudgetExceeded:
                        logger.info("Harness generation stopped at the run budget")
                        pipeline_status.record(
                            "harness_generator",
                            StageOutcome.SKIPPED,
                            fallback_description="Budget exhausted; continuing without more harnesses",
                        )
                    except Exception:
                        logger.warning("Harness generator failed", exc_info=True)
                        pipeline_status.record_degraded(
                            "harness_generator",
                            "No seeded crashes available; hunting without crash context",
                        )

            # Build a lookup so hunters for fuzzed files can pull their seeded
            # crash context via file path
            seeded_by_file: dict[str, dict] = {}
            for c in seeded_crashes:
                seeded_by_file[c.file] = {
                    "report": c.report,
                    "target_function": c.target_function,
                    "harness_source": c.harness_source,
                }

            # Build a per-file Semgrep hint lookup so hunters get their file's hits
            semgrep_hints_by_file: dict[str, list[dict]] = {}
            for sf in preprocess_result.semgrep_findings:
                semgrep_hints_by_file.setdefault(sf.get("file", ""), []).append(sf)

            # v0.3: Recall cross-run mechanisms and inject them into every hunter's
            # hint list as a synthetic entry. The hunter's prompt wraps these in
            # "static analysis hints — NOT ground truth" framing.
            if self._mechanism_store is not None:
                mechanism_hints = self._recalled_mechanism_hints(files)
                if mechanism_hints:
                    for ft in files:
                        key = ft.get("path", "")
                        semgrep_hints_by_file.setdefault(key, []).extend(mechanism_hints)

            # 2.7. Entry-point extraction (spec 004)
            entry_points_by_file: dict = {}
            if self._shard_entry_points and preprocess_result.callgraph is not None:
                total_loc = sum(ft.get("loc", 0) for ft in files)
                if total_loc >= self._min_project_loc:
                    try:
                        from .entry_points import extract_entry_points_batch

                        entry_points_by_file = extract_entry_points_batch(
                            file_targets=files,
                            callgraph=preprocess_result.callgraph,
                            repo_path=repo_path,
                            min_rank=self._min_shard_rank,
                        )
                    except Exception:
                        logger.warning("Entry-point extraction failed", exc_info=True)
                        pipeline_status.record_degraded(
                            "entry_points",
                            "Entry-point sharding unavailable; hunting at file level",
                        )

            # 2.8. Seed corpus ingestion (spec 004)
            seed_corpus_by_file: dict = {}
            if self._seed_corpus_sources:
                try:
                    from .seed_corpus import ingest_seed_corpus

                    sc_result = ingest_seed_corpus(
                        repo_path,
                        files,
                        self._seed_corpus_sources,
                    )
                    for entry in sc_result.entries:
                        seed_corpus_by_file.setdefault(entry.file_path, []).append(entry)
                    if sc_result.errors:
                        for err in sc_result.errors:
                            logger.warning("Seed corpus: %s", err)
                except Exception:
                    logger.warning("Seed corpus ingestion failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "seed_corpus",
                        "Seed corpus unavailable; hunting without CVE/crash history",
                    )

            # 2.9. Shared findings pool (spec 005)
            findings_pool = None
            historical_db = None
            if self._injected_findings_pool is not None:
                # Campaign mode: use shared pool (spec 012)
                findings_pool = self._injected_findings_pool
                historical_db = self._injected_historical_db
            elif self._enable_findings_pool:
                from .findings_pool import FindingsPool
                from .historical_findings_db import HistoricalFindingsDB

                checkpoint_path = Path(self.output_dir) / self._session_id / "findings_pool.jsonl"
                findings_pool = FindingsPool(checkpoint_path=checkpoint_path)
                try:
                    historical_db = HistoricalFindingsDB(path=self._historical_db_path)
                    prior = historical_db.query_prior(repo_url=self.repo_url)
                    if prior:
                        logger.info("Loaded %d historical findings for dedup", len(prior))
                except Exception:
                    logger.warning("Historical findings DB load failed", exc_info=True)
                    historical_db = None

            # 3. Tiered hunt
            hunt_result = await self._hunt(
                files=self._expand_target_windows(files),
                repo_path=repo_path,
                pipeline_status=pipeline_status,
                stage_files=stage_files,
                seeded_by_file=seeded_by_file,
                semgrep_hints_by_file=semgrep_hints_by_file,
                entry_points_by_file=entry_points_by_file,
                seed_corpus_by_file=seed_corpus_by_file,
                findings_pool=findings_pool,
                callgraph=preprocess_result.callgraph,
            )
            all_findings = hunt_result.findings
            all_potentials = hunt_result.potentials
            files_hunted = hunt_result.files_hunted
            spent_per_tier = hunt_result.spent_per_tier
            band_stats = hunt_result.band_stats
            subsystems_hunted = hunt_result.subsystems_hunted
            subsystem_spent = hunt_result.subsystem_spent_usd

            if self._target_files and not hunt_result.target_plan_completed:
                self._target_plan_incomplete = True
                if historical_db is not None:
                    historical_db.close()
                for stage in ("verify", "exploit"):
                    self._emit_stage(
                        stage,
                        "skipped",
                        findings_so_far=len(all_findings),
                        detail="Explicit target window plan was incomplete",
                        files=stage_files,
                        finding_ids=[finding.id for finding in all_findings],
                    )
                return self._finalize_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    findings=all_findings,
                    verified=[],
                    exploited=[],
                    files_ranked=files_ranked,
                    files_hunted=files_hunted,
                    spent_per_tier=spent_per_tier,
                    band_stats=band_stats,
                    findings_pool=findings_pool,
                    subsystems_hunted=subsystems_hunted,
                    subsystem_spent_usd=subsystem_spent,
                    subsystem_status=hunt_result.subsystem_status,
                    pipeline_status=pipeline_status,
                    potentials=all_potentials,
                )

            # 3.5. v0.6: Behavioral monitoring of findings text (spec 013).
            if self._enable_behavior_monitor and all_findings:
                try:
                    from .behavior_monitor import BehaviorMonitor

                    bmon = BehaviorMonitor(session_id=self._session_id)
                    for f in all_findings:
                        for field in ("description", "poc", "exploit", "evidence"):
                            text = f.get(field, "")
                            if text:
                                bmon.scan_text(str(text), finding_id=f.get("id", ""))
                    alerts = bmon.get_alerts()
                    if alerts:
                        logger.warning(
                            "Behavior monitor: %d alerts — %s",
                            len(alerts),
                            bmon.summary(),
                        )
                except Exception:
                    logger.debug("Behavior monitor failed", exc_info=True)

            # 3.5. Persist findings to historical DB (spec 005)
            # Skip when running under campaign — campaign handles bulk ingestion.
            if historical_db is not None and all_findings and self._injected_findings_pool is None:
                try:
                    count = historical_db.ingest_campaign(
                        all_findings,
                        repo_url=self.repo_url,
                        session_id=self._session_id,
                    )
                    logger.info("Persisted %d findings to historical DB", count)
                except Exception:
                    logger.warning("Historical DB ingest failed", exc_info=True)
                finally:
                    historical_db.close()

            if self._stop_after == "hunt":
                logger.info("--stop-after hunt: exiting early")
                for stage in ("verify", "exploit"):
                    self._emit_stage(
                        stage,
                        "skipped",
                        findings_so_far=len(all_findings),
                        detail="Run stopped after hunt",
                        files=[str(finding.file or "") for finding in all_findings],
                        symbols=self._finding_symbols(all_findings),
                        finding_ids=[finding.id for finding in all_findings],
                    )
                return self._finalize_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    findings=all_findings,
                    verified=[],
                    exploited=[],
                    files_ranked=files_ranked,
                    files_hunted=files_hunted,
                    spent_per_tier=spent_per_tier,
                    band_stats=band_stats,
                    findings_pool=findings_pool,
                    subsystems_hunted=subsystems_hunted,
                    subsystem_spent_usd=subsystem_spent,
                    subsystem_status=hunt_result.subsystem_status,
                    pipeline_status=pipeline_status,
                    potentials=all_potentials,
                )

            # 4. Verify (unless --no-verify)
            verification_result = await self._verify(
                all_findings, repo_path=repo_path, pipeline_status=pipeline_status
            )
            verified = verification_result.verified
            rejected = verification_result.rejected
            if rejected:
                self._write_rejected_findings(rejected)
            if verification_result.status != "completed" and not self.no_verify:
                self._verification_incomplete = True
                self._emit_stage(
                    "exploit",
                    "skipped",
                    findings_so_far=len(verified),
                    detail="Verification did not conclusively process every finding",
                    files=[str(finding.file or "") for finding in verified],
                    symbols=self._finding_symbols(verified),
                    finding_ids=[finding.id for finding in verified],
                )
                return self._finalize_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    findings=all_findings,
                    verified=verified,
                    exploited=[],
                    files_ranked=files_ranked,
                    files_hunted=files_hunted,
                    spent_per_tier=spent_per_tier,
                    band_stats=band_stats,
                    findings_pool=findings_pool,
                    subsystems_hunted=subsystems_hunted,
                    subsystem_spent_usd=subsystem_spent,
                    subsystem_status=hunt_result.subsystem_status,
                    pipeline_status=pipeline_status,
                    potentials=all_potentials,
                )

            # 4.5. v0.3: Extract mechanisms from verified findings and persist them
            #      to the cross-run store. Cheap LLM pass; failures are non-fatal.
            if self._mechanism_store is not None and verified and not self._budget_exhausted():
                verifier_llm_for_extract = self._get_native_client(
                    "verifier",
                    self.verifier_llm,
                    budget_stage="mechanism_extraction",
                )
                if verifier_llm_for_extract is not None:
                    try:
                        extractor = MechanismExtractor(verifier_llm_for_extract)
                        for finding in verified:
                            mech = await extractor.aextract(finding, source_repo=self.repo_url)
                            if mech is not None:
                                self._mechanism_store.append(mech)
                    except BudgetExceeded:
                        logger.info("Mechanism extraction stopped at the run budget")
                    except Exception:
                        logger.warning("Mechanism extraction failed", exc_info=True)
                        pipeline_status.record_degraded(
                            "mechanism_extraction",
                            "Mechanism extraction failed; cross-run memory not updated",
                        )

            # 4.75. v0.3: Variant Hunter Loop — compound finding density within
            #       this run. For each verified finding, generate a grep pattern,
            #       search the codebase for structural matches, and surface each
            #       match as a new suspicion-level finding linked back to the
            #       original. v0.3 scope: we surface the matches in the report;
            #       we don't re-spawn hunters on each match (that's a v1.0 pass).
            if self.enable_variant_loop and verified and not self._budget_exhausted():
                variant_llm = self._get_native_client(
                    "verifier",
                    self.verifier_llm,
                    budget_stage="variant_loop",
                )
                if variant_llm is not None:
                    try:
                        loop = VariantLoop(
                            pattern_gen=VariantPatternGenerator(variant_llm),
                        )
                        # Track locations we've already reported to avoid dupes
                        already_seen = {
                            (f.get("file", ""), f.get("line_number", 0)) for f in all_findings
                        }
                        # v0.4: drive the multi-iteration fixpoint loop rather
                        # than the single-pass run_once. Each iteration feeds
                        # its new seeds back in as starting points for the
                        # next pattern generation pass.
                        variant_result = await loop.arun(
                            verified_findings=verified,
                            repo_path=repo_path,
                            already_seen_locations=already_seen,
                            reverify_callback=None,
                        )
                        for seed in variant_result.seeds:
                            parent = seed.original_finding
                            stable_finding_id = stable_run_id(
                                "variant",
                                {
                                    "run_id": self._session_id,
                                    "parent_id": parent.id,
                                    "file": seed.match.file,
                                    "line": seed.match.line_number,
                                    "matched_text": seed.match.matched_text,
                                    "pattern": seed.match.pattern.semantic_description,
                                },
                            )
                            variant_finding = Finding(
                                id=f"variant-{uuid.uuid4().hex[:8]}",
                                file=seed.match.file,
                                line_number=seed.match.line_number,
                                finding_type=parent.finding_type or "variant",
                                cwe=parent.cwe,
                                severity=parent.effective_severity or "medium",
                                confidence="low",
                                description=(
                                    f"Variant of {parent.id}: {seed.match.pattern.semantic_description}"
                                ),
                                code_snippet=seed.match.matched_text,
                                evidence_level="suspicion",
                                discovered_by="variant_loop",
                                related_finding_id=parent.id or None,
                                related_cve=parent.related_cve,
                                hunter_session_id=self._session_id,
                                extra={"stable_finding_id": stable_finding_id},
                            )
                            all_findings.append(variant_finding)
                        logger.info(
                            "Variant loop: %d patterns, %d matches surfaced",
                            variant_result.patterns_generated,
                            variant_result.matches_found,
                        )
                    except BudgetExceeded:
                        logger.info("Variant loop stopped at the run budget")
                    except Exception:
                        logger.warning("Variant loop failed", exc_info=True)
                        pipeline_status.record_degraded(
                            "variant_loop",
                            "Variant loop failed; no sibling bugs surfaced",
                        )

            # 4.9. Stage 2.5: PoC stability verification (spec 010).
            # Rerun PoCs in fresh containers to measure reliability.
            if (
                self.enable_stability_verification
                and verified
                and self._sandbox_manager is not None
                and not self._budget_exhausted()
            ):
                from .stability import StabilityVerifier, apply_stability_result

                stability_llm = self._get_native_client(
                    "verifier",
                    self.verifier_llm,
                    budget_stage="stability",
                )
                sv = StabilityVerifier(
                    sandbox_manager=self._sandbox_manager,
                    hardening_llm=stability_llm,
                )
                stability_eligible = [
                    f
                    for f in verified
                    if f.get("poc")
                    and f.get("crash_evidence")
                    and evidence_at_or_above(
                        f.get("evidence_level", "suspicion"),
                        "crash_reproduced",
                    )
                ]
                stable_verified: list[Finding] = []
                for finding in stability_eligible:
                    try:
                        sr = await sv.averify(finding)
                        apply_stability_result(finding, sr)
                        if sr.classification != "unreliable":
                            stable_verified.append(finding)
                        else:
                            logger.info(
                                "Finding %s demoted to unreliable (%.0f%% success rate)",
                                finding.get("id"),
                                sr.success_rate * 100,
                            )
                    except BudgetExceeded:
                        logger.info("Stability verification stopped at the run budget")
                        break
                    except Exception:
                        logger.warning(
                            "Stability check failed for %s",
                            finding.get("id"),
                            exc_info=True,
                        )
                        stable_verified.append(finding)
                non_poc = [f for f in verified if f not in stability_eligible]
                verified = stable_verified + non_poc

            if self._stop_after == "verify":
                logger.info("--stop-after verify: exiting early")
                self._emit_stage(
                    "exploit",
                    "skipped",
                    findings_so_far=len(all_findings),
                    detail="Run stopped after verify",
                    files=[str(finding.file or "") for finding in all_findings],
                    symbols=self._finding_symbols(all_findings),
                    finding_ids=[finding.id for finding in all_findings],
                )
                return self._finalize_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    findings=all_findings,
                    verified=verified,
                    exploited=[],
                    files_ranked=files_ranked,
                    files_hunted=files_hunted,
                    spent_per_tier=spent_per_tier,
                    band_stats=band_stats,
                    findings_pool=findings_pool,
                    subsystems_hunted=subsystems_hunted,
                    subsystem_spent_usd=subsystem_spent,
                    subsystem_status=hunt_result.subsystem_status,
                    pipeline_status=pipeline_status,
                    potentials=all_potentials,
                )

            # 5. Exploit-triage (unless --no-exploit) — gated on evidence_level
            exploitation_result = await self._exploit(verified, findings_pool=findings_pool)
            verified = exploitation_result.verified
            exploited = exploitation_result.exploited
            # 5.5 v0.3: Auto-patch (opt-in) — runs after exploiter on verified
            #          critical/high findings with root_cause_explained evidence.
            patched: list[Finding] = []

            # 5.25. Stage 1.5: Exploit elaboration (autonomous, opt-in).
            elaborated: list[Finding] = []
            if self.enable_elaboration and exploited and not self._budget_exhausted():
                from .elaboration import (
                    ElaborationAgent,
                    prioritize_for_elaboration,
                )

                elaboration_llm = self._get_native_client(
                    "sourcehunt_exploit",
                    self.exploiter_llm,
                    budget_stage="elaboration",
                )
                if elaboration_llm is not None:
                    targets = prioritize_for_elaboration(
                        exploited,
                        self._elaboration_cap,
                    )
                    if targets:
                        elab_agent = ElaborationAgent(
                            llm=elaboration_llm,
                            sandbox_manager=self._sandbox_manager,
                            sandbox_factory=self.sandbox_factory,
                            findings_pool=findings_pool,
                            budget_band=self._exploit_budget_band,
                            output_dir=str(self._ensure_output_dir_layout()),
                            project_name=(
                                self.repo_url.split("/")[-1] if self.repo_url else "target"
                            ),
                        )
                        for finding in targets:
                            if self._budget_exhausted():
                                logger.info(
                                    "Elaboration halted: budget $%.2f exhausted ($%.2f spent)",
                                    self.budget_usd,
                                    self._run_spent_usd(),
                                )
                                break
                            try:
                                elab_result = await elab_agent.aattempt(finding)
                                if elab_result.elaborated:
                                    elab_finding = _apply_elaboration(
                                        finding,
                                        elab_result,
                                    )
                                    all_findings.append(elab_finding)
                                    elaborated.append(elab_finding)
                            except BudgetExceeded:
                                logger.info("Elaboration stopped at the run budget")
                                break
                            except Exception:
                                logger.warning(
                                    "Elaboration failed for %s",
                                    finding.get("id"),
                                    exc_info=True,
                                )

            # 5.5. v0.3: Auto-patch mode (opt-in).
            # The verify-by-recompile gate is MANDATORY — a patch is only marked
            # `validated` if we actually applied it, rebuilt, and re-ran the PoC.
            if self.enable_auto_patch and verified and not self._budget_exhausted():
                patcher_llm = self._get_native_client(
                    "sourcehunt_exploit",
                    self.exploiter_llm,
                    budget_stage="auto_patch",
                )
                if patcher_llm is not None:
                    try:
                        patcher = AutoPatcher(patcher_llm)
                        for finding in verified:
                            if not patcher.is_eligible(finding):
                                continue
                            patch_sandbox = None
                            rerun_cb = None
                            if self.sandbox_factory is not None:
                                try:
                                    patch_sandbox = self.sandbox_factory()
                                    rerun_cb = build_rerun_poc_callback(patch_sandbox)
                                except Exception:
                                    logger.debug(
                                        "Auto-patch sandbox spawn failed",
                                        exc_info=True,
                                    )
                                    patch_sandbox = None
                                    rerun_cb = None
                            try:
                                attempt = await patcher.aattempt(
                                    finding,
                                    file_content=self._load_file_content(repo_path, finding),
                                    sandbox=patch_sandbox,
                                    rerun_poc=rerun_cb,
                                )
                            finally:
                                if patch_sandbox is not None:
                                    try:
                                        patch_sandbox.stop()
                                    except Exception:
                                        pass
                            apply_patch_attempt(finding, attempt)
                            if attempt.validated:
                                patched.append(finding)
                                if self.auto_pr:
                                    self._open_draft_pr(finding, attempt)
                    except BudgetExceeded:
                        logger.info("Auto-patching stopped at the run budget")
                    except Exception:
                        logger.warning("Auto-patcher failed", exc_info=True)

            # 5.75. v0.3: Populate the cross-run knowledge graph with source
            #       findings. Best-effort — never blocks the run.
            try:
                if self.enable_knowledge_graph and all_findings:
                    self._populate_knowledge_graph_source(repo_path, all_findings)
            except Exception:
                logger.warning("Knowledge graph population failed", exc_info=True)

            # 5.85. v0.4: Coordinated-disclosure templates (opt-in).
            if self.export_disclosures and verified:
                try:
                    self._export_disclosure_bundle(verified)
                except Exception:
                    logger.warning("Disclosure export failed", exc_info=True)

                # 5.86. v0.5: Queue findings into disclosure DB (spec 011).
                try:
                    from .disclosure_db import DisclosureDB

                    disclosure_db = DisclosureDB()
                    try:
                        disclosure_db.queue_findings(
                            verified,
                            self.repo_url,
                            self._session_id,
                        )
                    finally:
                        disclosure_db.close()
                except Exception:
                    logger.warning("Disclosure DB queue failed", exc_info=True)

            # 5.87. v0.6: Store exploits in encrypted artifact store (spec 013).
            if self._enable_artifact_store and exploited:
                try:
                    from .artifact_store import ArtifactStore

                    artifact_store = ArtifactStore()
                    for f in exploited:
                        exploit_data = f.get("exploit") or f.get("poc")
                        if exploit_data:
                            if isinstance(exploit_data, str):
                                exploit_data = exploit_data.encode()
                            artifact_store.store_exploit(
                                f.get("id", ""),
                                exploit_data,
                                operator="pipeline",
                            )
                except Exception:
                    logger.warning("Artifact store failed", exc_info=True)

            # 5.88. v0.6: Auto-commit findings with root_cause_explained (spec 014).
            try:
                from .commitment import CommitmentLog

                committable = filter_by_evidence(verified, "root_cause_explained")
                if committable:
                    commitment_log = CommitmentLog()
                    for f in committable:
                        commitment_log.commit_finding(f, project=self.repo_url)
                    logger.info(
                        "Committed %d findings to commitment log",
                        len(committable),
                    )
            except Exception:
                logger.warning("Auto-commitment failed", exc_info=True)

            self._emit_stage(
                "exploit",
                (
                    "skipped"
                    if self.no_exploit
                    else "budget_exhausted"
                    if self._budget_exhausted()
                    else "completed"
                ),
                findings_so_far=len(all_findings),
                detail=f"{len(exploited)} exploited",
                files=[str(finding.file or "") for finding in all_findings],
                symbols=self._finding_symbols(all_findings),
                finding_ids=[finding.id for finding in all_findings],
            )

            return self._finalize_result(
                start_time=start_time,
                repo_path=repo_path,
                findings=all_findings,
                verified=verified,
                exploited=exploited,
                files_ranked=files_ranked,
                files_hunted=files_hunted,
                spent_per_tier=spent_per_tier,
                band_stats=band_stats,
                findings_pool=findings_pool,
                subsystems_hunted=subsystems_hunted,
                subsystem_spent_usd=subsystem_spent,
                subsystem_status=hunt_result.subsystem_status,
                pipeline_status=pipeline_status,
                potentials=all_potentials,
            )
        finally:
            if self._spend_ledger is not None:
                self._finalize_spend_ledger("failed")
            self._finalize_instrumentation("failed")
            if self._sandbox_manager is not None:
                try:
                    self._sandbox_manager.cleanup(remove_image=False)
                except Exception:
                    logger.debug("HunterSandbox cleanup failed", exc_info=True)
            if self._preprocessor is not None:
                self._preprocessor.cleanup()
                self._preprocessor = None

    @property
    def session_id(self) -> str:
        return self._session_id

    # --- Pipeline helpers ---------------------------------------------------

    def _ensure_output_dir_layout(self) -> Path:
        session_dir = Path(self.output_dir) / self._session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

    def _export_disclosure_bundle(
        self,
        verified_findings: list[Finding],
    ) -> dict[str, list[str]]:
        """Generate MITRE + HackerOne templates for verified findings.

        Returns a dict {format: [file_paths]} for the reporter to surface.
        """
        generator = DisclosureGenerator(
            repo_url=self.repo_url,
            reporter_name=self.disclosure_reporter_name,
            reporter_affiliation=self.disclosure_reporter_affiliation,
            reporter_email=self.disclosure_reporter_email,
        )
        bundle = generator.generate_bundle(verified_findings)
        if not bundle.templates:
            logger.info(
                "Disclosure export: no findings passed the eligibility gate "
                "(skipped=%d, reasons=%s)",
                bundle.skipped,
                bundle.skipped_reasons,
            )
            return {}
        return write_disclosure_bundle(bundle, self.output_dir, self._session_id)

    def _populate_knowledge_graph_source(
        self,
        repo_path: str,
        findings: list[Finding],
    ) -> None:
        """Auto-populate the KG with source-hunt entities. Best-effort."""
        kg = self._knowledge_graph
        if kg is None:
            try:
                from clearwing.core.config import clearwing_home
                from clearwing.data.knowledge import KnowledgeGraph

                kg = KnowledgeGraph(
                    persist_path=str(clearwing_home() / "knowledge_graph.json"),
                    auto_save=True,
                )
            except Exception:
                logger.debug("Could not import KnowledgeGraph", exc_info=True)
                return

        try:
            kg.add_repo(self.repo_url, local_path=repo_path)
        except Exception:
            pass

        # First pass: add all findings so VARIANT_OF edges can resolve parents
        for f in findings:
            try:
                kg.add_source_finding(
                    repo_url=self.repo_url,
                    file_path=f.get("file", ""),
                    finding=f,
                )
            except Exception:
                logger.debug("KG source finding add failed", exc_info=True)

        try:
            kg.save()
        except Exception:
            logger.debug("KG save failed", exc_info=True)

    def _open_draft_pr(self, finding: Finding, attempt: Any) -> None:
        """Open a draft PR for a validated auto-patch via the `gh` CLI.

        v0.3: best-effort only — failures are logged and the run continues.
        The PR is always opened as draft so a human reviews before merge.
        """
        if shutil.which("gh") is None:
            logger.info("auto_pr=True but `gh` CLI not found; skipping")
            return

        title = (
            attempt.commit_message
            or f"fix: {finding.get('finding_type', 'vulnerability')} "
            f"in {finding.get('file', 'unknown')}"
        )
        body = (
            f"## Auto-generated patch from clearwing sourcehunt\n\n"
            f"**Finding:** {finding.get('id', '')}\n"
            f"**File:** {finding.get('file', '')}:{finding.get('line_number', '')}\n"
            f"**CWE:** {finding.get('cwe', '')}\n"
            f"**Evidence level:** {finding.get('evidence_level', '')}\n\n"
            f"### Description\n{finding.get('description', '')}\n\n"
            f"### Fix explanation\n{attempt.explanation}\n\n"
            f"### Diff\n```\n{attempt.diff[:3000]}\n```\n\n"
            f"**Human review required before merge.**\n"
        )
        try:
            subprocess.run(
                ["gh", "pr", "create", "--draft", "--title", title, "--body", body],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except Exception:
            logger.debug("gh pr create failed", exc_info=True)

    async def _exploit(self, verified: list[Finding], *, findings_pool: Any) -> ExploitationResult:
        """Run or restore the completed exploitation stage."""

        options = {
            "no_exploit": self.no_exploit,
            "exploit_budget_band": self._exploit_budget_band,
            "agent_mode": self._effective_agent_mode,
            "verified_findings_sha256": self._finding_set_digest(verified),
        }
        self._exploitation_restored = False
        self._emit_stage(
            "exploit",
            "started",
            findings_so_far=len(verified),
            files=[str(finding.file or "") for finding in verified],
            symbols=self._finding_symbols(verified),
            finding_ids=[finding.id for finding in verified],
        )
        if self._checkpoint is not None and self._checkpoint.exploitation is not None:
            restored = self._checkpoint.exploitation.restore(options=options)
            if restored is None:
                raise ValueError("exploitation checkpoint is invalid or incompatible with this run")
            self._exploitation_restored = True
            self._emit_stage(
                "exploit",
                "completed",
                findings_so_far=len(restored.exploited),
                detail=f"Restored {len(restored.exploited)} exploited findings from checkpoint",
                finding_ids=[finding.id for finding in restored.exploited],
            )
            return restored

        result = ExploitationResult(verified=verified, exploited=[])
        if not self.no_exploit and not self._budget_exhausted():
            exploiter_llm = self._get_native_client(
                "sourcehunt_exploit", self.exploiter_llm, budget_stage="exploit"
            )
            if exploiter_llm is not None:
                eligible = filter_by_evidence(result.verified, "crash_reproduced")
                has_sandbox = self._sandbox_manager is not None or self.sandbox_factory is not None
                if eligible and has_sandbox:
                    exploiter = AgenticExploiter(
                        llm=exploiter_llm,
                        sandbox_manager=self._sandbox_manager,
                        sandbox_factory=self.sandbox_factory,
                        findings_pool=findings_pool,
                        budget_band=self._exploit_budget_band,
                        output_dir=str(self._ensure_output_dir_layout()),
                        project_name=self.repo_url.split("/")[-1] if self.repo_url else "target",
                    )
                else:
                    exploiter = Exploiter(exploiter_llm)
                for finding in eligible:
                    if self._budget_exhausted():
                        break
                    try:
                        exploit_result = await exploiter.aattempt(finding)
                        apply_exploiter_result(finding, exploit_result)
                        if exploit_result.success:
                            result.exploited.append(finding)
                        if has_sandbox and exploit_result.partial and findings_pool is not None:
                            finding["primitive_type"] = (
                                exploit_result.primitive_type or finding.get("primitive_type", "")
                            )
                            await findings_pool.add(finding)
                    except BudgetExceeded:
                        logger.info("Exploitation stopped at the run budget")
                        break
                    except Exception:
                        logger.warning("Exploiter failed for %s", finding.id, exc_info=True)
        if self._checkpoint is None:
            raise RuntimeError("exploitation requires a preprocessing checkpoint")
        self._checkpoint.exploitation = ExploitationCheckpoint.from_result(result, options=options)
        self._dump_checkpoint()
        self._emit_stage(
            "exploit",
            "completed" if not self._budget_exhausted() else "budget_exhausted",
            findings_so_far=len(result.exploited),
            detail=f"{len(result.exploited)} exploited findings",
            finding_ids=[finding.id for finding in result.exploited],
        )
        return result

    def _spawn_verification_sandbox(self) -> Any:
        """Spawn a writable sandbox for one independent verification pass."""
        factory = (
            self._sandbox_manager.spawn
            if self._sandbox_manager is not None
            else self.sandbox_factory
        )
        if factory is None:
            return None

        requested_options = {
            "writable_workspace": True,
            "timeout_seconds": 600,
        }
        if self._sandbox_manager is not None:
            requested_options.update(
                session_id=self._session_id + "-v",
                runtime=self._gvisor_runtime,
            )

        try:
            try:
                parameters = inspect.signature(factory).parameters.values()
            except (TypeError, ValueError):
                options = requested_options
            else:
                accepts_keywords = any(
                    parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters
                )
                supported_names = {parameter.name for parameter in parameters}
                options = {
                    key: value
                    for key, value in requested_options.items()
                    if accepts_keywords or key in supported_names
                }
            return factory(**options)
        except Exception:
            logger.warning("Verification sandbox spawn failed", exc_info=True)
            return None

    def _verification_resources(self, repo_path: str) -> tuple[Any, Any, list]:
        """Create the runner-owned context and tools for one verifier."""
        sandbox = self._spawn_verification_sandbox()
        if sandbox is None:
            self._verification_sandbox_failed = True
            return None, None, []
        try:
            from clearwing.agent.tools.hunt import (
                HunterContext,
                build_verification_tools,
            )

            sandbox_config = getattr(sandbox, "config", None)
            network_mode = getattr(sandbox_config, "network_mode", None)
            if (
                sandbox_config is not None
                and isinstance(network_mode, str)
                and network_mode != "none"
            ):
                raise RuntimeError("verification sandbox must disable networking")
            if (
                hasattr(sandbox, "workspace_baseline_commit")
                and not sandbox.workspace_baseline_commit
            ):
                raise RuntimeError("verification sandbox has no immutable workspace baseline")

            ctx = HunterContext(
                repo_path=repo_path,
                sandbox=sandbox,
                sandbox_manager=self._sandbox_manager,
                session_id=self._session_id + "-v",
                specialist="verifier",
            )
            return sandbox, ctx, build_verification_tools(ctx)
        except Exception:
            logger.warning("Verification tool setup failed", exc_info=True)
            self._verification_sandbox_failed = True
            self._stop_verification_sandbox(sandbox)
            return None, None, []

    @staticmethod
    def _stop_verification_sandbox(sandbox: Any, ctx: Any = None) -> None:
        if ctx is not None:
            try:
                ctx.cleanup_variants()
            except Exception:
                logger.debug("Verification variant cleanup failed", exc_info=True)
        if sandbox is None:
            return
        try:
            sandbox.stop()
        except Exception:
            logger.debug("Verification sandbox cleanup failed", exc_info=True)

    async def _verify(
        self,
        findings: list[Finding],
        *,
        repo_path: str,
        pipeline_status: PipelineStatus,
    ) -> VerificationResult:
        """Run or restore the completed verification stage."""

        verifier_llm = (
            None
            if self.no_verify
            else self._get_native_client(
                "verifier", self.verifier_llm, budget_stage="verify"
            )
        )
        options = {
            "no_verify": self.no_verify,
            "validator_mode": self.validator_mode,
            "adversarial_verifier": self.adversarial_verifier,
            "adversarial_threshold": self.adversarial_threshold,
            "enable_patch_oracle": self.enable_patch_oracle,
            "verification_protocol": "sandbox-tools-v2",
            "evidence_policy": "host-observed-v2",
            "sandbox_runtime": self._gvisor_runtime or "default",
            "verifier_provider": getattr(verifier_llm, "provider_name", None),
            "verifier_model": getattr(verifier_llm, "model_name", None),
            "findings_sha256": self._finding_set_digest(findings),
        }
        self._verification_restored = False
        self._verification_sandbox_failed = False
        self._verification_incomplete = False
        self._emit_stage(
            "verify",
            "started",
            findings_so_far=len(findings),
            detail=f"{len(findings)} findings to verify",
            files=[str(finding.file or "") for finding in findings],
            symbols=self._finding_symbols(findings),
            finding_ids=[finding.id for finding in findings],
        )
        if self._checkpoint is not None and self._checkpoint.verification is not None:
            restored = self._checkpoint.verification.restore(options=options)
            if restored is None:
                raise ValueError("verification checkpoint is invalid or incompatible with this run")
            self._verification_restored = True
            result = restored
            if result.status == "completed":
                pipeline_status.record_succeeded("verifier")
            else:
                self._verification_incomplete = True
                pipeline_status.record_degraded(
                    "verifier", "Restored verification was not complete"
                )
            detail = f"Restored {len(result.verified)} verified findings from checkpoint"
        else:
            result = VerificationResult(verified=[], rejected=[])
            if self.no_verify:
                for finding in findings:
                    finding["verified"] = False
                pipeline_status.record(
                    "verifier",
                    StageOutcome.SKIPPED,
                    fallback_description="Verification skipped (--no-verify)",
                )
            elif self._budget_exhausted():
                result.status = "budget_exhausted"
                self._verification_incomplete = True
                pipeline_status.record(
                    "verifier",
                    StageOutcome.SKIPPED,
                    fallback_description="Budget exhausted; findings remain unverified",
                )
            else:
                if verifier_llm is None:
                    if findings:
                        result.status = "incomplete"
                        self._verification_incomplete = True
                        for finding in findings:
                            finding["verified"] = False
                            finding["verifier_tie_breaker"] = (
                                "Independent verifier model unavailable; "
                                "finding left unverified"
                            )
                        pipeline_status.record_degraded(
                            "verifier", "Independent verifier model unavailable"
                        )
                    else:
                        pipeline_status.record_succeeded("verifier")
                elif self.validator_mode == "v2":
                    result.verified, result.rejected = await self._verify_v2(
                        verifier_llm, findings, repo_path
                    )
                else:
                    result.verified = await self._verify_v1(verifier_llm, findings, repo_path)
                if self._verification_sandbox_failed or self._verification_incomplete:
                    result.status = "incomplete"
                    self._verification_incomplete = True
                    pipeline_status.record_degraded(
                        "verifier",
                        "Dynamic verification did not conclusively process every finding",
                    )
                elif result.status == "completed":
                    pipeline_status.record_succeeded("verifier")
            if self._checkpoint is None:
                raise RuntimeError("verification requires a preprocessing checkpoint")
            if result.status != "completed":
                # Partial, transient, or operational failures are not durable.
                self._checkpoint.verification = None
                self._checkpoint.exploitation = None
            else:
                self._checkpoint.verification = VerificationCheckpoint.from_result(
                    result, options=options
                )
            self._dump_checkpoint()
            detail = (
                "Verification skipped (--no-verify)"
                if self.no_verify
                else f"{len(result.verified)} verified, {len(result.rejected)} rejected"
            )
        self._emit_stage(
            "verify",
            result.status,
            findings_so_far=len(findings),
            detail=detail,
            files=[str(finding.file or "") for finding in findings],
            symbols=self._finding_symbols(findings),
            finding_ids=[finding.id for finding in findings],
        )
        return result

    async def _verify_v1(
        self,
        verifier_llm: AsyncLLMClient,
        all_findings: list[Finding],
        repo_path: str,
    ) -> list[Finding]:
        """Legacy v1 verification using the Verifier class."""
        verified: list[Finding] = []
        v = Verifier(
            verifier_llm,
            adversarial=self.adversarial_verifier,
            adversarial_threshold=self.adversarial_threshold,
        )
        for finding in all_findings:
            verification_sandbox, verification_ctx, verification_tools = (
                self._verification_resources(repo_path)
            )
            try:
                if not verification_tools:
                    finding["verified"] = False
                    finding["verifier_tie_breaker"] = (
                        "Dynamic verification unavailable; finding left unverified"
                    )
                    continue
                result = await v.averify(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                    verification_tools=verification_tools,
                )
                outcome = result.outcome or (
                    "confirmed" if result.is_real else "refuted"
                )
                if outcome in {"operational_error", "inconclusive"}:
                    self._verification_incomplete = True
                    finding["verified"] = False
                    finding["verifier_tie_breaker"] = result.tie_breaker
                    if result.dynamic_evidence:
                        finding["verification_evidence"] = result.dynamic_evidence
                    continue
                if self.enable_patch_oracle and result.is_real:
                    result = await self._run_patch_oracle_v1(v, finding, repo_path, result)
                apply_verifier_result(
                    finding,
                    result,
                    session_id=self._session_id + "-v",
                )
                if finding.get("verified"):
                    verified.append(finding)
            except BudgetExceeded:
                logger.info("Verification stopped at the run budget")
                self._verification_incomplete = True
                break
            except Exception:
                self._verification_incomplete = True
                logger.warning(
                    "Verifier failed for %s",
                    finding.get("id"),
                    exc_info=True,
                )
            finally:
                self._stop_verification_sandbox(verification_sandbox, verification_ctx)
        return verified

    async def _verify_v2(
        self,
        verifier_llm: AsyncLLMClient,
        all_findings: list[Finding],
        repo_path: str,
    ) -> tuple[list[Finding], list[Finding]]:
        """4-axis validation (spec 009)."""
        from .validator import Validator, apply_validator_verdict

        verified: list[Finding] = []
        rejected: list[Finding] = []
        val = Validator(
            verifier_llm,
            gate_threshold=self.adversarial_threshold,
        )
        for finding in all_findings:
            verification_sandbox, verification_ctx, verification_tools = (
                self._verification_resources(repo_path)
            )
            try:
                if not verification_tools:
                    finding["verified"] = False
                    finding["verifier_tie_breaker"] = (
                        "Dynamic verification unavailable; finding left unverified"
                    )
                    continue
                discoverer_sev = finding.get("severity")
                verdict = await val.avalidate(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                    verification_tools=verification_tools,
                )
                outcome = verdict.outcome or (
                    "confirmed" if verdict.advance else "refuted"
                )
                if outcome in {"operational_error", "inconclusive"}:
                    self._verification_incomplete = True
                    finding["verified"] = False
                    finding["verifier_tie_breaker"] = verdict.tie_breaker
                    if verdict.dynamic_evidence:
                        finding["verification_evidence"] = verdict.dynamic_evidence
                    continue
                if self.enable_patch_oracle and verdict.advance:
                    verdict = await self._run_patch_oracle_v2(
                        val,
                        finding,
                        repo_path,
                        verdict,
                    )
                apply_validator_verdict(
                    finding,
                    verdict,
                    session_id=self._session_id + "-v",
                    discoverer_severity=discoverer_sev,
                )
                if finding.get("verified"):
                    verified.append(finding)
                else:
                    rejected.append(finding)
                self._record_calibration(finding, verdict, discoverer_sev)
            except BudgetExceeded:
                logger.info("Validation stopped at the run budget")
                self._verification_incomplete = True
                break
            except Exception:
                self._verification_incomplete = True
                logger.warning(
                    "Validator failed for %s",
                    finding.get("id"),
                    exc_info=True,
                )
            finally:
                self._stop_verification_sandbox(verification_sandbox, verification_ctx)
        return verified, rejected

    async def _run_patch_oracle_v1(self, v, finding, repo_path, result):
        try:
            oracle_sandbox = None
            oracle_rerun_poc = None
            if self.sandbox_factory is not None:
                try:
                    oracle_sandbox = self.sandbox_factory()
                    oracle_rerun_poc = build_rerun_poc_callback(oracle_sandbox)
                except Exception:
                    logger.debug("Patch-oracle sandbox spawn failed", exc_info=True)
            try:
                passed, diff, notes = await v.arun_patch_oracle(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                    sandbox=oracle_sandbox,
                    rerun_poc=oracle_rerun_poc,
                )
            finally:
                if oracle_sandbox is not None:
                    try:
                        oracle_sandbox.stop()
                    except Exception:
                        pass
            result.patch_oracle_attempted = True
            result.patch_oracle_passed = passed
            result.patch_oracle_diff = diff
            result.patch_oracle_notes = notes
        except BudgetExceeded:
            raise
        except Exception:
            logger.debug("Patch-oracle pass failed", exc_info=True)
        return result

    async def _run_patch_oracle_v2(self, val, finding, repo_path, verdict):
        try:
            oracle_sandbox = None
            oracle_rerun_poc = None
            if self.sandbox_factory is not None:
                try:
                    oracle_sandbox = self.sandbox_factory()
                    oracle_rerun_poc = build_rerun_poc_callback(oracle_sandbox)
                except Exception:
                    logger.debug("Patch-oracle sandbox spawn failed", exc_info=True)
            try:
                passed, diff, notes = await val.arun_patch_oracle(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                    sandbox=oracle_sandbox,
                    rerun_poc=oracle_rerun_poc,
                )
            finally:
                if oracle_sandbox is not None:
                    try:
                        oracle_sandbox.stop()
                    except Exception:
                        pass
            verdict.patch_oracle_attempted = True
            verdict.patch_oracle_passed = passed
            verdict.patch_oracle_diff = diff
            verdict.patch_oracle_notes = notes
        except BudgetExceeded:
            raise
        except Exception:
            logger.debug("Patch-oracle pass failed", exc_info=True)
        return verdict

    def _record_calibration(self, finding, verdict, discoverer_sev):
        if self._calibration_store is None:
            return
        try:
            import datetime

            from .calibration import CalibrationRecord

            self._calibration_store.append(
                CalibrationRecord(
                    finding_id=finding.get("id", ""),
                    session_id=self._session_id,
                    cwe=finding.get("cwe", ""),
                    discoverer_severity=discoverer_sev or "unknown",
                    validator_severity=verdict.severity_validated,
                    axes={k: v.passed for k, v in verdict.axes.items()},
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                )
            )
        except Exception:
            logger.debug("Calibration record failed", exc_info=True)

    def _write_rejected_findings(self, rejected: list[Finding]) -> None:
        import json as _json

        session_dir = self._ensure_output_dir_layout()
        path = session_dir / "rejected_findings.jsonl"
        try:
            with open(path, "w", encoding="utf-8") as f:
                for finding in rejected:
                    f.write(_json.dumps(redact_tree(finding), default=str) + "\n")
            logger.info("Wrote %d rejected findings to %s", len(rejected), path)
        except OSError:
            logger.warning("Failed to write rejected findings", exc_info=True)

    def _load_file_content(self, repo_path: str, finding: Finding) -> str:
        """Read a finding's file only when it resolves inside the repository."""
        source_path = resolve_repo_file(repo_path, finding.get("file", ""))
        if source_path is None:
            return ""
        try:
            with open(source_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _recalled_mechanism_hints(self, files: list) -> list[dict]:
        """Build a synthetic hint entry from cross-run mechanisms.

        Queries the MechanismStore once with the aggregate language + tag set
        across all files, and formats the top-N mechanisms as a single hint
        dict. Returns an empty list if no mechanisms are relevant.
        """
        if self._mechanism_store is None:
            return []

        # Aggregate languages and tags from the file set
        languages: dict[str, int] = {}
        tag_set: set[str] = set()
        for ft in files:
            lang = ft.get("language", "")
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            tag_set.update(ft.get("tags", []))

        if not languages:
            return []

        # Use the most common language
        primary_language = max(languages.items(), key=lambda kv: kv[1])[0]
        recalled = self._mechanism_store.recall(
            language=primary_language,
            tags=list(tag_set),
            top_n=3,
        )
        if not recalled:
            return []

        # Format as a single synthetic "hint" that flows through the
        # existing semgrep_hints channel into hunter prompts.
        formatted = format_mechanisms_for_prompt(recalled)
        return [
            {
                "line": 0,
                "description": formatted,
                "source": "mechanism_memory",
            }
        ]

    @tracer.chain(name="Hunt")
    async def _hunt(
        self,
        *,
        files: list[FileTarget],
        repo_path: str,
        pipeline_status: PipelineStatus,
        stage_files: list[str],
        seeded_by_file: dict[str, dict],
        semgrep_hints_by_file: dict[str, list[dict]],
        entry_points_by_file: dict,
        seed_corpus_by_file: dict,
        findings_pool: Any,
        callgraph: Any,
    ) -> HuntResult:
        """Run or restore per-file and subsystem source hunting."""

        options = {
            "no_per_file_hunt": self._no_per_file_hunt,
            "agent_mode": self._effective_agent_mode,
            "prompt_mode": self._prompt_mode,
            "campaign_hint": self._campaign_hint,
            "exploit_mode": self._exploit_mode,
            "starting_band": self._starting_band,
            "max_band": self._max_band,
            "redundancy_override": self._redundancy_override,
            "shard_entry_points": self._shard_entry_points,
            "max_parallel": self.max_parallel,
            "enable_subsystem_hunt": self._enable_subsystem_hunt,
            "subsystem_paths": sorted(self._subsystem_paths or []),
            "subsystem_budget_usd": self._subsystem_budget_usd,
            "subsystem_max_parallel": self._subsystem_max_parallel,
        }
        if self._target_files:
            options.update(
                {
                    "target_files": list(self._target_files),
                    "target_window_lines": self._target_window_lines,
                    "target_fingerprints": [
                        {
                            "path": file_target.get("path", ""),
                            "size_bytes": file_target.get("target_size_bytes"),
                            "sha256": file_target.get("target_sha256"),
                        }
                        for file_target in files
                        if file_target.get("target_start_line") in {None, 1}
                    ],
                }
            )
        self._hunt_restored = False
        hunt_symbols = sorted(
            {
                str(getattr(entry_point, "function_name", "") or "")
                for entry_points in entry_points_by_file.values()
                for entry_point in entry_points
                if getattr(entry_point, "function_name", "")
            }
        )
        if self._checkpoint is not None and self._checkpoint.hunt is not None:
            restored = self._checkpoint.hunt.restore(options=options)
            if restored is None:
                raise ValueError("hunt checkpoint is invalid or incompatible with this run")
            self._hunt_restored = True
            pipeline_status.record_succeeded("hunter_pool")
            self._emit_stage(
                "hunt",
                "completed",
                findings_so_far=len(restored.findings),
                detail=f"Restored {len(restored.findings)} findings from checkpoint",
                files=[str(finding.file or "") for finding in restored.findings],
                symbols=self._finding_symbols(restored.findings),
                finding_ids=[finding.id for finding in restored.findings],
            )
            if self._enable_subsystem_hunt:
                if restored.subsystem_status == "budget_exhausted":
                    pipeline_status.record(
                        "subsystem_hunt",
                        StageOutcome.SKIPPED,
                        fallback_description=(
                            "Budget exhausted; partial subsystem results retained"
                        ),
                    )
                elif restored.subsystem_status == "degraded":
                    pipeline_status.record_degraded(
                        "subsystem_hunt",
                        "Subsystem hunt failed; only per-file findings available",
                    )
                elif restored.subsystem_status == "completed":
                    pipeline_status.record_succeeded("subsystem_hunt")
                self._emit_stage(
                    "subsystem_hunt",
                    restored.subsystem_status,
                    findings_so_far=len(restored.findings),
                    cost_usd=restored.subsystem_spent_usd,
                    detail=(
                        f"Restored {restored.subsystems_hunted} hunted subsystems from checkpoint"
                    ),
                )
            return restored

        result = HuntResult(
            findings=[],
            files_hunted=0,
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        )
        target_plan_completed = not self._target_files
        hunter_llm = self._get_native_client("hunter", self.hunter_llm, budget_stage="hunt")
        if self._no_per_file_hunt:
            logger.info("Per-file hunt skipped (--no-per-file-hunt)")
            self._emit_stage(
                "hunt",
                "skipped",
                detail="Per-file hunt disabled",
                files=stage_files,
                symbols=hunt_symbols,
            )
        elif hunter_llm is not None and files and not self._budget_exhausted():
            self._emit_stage(
                "hunt",
                "started",
                detail=f"{len(files)} files",
                files=stage_files,
                symbols=hunt_symbols,
            )
            # Work-item-granular hunt resume: when this run is checkpointed
            # (always, once preprocessing has produced a checkpoint), memoize
            # each completed hunter work item under the session directory. A
            # resumed run reuses the finished work and re-runs only what was
            # interrupted, instead of the coarse all-or-nothing HuntCheckpoint.
            work_cache = (
                HuntWorkCache(self._ensure_output_dir_layout() / "hunt-work")
                if self._checkpoint is not None
                else None
            )
            pool = HunterPool(
                HuntPoolConfig(
                    files=files,
                    repo_path=repo_path,
                    sandbox_factory=self.sandbox_factory,
                    sandbox_manager=self._sandbox_manager,
                    hunter_factory=None,
                    llm=hunter_llm,
                    work_cache=work_cache,
                    max_parallel=self.max_parallel,
                    budget_usd=self.budget_usd,
                    tier_budget=self.tier_budget,
                    session_id_prefix=self._session_id,
                    seeded_crashes_by_file=seeded_by_file,
                    semgrep_hints_by_file=semgrep_hints_by_file,
                    agent_mode=self._effective_agent_mode,
                    prompt_mode=self._prompt_mode,
                    campaign_hint=self._campaign_hint,
                    exploit_mode=self._exploit_mode,
                    starting_band=self._starting_band,
                    max_band=self._max_band,
                    redundancy_override=self._redundancy_override,
                    entry_points_by_file=entry_points_by_file,
                    seed_corpus_by_file=seed_corpus_by_file,
                    shard_entry_points=self._shard_entry_points,
                    findings_pool=findings_pool,
                    trajectory_root=Path(self.output_dir) / self._session_id / "trajectories",
                    instrumentation=self._instrumentation,
                    explicit_target_windows=bool(self._target_files),
                    callgraph=callgraph,
                )
            )
            try:
                result.findings = await pool.arun()
                target_plan_completed = pool.all_targets_completed
                if pool.budget_exhausted or self._budget_exhausted():
                    if pool.budget_exhausted:
                        target_plan_completed = False
                    pipeline_status.record(
                        "hunter_pool",
                        StageOutcome.SKIPPED,
                        fallback_description="Budget exhausted; partial hunter results retained",
                    )
                    self._emit_stage(
                        "hunt",
                        "budget_exhausted",
                        findings_so_far=len(result.findings),
                        cost_usd=pool.total_spent,
                        detail=f"{len(result.findings)} partial findings",
                        files=[str(finding.file or "") for finding in result.findings],
                        symbols=self._finding_symbols(result.findings),
                        finding_ids=[finding.id for finding in result.findings],
                    )
                elif self._target_files and not target_plan_completed:
                    pipeline_status.record_degraded(
                        "hunter_pool", "Explicit target plan did not complete every window"
                    )
                    self._emit_stage(
                        "hunt",
                        "degraded",
                        findings_so_far=len(result.findings),
                        cost_usd=pool.total_spent,
                        detail="Explicit target plan was incomplete",
                        files=stage_files,
                        finding_ids=[finding.id for finding in result.findings],
                    )
                else:
                    pipeline_status.record_succeeded("hunter_pool")
                    self._emit_stage(
                        "hunt",
                        "completed",
                        findings_so_far=len(result.findings),
                        cost_usd=pool.total_spent,
                        detail=f"{len(result.findings)} findings",
                        files=[str(finding.file or "") for finding in result.findings],
                        symbols=self._finding_symbols(result.findings),
                        finding_ids=[finding.id for finding in result.findings],
                    )
            except BudgetExceeded:
                target_plan_completed = False
                logger.info("HunterPool stopped because the run budget is exhausted")
                pipeline_status.record(
                    "hunter_pool",
                    StageOutcome.SKIPPED,
                    fallback_description="Budget exhausted; partial hunter results retained",
                )
                self._emit_stage(
                    "hunt",
                    "budget_exhausted",
                    findings_so_far=len(result.findings),
                    files=stage_files,
                    symbols=hunt_symbols,
                    finding_ids=[finding.id for finding in result.findings],
                )
            except Exception as exc:
                target_plan_completed = False
                logger.warning("HunterPool run failed", exc_info=True)
                pipeline_status.record_degraded(
                    "hunter_pool", "Hunter phase produced no findings due to error"
                )
                self._emit_stage(
                    "hunt",
                    "degraded",
                    findings_so_far=len(result.findings),
                    files=stage_files,
                    symbols=hunt_symbols,
                    finding_ids=[finding.id for finding in result.findings],
                    error={"type": type(exc).__name__, "message": str(exc)},
                )
            result.spent_per_tier = pool.spent_per_tier
            result.band_stats = {
                "fast_runs": pool.runs_per_band.get("fast", 0),
                "fast_cost": pool.spent_per_band.get("fast", 0.0),
                "standard_runs": pool.runs_per_band.get("standard", 0),
                "standard_cost": pool.spent_per_band.get("standard", 0.0),
                "deep_runs": pool.runs_per_band.get("deep", 0),
                "deep_cost": pool.spent_per_band.get("deep", 0.0),
                "promotions": pool.promotion_counts,
            }
            result.files_hunted = pool.completed_target_count
        else:
            logger.info("HunterPool skipped; no LLM available")
            if not files:
                hunt_status = "skipped"
                hunt_detail = "No source files were available"
            elif self._budget_exhausted():
                hunt_status = "budget_exhausted"
                hunt_detail = "Run budget was exhausted before hunting"
            else:
                hunt_status = "degraded"
                hunt_detail = "No hunter model was available"
            self._emit_stage(
                "hunt",
                hunt_status,
                detail=hunt_detail,
                files=stage_files,
                symbols=hunt_symbols,
            )

        await self._hunt_subsystems(
            result,
            files=files,
            repo_path=repo_path,
            callgraph=callgraph,
            entry_points_by_file=entry_points_by_file,
            findings_pool=findings_pool,
            pipeline_status=pipeline_status,
        )

        if self._checkpoint is None:
            raise RuntimeError("hunting requires a preprocessing checkpoint")
        if self._target_files and not target_plan_completed:
            # Target coverage is all-or-nothing at the stage-checkpoint level.
            # A later resume must rerun the explicit window plan rather than
            # treating partial coverage as complete.
            self._checkpoint.hunt = None
            self._checkpoint.verification = None
            self._checkpoint.exploitation = None
            result.target_plan_completed = False
            self._dump_checkpoint()
            return result
        result.target_plan_completed = target_plan_completed
        self._checkpoint.hunt = HuntCheckpoint.from_result(result, options=options)
        self._dump_checkpoint()
        return result

    async def _hunt_subsystems(
        self,
        result: HuntResult,
        *,
        files: list[FileTarget],
        repo_path: str,
        callgraph: Any,
        entry_points_by_file: dict,
        findings_pool: Any,
        pipeline_status: PipelineStatus,
    ) -> None:
        """Run the subsystem portion of the hunt into the shared phase result."""

        if not self._enable_subsystem_hunt:
            return
        if self._budget_exhausted():
            result.subsystem_status = "budget_exhausted"
            pipeline_status.record(
                "subsystem_hunt",
                StageOutcome.SKIPPED,
                fallback_description="Budget exhausted before subsystem hunting",
            )
            self._emit_stage(
                "subsystem_hunt",
                "budget_exhausted",
                cost_usd=self._run_spent_usd(),
                detail="Run budget was exhausted before subsystem hunting",
            )
            logger.info(
                "Subsystem hunt skipped: budget $%.2f exhausted ($%.2f spent)",
                self.budget_usd,
                self._run_spent_usd(),
            )
            return
        subsystem_llm = self._get_native_client(
            "hunter", self.hunter_llm, budget_stage="subsystem_hunt"
        )
        if subsystem_llm is None:
            logger.info("Subsystem hunt skipped; no hunter model available")
            return

        from .subsystem import (
            SubsystemHuntConfig,
            SubsystemHuntRunner,
            identify_subsystems_auto,
            subsystem_from_path,
        )

        subsystem_targets: list = []
        if self._subsystem_paths:
            for path in self._subsystem_paths:
                try:
                    subsystem_targets.append(
                        subsystem_from_path(
                            path,
                            files,
                            callgraph=callgraph,
                            entry_points_by_file=entry_points_by_file,
                            max_files=self._subsystem_max_files,
                        )
                    )
                except ValueError:
                    logger.warning("No files match subsystem path: %s", path)
        else:
            auto_kwargs: dict = {}
            if self._subsystem_max_files is not None:
                auto_kwargs["max_files_per_subsystem"] = self._subsystem_max_files
            subsystem_targets = identify_subsystems_auto(
                files,
                callgraph=callgraph,
                entry_points_by_file=entry_points_by_file,
                **auto_kwargs,
            )
        if not subsystem_targets:
            return

        subsystem_files = sorted(
            {
                str(file_target.get("path") or "")
                for subsystem in subsystem_targets
                for file_target in subsystem.files
            }
        )
        subsystem_symbols = sorted(
            {
                str(getattr(entry_point, "function_name", "") or "")
                for subsystem in subsystem_targets
                for entry_point in subsystem.entry_points
                if getattr(entry_point, "function_name", "")
            }
        )
        self._emit_stage(
            "subsystem_hunt",
            "started",
            detail=f"{len(subsystem_targets)} subsystems",
            files=subsystem_files,
            symbols=subsystem_symbols,
        )
        if self.budget_usd:
            assert self._spend_ledger is not None
            per_subsystem_budget = (self._spend_ledger.remaining_usd or 0.0) / len(
                subsystem_targets
            )
            if self._subsystem_budget_usd:
                per_subsystem_budget = min(per_subsystem_budget, self._subsystem_budget_usd)
        else:
            per_subsystem_budget = self._subsystem_budget_usd or 100.0
        subsystem_runner = SubsystemHuntRunner(
            SubsystemHuntConfig(
                subsystems=subsystem_targets,
                repo_path=repo_path,
                sandbox_factory=self.sandbox_factory,
                llm=subsystem_llm,
                max_parallel=self._subsystem_max_parallel,
                budget_per_subsystem_usd=per_subsystem_budget,
                findings_pool=findings_pool,
                session_id_prefix=f"{self._session_id}-subsys",
                sandbox_manager=self._sandbox_manager,
                campaign_hint=self._campaign_hint,
                callgraph=callgraph,
                max_files_in_prompt=self._subsystem_max_files,
                trajectory_root=Path(self.output_dir) / self._session_id / "trajectories",
                instrumentation=self._instrumentation,
            )
        )
        try:
            subsystem_findings = await subsystem_runner.arun()
            result.findings.extend(subsystem_findings)
            result.potentials.extend(subsystem_runner.all_potentials)
            result.subsystems_hunted = len(subsystem_targets)
            result.subsystem_spent_usd = subsystem_runner.total_spent
            result.subsystem_status = (
                "budget_exhausted" if subsystem_runner.budget_exhausted else "completed"
            )
            if result.subsystem_status == "budget_exhausted":
                pipeline_status.record(
                    "subsystem_hunt",
                    StageOutcome.SKIPPED,
                    fallback_description="Budget exhausted; partial subsystem results retained",
                )
            else:
                pipeline_status.record_succeeded("subsystem_hunt")
            self._emit_stage(
                "subsystem_hunt",
                result.subsystem_status,
                findings_so_far=len(subsystem_findings),
                cost_usd=result.subsystem_spent_usd,
                files=subsystem_files,
                symbols=subsystem_symbols,
                finding_ids=[finding.id for finding in subsystem_findings],
            )
        except Exception as exc:
            result.subsystem_status = "degraded"
            logger.warning("Subsystem hunt failed", exc_info=True)
            pipeline_status.record_degraded(
                "subsystem_hunt",
                "Subsystem hunt failed; only per-file findings available",
            )
            self._emit_stage(
                "subsystem_hunt",
                "degraded",
                files=subsystem_files,
                symbols=subsystem_symbols,
                error={"type": type(exc).__name__, "message": str(exc)},
            )

    @tracer.chain(name="Preprocess")
    def _preprocess(self) -> PreprocessResult:
        # Callgraph, reachability, and taint run by default at standard/deep
        # depths. Semgrep is an external subprocess and remains explicitly
        # opt-in at every depth.
        options = {
            "tag_files": True,
            "build_callgraph": self.depth != "quick" and self._preprocessing,
            "propagate_reachability": self.depth != "quick" and self._preprocessing,
            "run_semgrep": self._enable_semgrep and self._preprocessing,
            "run_taint": self.depth != "quick" and self._preprocessing,
            "respect_gitignore": self._respect_gitignore,
            "subsystem_paths": sorted(self._subsystem_paths or []),
        }
        self._preprocess_restored = False
        self._preprocessor = Preprocessor(
            repo_url=self.repo_url,
            branch=self.branch,
            local_path=self.local_path,
            tag_files=options["tag_files"],
            build_callgraph=options["build_callgraph"],
            propagate_reachability=options["propagate_reachability"],
            run_semgrep=options["run_semgrep"],
            run_taint=options["run_taint"],
            respect_gitignore=self._respect_gitignore,
            subsystem_paths=self._subsystem_paths,
        )
        repo_path: str | None = None
        if self._target_files:
            repo_path = self._preprocessor.resolve_repository()
            self._target_metadata = self._inspect_target_files(repo_path)
            options.update(
                {
                    "target_files": list(self._target_files),
                    "target_window_lines": self._target_window_lines,
                    "target_fingerprints": [
                        {
                            "path": path,
                            "size_bytes": self._target_metadata[path]["size_bytes"],
                            "sha256": self._target_metadata[path]["sha256"],
                        }
                        for path in self._target_files
                    ],
                }
            )
        if self._checkpoint is not None and self._checkpoint.preprocess is not None:
            repo_path = repo_path or self._preprocessor.resolve_repository()
            restored = self._checkpoint.preprocess.restore(repo_path=repo_path, options=options)
            if restored is not None:
                self._preprocess_restored = True
                logger.info("Restored preprocess result from session %s", self._session_id)
                return restored
            if self._stop_after == "preprocess":
                logger.warning(
                    "Stale preprocess checkpoint does not match current options; re-running"
                )
                self._checkpoint.preprocess = None
            else:
                raise ValueError("preprocess checkpoint is invalid or incompatible with this run")

        result = self._preprocessor.run(repo_path=repo_path)
        preprocess_checkpoint = PreprocessCheckpoint.from_result(result, options=options)
        if self._checkpoint is None:
            self._checkpoint = SourceHuntCheckpoint(preprocess=preprocess_checkpoint)
        else:
            self._checkpoint.preprocess = preprocess_checkpoint
        self._dump_checkpoint()
        return result

    @tracer.chain(name="Rank")
    async def _rank(
        self,
        files: list[FileTarget],
        pipeline_status: PipelineStatus,
        stage_files: list[str],
    ) -> list[FileTarget]:
        """Rank files or restore the completed ranking stage from the checkpoint."""

        options = {
            "preprocessing": self._preprocessing,
        }
        self._rank_restored = False
        self._emit_stage("rank", "started", detail=f"{len(files)} files", files=stage_files)

        if self._checkpoint is not None and self._checkpoint.rank is not None:
            restored = self._checkpoint.rank.restore(files, options=options)
            if restored is None:
                raise ValueError("rank checkpoint is invalid or incompatible with this run")
            self._rank_restored = True
            pipeline_status.record_succeeded("ranker")
            self._emit_stage(
                "rank",
                "completed",
                detail=f"Restored {len(restored)} ranked files from checkpoint",
                files=stage_files,
            )
            logger.info("Restored rank result from session %s", self._session_id)
            return restored

        ranker_llm = self._get_native_client("ranker", self.ranker_llm, budget_stage="rank")
        if ranker_llm is not None and files:
            logger.info("Ranker starting on %d files", len(files))
            try:
                ranker_config = RankerConfig()
                if not self._preprocessing:
                    ranker_config.include_static_hints = False
                    ranker_config.include_imports_by = False
                if ranker_llm.provider_name in ("openai_resp", "openai_codex", "openai"):
                    ranker_config.chunk_size = 30
                    ranker_config.max_inflight_chunks = self.max_parallel
                    logger.info(
                        "Ranker tuned for %s backend: chunk_size=%d max_inflight_chunks=%d",
                        ranker_llm.provider_name,
                        ranker_config.chunk_size,
                        ranker_config.max_inflight_chunks,
                    )
                await Ranker(ranker_llm, ranker_config).arank(files)
                logger.info("Ranker completed")
                pipeline_status.record_succeeded("ranker")
                self._emit_stage(
                    "rank", "completed", detail=f"Ranked {len(files)} files", files=stage_files
                )
            except BudgetExceeded:
                logger.info("Ranker stopped because the run budget is exhausted")
                pipeline_status.record(
                    "ranker",
                    StageOutcome.SKIPPED,
                    fallback_description="Budget exhausted; remaining files use heuristic ranks",
                )
                self._emit_stage(
                    "rank", "budget_exhausted", detail="Using heuristic ranks", files=stage_files
                )
            except Exception:
                logger.warning("Ranker failed", exc_info=True)
                pipeline_status.record_degraded(
                    "ranker",
                    "All files assigned default priority scores (surface=3, influence=2)",
                )
                self._emit_stage(
                    "rank", "degraded", detail="Default priority scores used", files=stage_files
                )
        else:
            logger.info("Ranker skipped; no LLM available")
            pipeline_status.record_degraded(
                "ranker", "All files assigned default priority scores (surface=3, influence=2)"
            )
            self._emit_stage(
                "rank",
                "degraded",
                detail="No ranker model available; default priority scores used",
                files=stage_files,
            )

        # A partial or failed rank pass is still a completed stage once
        # every file has deterministic fallback scores.
        self._apply_rank_fallbacks(files)

        if self._checkpoint is None:
            raise RuntimeError("ranking requires a preprocessing checkpoint")
        self._checkpoint.rank = RankCheckpoint.from_result(files, options=options)
        self._dump_checkpoint()
        return files

    @staticmethod
    def _apply_rank_fallbacks(files: list[FileTarget]) -> None:
        """Ensure every file has deterministic scores when ranking is unavailable."""

        for target in files:
            target["surface"] = target.get("surface") or 3
            target["influence"] = target.get("influence") or 2
            target["reachability"] = target.get("reachability") or 3
            target["priority"] = target.get("priority") or (
                target["surface"] * 0.5 + target["influence"] * 0.2 + target["reachability"] * 0.3
            )

    def _ensure_sandbox_factory(self, repo_path: str, files: list[FileTarget]) -> None:
        if self.depth == "quick":
            return
        if self.sandbox_factory is not None:
            return
        if self._sandbox_manager is not None:
            self.sandbox_factory = self._sandbox_manager.spawn
            return

        languages = sorted(
            {
                str(ft.get("language", "")).lower()
                for ft in files
                if str(ft.get("language", "")).strip()
            }
        )
        logger.info(
            "Initializing HunterSandbox for %s languages=%s",
            repo_path,
            ",".join(languages) or "unknown",
        )
        use_deep = self._agent_mode == "deep"
        try:
            manager = HunterSandbox(
                repo_path=repo_path,
                languages=languages,
                deep_agent_mode=use_deep,
                default_cpus=self._sandbox_cpus,
            )
            image_tag = manager.build_image()
        except Exception as exc:
            logger.error(
                "HunterSandbox startup failed: %s",
                exc,
            )
            logger.debug("HunterSandbox initialization failed", exc_info=True)
            EventBus().emit_message(
                f"ERROR: sandbox startup failed ({exc}); aborting sourcehunt.",
                "error",
            )
            raise RuntimeError(f"HunterSandbox startup failed: {exc}") from exc

        self._sandbox_manager = manager
        cpu_limit = manager.default_cpu_limit
        available_cpus = manager.available_cpus
        logger.info(
            "HunterSandbox ready image=%s cpu_limit=%.2f available_cpus=%.2f",
            image_tag,
            cpu_limit,
            available_cpus,
        )
        aggregate_limit = cpu_limit * self.max_parallel
        if cpu_limit > 0 and aggregate_limit > available_cpus:
            logger.warning(
                "Sandbox CPU limits are per-container: max_parallel=%d x %.2f CPUs "
                "= %.2f, exceeding the detected %.2f CPUs. Lower --max-parallel or "
                "--sandbox-cpus to preserve aggregate host headroom.",
                self.max_parallel,
                cpu_limit,
                aggregate_limit,
                available_cpus,
            )
        gvisor_rt = self._gvisor_runtime
        if use_deep:
            self.sandbox_factory = lambda **kw: manager.spawn(
                writable_workspace=True,
                memory_mb=kw.pop("memory_mb", 16384),
                timeout_seconds=kw.pop("timeout_seconds", 30),
                runtime=kw.pop("runtime", gvisor_rt),
                **kw,
            )
        else:
            if gvisor_rt:
                self.sandbox_factory = lambda **kw: manager.spawn(
                    runtime=kw.pop("runtime", gvisor_rt),
                    **kw,
                )
            else:
                self.sandbox_factory = manager.spawn

    def _build_quick_result(
        self,
        start_time: float,
        repo_path: str,
        preprocess_result: PreprocessResult,
        files_ranked: int,
        pipeline_status: PipelineStatus | None = None,
    ) -> SourceHuntResult:
        """depth=quick exit — only static findings, no LLM hunters."""
        all_findings = self._merge_static_findings([], preprocess_result)
        target_files = [str(item.get("path") or "") for item in preprocess_result.file_targets]
        finding_files = [str(finding.file or "") for finding in all_findings]
        finding_symbols = self._finding_symbols(all_findings)
        finding_ids = [finding.id for finding in all_findings]
        self._emit_stage(
            "hunt",
            "skipped",
            detail="Quick depth performs static analysis only",
            files=target_files,
        )
        for stage in ("verify", "exploit"):
            self._emit_stage(
                stage,
                "skipped",
                findings_so_far=len(all_findings),
                detail="Quick depth performs static analysis only",
                files=finding_files,
                symbols=finding_symbols,
                finding_ids=finding_ids,
            )
        # Populate KG even for the quick path
        if self.enable_knowledge_graph and all_findings:
            try:
                self._populate_knowledge_graph_source(repo_path, all_findings)
            except Exception:
                logger.warning("Knowledge graph population failed", exc_info=True)
        run_status = "budget_exhausted" if self._budget_exhausted() else "completed"
        if run_status == "budget_exhausted" and pipeline_status is not None:
            pipeline_status.record(
                "budget",
                StageOutcome.SKIPPED,
                fallback_description="Dollar cap reached; partial results retained",
            )
        budget_summary = self._finalize_spend_ledger(run_status)
        self._emit_stage(
            "report",
            "started",
            findings_so_far=len(all_findings),
            files=finding_files,
            symbols=finding_symbols,
            finding_ids=finding_ids,
        )
        output_paths = self._write_report(
            repo_path=repo_path,
            findings=all_findings,
            verified=[],
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
            pipeline_status=pipeline_status,
            budget_summary=budget_summary,
        )
        report_status = "degraded" if self._last_reporting_error else "completed"
        self._emit_stage(
            "report",
            report_status,
            findings_so_far=len(all_findings),
            files=[str(finding.file or "") for finding in all_findings],
            symbols=self._finding_symbols(all_findings),
            finding_ids=[finding.id for finding in all_findings],
            error=self._last_reporting_error,
        )
        self._finalize_instrumentation(run_status)
        output_paths.update(
            {
                "instrumentation": str(self._instrumentation.summary_path),
                "instrumentation_events": str(self._instrumentation.events_path),
            }
        )
        duration = time.monotonic() - start_time
        return SourceHuntResult(
            exit_code=(
                0
                if self._stop_after
                else (3 if run_status == "budget_exhausted" else self._exit_code(all_findings))
            ),
            repo_url=self.repo_url,
            repo_path=repo_path,
            findings=all_findings,
            verified_findings=[],
            exploited_findings=[],
            files_ranked=files_ranked,
            files_hunted=0,
            duration_seconds=round(duration, 2),
            cost_usd=budget_summary["total_spent"],
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
            tokens_used=budget_summary["total_tokens"],
            output_paths=output_paths,
            checkpoint=(
                self._checkpoint.model_dump(mode="json") if self._checkpoint is not None else None
            ),
            session_id=self._session_id,
            pipeline_status=pipeline_status or PipelineStatus(),
            status=run_status,
            budget_usd=self.budget_usd,
        )

    def _finalize_result(
        self,
        *,
        start_time: float,
        repo_path: str,
        findings: list[Finding],
        verified: list[Finding],
        exploited: list[Finding],
        files_ranked: int,
        files_hunted: int,
        spent_per_tier: dict[str, float],
        band_stats: dict[str, Any] | None,
        findings_pool: Any,
        subsystems_hunted: int,
        subsystem_spent_usd: float,
        subsystem_status: str,
        pipeline_status: PipelineStatus,
        potentials: list[dict[str, Any]],
    ) -> SourceHuntResult:
        """Write final outputs and preserve the pipeline state accumulated so far."""
        finding_files = [str(finding.file or "") for finding in findings]
        finding_symbols = self._finding_symbols(findings)
        finding_ids = [finding.id for finding in findings]
        self._emit_stage(
            "report",
            "started",
            findings_so_far=len(findings),
            files=finding_files,
            symbols=finding_symbols,
            finding_ids=finding_ids,
        )
        assert self._spend_ledger is not None
        ledger_tier_spend = self._spend_ledger.spent_by("tier", stage="hunt")
        if ledger_tier_spend:
            spent_per_tier = {tier: ledger_tier_spend.get(tier, 0.0) for tier in ("A", "B", "C")}
        ledger_band_spend = self._spend_ledger.spent_by("band", stage="hunt")
        if band_stats is not None and ledger_band_spend:
            for band in ("fast", "standard", "deep"):
                band_stats[f"{band}_cost"] = ledger_band_spend.get(band, 0.0)
        ledger_subsystem_spend = self._spend_ledger.spent_by("stage").get("subsystem_hunt", 0.0)
        if ledger_subsystem_spend:
            subsystem_spent_usd = ledger_subsystem_spend

        run_status = (
            "incomplete"
            if self._target_plan_incomplete or self._verification_incomplete
            else (
                "budget_exhausted"
                if self._budget_exhausted() or subsystem_status == "budget_exhausted"
                else "completed"
            )
        )
        if run_status == "budget_exhausted":
            pipeline_status.record(
                "budget",
                StageOutcome.SKIPPED,
                fallback_description=(
                    "Dollar cap reached; partial results retained"
                    if self._budget_exhausted()
                    else "Subsystem hunt budget exhausted; partial results retained"
                ),
            )
        budget_summary = self._finalize_spend_ledger(run_status)
        pool_stats = findings_pool.pool_stats() if findings_pool is not None else None
        subsystem_stats = (
            {
                "subsystems_hunted": subsystems_hunted,
                "subsystem_spent_usd": subsystem_spent_usd,
            }
            if subsystems_hunted > 0
            else None
        )
        output_paths = self._write_report(
            repo_path=repo_path,
            findings=findings,
            verified=verified,
            spent_per_tier=spent_per_tier,
            band_stats=band_stats,
            pool_stats=pool_stats,
            subsystem_stats=subsystem_stats,
            pipeline_status=pipeline_status,
            budget_summary=budget_summary,
            potentials=potentials,
        )
        report_status = "degraded" if self._last_reporting_error else "completed"
        self._emit_stage(
            "report",
            report_status,
            findings_so_far=len(findings),
            cost_usd=budget_summary["total_spent"],
            files=finding_files,
            symbols=finding_symbols,
            finding_ids=finding_ids,
            error=self._last_reporting_error,
        )
        self._finalize_instrumentation(run_status)
        output_paths.update(
            {
                "instrumentation": str(self._instrumentation.summary_path),
                "instrumentation_events": str(self._instrumentation.events_path),
            }
        )

        return SourceHuntResult(
            exit_code=(
                3
                if run_status in {"budget_exhausted", "incomplete"}
                else (0 if self._stop_after else self._exit_code(findings if self.no_verify else verified))
            ),
            repo_url=self.repo_url,
            repo_path=repo_path,
            findings=findings,
            verified_findings=verified,
            exploited_findings=exploited,
            files_ranked=files_ranked,
            files_hunted=files_hunted,
            duration_seconds=round(time.monotonic() - start_time, 2),
            cost_usd=budget_summary["total_spent"],
            spent_per_tier=spent_per_tier,
            tokens_used=budget_summary["total_tokens"],
            output_paths=output_paths,
            checkpoint=(
                self._checkpoint.model_dump(mode="json") if self._checkpoint is not None else None
            ),
            session_id=self._session_id,
            subsystems_hunted=subsystems_hunted,
            subsystem_spent_usd=subsystem_spent_usd,
            potentials=potentials,
            pipeline_status=pipeline_status,
            status=run_status,
            budget_usd=self.budget_usd,
        )

    def _merge_static_findings(
        self,
        existing: list[Finding],
        preprocess_result: PreprocessResult,
    ) -> list[Finding]:
        """Promote SourceAnalyzer static findings into the Finding shape.

        These get evidence_level="static_corroboration" because they're
        regex/AST hits, not just suspicion.
        """
        out = list(existing)
        for sf in preprocess_result.static_findings:
            relative_file = Path(
                os.path.relpath(sf.file_path, preprocess_result.repo_path)
            ).as_posix()
            stable_finding_id = stable_run_id(
                "static",
                {
                    "run_id": getattr(self, "_session_id", "unscoped"),
                    "file": relative_file,
                    "line": sf.line_number,
                    "type": sf.finding_type,
                    "cwe": sf.cwe,
                    "description": sf.description,
                },
            )
            out.append(
                Finding(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    file=relative_file,
                    line_number=sf.line_number,
                    finding_type=sf.finding_type,
                    cwe=sf.cwe,
                    severity=sf.severity,  # type: ignore[arg-type]
                    confidence=sf.confidence,  # type: ignore[arg-type]
                    description=sf.description,
                    code_snippet=sf.code_snippet,
                    evidence_level="static_corroboration",
                    discovered_by="source_analyzer",
                    extra={"stable_finding_id": stable_finding_id},
                )
            )
        return out

    @staticmethod
    def _finding_set_digest(findings: list[Finding]) -> str:
        """Bind downstream checkpoints to their exact ordered finding input."""
        portable = [
            dict(finding) if isinstance(finding, dict) else asdict(finding)
            for finding in findings
        ]
        encoded = json.dumps(
            portable,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _finding_symbols(findings: list[Finding]) -> list[str]:
        symbols: set[str] = set()
        for finding in findings:
            trace = finding.vulnerability_trace or {}
            for step in trace.get("steps", []):
                function = (
                    step.get("function", "")
                    if isinstance(step, dict)
                    else getattr(step, "function", "")
                )
                if function:
                    symbols.add(str(function))
        return sorted(symbols)

    def _exit_code(self, findings: list[Finding]) -> int:
        severities = {
            (f.get("severity_verified") or f.get("severity") or "info").lower() for f in findings
        }
        if severities & {"critical", "high"}:
            return 2
        if "medium" in severities:
            return 1
        return 0

    # --- LLM resolution -----------------------------------------------------

    def _get_native_client(
        self,
        task: str,
        override: AsyncLLMClient | None,
        *,
        budget_stage: str | None = None,
    ) -> AsyncLLMClient | None:
        """Return a native async LLM client for sourcehunt tasks.

        When a provider_manager is injected (the normal CLI path), it is
        the single source of truth — failures propagate instead of
        silently falling through to a different provider/model.
        """
        client: AsyncLLMClient | None = None
        if override is not None:
            client = override
        elif self.provider_manager is not None:
            client = self.provider_manager.get_native_client(task)
        elif self.model_override:
            client = self._build_native_from_model_string(self.model_override)
        else:
            try:
                endpoint = resolve_llm_endpoint()
                if endpoint.api_key:
                    client = ProviderManager.for_endpoint(endpoint).get_native_client(task)
            except Exception:
                logger.debug(
                    "Default endpoint native resolution failed for task=%s",
                    task,
                    exc_info=True,
                )

        if client is None or self._spend_ledger is None:
            self._remember_model_role(task, client)
            return client
        # AsyncMock/MagicMock overrides are test seams rather than real
        # transports. Production native clients expose with_spend_ledger.
        if not isinstance(client, AsyncLLMClient):
            self._remember_model_role(task, client)
            return client
        stage = budget_stage or task
        key = (id(client), stage)
        bound = self._metered_clients.get(key)
        if bound is None:
            bound = client.with_spend_ledger(self._spend_ledger, stage=stage)
            self._metered_clients[key] = bound
        self._remember_model_role(task, bound)
        return bound

    def _remember_model_role(self, task: str, client: Any) -> None:
        if client is None:
            return
        model = getattr(client, "model_name", None)
        provider = getattr(client, "provider_name", None)
        if model or provider:
            self._resolved_model_roles[task] = {
                "model": str(model or "unknown"),
                "provider": str(provider or "unknown"),
            }

    def _build_native_from_model_string(self, model: str) -> AsyncLLMClient | None:
        try:
            endpoint = resolve_llm_endpoint(cli_model=model)
            return ProviderManager.for_endpoint(endpoint).get_native_client("default")
        except Exception:
            logger.warning("Failed to build native client from model string", exc_info=True)
            return None

    # --- Reporting ----------------------------------------------------------

    def _record_reporting_failure(
        self,
        exc: Exception,
        findings: list[Finding],
    ) -> None:
        """Retain reporting failures without allowing telemetry to mask them."""

        try:
            self._instrumentation.reporting_failure(
                str(exc),
                error_type=type(exc).__name__,
                finding_ids=[finding.id for finding in findings],
            )
        except Exception:
            logger.debug("Could not persist sourcehunt reporting failure", exc_info=True)

    def _write_report(
        self,
        repo_path: str,
        findings: list[Finding],
        verified: list[Finding],
        spent_per_tier: dict,
        band_stats: dict | None = None,
        pool_stats: dict | None = None,
        subsystem_stats: dict | None = None,
        pipeline_status: PipelineStatus | None = None,
        budget_summary: dict[str, Any] | None = None,
        potentials: list[dict] | None = None,
    ) -> dict[str, str]:
        """Write SARIF / markdown / JSON outputs to the output directory.

        v0.1 implementation lives in reporter.py — but that module isn't built
        yet at the time this runner is being constructed. Keep the call here
        and let reporter.py register itself lazily.
        """
        try:
            from .reporter import write_sourcehunt_report
        except ImportError as exc:
            logger.warning("reporter.py not yet available; skipping report")
            self._last_reporting_error = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            self._record_reporting_failure(exc, findings)
            return {}
        try:
            duration_seconds = (
                time.monotonic() - self._run_started_monotonic
                if self._run_started_monotonic is not None
                else None
            )
            run_metadata = build_run_metadata(
                repo_path=repo_path,
                configuration={
                    "branch": self.branch,
                    "depth": self.depth,
                    "flow": self._flow,
                    "budget_usd": self.budget_usd,
                    "max_parallel": self.max_parallel,
                    "output_formats": list(self.output_formats),
                    "verify": not self.no_verify,
                    "exploit": not self.no_exploit,
                    "adversarial_verifier": self.adversarial_verifier,
                    "validator_mode": self.validator_mode,
                    "patch_oracle": self.enable_patch_oracle,
                    "auto_patch": self.enable_auto_patch,
                    "variant_loop": self.enable_variant_loop,
                    "mechanism_memory": self.enable_mechanism_memory,
                    "sandbox_runtime": self._gvisor_runtime or "default",
                },
                model_roles=dict(sorted(self._resolved_model_roles.items())),
                started_at=self._run_started_at,
                duration_seconds=duration_seconds,
            )
            return write_sourcehunt_report(
                output_dir=self.output_dir,
                session_id=self._session_id,
                repo_url=self.repo_url,
                findings=findings,
                verified_findings=verified,
                spent_per_tier=spent_per_tier,
                formats=self.output_formats,
                band_stats=band_stats,
                pool_stats=pool_stats,
                subsystem_stats=subsystem_stats,
                pipeline_status=pipeline_status,
                budget_summary=budget_summary,
                run_metadata=run_metadata,
                potentials=potentials,
                trace_id=getattr(self, "_otel_trace_id", None),
                run_started_at=getattr(self, "_run_started_at", None),
                run_ended_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            logger.warning("Reporter failed", exc_info=True)
            self._last_reporting_error = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            self._record_reporting_failure(exc, findings)
            return {}
