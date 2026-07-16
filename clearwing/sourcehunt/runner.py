"""SourceHuntRunner — the public orchestrator for the sourcehunt pipeline.

Analog of clearwing/runners/cicd/runner.py::CICDRunner, but for source-code
hunting instead of network targets.

Pipeline:
    preprocess → sandbox build → rank → tiered hunt → verify → exploit → report
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.core.event_payloads import SourcehuntStagePayload
from clearwing.core.events import EventBus
from clearwing.llm.budget import BudgetExceeded, SpendLedger
from clearwing.llm.native import AsyncLLMClient
from clearwing.providers import (
    ProviderManager,
    resolve_llm_endpoint,
)

from ..sandbox.hunter_sandbox import HunterSandbox
from .config import SourceHuntConfig
from .disclosure import (
    DisclosureGenerator,
)
from .disclosure import (
    write_bundle as write_disclosure_bundle,
)
from .exploiter import AgenticExploiter, Exploiter, apply_exploiter_result
from .harness_generator import HarnessGenerator, HarnessGeneratorConfig, SeededCrash
from .instrumentation import SourceHuntInstrumentation, stable_run_id
from .mechanism_memory import (
    MechanismExtractor,
    MechanismStore,
    format_mechanisms_for_prompt,
)
from .patcher import AutoPatcher, apply_patch_attempt
from .poc_runner import build_rerun_poc_callback
from .pool import HunterPool, HuntPoolConfig, TierBudget
from .preprocessor import Preprocessor, PreprocessResult
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
from .variant_loop import (
    VariantLoop,
    VariantPatternGenerator,
)
from .verifier import Verifier, apply_verifier_result

logger = logging.getLogger(__name__)


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
    session_id: str = ""
    subsystems_hunted: int = 0
    subsystem_spent_usd: float = 0.0
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
        enable_behavior_monitor: bool = True,
        enable_artifact_store: bool = False,
        gvisor_runtime: str | None = None,
        preprocessing: bool = True,
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

        if not repo_url:
            raise ValueError(
                "repo_url is required — pass it directly or via "
                "config=SourceHuntConfig(target=TargetConfig(repo_url=...))"
            )
        if sandbox_cpus is not None and (not math.isfinite(sandbox_cpus) or sandbox_cpus < 0):
            raise ValueError("sandbox_cpus must be a finite number greater than or equal to 0")
        if flow not in {"legacy", "proof"}:
            raise ValueError("flow must be 'legacy' or 'proof'")
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
        self._session_id = parent_session_id or f"sh-{uuid.uuid4().hex[:8]}"
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
        self._no_rank = no_rank
        self._subsystem_budget_usd = subsystem_budget_usd
        self._subsystem_max_parallel = subsystem_max_parallel
        self._injected_findings_pool = None
        self._injected_historical_db = None
        self._enable_behavior_monitor = enable_behavior_monitor
        self._enable_artifact_store = enable_artifact_store
        self._sandbox_cpus = None if sandbox_cpus is None else float(sandbox_cpus)
        self._gvisor_runtime = self._check_runtime_available(gvisor_runtime)
        self._preprocessing = preprocessing
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
            json.dump(combined, stream, indent=2, sort_keys=True, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest_path)
        proof_result.output_paths.update(outputs)

    async def arun(self) -> SourceHuntResult:
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
            preprocess_result = self._preprocess()
            repo_path = preprocess_result.repo_path
            files = preprocess_result.file_targets
            files_ranked = len(files)
            logger.info("Preprocessor enumerated %d files", files_ranked)
            stage_files = [str(file_target.get("path") or "") for file_target in files]
            self._emit_stage(
                "preprocess",
                "completed",
                detail=f"Enumerated {files_ranked} files",
                files=stage_files,
            )
            self._ensure_sandbox_factory(repo_path, files)

            # 2. Rank — unless depth=quick AND no LLM available, or --no-rank
            ranker_llm = (
                None
                if self._no_rank
                else self._get_native_client(
                    "ranker",
                    self.ranker_llm,
                    budget_stage="rank",
                )
            )
            self._emit_stage(
                "rank",
                "started",
                detail=f"{len(files)} files",
                files=stage_files,
            )
            if self._no_rank:
                logger.info("Ranker skipped (--no-rank); assigning default priority scores")
                for ft in files:
                    ft["surface"] = ft.get("surface") or 3
                    ft["influence"] = ft.get("influence") or 2
                    ft["reachability"] = ft.get("reachability") or 3
                    ft["priority"] = (
                        ft["surface"] * 0.5 + ft["influence"] * 0.2 + ft["reachability"] * 0.3
                    )
                pipeline_status.record_degraded(
                    "ranker",
                    "All files assigned default priority scores (--no-rank)",
                )
                self._emit_stage(
                    "rank",
                    "degraded",
                    detail="Skipped (--no-rank)",
                    files=stage_files,
                )
            elif ranker_llm is not None and files:
                logger.info("Ranker starting on %d files", len(files))
                try:
                    ranker_config = RankerConfig()
                    if not self._preprocessing:
                        ranker_config.include_static_hints = False
                        ranker_config.include_imports_by = False
                    if ranker_llm.provider_name in ("openai_resp", "openai_codex"):
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
                        "rank",
                        "completed",
                        detail=f"Ranked {len(files)} files",
                        files=stage_files,
                    )
                except BudgetExceeded:
                    logger.info("Ranker stopped because the run budget is exhausted")
                    pipeline_status.record(
                        "ranker",
                        StageOutcome.SKIPPED,
                        fallback_description="Budget exhausted; remaining files use heuristic ranks",
                    )
                    self._emit_stage(
                        "rank",
                        "budget_exhausted",
                        detail="Using heuristic ranks",
                        files=stage_files,
                    )
                except Exception:
                    logger.warning("Ranker failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "ranker",
                        "All files assigned default priority scores (surface=3, influence=2)",
                    )
                    self._emit_stage(
                        "rank",
                        "degraded",
                        detail="Default priority scores used",
                        files=stage_files,
                    )
            else:
                logger.info("Ranker skipped; no LLM available")
                pipeline_status.record_degraded(
                    "ranker",
                    "All files assigned default priority scores (surface=3, influence=2)",
                )
                # Fallback: assign reasonable defaults so tier assignment still works
                for ft in files:
                    ft["surface"] = ft.get("surface") or 3
                    ft["influence"] = ft.get("influence") or 2
                    ft["reachability"] = ft.get("reachability") or 3
                    ft["priority"] = (
                        ft["surface"] * 0.5 + ft["influence"] * 0.2 + ft["reachability"] * 0.3
                    )
                self._emit_stage(
                    "rank",
                    "degraded",
                    detail="No ranker model available; default priority scores used",
                    files=stage_files,
                )

            # Ensure a partial/failed rank pass still leaves every file
            # schedulable by the deterministic fallback.
            for ft in files:
                ft["surface"] = ft.get("surface") or 3
                ft["influence"] = ft.get("influence") or 2
                ft["reachability"] = ft.get("reachability") or 3
                ft["priority"] = ft.get("priority") or (
                    ft["surface"] * 0.5 + ft["influence"] * 0.2 + ft["reachability"] * 0.3
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
            hunter_llm = self._get_native_client(
                "hunter",
                self.hunter_llm,
                budget_stage="hunt",
            )
            all_findings: list[Finding] = []
            files_hunted = 0
            spent_per_tier: dict[str, float] = {"A": 0.0, "B": 0.0, "C": 0.0}
            band_stats: dict | None = None
            hunt_symbols = sorted(
                {
                    str(getattr(entry_point, "function_name", "") or "")
                    for entry_points in entry_points_by_file.values()
                    for entry_point in entry_points
                    if getattr(entry_point, "function_name", "")
                }
            )

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
                logger.info("HunterPool starting on %d files", len(files))
                pool = HunterPool(
                    HuntPoolConfig(
                        files=files,
                        repo_path=repo_path,
                        sandbox_factory=self.sandbox_factory,
                        sandbox_manager=self._sandbox_manager,
                        hunter_factory=None,
                        llm=hunter_llm,
                        max_parallel=self.max_parallel,
                        budget_usd=self.budget_usd,
                        tier_budget=self.tier_budget,
                        session_id_prefix=self._session_id,
                        seeded_crashes_by_file=seeded_by_file,
                        semgrep_hints_by_file=semgrep_hints_by_file,
                        agent_mode=self._agent_mode,
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
                        trajectory_root=(Path(self.output_dir) / self._session_id / "trajectories"),
                        instrumentation=self._instrumentation,
                    )
                )
                try:
                    all_findings = await pool.arun()
                    logger.info("HunterPool completed with %d findings", len(all_findings))
                    if pool.budget_exhausted or self._budget_exhausted():
                        pipeline_status.record(
                            "hunter_pool",
                            StageOutcome.SKIPPED,
                            fallback_description="Budget exhausted; partial hunter results retained",
                        )
                        self._emit_stage(
                            "hunt",
                            "budget_exhausted",
                            findings_so_far=len(all_findings),
                            cost_usd=pool.total_spent,
                            detail=f"{len(all_findings)} partial findings",
                            files=[str(finding.file or "") for finding in all_findings],
                            symbols=self._finding_symbols(all_findings),
                            finding_ids=[finding.id for finding in all_findings],
                        )
                    else:
                        pipeline_status.record_succeeded("hunter_pool")
                        self._emit_stage(
                            "hunt",
                            "completed",
                            findings_so_far=len(all_findings),
                            cost_usd=pool.total_spent,
                            detail=f"{len(all_findings)} findings",
                            files=[str(finding.file or "") for finding in all_findings],
                            symbols=self._finding_symbols(all_findings),
                            finding_ids=[finding.id for finding in all_findings],
                        )
                except BudgetExceeded:
                    logger.info("HunterPool stopped because the run budget is exhausted")
                    pipeline_status.record(
                        "hunter_pool",
                        StageOutcome.SKIPPED,
                        fallback_description="Budget exhausted; partial hunter results retained",
                    )
                    self._emit_stage(
                        "hunt",
                        "budget_exhausted",
                        findings_so_far=len(all_findings),
                        files=stage_files,
                        symbols=hunt_symbols,
                        finding_ids=[finding.id for finding in all_findings],
                    )
                except Exception as exc:
                    logger.warning("HunterPool run failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "hunter_pool",
                        "Hunter phase produced no findings due to error",
                    )
                    self._emit_stage(
                        "hunt",
                        "degraded",
                        findings_so_far=len(all_findings),
                        files=stage_files,
                        symbols=hunt_symbols,
                        finding_ids=[finding.id for finding in all_findings],
                        error={"type": type(exc).__name__, "message": str(exc)},
                    )
                spent_per_tier = pool.spent_per_tier
                band_stats = {
                    "fast_runs": pool.runs_per_band.get("fast", 0),
                    "fast_cost": pool.spent_per_band.get("fast", 0.0),
                    "standard_runs": pool.runs_per_band.get("standard", 0),
                    "standard_cost": pool.spent_per_band.get("standard", 0.0),
                    "deep_runs": pool.runs_per_band.get("deep", 0),
                    "deep_cost": pool.spent_per_band.get("deep", 0.0),
                    "promotions": pool.promotion_counts,
                }
                files_hunted = pool.completed_target_count
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

            # Promote static findings into the all_findings list so depth=quick
            # output is still useful when no hunter llm is available
            all_findings = self._merge_static_findings(all_findings, preprocess_result)

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

            # 3.7. Subsystem hunt (spec 006)
            subsystems_hunted = 0
            subsystem_spent = 0.0
            if self._enable_subsystem_hunt and hunter_llm is not None and self._budget_exhausted():
                logger.info(
                    "Subsystem hunt skipped: budget $%.2f exhausted ($%.2f spent)",
                    self.budget_usd,
                    self._run_spent_usd(),
                )
            elif self._enable_subsystem_hunt and hunter_llm is not None:
                from .subsystem import (
                    SubsystemHuntConfig,
                    identify_subsystems_auto,
                    subsystem_from_path,
                )
                from .subsystem import (
                    SubsystemHuntRunner as SubsysRunner,
                )

                subsystem_llm = self._get_native_client(
                    "hunter",
                    self.hunter_llm,
                    budget_stage="subsystem_hunt",
                )

                subsystem_targets: list = []
                if self._subsystem_paths:
                    for sp in self._subsystem_paths:
                        try:
                            st = subsystem_from_path(
                                sp,
                                files,
                                callgraph=preprocess_result.callgraph,
                                entry_points_by_file=entry_points_by_file,
                            )
                            subsystem_targets.append(st)
                        except ValueError:
                            logger.warning("No files match subsystem path: %s", sp)
                else:
                    subsystem_targets = identify_subsystems_auto(
                        files,
                        callgraph=preprocess_result.callgraph,
                        entry_points_by_file=entry_points_by_file,
                    )

                if subsystem_targets:
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
                    logger.info(
                        "Subsystem hunt: %d targets identified",
                        len(subsystem_targets),
                    )
                    for st in subsystem_targets:
                        logger.info(
                            "  %s (%d files, priority=%.2f)",
                            st.name,
                            len(st.files),
                            st.priority,
                        )
                    # Bound the whole subsystem phase to whatever --budget is
                    # left, split evenly across targets, so 3 subsystems can't
                    # each burn the internal $100 default ($300 total) past the
                    # budget the user set. Falls back to the explicit override /
                    # $100 default only when no --budget is in play.
                    if self.budget_usd:
                        assert self._spend_ledger is not None
                        remaining = self._spend_ledger.remaining_usd or 0.0
                        per_subsystem_budget = remaining / len(subsystem_targets)
                        if self._subsystem_budget_usd:
                            per_subsystem_budget = min(
                                per_subsystem_budget,
                                self._subsystem_budget_usd,
                            )
                    else:
                        per_subsystem_budget = self._subsystem_budget_usd or 100.0
                    subsys_runner = SubsysRunner(
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
                            callgraph=preprocess_result.callgraph,
                            trajectory_root=(
                                Path(self.output_dir) / self._session_id / "trajectories"
                            ),
                            instrumentation=self._instrumentation,
                        )
                    )
                    try:
                        subsys_findings = await subsys_runner.arun()
                        all_findings.extend(subsys_findings)
                        subsystems_hunted = len(subsystem_targets)
                        subsystem_spent = subsys_runner.total_spent
                        logger.info(
                            "Subsystem hunt completed: %d findings, $%.4f spent",
                            len(subsys_findings),
                            subsystem_spent,
                        )
                        self._emit_stage(
                            "subsystem_hunt",
                            "completed",
                            findings_so_far=len(subsys_findings),
                            cost_usd=subsystem_spent,
                            files=subsystem_files,
                            symbols=subsystem_symbols,
                            finding_ids=[finding.id for finding in subsys_findings],
                        )
                    except Exception as exc:
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

            # 4. Verify (unless --no-verify)
            verified: list[Finding] = []
            rejected: list[Finding] = []
            verify_status = "completed"
            self._emit_stage(
                "verify",
                "started",
                findings_so_far=len(all_findings),
                detail=f"{len(all_findings)} findings to verify",
                files=[str(finding.file or "") for finding in all_findings],
                symbols=self._finding_symbols(all_findings),
                finding_ids=[finding.id for finding in all_findings],
            )
            if not self.no_verify:
                if self._budget_exhausted():
                    verify_status = "budget_exhausted"
                    pipeline_status.record(
                        "verifier",
                        StageOutcome.SKIPPED,
                        fallback_description="Budget exhausted; findings remain unverified",
                    )
                else:
                    verifier_llm = self._get_native_client(
                        "verifier",
                        self.verifier_llm,
                        budget_stage="verify",
                    )
                    if verifier_llm is not None:
                        if self.validator_mode == "v2":
                            verified, rejected = await self._verify_v2(
                                verifier_llm,
                                all_findings,
                                repo_path,
                            )
                        else:
                            verified = await self._verify_v1(
                                verifier_llm,
                                all_findings,
                                repo_path,
                            )
                    else:
                        verify_status = "degraded"
                        for f in all_findings:
                            f["verified"] = True
                        verified = all_findings
                        pipeline_status.record_degraded(
                            "verifier",
                            "Findings auto-verified without independent review",
                        )
            else:
                for finding in all_findings:
                    finding["verified"] = False
                verified = []
                pipeline_status.record(
                    "verifier",
                    StageOutcome.SKIPPED,
                    fallback_description="Verification skipped (--no-verify)",
                )

            verify_detail = (
                "Verification skipped (--no-verify)"
                if self.no_verify
                else f"{len(verified)} verified, {len(rejected)} rejected"
            )
            self._emit_stage(
                "verify",
                verify_status,
                findings_so_far=len(all_findings),
                detail=verify_detail,
                files=[str(finding.file or "") for finding in all_findings],
                symbols=self._finding_symbols(all_findings),
                finding_ids=[finding.id for finding in all_findings],
            )
            if rejected:
                self._write_rejected_findings(rejected)

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

            # 5. Exploit-triage (unless --no-exploit) — gated on evidence_level
            self._emit_stage(
                "exploit",
                "started",
                findings_so_far=len(all_findings),
                files=[str(finding.file or "") for finding in verified],
                symbols=self._finding_symbols(verified),
                finding_ids=[finding.id for finding in verified],
            )
            exploited: list[Finding] = []
            # 5.5 v0.3: Auto-patch (opt-in) — runs after exploiter on verified
            #          critical/high findings with root_cause_explained evidence.
            patched: list[Finding] = []
            if not self.no_exploit and not self._budget_exhausted():
                exploiter_llm = self._get_native_client(
                    "sourcehunt_exploit",
                    self.exploiter_llm,
                    budget_stage="exploit",
                )
                if exploiter_llm is not None:
                    eligible = filter_by_evidence(verified, "crash_reproduced")
                    has_sandbox = (
                        self._sandbox_manager is not None or self.sandbox_factory is not None
                    )
                    if eligible and has_sandbox:
                        agentic = AgenticExploiter(
                            llm=exploiter_llm,
                            sandbox_manager=self._sandbox_manager,
                            sandbox_factory=self.sandbox_factory,
                            findings_pool=findings_pool,
                            budget_band=self._exploit_budget_band,
                            output_dir=str(self._ensure_output_dir_layout()),
                            project_name=(
                                self.repo_url.split("/")[-1] if self.repo_url else "target"
                            ),
                        )
                        for finding in eligible:
                            if self._budget_exhausted():
                                logger.info(
                                    "Exploit phase halted: budget $%.2f exhausted ($%.2f spent)",
                                    self.budget_usd,
                                    self._run_spent_usd(),
                                )
                                break
                            try:
                                exploit_result = await agentic.aattempt(finding)
                                apply_exploiter_result(finding, exploit_result)
                                if exploit_result.success:
                                    exploited.append(finding)
                                if exploit_result.partial and findings_pool is not None:
                                    finding["primitive_type"] = (
                                        exploit_result.primitive_type
                                        or finding.get("primitive_type", "")
                                    )
                                    await findings_pool.add(finding)
                            except BudgetExceeded:
                                logger.info("Exploit generation stopped at the run budget")
                                break
                            except Exception:
                                logger.warning(
                                    "Agentic exploiter failed for %s",
                                    finding.get("id"),
                                    exc_info=True,
                                )
                    elif eligible:
                        e = Exploiter(exploiter_llm)
                        for finding in eligible:
                            try:
                                exploit_result = await e.aattempt(finding)
                                apply_exploiter_result(finding, exploit_result)
                                if exploit_result.success:
                                    exploited.append(finding)
                            except BudgetExceeded:
                                logger.info("Exploit triage stopped at the run budget")
                                break
                            except Exception:
                                logger.warning("Exploiter failed", exc_info=True)

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

            # 6. Report
            self._emit_stage(
                "report",
                "started",
                findings_so_far=len(all_findings),
                files=[str(finding.file or "") for finding in all_findings],
                symbols=self._finding_symbols(all_findings),
                finding_ids=[finding.id for finding in all_findings],
            )
            assert self._spend_ledger is not None
            ledger_tier_spend = self._spend_ledger.spent_by("tier", stage="hunt")
            if ledger_tier_spend:
                spent_per_tier = {
                    tier: ledger_tier_spend.get(tier, 0.0) for tier in ("A", "B", "C")
                }
            ledger_band_spend = self._spend_ledger.spent_by("band", stage="hunt")
            if band_stats is not None and ledger_band_spend:
                for band in ("fast", "standard", "deep"):
                    band_stats[f"{band}_cost"] = ledger_band_spend.get(band, 0.0)
            ledger_subsystem_spend = self._spend_ledger.spent_by("stage").get("subsystem_hunt", 0.0)
            if ledger_subsystem_spend:
                subsystem_spent = ledger_subsystem_spend

            run_status = "budget_exhausted" if self._budget_exhausted() else "completed"
            if run_status == "budget_exhausted":
                pipeline_status.record(
                    "budget",
                    StageOutcome.SKIPPED,
                    fallback_description="Dollar cap reached; partial results retained",
                )
            budget_summary = self._finalize_spend_ledger(run_status)
            _pool_stats = findings_pool.pool_stats() if findings_pool is not None else None
            _subsystem_stats = (
                {"subsystems_hunted": subsystems_hunted, "subsystem_spent_usd": subsystem_spent}
                if subsystems_hunted > 0
                else None
            )
            output_paths = self._write_report(
                findings=all_findings,
                verified=verified,
                spent_per_tier=spent_per_tier,
                band_stats=band_stats,
                pool_stats=_pool_stats,
                subsystem_stats=_subsystem_stats,
                pipeline_status=pipeline_status,
                budget_summary=budget_summary,
            )

            report_status = "degraded" if self._last_reporting_error else "completed"
            self._emit_stage(
                "report",
                report_status,
                findings_so_far=len(all_findings),
                cost_usd=budget_summary["total_spent"],
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
            exit_findings = all_findings if self.no_verify else verified
            return SourceHuntResult(
                exit_code=(
                    3 if run_status == "budget_exhausted" else self._exit_code(exit_findings)
                ),
                repo_url=self.repo_url,
                repo_path=repo_path,
                findings=all_findings,
                verified_findings=verified,
                exploited_findings=exploited,
                files_ranked=files_ranked,
                files_hunted=files_hunted,
                duration_seconds=round(duration, 2),
                cost_usd=budget_summary["total_spent"],
                spent_per_tier=spent_per_tier,
                tokens_used=budget_summary["total_tokens"],
                output_paths=output_paths,
                session_id=self._session_id,
                subsystems_hunted=subsystems_hunted,
                subsystem_spent_usd=subsystem_spent,
                pipeline_status=pipeline_status,
                status=run_status,
                budget_usd=self.budget_usd,
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
            try:
                result = await v.averify(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                )
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
                break
            except Exception:
                logger.warning(
                    "Verifier failed for %s",
                    finding.get("id"),
                    exc_info=True,
                )
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
            try:
                discoverer_sev = finding.get("severity")
                verdict = await val.avalidate(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                )
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
                break
            except Exception:
                logger.warning(
                    "Validator failed for %s",
                    finding.get("id"),
                    exc_info=True,
                )
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
                    f.write(_json.dumps(finding, default=str) + "\n")
            logger.info("Wrote %d rejected findings to %s", len(rejected), path)
        except OSError:
            logger.warning("Failed to write rejected findings", exc_info=True)

    def _load_file_content(self, repo_path: str, finding: Finding) -> str:
        """Read the file referenced by a finding. Used by the patch oracle."""
        rel = finding.get("file", "")
        if not rel:
            return ""
        abs_path = os.path.join(repo_path, rel)
        try:
            with open(abs_path, encoding="utf-8", errors="replace") as f:
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

    def _preprocess(self) -> PreprocessResult:
        # v0.2: enable callgraph + reachability + Semgrep by default at
        # standard/deep depths. Quick depth stays cheap — just enumerate
        # and tag files.
        pp = Preprocessor(
            repo_url=self.repo_url,
            branch=self.branch,
            local_path=self.local_path,
            tag_files=True,
            build_callgraph=(self.depth != "quick" and self._preprocessing),
            propagate_reachability=(self.depth != "quick" and self._preprocessing),
            run_semgrep=(self.depth != "quick" and self._preprocessing),
            run_taint=(self.depth != "quick" and self._preprocessing),
            respect_gitignore=self._respect_gitignore,
        )
        return pp.run()

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
            logger.warning(
                "HunterSandbox unavailable (%s); falling back to host mode. "
                "Start Docker to enable sanitizer-backed containers.",
                exc,
            )
            logger.debug("HunterSandbox initialization failed", exc_info=True)
            return

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
        self._sandbox_manager = manager
        gvisor_rt = self._gvisor_runtime
        if use_deep:
            self.sandbox_factory = lambda **kw: manager.spawn(
                writable_workspace=True,
                memory_mb=kw.pop("memory_mb", 16384),
                timeout_seconds=kw.pop("timeout_seconds", 600),
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
            exit_code=(3 if run_status == "budget_exhausted" else self._exit_code(all_findings)),
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
            session_id=self._session_id,
            pipeline_status=pipeline_status or PipelineStatus(),
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
            return client
        # AsyncMock/MagicMock overrides are test seams rather than real
        # transports. Production native clients expose with_spend_ledger.
        if not isinstance(client, AsyncLLMClient):
            return client
        stage = budget_stage or task
        key = (id(client), stage)
        bound = self._metered_clients.get(key)
        if bound is None:
            bound = client.with_spend_ledger(self._spend_ledger, stage=stage)
            self._metered_clients[key] = bound
        return bound

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
        findings: list[Finding],
        verified: list[Finding],
        spent_per_tier: dict,
        band_stats: dict | None = None,
        pool_stats: dict | None = None,
        subsystem_stats: dict | None = None,
        pipeline_status: PipelineStatus | None = None,
        budget_summary: dict[str, Any] | None = None,
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
            )
        except Exception as exc:
            logger.warning("Reporter failed", exc_info=True)
            self._last_reporting_error = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            self._record_reporting_failure(exc, findings)
            return {}
