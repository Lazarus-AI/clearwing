"""Configuration dataclasses for the sourcehunt pipeline.

Groups the 60+ constructor parameters of SourceHuntRunner into cohesive,
frozen dataclasses. This is the first step of Task 1 (runner decomposition);
the runner constructor accepts an optional ``SourceHuntConfig`` alongside the
legacy keyword arguments for full backward compatibility.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_RUNTIME_TUNING_ENV_KEY = "CLEARWING_RUNTIME_TUNING_JSON"


@dataclass(frozen=True)
class TargetConfig:
    """Where to find the code to hunt."""

    repo_url: str
    branch: str = "main"
    local_path: str | None = None
    depth: str = "standard"  # quick | standard | deep


@dataclass(frozen=True)
class BudgetConfig:
    """Cost and parallelism knobs."""

    budget_usd: float = 0.0
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None
    max_parallel: int = 8
    tier_budget: Any = None  # TierBudget | None
    exploit_budget: str | None = None  # "standard" | "deep" | "campaign" | None (auto)
    elaboration_cap: str = "10%"
    subsystem_budget_usd: float = 0.0
    subsystem_max_parallel: int = 4


@dataclass(frozen=True)
class OutputConfig:
    """Report output settings."""

    output_dir: str = ""
    output_formats: list[str] = field(default_factory=lambda: ["sarif", "markdown", "json"])
    export_disclosures: bool = False
    disclosure_reporter_name: str = "(your name)"
    disclosure_reporter_affiliation: str = "(your affiliation)"
    disclosure_reporter_email: str = "(your email)"


@dataclass(frozen=True)
class FeatureFlags:
    """Boolean and modal switches that enable/disable pipeline stages."""

    no_verify: bool = False
    no_exploit: bool = False
    enable_elaboration: bool = False
    enable_variant_loop: bool = True
    enable_stability_verification: bool = True
    enable_mechanism_memory: bool = True
    enable_behavior_monitor: bool = True
    enable_patch_oracle: bool = True
    enable_findings_pool: bool = True
    enable_subsystem_hunt: bool = False
    enable_auto_patch: bool = False
    auto_pr: bool = False
    enable_knowledge_graph: bool = True
    enable_calibration: bool = True
    enable_artifact_store: bool = False
    no_per_file_hunt: bool = False
    no_rank: bool = False
    seed_harness_crashes: bool = False
    preprocessing: bool = True
    adversarial_verifier: bool = True
    adversarial_threshold: str | None = "static_corroboration"
    validator_mode: str = "v2"  # "v1" (old Verifier) | "v2" (4-axis Validator)
    exploit_mode: bool = False
    agent_mode: str = "auto"  # "auto" | "constrained" | "deep"
    prompt_mode: str = "unconstrained"  # "unconstrained" | "specialist"


@dataclass(frozen=True)
class HuntTuning:
    """Advanced tuning knobs for the hunt loop."""

    starting_band: str | None = None  # "fast" | "standard" | "deep" | None (auto)
    redundancy_override: int | None = None
    shard_entry_points: bool | None = None  # None = auto (deep depth)
    min_shard_rank: int = 4
    min_project_loc: int = 50_000
    seed_corpus_sources: list[str] | None = None
    subsystem_paths: list[str] | None = None
    campaign_hint: str | None = None
    gvisor_runtime: str | None = None
    sandbox_cpus: float | None = None  # None = auto, 0 = unlimited


@dataclass(frozen=True)
class ProofConfig:
    """Proof-carrying investigation controls used during migration."""

    flow: str = "legacy"  # legacy | proof
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


@dataclass(frozen=True)
class SourceHuntConfig:
    """Top-level configuration container for SourceHuntRunner.

    Usage::

        cfg = SourceHuntConfig(
            target=TargetConfig(repo_url="https://github.com/example/repo"),
            budget=BudgetConfig(budget_usd=5.0),
        )
        runner = SourceHuntRunner(config=cfg)
        result = runner.run()
    """

    target: TargetConfig
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    features: FeatureFlags = field(default_factory=FeatureFlags)
    tuning: HuntTuning = field(default_factory=HuntTuning)
    proof: ProofConfig = field(default_factory=ProofConfig)



@dataclass(frozen=True)
class SourceHuntCoverageRuntimeTuning:
    traversal_depth: int = 10
    max_file_size_bytes: int = 4_194_304
    large_repo_quality_cutoff: int = 5_000
    imports_by_file_cap: int = 2_000
    ranker_llm_file_limit: int = 1_200


@dataclass(frozen=True)
class SourceHuntThroughputBudgetRuntimeTuning:
    hunt_parallelism: int = 8
    ranker_max_inflight_chunks: int = 8
    default_depth: str = "deep"
    # 0 = unlimited. Hexis injects CLEARWING_RUNTIME_TUNING_JSON; a non-zero
    # default here silently capped hunts that omitted --budget.
    total_usd_ceiling: float = 0.0
    tier_a_fraction: float = 0.70
    tier_b_fraction: float = 0.25
    tier_c_fraction: float = 0.05
    per_file_cap_a_usd: float = 0.25
    per_file_cap_b_usd: float = 0.15
    per_file_cap_c_usd: float = 0.04
    band_fast_usd: float = 5.0
    band_standard_usd: float = 25.0
    band_deep_usd: float = 100.0

    def normalized_tier_fractions(self) -> tuple[float, float, float]:
        total = (
            float(self.tier_a_fraction)
            + float(self.tier_b_fraction)
            + float(self.tier_c_fraction)
        )
        if total <= 0:
            return (0.70, 0.25, 0.05)
        return (
            float(self.tier_a_fraction) / total,
            float(self.tier_b_fraction) / total,
            float(self.tier_c_fraction) / total,
        )


@dataclass(frozen=True)
class SourceHuntVerificationRuntimeTuning:
    adversarial_threshold: str = "static_corroboration"
    hunter_max_steps_constrained: int = 20
    hunter_max_steps_deep: int = 500
    hunter_max_steps_subsystem: int = 2_000
    stability_num_containers: int = 3
    stability_runs_per_container: int = 20
    stability_race_runs_per_container: int = 100
    stability_threshold: float = 0.90
    stability_race_threshold: float = 0.70
    stability_flaky_threshold: float = 0.50
    variant_max_iterations: int = 3
    variant_max_variants_per_finding: int = 5
    mechanism_recall_top_n: int = 3


@dataclass(frozen=True)
class SourceHuntExploitRuntimeTuning:
    band_standard_budget_usd: float = 25.0
    band_standard_timeout_seconds: int = 3_600
    band_standard_max_steps: int = 500
    band_deep_budget_usd: float = 200.0
    band_deep_timeout_seconds: int = 14_400
    band_deep_max_steps: int = 2_000
    band_campaign_budget_usd: float = 2_000.0
    band_campaign_timeout_seconds: int = 43_200
    band_campaign_max_steps: int = 5_000
    harness_total_time_budget_seconds: int = 7_200
    harness_per_harness_duration_seconds: int = 30
    harness_max_harnesses: int = 10
    harness_min_surface: int = 4
    harness_max_parallel: int = 2
    harness_compile_timeout_seconds: int = 120

    def exploit_budget_bands(self) -> dict[str, dict[str, float | int]]:
        return {
            "standard": {
                "budget_usd": self.band_standard_budget_usd,
                "timeout_seconds": self.band_standard_timeout_seconds,
                "max_steps": self.band_standard_max_steps,
            },
            "deep": {
                "budget_usd": self.band_deep_budget_usd,
                "timeout_seconds": self.band_deep_timeout_seconds,
                "max_steps": self.band_deep_max_steps,
            },
            "campaign": {
                "budget_usd": self.band_campaign_budget_usd,
                "timeout_seconds": self.band_campaign_timeout_seconds,
                "max_steps": self.band_campaign_max_steps,
            },
        }


@dataclass(frozen=True)
class SourceHuntRepairRuntimeTuning:
    detect_batch_limit: int = 25
    plan_batch_limit: int = 10
    dispatch_batch_limit: int = 2
    cooldown_minutes: int = 180
    max_attempts: int = 2
    lease_timeout_seconds: int = 900
    verification_timeout_s: int = 240


@dataclass(frozen=True)
class SourceHuntRuntimeTuning:
    coverage: SourceHuntCoverageRuntimeTuning = field(
        default_factory=SourceHuntCoverageRuntimeTuning
    )
    throughput_budget: SourceHuntThroughputBudgetRuntimeTuning = field(
        default_factory=SourceHuntThroughputBudgetRuntimeTuning
    )


@dataclass(frozen=True)
class ClearWingRuntimeTuningPolicy:
    sourcehunt: SourceHuntRuntimeTuning = field(default_factory=SourceHuntRuntimeTuning)
    verification: SourceHuntVerificationRuntimeTuning = field(
        default_factory=SourceHuntVerificationRuntimeTuning
    )
    exploit: SourceHuntExploitRuntimeTuning = field(
        default_factory=SourceHuntExploitRuntimeTuning
    )
    repair: SourceHuntRepairRuntimeTuning = field(
        default_factory=SourceHuntRepairRuntimeTuning
    )


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _coerce_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        numeric = default
    return max(minimum, min(maximum, numeric))


def _coerce_float(
    value: Any,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = default
    return max(minimum, min(maximum, numeric))


def _coerce_enum(
    value: Any,
    *,
    default: str,
    options: set[str],
) -> str:
    text = str(value or "").strip().lower()
    if text in options:
        return text
    return default


def parse_runtime_tuning_policy(payload: Any) -> ClearWingRuntimeTuningPolicy:
    root = _as_dict(payload)
    policy_root = _as_dict(root.get("policy")) if "policy" in root else root

    sourcehunt = _as_dict(policy_root.get("sourcehunt"))
    coverage = _as_dict(sourcehunt.get("coverage"))
    throughput = _as_dict(sourcehunt.get("throughput_budget"))
    verification = _as_dict(policy_root.get("verification"))
    exploit = _as_dict(policy_root.get("exploit"))
    repair = _as_dict(policy_root.get("repair"))

    return ClearWingRuntimeTuningPolicy(
        sourcehunt=SourceHuntRuntimeTuning(
            coverage=SourceHuntCoverageRuntimeTuning(
                traversal_depth=_coerce_int(
                    coverage.get("traversal_depth"),
                    default=10,
                    minimum=1,
                    maximum=20,
                ),
                max_file_size_bytes=_coerce_int(
                    coverage.get("max_file_size_bytes"),
                    default=4_194_304,
                    minimum=65_536,
                    maximum=16_777_216,
                ),
                large_repo_quality_cutoff=_coerce_int(
                    coverage.get("large_repo_quality_cutoff"),
                    default=5_000,
                    minimum=500,
                    maximum=50_000,
                ),
                imports_by_file_cap=_coerce_int(
                    coverage.get("imports_by_file_cap"),
                    default=2_000,
                    minimum=0,
                    maximum=20_000,
                ),
                ranker_llm_file_limit=_coerce_int(
                    coverage.get("ranker_llm_file_limit"),
                    default=1_200,
                    minimum=0,
                    maximum=10_000,
                ),
            ),
            throughput_budget=SourceHuntThroughputBudgetRuntimeTuning(
                hunt_parallelism=_coerce_int(
                    throughput.get("hunt_parallelism"),
                    default=8,
                    minimum=1,
                    maximum=32,
                ),
                ranker_max_inflight_chunks=_coerce_int(
                    throughput.get("ranker_max_inflight_chunks"),
                    default=8,
                    minimum=1,
                    maximum=32,
                ),
                default_depth=_coerce_enum(
                    throughput.get("default_depth"),
                    default="deep",
                    options={"quick", "standard", "deep"},
                ),
                total_usd_ceiling=_coerce_float(
                    throughput.get("total_usd_ceiling"),
                    default=0.0,  # 0 = unlimited (safe-no-op)
                    minimum=0.0,
                    maximum=10_000.0,
                ),
                tier_a_fraction=_coerce_float(
                    throughput.get("tier_a_fraction"),
                    default=0.70,
                    minimum=0.0,
                    maximum=1.0,
                ),
                tier_b_fraction=_coerce_float(
                    throughput.get("tier_b_fraction"),
                    default=0.25,
                    minimum=0.0,
                    maximum=1.0,
                ),
                tier_c_fraction=_coerce_float(
                    throughput.get("tier_c_fraction"),
                    default=0.05,
                    minimum=0.0,
                    maximum=1.0,
                ),
                per_file_cap_a_usd=_coerce_float(
                    throughput.get("per_file_cap_a_usd"),
                    default=0.25,
                    minimum=0.0,
                    maximum=50.0,
                ),
                per_file_cap_b_usd=_coerce_float(
                    throughput.get("per_file_cap_b_usd"),
                    default=0.15,
                    minimum=0.0,
                    maximum=50.0,
                ),
                per_file_cap_c_usd=_coerce_float(
                    throughput.get("per_file_cap_c_usd"),
                    default=0.04,
                    minimum=0.0,
                    maximum=50.0,
                ),
                band_fast_usd=_coerce_float(
                    throughput.get("band_fast_usd"),
                    default=5.0,
                    minimum=0.0,
                    maximum=1_000.0,
                ),
                band_standard_usd=_coerce_float(
                    throughput.get("band_standard_usd"),
                    default=25.0,
                    minimum=0.0,
                    maximum=5_000.0,
                ),
                band_deep_usd=_coerce_float(
                    throughput.get("band_deep_usd"),
                    default=100.0,
                    minimum=0.0,
                    maximum=10_000.0,
                ),
            ),
        ),
        verification=SourceHuntVerificationRuntimeTuning(
            adversarial_threshold=_coerce_enum(
                verification.get("adversarial_threshold"),
                default="static_corroboration",
                options={
                    "suspicion",
                    "static_corroboration",
                    "crash_reproduced",
                    "root_cause_explained",
                    "always",
                },
            ),
            hunter_max_steps_constrained=_coerce_int(
                verification.get("hunter_max_steps_constrained"),
                default=20,
                minimum=1,
                maximum=200,
            ),
            hunter_max_steps_deep=_coerce_int(
                verification.get("hunter_max_steps_deep"),
                default=500,
                minimum=10,
                maximum=5_000,
            ),
            hunter_max_steps_subsystem=_coerce_int(
                verification.get("hunter_max_steps_subsystem"),
                default=2_000,
                minimum=50,
                maximum=10_000,
            ),
            stability_num_containers=_coerce_int(
                verification.get("stability_num_containers"),
                default=3,
                minimum=1,
                maximum=10,
            ),
            stability_runs_per_container=_coerce_int(
                verification.get("stability_runs_per_container"),
                default=20,
                minimum=1,
                maximum=200,
            ),
            stability_race_runs_per_container=_coerce_int(
                verification.get("stability_race_runs_per_container"),
                default=100,
                minimum=1,
                maximum=500,
            ),
            stability_threshold=_coerce_float(
                verification.get("stability_threshold"),
                default=0.90,
                minimum=0.5,
                maximum=1.0,
            ),
            stability_race_threshold=_coerce_float(
                verification.get("stability_race_threshold"),
                default=0.70,
                minimum=0.3,
                maximum=1.0,
            ),
            stability_flaky_threshold=_coerce_float(
                verification.get("stability_flaky_threshold"),
                default=0.50,
                minimum=0.1,
                maximum=0.95,
            ),
            variant_max_iterations=_coerce_int(
                verification.get("variant_max_iterations"),
                default=3,
                minimum=1,
                maximum=10,
            ),
            variant_max_variants_per_finding=_coerce_int(
                verification.get("variant_max_variants_per_finding"),
                default=5,
                minimum=1,
                maximum=25,
            ),
            mechanism_recall_top_n=_coerce_int(
                verification.get("mechanism_recall_top_n"),
                default=3,
                minimum=1,
                maximum=20,
            ),
        ),
        exploit=SourceHuntExploitRuntimeTuning(
            band_standard_budget_usd=_coerce_float(
                exploit.get("band_standard_budget_usd"),
                default=25.0,
                minimum=1.0,
                maximum=5_000.0,
            ),
            band_standard_timeout_seconds=_coerce_int(
                exploit.get("band_standard_timeout_seconds"),
                default=3_600,
                minimum=60,
                maximum=86_400,
            ),
            band_standard_max_steps=_coerce_int(
                exploit.get("band_standard_max_steps"),
                default=500,
                minimum=50,
                maximum=10_000,
            ),
            band_deep_budget_usd=_coerce_float(
                exploit.get("band_deep_budget_usd"),
                default=200.0,
                minimum=1.0,
                maximum=20_000.0,
            ),
            band_deep_timeout_seconds=_coerce_int(
                exploit.get("band_deep_timeout_seconds"),
                default=14_400,
                minimum=60,
                maximum=172_800,
            ),
            band_deep_max_steps=_coerce_int(
                exploit.get("band_deep_max_steps"),
                default=2_000,
                minimum=50,
                maximum=20_000,
            ),
            band_campaign_budget_usd=_coerce_float(
                exploit.get("band_campaign_budget_usd"),
                default=2_000.0,
                minimum=1.0,
                maximum=100_000.0,
            ),
            band_campaign_timeout_seconds=_coerce_int(
                exploit.get("band_campaign_timeout_seconds"),
                default=43_200,
                minimum=60,
                maximum=259_200,
            ),
            band_campaign_max_steps=_coerce_int(
                exploit.get("band_campaign_max_steps"),
                default=5_000,
                minimum=50,
                maximum=50_000,
            ),
            harness_total_time_budget_seconds=_coerce_int(
                exploit.get("harness_total_time_budget_seconds"),
                default=7_200,
                minimum=60,
                maximum=86_400,
            ),
            harness_per_harness_duration_seconds=_coerce_int(
                exploit.get("harness_per_harness_duration_seconds"),
                default=30,
                minimum=5,
                maximum=3_600,
            ),
            harness_max_harnesses=_coerce_int(
                exploit.get("harness_max_harnesses"),
                default=10,
                minimum=1,
                maximum=100,
            ),
            harness_min_surface=_coerce_int(
                exploit.get("harness_min_surface"),
                default=4,
                minimum=1,
                maximum=5,
            ),
            harness_max_parallel=_coerce_int(
                exploit.get("harness_max_parallel"),
                default=2,
                minimum=1,
                maximum=16,
            ),
            harness_compile_timeout_seconds=_coerce_int(
                exploit.get("harness_compile_timeout_seconds"),
                default=120,
                minimum=10,
                maximum=3_600,
            ),
        ),
        repair=SourceHuntRepairRuntimeTuning(
            detect_batch_limit=_coerce_int(
                repair.get("detect_batch_limit"),
                default=25,
                minimum=1,
                maximum=200,
            ),
            plan_batch_limit=_coerce_int(
                repair.get("plan_batch_limit"),
                default=10,
                minimum=1,
                maximum=100,
            ),
            dispatch_batch_limit=_coerce_int(
                repair.get("dispatch_batch_limit"),
                default=2,
                minimum=1,
                maximum=20,
            ),
            cooldown_minutes=_coerce_int(
                repair.get("cooldown_minutes"),
                default=180,
                minimum=1,
                maximum=10_080,
            ),
            max_attempts=_coerce_int(
                repair.get("max_attempts"),
                default=2,
                minimum=1,
                maximum=20,
            ),
            lease_timeout_seconds=_coerce_int(
                repair.get("lease_timeout_seconds"),
                default=900,
                minimum=60,
                maximum=7_200,
            ),
            verification_timeout_s=_coerce_int(
                repair.get("verification_timeout_s"),
                default=240,
                minimum=30,
                maximum=1_800,
            ),
        ),
    )


def load_runtime_tuning_policy_from_env() -> ClearWingRuntimeTuningPolicy:
    raw = str(os.getenv(_RUNTIME_TUNING_ENV_KEY) or "").strip()
    if not raw:
        return parse_runtime_tuning_policy({})
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(
            "CLEARWING_RUNTIME_TUNING_JSON is invalid JSON; using defaults"
        )
        return parse_runtime_tuning_policy({})
    return parse_runtime_tuning_policy(payload)
