"""Configuration dataclasses for the sourcehunt pipeline.

Groups the 60+ constructor parameters of SourceHuntRunner into cohesive,
frozen dataclasses. This is the first step of Task 1 (runner decomposition);
the runner constructor accepts an optional ``SourceHuntConfig`` alongside the
legacy keyword arguments for full backward compatibility.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any


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
    prompt_bundle: str = "legacy-v1"
    scaffold_profile: str = "native-v1"
    context_profile: str = "legacy-context-v1"


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
    mechanism_store_path: str | None = None
    historical_db_path: str | None = None
    gvisor_runtime: str | None = None
    sandbox_cpus: float | None = None  # None = auto, 0 = unlimited
    respect_gitignore: bool = False


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

    @classmethod
    def from_options(cls, options: dict[str, Any]) -> SourceHuntConfig:
        """Group the runner's effective legacy options into typed config."""

        def build(
            model: type[Any],
            prefix: str = "",
            source: dict[str, Any] = options,
        ) -> Any:
            values = {
                item.name: source[f"{prefix}{item.name}"]
                for item in fields(model)
                if f"{prefix}{item.name}" in source
            }
            return model(**values)

        proof_options = dict(options)
        for name in ("flow", "retain_incomplete_certificates", "emit_rejection_certificates", "falsify"):
            proof_options[f"proof_{name}"] = options[name]
        return cls(
            target=build(TargetConfig),
            budget=build(BudgetConfig),
            output=build(OutputConfig),
            features=build(FeatureFlags),
            tuning=build(HuntTuning),
            proof=build(ProofConfig, "proof_", proof_options),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible representation persisted with a session."""

        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SourceHuntConfig:
        """Restore a config previously produced by :meth:`to_dict`."""

        budget = dict(payload.get("budget") or {})
        tier_budget = budget.get("tier_budget")
        if isinstance(tier_budget, dict):
            from .pool import TierBudget

            budget["tier_budget"] = TierBudget(**tier_budget)
        return cls(
            target=TargetConfig(**payload["target"]),
            budget=BudgetConfig(**budget),
            output=OutputConfig(**(payload.get("output") or {})),
            features=FeatureFlags(**(payload.get("features") or {})),
            tuning=HuntTuning(**(payload.get("tuning") or {})),
            proof=ProofConfig(**(payload.get("proof") or {})),
        )


@dataclass(frozen=True)
class SourceHuntResumeOptions:
    """Runtime-only options permitted while resuming a saved hunt plan."""

    session_id: str
    output_dir: str
    model_override: str | None = None
    live: bool = False
