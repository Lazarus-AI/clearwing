"""Campaign YAML config parsing — spec 012.

Parses campaign definition files into typed dataclasses for
campaign-scale orchestration across multiple projects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_VALID_DEPTHS = {"quick", "standard", "deep"}


@dataclass
class CampaignTargetConfig:
    repo: str
    budget: float = 0.0
    depth: str = ""
    focus: list[str] = field(default_factory=list)
    branch: str = "main"
    max_parallel: int = 0
    redundancy: int | None = None
    campaign_hint: str | None = None


@dataclass
class OSSFuzzCorpusConfig:
    categories: list[str] = field(default_factory=list)
    max_projects: int = 100
    budget_per_project: float = 100.0


@dataclass
class CampaignConfig:
    name: str
    budget: float
    max_concurrent_containers: int = 200
    depth: str = "deep"
    prompt_mode: str = "unconstrained"
    prompt_bundle: str = "legacy-v1"
    scaffold_profile: str = "native-v1"
    context_profile: str = "legacy-context-v1"
    campaign_hint: str | None = None
    targets: list[CampaignTargetConfig] = field(default_factory=list)
    oss_fuzz_corpus: OSSFuzzCorpusConfig | None = None
    diminishing_returns_window: int = 200
    diminishing_returns_threshold: float = 0.02
    triage_backlog_limit: int = 100
    checkpoint_interval_seconds: int = 300
    output_dir: str = ""
    output_formats: list[str] = field(
        default_factory=lambda: ["sarif", "markdown", "json"],
    )

    def __post_init__(self):
        if not self.output_dir:
            from clearwing.core.config import default_results_dir

            self.output_dir = default_results_dir("campaign")


def load_campaign_config(path: str | Path) -> CampaignConfig:
    """Load and validate a campaign YAML file."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError("Campaign config must be a YAML mapping")

    targets = []
    for t in raw.get("targets", []):
        if isinstance(t, dict):
            if "oss_fuzz_corpus" in t:
                continue
            targets.append(_parse_target(t))

    oss_fuzz = None
    for t in raw.get("targets", []):
        if isinstance(t, dict) and "oss_fuzz_corpus" in t:
            ofc = t["oss_fuzz_corpus"]
            oss_fuzz = OSSFuzzCorpusConfig(
                categories=ofc.get("categories", []),
                max_projects=ofc.get("max_projects", 100),
                budget_per_project=ofc.get("budget_per_project", 100.0),
            )
            break
    if raw.get("oss_fuzz_corpus") and oss_fuzz is None:
        ofc = raw["oss_fuzz_corpus"]
        oss_fuzz = OSSFuzzCorpusConfig(
            categories=ofc.get("categories", []),
            max_projects=ofc.get("max_projects", 100),
            budget_per_project=ofc.get("budget_per_project", 100.0),
        )

    if oss_fuzz:
        targets.extend(_expand_oss_fuzz(oss_fuzz))

    config = CampaignConfig(
        name=raw.get("name", "unnamed-campaign"),
        budget=float(raw.get("budget", 0)),
        max_concurrent_containers=int(raw.get("max_concurrent_containers", 200)),
        depth=raw.get("depth", "deep"),
        prompt_mode=raw.get("prompt_mode", "unconstrained"),
        prompt_bundle=raw.get("prompt_bundle", "legacy-v1"),
        scaffold_profile=raw.get("scaffold_profile", "native-v1"),
        context_profile=raw.get("context_profile", "legacy-context-v1"),
        campaign_hint=raw.get("campaign_hint"),
        targets=targets,
        oss_fuzz_corpus=oss_fuzz,
        diminishing_returns_window=int(
            raw.get("diminishing_returns_window", 200),
        ),
        diminishing_returns_threshold=float(
            raw.get("diminishing_returns_threshold", 0.02),
        ),
        triage_backlog_limit=int(raw.get("triage_backlog_limit", 100)),
        checkpoint_interval_seconds=int(
            raw.get("checkpoint_interval_seconds", 300),
        ),
        output_dir=raw.get("output_dir", ""),
        output_formats=raw.get(
            "output_formats", ["sarif", "markdown", "json"],
        ),
    )
    validate_campaign_config(config)
    return config


def validate_campaign_config(config: CampaignConfig) -> None:
    """Raise ValueError on invalid config."""
    if not config.name:
        raise ValueError("Campaign name is required")
    if config.budget <= 0:
        raise ValueError("Campaign budget must be > 0")
    if not config.targets:
        raise ValueError("Campaign must have at least one target")
    if config.depth not in _VALID_DEPTHS:
        raise ValueError(
            f"Invalid campaign depth '{config.depth}', "
            f"must be one of: {', '.join(sorted(_VALID_DEPTHS))}",
        )
    from .optimization import get_context_profile, get_prompt_bundle, get_scaffold_profile

    get_prompt_bundle(config.prompt_bundle)
    get_scaffold_profile(config.scaffold_profile)
    get_context_profile(config.context_profile)
    for t in config.targets:
        if not t.repo:
            raise ValueError("Target repo URL is required")
        if t.depth and t.depth not in _VALID_DEPTHS:
            raise ValueError(
                f"Invalid target depth '{t.depth}' for {t.repo}",
            )


def _parse_target(raw: dict[str, Any]) -> CampaignTargetConfig:
    return CampaignTargetConfig(
        repo=raw.get("repo", ""),
        budget=float(raw.get("budget", 0)),
        depth=raw.get("depth", ""),
        focus=raw.get("focus", []),
        branch=raw.get("branch", "main"),
        max_parallel=int(raw.get("max_parallel", 0)),
        redundancy=raw.get("redundancy"),
        campaign_hint=raw.get("campaign_hint"),
    )


def _expand_oss_fuzz(corpus: OSSFuzzCorpusConfig) -> list[CampaignTargetConfig]:
    """Expand OSS-Fuzz corpus config into individual target entries.

    Stub: returns placeholder targets based on categories. Full implementation
    requires querying the OSS-Fuzz project registry.
    """
    targets = []
    for category in corpus.categories:
        targets.append(
            CampaignTargetConfig(
                repo=f"oss-fuzz:{category}",
                budget=corpus.budget_per_project,
                campaign_hint=f"OSS-Fuzz {category} corpus project",
            ),
        )
    return targets[:corpus.max_projects]
