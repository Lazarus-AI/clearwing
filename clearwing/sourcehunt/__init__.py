"""Clearwing source-code vulnerability hunting pipelines.

The migration-compatible legacy engine is file-parallel and agent-driven:
    preprocess (clone + enumerate + tag)
    → rank (three axes: surface, influence, reachability)
    → tiered HunterPool (70/25/5 budget across A/B/C)
    → verify (independent context, adversarial in v0.2)
    → exploit (sandboxed PoC, gated on evidence_level >= crash_reproduced)
    → report (SARIF + markdown + JSON)

The opt-in proof engine (`--flow proof`) extracts typed facts, generates
invariant candidates, resolves obligation DAGs with mechanical and bounded
model actions, performs finite falsification, and emits evidence-gated
finding, rejection, or incomplete certificates.

Public entry points: SourceHuntRunner (programmatic), `clearwing sourcehunt`
(CLI), and `hunt_source_code` (interactive @tool).
"""

from clearwing.findings.types import Finding

from .config import (
    BudgetConfig,
    FeatureFlags,
    HuntTuning,
    OutputConfig,
    ProofConfig,
    SourceHuntConfig,
    TargetConfig,
)
from .state import (
    EVIDENCE_LEVELS,
    EvidenceLevel,
    FileTag,
    FileTarget,
    SourceHuntState,
    evidence_at_or_above,
    evidence_compare,
    filter_by_evidence,
)

__all__ = [
    "BudgetConfig",
    "EvidenceLevel",
    "FeatureFlags",
    "FileTag",
    "FileTarget",
    "Finding",
    "HuntTuning",
    "OutputConfig",
    "ProofConfig",
    "SourceHuntConfig",
    "SourceHuntState",
    "TargetConfig",
    "EVIDENCE_LEVELS",
    "evidence_at_or_above",
    "evidence_compare",
    "filter_by_evidence",
]
