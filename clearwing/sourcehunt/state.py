"""State schemas for the Clearwing source-hunt pipeline.

Critical schema discipline: every v0.1 type accepts v0.2/v0.3 fields with
sensible defaults. Future phases land as feature additions, not refactors.

Evidence ladder gates downstream budget allocation:
    suspicion < static_corroboration < crash_reproduced
        < root_cause_explained < exploit_demonstrated < patch_validated

The Exploiter only runs on findings >= crash_reproduced.
The Auto-Patcher only runs on findings >= root_cause_explained.
Findings reaching patch_validated are the gold standard in reports.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field
from typing_extensions import TypedDict

from clearwing.findings.types import (
    EVIDENCE_LEVELS,  # noqa: F401 — re-exported for backwards compatibility
    EvidenceLevel,
    Finding,
    evidence_at_or_above,
    evidence_compare,  # noqa: F401 — re-exported for backwards compatibility
)
from clearwing.llm import BaseMessage

# --- Evidence ladder ---------------------------------------------------------
# Canonical definitions now live in clearwing.findings.types.
# Re-exported here for backwards compatibility.


def filter_by_evidence(
    findings: list[Finding],
    threshold: EvidenceLevel,
) -> list[Finding]:
    """Return only findings with evidence_level >= threshold.

    Findings without an evidence_level field are treated as 'suspicion'.
    Used as a budget gate before passing to expensive downstream agents.
    """
    return [
        f for f in findings if evidence_at_or_above(f.get("evidence_level", "suspicion"), threshold)
    ]


# --- File tagging ------------------------------------------------------------

FileTag = Literal[
    "memory_unsafe",
    "parser",
    "crypto",
    "auth_boundary",
    "syscall_entry",
    "fuzzable",
    "attacker_reachable",
]


# --- FileTarget --------------------------------------------------------------


class FileTarget(TypedDict, total=False):
    """A source file to be ranked and (potentially) hunted.

    All fields are optional in the TypedDict to allow incremental population:
    the preprocessor sets path/language/loc/static_hint/imports_by/tags;
    the ranker fills in surface/influence/rationale; the pool computes tier.

    v0.2 fields (transitive_callers, semgrep_hint, has_fuzz_entry_point,
    fuzz_harness_path, reachability_rationale) are present from v0.1 with
    safe defaults so the schema is forward-compatible.
    """

    path: str  # relative to repo root
    absolute_path: str
    surface: int  # 1-5 — direct vulnerability likelihood
    influence: int  # 1-5 — downstream danger if this file is wrong
    reachability: int  # 1-5 — attacker-reachability through callgraph
    # v0.1: defaults to 3 (unknown); v0.2: real propagation
    priority: float  # surface*0.5 + influence*0.2 + reachability*0.3
    tier: Literal["A", "B", "C"]
    tags: list[FileTag]  # v0.1: heuristic tagger; v0.2: + LLM polish
    language: str
    loc: int
    surface_rationale: str
    influence_rationale: str
    reachability_rationale: str
    static_hint: int  # SourceAnalyzer regex hits → surface boost
    semgrep_hint: int  # v0.2: Semgrep findings count → surface boost + hint
    taint_hits: int  # v0.4: tree-sitter taint paths touching this file
    imports_by: int  # v0.1 cheap influence signal
    transitive_callers: int  # v0.2: tree-sitter callgraph (better influence)
    defines_constants: bool
    has_fuzz_entry_point: bool  # v0.2: detected by tagger
    fuzz_harness_path: str | None  # v0.2: filled by Harness Generator


# Phase 3 unified the legacy sourcehunt finding TypedDict with the
# canonical `Finding` dataclass from `clearwing.findings.types`. The
# dataclass is imported at the top of this module and used directly in
# the state TypedDicts below.


# --- SubsystemTarget (spec 006) ---------------------------------------------


@dataclass
class SubsystemTarget:
    """A group of related files to hunt as a unit (spec 006)."""

    name: str  # e.g. "tcp_sack", "h264_decoder"
    root_path: str  # e.g. "net/ipv4/", "libavcodec/"
    files: list[FileTarget]  # max 50 files, sorted by priority
    entry_points: list[Any] = field(default_factory=list)
    description: str = ""
    priority: float = 0.0  # max(file.priority for file in files)
    source: str = "auto"  # "auto" | "manual"


# --- ElaborationResult (spec 008) --------------------------------------------


@dataclass
class ElaborationResult:
    """Result of a Stage 1.5 exploit elaboration attempt."""

    original_finding_id: str
    elaborated: bool
    upgraded_impact: str | None = None
    upgraded_exploit_code: str | None = None
    chained_findings: list[str] = field(default_factory=list)
    upgrade_path: str = ""
    blocking_mitigations: list[str] = field(default_factory=list)
    human_guided: bool = False
    cost: float = 0.0
    transcript_path: str = ""


# --- Validation types (spec 009) ---------------------------------------------


class AxisResult(BaseModel):
    """One validation axis: pass/fail with a confidence and short rationale.

    A single struct shared by the validator's wire schema (constrained decoding)
    and the domain verdict — the fields are identical, so there is no DTO plus a
    near-duplicate dataclass and no field-by-field mapper between them. The
    docstring and Field descriptions are emitted into the JSON schema, so the
    guidance reaches the model inline, not only via the prose prompt.
    """

    passed: bool = Field(
        description="True if this axis is satisfied, false if it fails."
    )
    confidence: Literal["high", "medium", "low"] = Field(
        description="Confidence in this axis's pass/fail judgment."
    )
    rationale: str = Field(
        default="",
        description=(
            "One to three sentences justifying the decision; keep it under 500 "
            "characters."
        ),
    )
    boundary_crossed: Literal[
        "privilege", "tenant", "origin", "user", "kernel", "sandbox", "none"
    ] = Field(
        default="none",
        description=(
            "Security boundary the bug crosses. Set only for the impactful axis; "
            "leave as 'none' for the others."
        ),
    )


@dataclass
class Axes:
    """The validator's per-axis results, as typed fields rather than a dict.

    All four are optional because the set evaluated varies: the full pass fills
    all four, the two-axis quick pass fills only ``real``/``triggerable``, and an
    error verdict fills none. Typed fields give callers static checking and make
    the axis identity the field name — no stringly-typed keys.
    """

    real: AxisResult | None = None
    triggerable: AxisResult | None = None
    impactful: AxisResult | None = None
    general: AxisResult | None = None

    def items(self) -> Iterator[tuple[str, AxisResult]]:
        """Yield ``(name, result)`` for each evaluated axis, in canonical order.

        Absent axes (``None``) are skipped, so callers that build per-axis maps
        or lists see only what was actually judged.
        """
        for name, result in vars(self).items():
            if result is not None:
                yield name, result


@dataclass
class ValidatorVerdict:
    """Output of the unified 4-axis validator (spec 009)."""

    finding_id: str
    axes: Axes
    advance: bool
    severity_validated: str | None
    evidence_level: EvidenceLevel
    pro_argument: str
    counter_argument: str
    tie_breaker: str
    duplicate_cve: str | None
    raw_response: str = ""
    patch_oracle_attempted: bool = False
    patch_oracle_passed: bool | None = None
    patch_oracle_diff: str = ""
    patch_oracle_notes: str = ""

    def to_verifier_result(self):
        from clearwing.sourcehunt.verifier import VerifierResult

        return VerifierResult(
            finding_id=self.finding_id,
            is_real=self.advance,
            severity_verified=self.severity_validated,
            evidence_level=self.evidence_level,
            pro_argument=self.pro_argument,
            counter_argument=self.counter_argument,
            tie_breaker=self.tie_breaker,
            duplicate_cve=self.duplicate_cve,
            raw_response=self.raw_response,
            patch_oracle_attempted=self.patch_oracle_attempted,
            patch_oracle_passed=self.patch_oracle_passed,
            patch_oracle_diff=self.patch_oracle_diff,
            patch_oracle_notes=self.patch_oracle_notes,
        )


# --- Stability types (spec 010) -----------------------------------------------


@dataclass
class StabilityResult:
    """Output of Stage 2.5 PoC stability verification (spec 010)."""

    finding_id: str
    total_runs: int
    successes: int
    success_rate: float  # 0.0-1.0
    per_container_rates: list[float]
    classification: str  # "stable" | "flaky" | "unreliable"
    hardened: bool = False
    hardening_improved: bool = False
    failure_analysis: str = ""
    original_poc: str = ""
    hardened_poc: str | None = None


# --- Disclosure lifecycle (spec 011) ------------------------------------------


class StageOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageStatus:
    """Status of a single pipeline stage."""

    name: str
    outcome: StageOutcome
    error: str | None = None
    fallback_description: str | None = None


@dataclass
class PipelineStatus:
    """Aggregated health status for the full pipeline run."""

    stages: dict[str, StageStatus] = field(default_factory=dict)

    def record(self, name: str, outcome: StageOutcome, **kwargs: Any) -> None:
        self.stages[name] = StageStatus(name=name, outcome=outcome, **kwargs)

    def record_degraded(
        self, name: str, fallback: str, error: str = "",
    ) -> None:
        self.stages[name] = StageStatus(
            name=name,
            outcome=StageOutcome.DEGRADED,
            error=error or None,
            fallback_description=fallback,
        )

    def record_succeeded(self, name: str) -> None:
        self.stages[name] = StageStatus(name=name, outcome=StageOutcome.SUCCEEDED)

    @property
    def any_degraded(self) -> bool:
        return any(s.outcome == StageOutcome.DEGRADED for s in self.stages.values())

    @property
    def any_failed(self) -> bool:
        return any(s.outcome == StageOutcome.FAILED for s in self.stages.values())

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        for s in self.stages.values():
            line = f"  {s.name}: {s.outcome.value}"
            if s.fallback_description:
                line += f" — {s.fallback_description}"
            if s.error:
                line += f" (error: {s.error})"
            lines.append(line)
        return lines


class DisclosureState(str, Enum):
    PENDING_REVIEW = "pending_review"
    IN_REVIEW = "in_review"
    VALIDATED = "validated"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"
    PENDING_DISCLOSURE = "pending_disclosure"
    DISCLOSED = "disclosed"
    ACKNOWLEDGED = "acknowledged"
    PATCH_IN_PROGRESS = "patch_in_progress"
    PATCHED = "patched"
    PUBLIC = "public"
    WONTFIX = "wontfix"


# --- SourceHuntState ---------------------------------------------------------


class SourceHuntState(TypedDict, total=False):
    """State for hunter/verifier/exploiter sub-graphs.

    Every v0.2/v0.3 field is present from v0.1 with safe defaults so the
    schema is forward-compatible. v0.1 code paths simply don't read or
    write the future fields.
    """

    messages: list[BaseMessage]
    repo_url: str
    repo_path: str
    branch: str
    files: list[FileTarget]
    files_scanned: list[str]
    current_file: str | None

    # v0.2 seams
    callgraph: dict | None  # tree-sitter callgraph
    semgrep_findings: list[dict]  # pre-scan hits used as hints
    fuzz_corpora: list[dict]  # detected OSS-Fuzz / project corpora
    seeded_crashes: list[dict]  # harness generator output

    findings: list[Finding]
    verified_findings: list[Finding]

    # v0.3 seams
    variant_seeds: list[dict]  # hypotheses from variant hunter loop
    exploited_findings: list[Finding]
    patch_attempts: list[dict]  # auto-patcher output (validated or not)

    # Budget & cost
    budget_usd: float
    spent_usd: float
    spent_per_tier: dict[str, float]  # {"A": ..., "B": ..., "C": ...}
    total_tokens: int

    phase: Literal[
        "preprocess",
        "tag",
        "rank",
        "fuzz",
        "hunt",
        "verify",
        "variant_loop",
        "stability",
        "exploit",
        "elaborate",
        "auto_patch",
        "report",
    ]
    session_id: str | None
    flags_found: list[dict]
