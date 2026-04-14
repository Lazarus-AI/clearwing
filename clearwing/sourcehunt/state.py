"""State schemas for the Overwing source-hunt pipeline.

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

from typing import Annotated, Literal, Optional

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

from clearwing.findings.types import Finding


# --- Evidence ladder ---------------------------------------------------------

EvidenceLevel = Literal[
    "suspicion",
    "static_corroboration",
    "crash_reproduced",
    "root_cause_explained",
    "exploit_demonstrated",
    "patch_validated",
]

EVIDENCE_LEVELS: tuple[EvidenceLevel, ...] = (
    "suspicion",
    "static_corroboration",
    "crash_reproduced",
    "root_cause_explained",
    "exploit_demonstrated",
    "patch_validated",
)

_EVIDENCE_RANK = {level: idx for idx, level in enumerate(EVIDENCE_LEVELS)}


def evidence_compare(a: EvidenceLevel, b: EvidenceLevel) -> int:
    """Return -1, 0, or 1 like Python 2's cmp."""
    ra = _EVIDENCE_RANK[a]
    rb = _EVIDENCE_RANK[b]
    return (ra > rb) - (ra < rb)


def evidence_at_or_above(level: EvidenceLevel, threshold: EvidenceLevel) -> bool:
    """True if `level` is at least as strong as `threshold`."""
    return _EVIDENCE_RANK[level] >= _EVIDENCE_RANK[threshold]


def filter_by_evidence(
    findings: list[dict],
    threshold: EvidenceLevel,
) -> list[dict]:
    """Return only findings with evidence_level >= threshold.

    Findings without an evidence_level field are treated as 'suspicion'.
    Used as a budget gate before passing to expensive downstream agents.
    """
    return [
        f for f in findings
        if evidence_at_or_above(f.get("evidence_level", "suspicion"), threshold)
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
    path: str            # relative to repo root
    absolute_path: str
    surface: int         # 1-5 — direct vulnerability likelihood
    influence: int       # 1-5 — downstream danger if this file is wrong
    reachability: int    # 1-5 — attacker-reachability through callgraph
                         # v0.1: defaults to 3 (unknown); v0.2: real propagation
    priority: float      # surface*0.5 + influence*0.2 + reachability*0.3
    tier: Literal["A", "B", "C"]
    tags: list[FileTag]  # v0.1: heuristic tagger; v0.2: + LLM polish
    language: str
    loc: int
    surface_rationale: str
    influence_rationale: str
    reachability_rationale: str
    static_hint: int     # SourceAnalyzer regex hits → surface boost
    semgrep_hint: int    # v0.2: Semgrep findings count → surface boost + hint
    taint_hits: int      # v0.4: tree-sitter taint paths touching this file
    imports_by: int      # v0.1 cheap influence signal
    transitive_callers: int   # v0.2: tree-sitter callgraph (better influence)
    defines_constants: bool
    has_fuzz_entry_point: bool   # v0.2: detected by tagger
    fuzz_harness_path: Optional[str]   # v0.2: filled by Harness Generator


# Phase 3 unified the legacy sourcehunt finding TypedDict with the
# canonical `Finding` dataclass from `clearwing.findings.types`. The
# dataclass is imported at the top of this module and used directly in
# the state TypedDicts below.


# --- SourceHuntState ---------------------------------------------------------

class SourceHuntState(TypedDict, total=False):
    """LangGraph state for hunter/verifier/exploiter sub-graphs.

    Every v0.2/v0.3 field is present from v0.1 with safe defaults so the
    schema is forward-compatible. v0.1 code paths simply don't read or
    write the future fields.
    """
    messages: Annotated[list[BaseMessage], add_messages]
    repo_url: str
    repo_path: str
    branch: str
    files: list[FileTarget]
    files_scanned: list[str]
    current_file: Optional[str]

    # v0.2 seams
    callgraph: Optional[dict]              # tree-sitter callgraph
    semgrep_findings: list[dict]           # pre-scan hits used as hints
    fuzz_corpora: list[dict]               # detected OSS-Fuzz / project corpora
    seeded_crashes: list[dict]             # harness generator output

    findings: list[Finding]
    verified_findings: list[Finding]

    # v0.3 seams
    variant_seeds: list[dict]              # hypotheses from variant hunter loop
    exploited_findings: list[Finding]
    patch_attempts: list[dict]             # auto-patcher output (validated or not)

    # Budget & cost
    budget_usd: float
    spent_usd: float
    spent_per_tier: dict[str, float]       # {"A": ..., "B": ..., "C": ...}
    total_tokens: int

    phase: Literal[
        "preprocess", "tag", "rank", "fuzz", "hunt", "verify", "variant_loop",
        "exploit", "auto_patch", "report"
    ]
    session_id: Optional[str]
    flags_found: list[dict]
