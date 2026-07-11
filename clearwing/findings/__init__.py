"""Unified Finding type for clearwing.

One dataclass that can represent every finding shape in the project:
    - network-pentest findings from CICDRunner
    - file-level findings from SourceAnalyzer (static regex/AST)
    - source-hunt findings from the sourcehunt pipeline

Backwards-compat converters let every existing caller keep using its own
dict/dataclass shape — the Finding type is additive. Internal refactors can
move to it incrementally.
"""

from .types import (
    CRYPTO_ATTACK_CLASSES,
    EVIDENCE_LEVELS,
    SEVERITY_VALUES,
    EvidenceLevel,
    Finding,
    Severity,
    evidence_at_or_above,
    evidence_compare,
    from_analysis_finding,
    from_cicd_dict,
    to_cicd_dict,
)

__all__ = [
    "CRYPTO_ATTACK_CLASSES",
    "EVIDENCE_LEVELS",
    "EvidenceLevel",
    "Finding",
    "Severity",
    "SEVERITY_VALUES",
    "evidence_at_or_above",
    "evidence_compare",
    "from_cicd_dict",
    "from_analysis_finding",
    "to_cicd_dict",
]
