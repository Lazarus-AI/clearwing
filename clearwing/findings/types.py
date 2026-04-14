"""Unified Finding dataclass and converters.

This type is a superset of every finding shape the project uses. The field
set is dominated by the sourcehunt pipeline (the most complete shape),
extended with optional network fields for CICDRunner compatibility.

Conversion functions are pure — they never mutate their inputs. Round-trip
through `from_*` + `to_*` preserves every field present in the source shape.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Literal, Optional


Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_VALUES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


EvidenceLevel = Literal[
    "suspicion",
    "static_corroboration",
    "crash_reproduced",
    "root_cause_explained",
    "exploit_demonstrated",
    "patch_validated",
]


# --- The unified Finding ----------------------------------------------------


@dataclass
class Finding:
    """The single canonical finding type. Every field is optional by default
    so every legacy shape round-trips cleanly.

    Field categories:
      - identification: id, finding_type, cwe
      - source location: file, line_number, end_line, code_snippet
      - network location: target, port, protocol, service
      - severity + confidence: severity, severity_verified, confidence
      - hunter output: description, crash_evidence, poc, discovered_by
      - evidence ladder: evidence_level
      - relationships: related_finding_id, related_cve, seeded_from_crash
      - verifier (v0.2): verified, verifier_pro_argument, verifier_counter_argument,
        verifier_tie_breaker
      - patch oracle (v0.3): patch_oracle_passed
      - exploit triage: exploit, exploit_success
      - auto-patch (v0.3): auto_patch, auto_patch_validated
      - session: hunter_session_id, verifier_session_id
      - legacy network fields: cve, cvss, details (for CICDRunner compatibility)
    """

    # Identification
    id: str = ""
    finding_type: str = ""
    cwe: str = ""

    # Source location
    file: Optional[str] = None
    line_number: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: str = ""

    # Network location (for CICDRunner-style findings)
    target: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None

    # Severity & confidence
    severity: Severity = "info"
    severity_verified: Optional[Severity] = None
    confidence: Literal["high", "medium", "low"] = "medium"

    # Hunter output
    description: str = ""
    crash_evidence: Optional[str] = None
    poc: Optional[str] = None
    discovered_by: str = "unknown"

    # Evidence ladder
    evidence_level: EvidenceLevel = "suspicion"

    # Relationships
    related_finding_id: Optional[str] = None
    related_cve: Optional[str] = None
    seeded_from_crash: bool = False

    # Verifier (v0.2 adversarial)
    verified: bool = False
    verifier_pro_argument: Optional[str] = None
    verifier_counter_argument: Optional[str] = None
    verifier_tie_breaker: Optional[str] = None

    # Patch oracle (v0.3)
    patch_oracle_passed: Optional[bool] = None

    # Exploit triage
    exploit: Optional[str] = None
    exploit_success: Optional[bool] = None

    # Auto-patch (v0.3)
    auto_patch: Optional[str] = None
    auto_patch_validated: Optional[bool] = None

    # Session tracking
    hunter_session_id: str = ""
    verifier_session_id: Optional[str] = None

    # Legacy network-finding fields (CICDRunner)
    cve: Optional[str] = None           # CVE identifier for network findings
    cvss: Optional[float] = None        # CVSS score
    details: str = ""                   # legacy details blob

    # Extensible payload — v0.2/v0.3 seams, retro-hunt fields, etc.
    extra: dict[str, Any] = field(default_factory=dict)

    # --- Derived properties -------------------------------------------------

    @property
    def effective_severity(self) -> Severity:
        """severity_verified wins over severity when both are set."""
        return self.severity_verified or self.severity

    @property
    def is_source_finding(self) -> bool:
        """True if this Finding has a file path (came from a source scan)."""
        return bool(self.file)

    @property
    def is_network_finding(self) -> bool:
        """True if this Finding has a target (came from a network scan) and
        no file path."""
        return bool(self.target) and not self.file

    @property
    def is_validated_patch(self) -> bool:
        """True if a patch has been recompile+re-run validated."""
        return bool(self.auto_patch_validated)

    @property
    def is_strong_evidence(self) -> bool:
        """True if evidence_level is crash_reproduced or higher."""
        order = (
            "suspicion", "static_corroboration", "crash_reproduced",
            "root_cause_explained", "exploit_demonstrated", "patch_validated",
        )
        try:
            return order.index(self.evidence_level) >= order.index("crash_reproduced")
        except ValueError:
            return False

    # --- Dict-style access shim --------------------------------------------
    # Phase-3 bridge for callers still using the legacy TypedDict access
    # patterns (`.get`, `["k"]`, `["k"] = v`, `in`). Every call site under
    # clearwing/ can construct a `Finding` dataclass, but some apply_* merge
    # functions and many test fixtures still supply plain dicts — these four
    # methods let both shapes flow through the same API.

    def __getitem__(self, key: str) -> Any:
        if key in self.__dataclass_fields__:
            return getattr(self, key)
        if key in self.extra:
            return self.extra[key]
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__dataclass_fields__:
            setattr(self, key, value)
        else:
            self.extra[key] = value

    def __contains__(self, key: object) -> bool:
        return (
            isinstance(key, str)
            and (key in self.__dataclass_fields__ or key in self.extra)
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Mimic dict.get() semantics against Finding attributes.

        Treats None / empty string as 'field not really set' so legacy
        TypedDict callers that rely on default-when-absent keep working.
        """
        if key in self.__dataclass_fields__:
            val = getattr(self, key)
            if val in (None, "") and default is not None:
                return default
            return val
        return self.extra.get(key, default)


# --- Converters: from legacy shapes → Finding ------------------------------


def from_cicd_dict(d: dict, *, target: Optional[str] = None) -> Finding:
    """Build a Finding from a CICDRunner finding dict.

    CICD findings have shape `{description, severity, cve, details}` plus the
    target comes from the runner context. Optional `target=` kwarg fills the
    network location.
    """
    f = Finding(
        id=d.get("id") or f"cicd-{uuid.uuid4().hex[:8]}",
        description=d.get("description", ""),
        severity=_coerce_severity(d.get("severity", "info")),
        cve=d.get("cve"),
        details=d.get("details", ""),
        cwe=d.get("cve") or "",      # CWE often shares rule ID with CVE
        target=target or d.get("target"),
        port=d.get("port"),
        protocol=d.get("protocol"),
        service=d.get("service"),
        finding_type=d.get("finding_type", "network_vulnerability"),
        discovered_by=d.get("discovered_by", "network_scanner"),
        # Network findings are typically evidence_level=static_corroboration
        # (something scanned and matched a signature). Override explicitly if
        # the caller knows better.
        evidence_level=d.get("evidence_level", "static_corroboration"),
    )
    return f


def from_analysis_finding(finding) -> Finding:
    """Build a Finding from a `clearwing.analysis.source_analyzer.Finding`.

    Accepts either the dataclass instance or a dict with the same keys.
    """
    if hasattr(finding, "__dataclass_fields__"):
        # It's the dataclass — use asdict
        d = asdict(finding)
    elif isinstance(finding, dict):
        d = finding
    else:
        raise TypeError(f"unsupported source_analyzer finding type: {type(finding)}")

    return Finding(
        id=f"static-{uuid.uuid4().hex[:8]}",
        file=d.get("file_path"),
        line_number=d.get("line_number"),
        finding_type=d.get("finding_type", "static_analysis"),
        severity=_coerce_severity(d.get("severity", "info")),
        description=d.get("description", ""),
        code_snippet=d.get("code_snippet", ""),
        cwe=d.get("cwe", ""),
        confidence=d.get("confidence", "medium"),
        discovered_by="source_analyzer",
        evidence_level="static_corroboration",
    )


# --- Converters: Finding → legacy shapes -----------------------------------


def to_cicd_dict(finding: Finding) -> dict:
    """Build a CICDRunner-shape finding dict from a Finding.

    Fields: description, severity, cve, details — the legacy four.
    Also preserves file / line_number if present so R2's file-aware SARIF
    generator can render source-hunt findings.
    """
    out: dict[str, Any] = {
        "description": finding.description,
        "severity": finding.severity_verified or finding.severity,
        "cve": finding.cve or finding.cwe or None,
        "details": finding.details,
    }
    if finding.file:
        out["file"] = finding.file
    if finding.line_number is not None:
        out["line_number"] = finding.line_number
    if finding.end_line is not None:
        out["end_line"] = finding.end_line
    return out


# --- Helpers ----------------------------------------------------------------


def _coerce_severity(value: Any) -> Severity:
    """Map a free-form severity string to one of the five canonical values."""
    if not value:
        return "info"
    s = str(value).lower().strip()
    if s in SEVERITY_VALUES:
        return s   # type: ignore[return-value]
    # Common variants
    mapping = {
        "err": "high", "error": "high", "warn": "medium", "warning": "medium",
        "note": "low", "none": "info", "unknown": "info",
    }
    return mapping.get(s, "info")   # type: ignore[return-value]
