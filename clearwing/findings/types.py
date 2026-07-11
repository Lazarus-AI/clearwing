"""Unified Finding dataclass and converters.

This type is a superset of every finding shape the project uses. The field
set is dominated by the sourcehunt pipeline (the most complete shape),
extended with optional network fields for CICDRunner compatibility.

Conversion functions are pure — they never mutate their inputs. Round-trip
through `from_*` + `to_*` preserves every field present in the source shape.
"""

from __future__ import annotations

import logging
import uuid
import warnings
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_VALUES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

CRYPTO_ATTACK_CLASSES: tuple[str, ...] = (
    "timing_side_channel",
    "parameter_validation",
    "nonce_reuse",
    "padding_oracle",
    "downgrade",
    "key_lifecycle",
    "weak_prng",
    "point_validation",
    "mac_order",
)


EvidenceLevel = Literal[
    "suspicion",
    "static_corroboration",
    "parameter_anomaly",
    "timing_confirmed",
    "crash_reproduced",
    "root_cause_explained",
    "assumption_broken",
    "exploit_demonstrated",
    "key_material_recovered",
    "patch_validated",
]


# --- Evidence ladder helpers --------------------------------------------------

EVIDENCE_LEVELS: tuple[EvidenceLevel, ...] = (
    "suspicion",
    "static_corroboration",
    "parameter_anomaly",
    "timing_confirmed",
    "crash_reproduced",
    "root_cause_explained",
    "assumption_broken",
    "exploit_demonstrated",
    "key_material_recovered",
    "patch_validated",
)

_EVIDENCE_RANK: dict[str, int] = {level: idx for idx, level in enumerate(EVIDENCE_LEVELS)}


def evidence_compare(a: EvidenceLevel, b: EvidenceLevel) -> int:
    """Return -1, 0, or 1 like Python 2's cmp."""
    ra = _EVIDENCE_RANK[a]
    rb = _EVIDENCE_RANK[b]
    return (ra > rb) - (ra < rb)


def evidence_at_or_above(level: EvidenceLevel, threshold: EvidenceLevel) -> bool:
    """True if `level` is at least as strong as `threshold`."""
    return _EVIDENCE_RANK[level] >= _EVIDENCE_RANK[threshold]


# --- The unified Finding ----------------------------------------------------


@dataclass
class Finding:
    """The single canonical finding type. Every field is optional by default
    so every legacy shape round-trips cleanly.

    Field categories:
      - identification: id, finding_type, cwe
      - source location: file, line_number, end_line, code_snippet
      - network location: target, port, protocol, service
      - crypto context (v0.4): crypto_protocol, algorithm, crypto_attack_class,
        key_material_exposed, crypto_evidence
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
    file: str | None = None
    line_number: int | None = None
    end_line: int | None = None
    code_snippet: str = ""

    # Network location (for CICDRunner-style findings)
    target: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None

    # Crypto context (v0.4)
    crypto_protocol: str | None = None
    algorithm: str | None = None
    crypto_attack_class: str | None = None
    key_material_exposed: str | None = None
    crypto_evidence: dict[str, Any] | None = None

    # Severity & confidence
    severity: Severity = "info"
    severity_verified: Severity | None = None
    confidence: Literal["high", "medium", "low"] = "medium"

    # Hunter output
    description: str = ""
    crash_evidence: str | None = None
    poc: str | None = None
    discovered_by: str = "unknown"

    # Evidence ladder
    evidence_level: EvidenceLevel = "suspicion"

    # Relationships
    related_finding_id: str | None = None
    related_cve: str | None = None
    seeded_from_crash: bool = False

    # Shared findings pool (spec 005)
    primitive_type: str = ""
    cluster_id: str = ""

    # Verifier (v0.2 adversarial)
    verified: bool = False
    verifier_pro_argument: str | None = None
    verifier_counter_argument: str | None = None
    verifier_tie_breaker: str | None = None

    # Patch oracle (v0.3)
    patch_oracle_passed: bool | None = None

    # Exploit triage
    exploit: str | None = None
    exploit_success: bool | None = None

    # Auto-patch (v0.3)
    auto_patch: str | None = None
    auto_patch_validated: bool | None = None

    # Session tracking
    hunter_session_id: str = ""
    verifier_session_id: str | None = None

    # Legacy network-finding fields (CICDRunner)
    cve: str | None = None  # CVE identifier for network findings
    cvss: float | None = None  # CVSS score
    details: str = ""  # legacy details blob

    # Extensible payload — v0.2/v0.3 seams, retro-hunt fields, etc.
    extra: dict[str, Any] = field(default_factory=dict)

    # --- Post-init validation ------------------------------------------------

    def __post_init__(self) -> None:
        """Auto-generate id, coerce severity, validate evidence_level."""
        if not self.id:
            self.id = f"f-{uuid.uuid4().hex[:8]}"
        self.severity = _coerce_severity(self.severity)
        if self.evidence_level not in _EVIDENCE_RANK:
            self.evidence_level = "suspicion"
        if self.file is None and self.target is None and self.finding_type:
            warnings.warn(
                f"Finding {self.id!r} has finding_type={self.finding_type!r} "
                "but neither file nor target is set",
                stacklevel=2,
            )

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
        try:
            return EVIDENCE_LEVELS.index(self.evidence_level) >= EVIDENCE_LEVELS.index("crash_reproduced")
        except ValueError:
            return False

    @property
    def is_crypto_finding(self) -> bool:
        """True if this Finding has crypto-specific context."""
        return bool(self.crypto_protocol or self.algorithm or self.crypto_attack_class)

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
        return isinstance(key, str) and (key in self.__dataclass_fields__ or key in self.extra)

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

    # --- Typed mutation methods ---------------------------------------------

    def mark_verified(
        self,
        *,
        is_real: bool = False,
        severity_verified: Severity | None = None,
        evidence_level: EvidenceLevel | None = None,
        pro_argument: str | None = None,
        counter_argument: str | None = None,
        tie_breaker: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Apply verifier results to this finding."""
        self.verified = is_real
        if severity_verified is not None:
            self.severity_verified = severity_verified
        if pro_argument is not None:
            self.verifier_pro_argument = pro_argument
        if counter_argument is not None:
            self.verifier_counter_argument = counter_argument
        if tie_breaker is not None:
            self.verifier_tie_breaker = tie_breaker
        if session_id is not None:
            self.verifier_session_id = session_id
        if evidence_level is not None:
            self.bump_evidence(evidence_level)

    def mark_exploited(
        self,
        *,
        exploit: str | None = None,
        success: bool | None = None,
        cost_usd: float | None = None,
        duration_seconds: float | None = None,
        partial: bool | None = None,
        primitive_type: str | None = None,
    ) -> None:
        """Apply exploiter results to this finding."""
        if exploit is not None:
            self.exploit = exploit
        if success is not None:
            self.exploit_success = success
        if cost_usd is not None:
            self.extra["exploit_cost_usd"] = cost_usd
        if duration_seconds is not None:
            self.extra["exploit_duration_seconds"] = duration_seconds
        if partial is not None and partial:
            self.extra["exploit_partial"] = True
            if primitive_type is not None:
                self.extra["exploit_primitive_type"] = primitive_type

    def apply_patch_result(
        self,
        *,
        diff: str | None = None,
        validated: bool | None = None,
        attempted: bool | None = None,
    ) -> None:
        """Apply auto-patcher results to this finding."""
        self.auto_patch = diff if diff else None
        if attempted is not None:
            self.auto_patch_validated = validated if attempted else None
        elif validated is not None:
            self.auto_patch_validated = validated
        if validated:
            self.bump_evidence("patch_validated")

    def bump_evidence(self, new_level: EvidenceLevel) -> None:
        """Bump evidence_level only if *new_level* is strictly higher."""
        current = self.evidence_level
        if current not in _EVIDENCE_RANK:
            current = "suspicion"
        if new_level not in _EVIDENCE_RANK:
            return
        if _EVIDENCE_RANK[new_level] > _EVIDENCE_RANK[current]:
            self.evidence_level = new_level


# --- Converters: from legacy shapes → Finding ------------------------------


def from_cicd_dict(d: dict, *, target: str | None = None) -> Finding:
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
        cwe=d.get("cve") or "",  # CWE often shares rule ID with CVE
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


def from_analysis_finding(finding: Any) -> Finding:
    """Build a Finding from a `clearwing.analysis.source_analyzer.AnalyzerFinding`.

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
        return s  # type: ignore[return-value]
    # Common variants
    mapping = {
        "err": "high",
        "error": "high",
        "warn": "medium",
        "warning": "medium",
        "note": "low",
        "none": "info",
        "unknown": "info",
    }
    return mapping.get(s, "info")  # type: ignore[return-value]
