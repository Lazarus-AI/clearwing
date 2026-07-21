"""MITRE ATT&CK technique chain tracker for the Operator agent.

Tracks technique progression during autonomous exploitation and maps
tool invocations to ATT&CK technique IDs with context-aware inference.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

# ─── Tool → Technique mapping ───────────────────────────────────────────────

TOOL_TECHNIQUE_MAP: dict[str, str] = {
    "scan_ports": "T1595.002",
    "detect_services": "T1595.002",
    "scan_vulnerabilities": "T1595.002",
    "scan_tls_config": "T1595.002",
    "proxy_request": "T1190",  # contextual — see infer_technique()
    "kali_execute": "T1059.004",
    "start_callback_listener": "T1071.001",
    "check_callback_received": "T1071.001",
    "generate_c2_beacon": "T1071.001",
}

# Headers that indicate exploitation (vs. normal recon requests)
_EXPLOIT_HEADERS = (
    "spring.cloud.function.routing-expression",
    "x-forwarded-for",  # header injection
    "transfer-encoding",  # smuggling
)


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass
class AttackTechnique:
    """A single MITRE ATT&CK technique in the chain."""

    technique_id: str
    name: str
    tactic: str
    status: Literal["pending", "active", "completed"] = "pending"
    started_at: float | None = None
    completed_at: float | None = None
    evidence: str = ""


@dataclass
class AttackChain:
    """Ordered sequence of ATT&CK techniques representing the kill chain."""

    techniques: list[AttackTechnique] = field(default_factory=list)

    def advance(self, technique_id: str, status: str, evidence: str = "") -> AttackTechnique | None:
        """Advance a technique's status. Returns the technique if found."""
        for tech in self.techniques:
            if tech.technique_id == technique_id:
                if status == "active" and tech.status == "pending":
                    tech.status = "active"
                    tech.started_at = time.time()
                elif status == "completed" and tech.status in ("pending", "active"):
                    tech.status = "completed"
                    tech.completed_at = time.time()
                    if not tech.started_at:
                        tech.started_at = tech.completed_at
                if evidence:
                    tech.evidence = evidence
                return tech
        return None

    def current(self) -> AttackTechnique | None:
        """Return the currently active technique, or None."""
        for tech in self.techniques:
            if tech.status == "active":
                return tech
        return None

    def next_pending(self) -> AttackTechnique | None:
        """Return the next pending technique."""
        for tech in self.techniques:
            if tech.status == "pending":
                return tech
        return None

    def all_completed(self) -> bool:
        return all(t.status == "completed" for t in self.techniques)

    def summary(self) -> list[dict[str, Any]]:
        """Return a serializable summary for OperatorResult."""
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "status": t.status,
                "evidence": t.evidence,
                "duration_s": round(t.completed_at - t.started_at, 1)
                if t.completed_at and t.started_at
                else None,
            }
            for t in self.techniques
        ]


# ─── Default chain for CVE-2022-22963 demo ──────────────────────────────────


def default_chain() -> AttackChain:
    """Pre-populated chain for the Spring Cloud Function exploit demo."""
    return AttackChain(
        techniques=[
            AttackTechnique(
                technique_id="T1595.002",
                name="Active Scanning: Vulnerability Scanning",
                tactic="Reconnaissance",
            ),
            AttackTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
            ),
            AttackTechnique(
                technique_id="T1059.004",
                name="Command and Scripting Interpreter: Unix Shell",
                tactic="Execution",
            ),
            AttackTechnique(
                technique_id="T1071.001",
                name="Application Layer Protocol: Web Protocols",
                tactic="Command and Control",
            ),
            AttackTechnique(
                technique_id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic="Exfiltration",
            ),
        ]
    )


# ─── Context-aware technique inference ───────────────────────────────────────


def infer_technique(
    tool_name: str,
    tool_args: dict[str, Any] | None = None,
) -> str | None:
    """Infer ATT&CK technique ID from a tool invocation.

    Returns technique_id or None if the tool call doesn't map to a technique.
    Context-aware: proxy_request maps differently depending on headers.
    """
    if tool_name not in TOOL_TECHNIQUE_MAP:
        return None

    # proxy_request is contextual
    if tool_name == "proxy_request" and tool_args:
        headers = tool_args.get("headers", {})
        if isinstance(headers, dict):
            header_keys_lower = [k.lower() for k in headers]
            # Exploit delivery — check for known attack headers
            if any(h in header_keys_lower for h in _EXPLOIT_HEADERS):
                # Check if this looks like exfil (body contains file read / curl -d)
                body = str(tool_args.get("body", ""))
                if "passwd" in body or "shadow" in body or "exfil" in body.lower():
                    return "T1041"
                return "T1190"
        # Plain HTTP request during recon
        return None

    # kali_execute with curl to callback = T1059.004 (execution via shell)
    if tool_name == "kali_execute" and tool_args:
        command = str(tool_args.get("command", ""))
        if "curl" in command and "callback" in command:
            return "T1059.004"

    return TOOL_TECHNIQUE_MAP.get(tool_name)
