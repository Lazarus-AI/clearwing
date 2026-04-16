"""Finding-reporting tool for the source-hunt hunter.

A single tool, `record_finding`, that the hunter calls to surface a
vulnerability into `ctx.findings`. This is where hunter-emitted hits
become `clearwing.findings.Finding` dataclass instances — the canonical
shape consumed by the sourcehunt verifier, exploiter, patcher, and
reporter stages downstream.
"""

from __future__ import annotations

import uuid

from clearwing.llm import NativeToolSpec
from clearwing.sourcehunt.state import Finding

from .sandbox import HunterContext


def build_reporting_tools(ctx: HunterContext) -> list:
    """Build the single finding-reporter tool for a hunter session."""

    def record_finding(
        file: str,
        line_number: int,
        finding_type: str,
        severity: str,
        cwe: str,
        description: str,
        code_snippet: str = "",
        crash_evidence: str = "",
        poc: str = "",
        confidence: str = "medium",
        evidence_level: str = "suspicion",
    ) -> str:
        """Record a finding into the hunter's state.

        The hunter MUST call this tool to report a vulnerability. Findings
        are appended to ctx.findings and surfaced via the hunter's output.

        Args:
            file: Repo-relative file path where the finding lives.
            line_number: 1-indexed line number.
            finding_type: e.g. sql_injection, memory_safety, propagation_buffer_size.
            severity: critical / high / medium / low / info.
            cwe: CWE identifier (e.g. CWE-89, CWE-787).
            description: One- or two-sentence description of the bug.
            code_snippet: Relevant code snippet (helpful for triage).
            crash_evidence: Sanitizer/PoC output if available.
            poc: Proof-of-concept input.
            confidence: high / medium / low.
            evidence_level: One of [suspicion, static_corroboration,
                crash_reproduced, root_cause_explained, exploit_demonstrated,
                patch_validated]. Defaults to suspicion; bump to crash_reproduced
                if you have a sanitizer report, or root_cause_explained if you
                wrote a coherent explanation.
        """
        finding = Finding(
            id=f"hunter-{uuid.uuid4().hex[:8]}",
            file=file,
            line_number=line_number,
            finding_type=finding_type,
            cwe=cwe,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            description=description,
            code_snippet=code_snippet,
            crash_evidence=crash_evidence or None,
            poc=poc or None,
            evidence_level=evidence_level,  # type: ignore[arg-type]
            discovered_by=f"hunter:{ctx.specialist}",
            seeded_from_crash=ctx.seeded_crash is not None,
            hunter_session_id=ctx.session_id or "",
        )
        ctx.findings.append(finding)
        return (
            f"Finding recorded: {finding_type} at {file}:{line_number} "
            f"(severity={severity}, evidence_level={evidence_level})"
        )

    return [
        NativeToolSpec(
            name="record_finding",
            description="Record a verified or suspected finding into the hunter state.",
            schema={
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "finding_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "cwe": {"type": "string"},
                    "description": {"type": "string"},
                    "code_snippet": {"type": "string", "default": ""},
                    "crash_evidence": {"type": "string", "default": ""},
                    "poc": {"type": "string", "default": ""},
                    "confidence": {"type": "string", "default": "medium"},
                    "evidence_level": {"type": "string", "default": "suspicion"},
                },
                "required": [
                    "file",
                    "line_number",
                    "finding_type",
                    "severity",
                    "cwe",
                    "description",
                ],
            },
            handler=record_finding,
        )
    ]
