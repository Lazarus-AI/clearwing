"""Per-hunter ReAct tools, scoped to a single sandboxed hunt session.

All tools are built via `build_hunter_tools(ctx)` where `ctx` is a
HunterContext containing the SandboxContainer and a mutable findings list.
The closure prevents path traversal and routes every command through the
sandbox.

Tool subsets:
    build_hunter_tools(ctx)            — full set for memory_safety / general
    build_propagation_auditor_tools(ctx) — narrower set for Tier C auditors
                                           (no compile/run; just read/grep)
"""

from __future__ import annotations

import logging
import uuid

from langchain_core.tools import tool

from clearwing.sourcehunt.state import Finding

from .analysis import (  # noqa: F401 — re-exported for tests
    _default_libfuzzer_template,
    _parse_sanitizer_report,
    build_analysis_tools,
)
from .discovery import (  # noqa: F401 — re-exported for tests
    _container_path,
    _grep_python_fallback,
    _normalize_path,
    _parse_rg_output,
    build_discovery_tools,
)
from .sandbox import HunterContext, _parse_variant_arg  # noqa: F401 — re-exported

logger = logging.getLogger(__name__)


# --- Tool builders ----------------------------------------------------------


def build_hunter_tools(ctx: HunterContext) -> list:
    """Full hunter tool set for memory_safety / logic_auth / general specialists.

    Includes file I/O, grep, compile + run with sanitizer, scratch writes,
    and record_finding.
    """

    discovery_tools = build_discovery_tools(ctx)

    analysis_tools = build_analysis_tools(ctx)

    @tool
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
        *discovery_tools,
        *analysis_tools,
        record_finding,
    ]


def build_propagation_auditor_tools(ctx: HunterContext) -> list:
    """Narrower tool set for Tier C propagation auditors.

    Tier C auditors don't compile or run — they grep and reason about
    downstream usages of definitions. This subset keeps them cheap and
    on-task.
    """
    full = build_hunter_tools(ctx)
    # Names of the tools we want to keep
    keep = {"read_source_file", "list_source_tree", "grep_source", "find_callers", "record_finding"}
    return [t for t in full if t.name in keep]
