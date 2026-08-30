"""Finding-reporting and trace-building tools for the source-hunt hunter.

Two tools:
  - `record_trace_step`: incrementally build a vulnerability trace as
    the hunter explores code. Steps accumulate on ctx.trace_steps.
  - `record_finding`: surface a vulnerability into ctx.findings, consuming
    any accumulated trace steps into a VulnerabilityTrace.

This is where hunter-emitted hits become `clearwing.findings.Finding`
dataclass instances — the canonical shape consumed by the sourcehunt
verifier, exploiter, patcher, and reporter stages downstream.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Literal

from pydantic import Field

from clearwing.core.events import EventBus, EventType
from clearwing.findings.types import EvidenceLevel, Severity, TraceStep, VulnerabilityTrace
from clearwing.llm import NativeToolSpec, ToolInputModel
from clearwing.sourcehunt.instrumentation import stable_run_id
from clearwing.sourcehunt.state import Finding

from .sandbox import HunterContext

logger = logging.getLogger(__name__)

FindingType = Literal[
    "auth_bypass",
    "authorization_bypass",
    "buffer_overflow",
    "code_injection",
    "command_injection",
    "crypto_weakness",
    "cve_variant",
    "denial_of_service",
    "double_free",
    "heap_overflow",
    "info_leak",
    "insecure_deserialization",
    "integer_overflow",
    "integer_underflow",
    "logic_error",
    "memory_safety",
    "memory_safety_heap_overflow",
    "nonce_reuse",
    "oob",
    "out_of_bounds_read",
    "out_of_bounds_write",
    "padding_oracle",
    "parameter_validation",
    "path_traversal",
    "propagation_buffer_size",
    "propagation_default",
    "propagation_macro",
    "propagation_sentinel",
    "propagation_truncation",
    "race_condition",
    "signature_forgery",
    "sql_injection",
    "ssrf",
    "stack_overflow",
    "timing_side_channel",
    "truncation",
    "uaf",
    "use_after_free",
    "xss",
    "xxe",
    "other",
]
Confidence = Literal["high", "medium", "low"]

_INVARIANT_MAP_FIELDS = (
    "security_boundary",
    "security_invariant",
    "attacker_inputs",
    "required_relationships",
    "observed_checks",
    "missing_checks",
)


def _tool_error(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}


def _completed_invariant_potential(
    ctx: HunterContext, file: str, potential_id: str = ""
) -> dict | None:
    """Return a same-file potential whose security-boundary map is complete."""
    for potential in reversed(ctx.potentials):
        if potential_id and potential.get("id") != potential_id:
            continue
        if str(potential.get("file", "")).removeprefix("/workspace/") != file.removeprefix(
            "/workspace/"
        ):
            continue
        if all(potential.get(field) for field in _INVARIANT_MAP_FIELDS):
            return potential
    return None


class RecordTraceStepInput(ToolInputModel):
    file: str = Field(description="Repo-relative file path")
    line: int = Field(description="1-indexed line number")
    function: str = Field(default="", description="Enclosing function name")
    code_snippet: str = Field(
        default="",
        description="Exact code from read_source_file (do NOT fabricate)",
    )
    note: str = Field(
        default="",
        description="Free-form: role (entry/propagation/condition/sink), taint state, assumptions, reasoning",
    )


class CompatibilityTraceStepInput(ToolInputModel):
    file: str = Field(description="Repo-relative file path")
    line: int = Field(description="1-indexed line number")
    function: str = ""
    code_snippet: str = ""
    note: str = Field(
        default="",
        description="Role (ENTRY/PROPAGATION/CONDITION/SINK), taint state, assumptions",
    )


class CompatibilityTraceInput(ToolInputModel):
    steps: list[CompatibilityTraceStepInput] = Field(
        description="Ordered steps from entry to sink; include at least one ENTRY step and one SINK step."
    )
    summary: str = Field(default="", description="One-line dataflow summary")


class RecordFindingInput(ToolInputModel):
    file: str
    line_number: int
    finding_type: FindingType
    severity: Severity
    cwe: str = Field(
        default="",
        description=(
            "CWE identifier (for example CWE-89 or CWE-787). "
            "Leave blank when the finding is not yet classified."
        ),
    )
    description: str
    potential_id: str = Field(
        default="",
        description="ID of the completed invariant-mapped potential being promoted.",
    )
    code_snippet: str = ""
    crash_evidence: str = ""
    poc: str = ""
    confidence: Confidence = "medium"
    evidence_level: EvidenceLevel = "suspicion"
    crypto_protocol: str = ""
    algorithm: str = ""
    crypto_attack_class: str = ""
    key_material_exposed: str = ""
    trace: CompatibilityTraceInput | None = Field(
        default=None,
        description=(
            "Optional compatibility dataflow trace. Steps streamed via "
            "record_trace_step are authoritative and automatically persisted on the finding."
        ),
    )


def build_reporting_tools(ctx: HunterContext) -> list:
    """Build the finding-reporter and trace-step tools for a hunter session."""

    def record_trace_step(
        file: str,
        line: int,
        function: str = "",
        code_snippet: str = "",
        note: str = "",
        **_: object,
    ) -> str:
        """Record one step in the vulnerability trace being built.

        Call this AS YOU READ CODE to build an incremental path from
        attacker input to vulnerable sink. The code_snippet MUST come
        from a prior read_source_file result.

        Args:
            file: Repo-relative file path.
            line: 1-indexed line number.
            function: Enclosing function name.
            code_snippet: Exact code from read_source_file (do NOT fabricate).
            note: Free-form reasoning — role, taint state, assumptions.
        """
        # The files_read set is only populated by the constrained
        # read_source_file tool. Deep hunters read via read_file/execute
        # (cat/sed/grep), so files_read is not authoritative there — enforcing
        # it would reject every trace step. Skip the guard in deep mode;
        # downstream validators independently re-verify the assembled trace.
        if ctx.agent_mode != "deep" and file not in ctx.files_read:
            return _tool_error(
                "UNREAD_TRACE_SOURCE",
                f"File '{file}' has not been read yet. Call read_source_file first.",
            )
        ranges = ctx.read_ranges.get(file, [])
        if ctx.agent_mode != "deep" and ranges and not any(
            start <= line <= end for start, end in ranges
        ):
            return _tool_error(
                "UNREAD_TRACE_SOURCE",
                f"Line {line} of '{file}' has not been read yet. "
                "Call read_source_file for that range first.",
            )
        step = TraceStep(
            file=file,
            line=line,
            function=function,
            code_snippet=code_snippet,
            note=note,
        )
        ctx.trace_steps.append(step)
        n = len(ctx.trace_steps)
        EventBus().emit(
            EventType.TRACE_STEP,
            {
                "hunter_target": ctx.file_path,
                "file": file,
                "line": line,
                "function": function,
                "note": note,
                "step_number": n,
            },
        )
        logger.info(
            "[%s] trace#%d %s:%s%s%s",
            ctx.file_path,
            n,
            file,
            line,
            f" ({function})" if function else "",
            f" — {note[:120]}" if note else "",
        )
        return f"Trace step {n} recorded."

    def record_finding(
        file: str,
        line_number: int,
        finding_type: str,
        severity: str,
        description: str,
        potential_id: str = "",
        cwe: str = "",
        code_snippet: str = "",
        crash_evidence: str = "",
        poc: str = "",
        confidence: str = "medium",
        evidence_level: str = "suspicion",
        crypto_protocol: str = "",
        algorithm: str = "",
        crypto_attack_class: str = "",
        key_material_exposed: str = "",
        trace: dict | None = None,
        **_: object,
    ) -> str:
        """Record a finding into the hunter's state.

        The hunter MUST call this tool to report a vulnerability. Findings
        are appended to ctx.findings and surfaced via the hunter's output.

        Steps emitted by `record_trace_step` are the authoritative trace and
        are persisted on the finding. The optional `trace` argument remains a
        compatibility fallback for callers that cannot stream steps.

        Args:
            file: Repo-relative file path where the finding lives.
            line_number: 1-indexed line number.
            finding_type: e.g. sql_injection, memory_safety, timing_side_channel.
            severity: critical / high / medium / low / info.
            description: One- or two-sentence description of the bug.
            cwe: CWE identifier (e.g. CWE-89, CWE-787, CWE-208). Leave blank
                if unclassified — don't block on picking one.
            code_snippet: Relevant code snippet (helpful for triage).
            crash_evidence: Sanitizer/PoC output if available.
            poc: Proof-of-concept input.
            confidence: high / medium / low.
            evidence_level: One of [suspicion, static_corroboration,
                parameter_anomaly, timing_confirmed, crash_reproduced,
                root_cause_explained, assumption_broken, exploit_demonstrated,
                key_material_recovered, patch_validated]. Defaults to suspicion.
            crypto_protocol: Crypto protocol name (e.g. SRP-6a, TLS 1.3).
            algorithm: Algorithm name (e.g. PBKDF2-HMAC-SHA256, AES-256-GCM).
            crypto_attack_class: Attack class (e.g. timing_side_channel,
                parameter_validation, nonce_reuse, padding_oracle).
            key_material_exposed: Description of key material at risk.
            trace: Optional compatibility trace or summary. Streamed trace
                steps take precedence when present.
        """
        if isinstance(trace, str):
            try:
                trace = json.loads(trace)
            except json.JSONDecodeError as exc:
                return _tool_error("INVALID_TRACE_JSON", f"Invalid trace JSON ({exc}).")
        explicit_steps = trace.get("steps", []) if trace else []
        try:
            authoritative_steps = (
                list(ctx.trace_steps)
                if ctx.trace_steps
                else [TraceStep(**step) for step in explicit_steps]
            )
            if not authoritative_steps:
                return _tool_error(
                    "MISSING_TRACE",
                    "record_finding requires at least one trace step. Call "
                    "record_trace_step while reading the entry-to-sink path, or "
                    "pass a compatibility trace.",
                )
            notes = "\n".join(step.note for step in authoritative_steps)
            missing_roles = [
                role
                for role in ("ENTRY", "SINK")
                if re.search(rf"\b{role}\b", notes, re.IGNORECASE) is None
            ]
            if missing_roles:
                return _tool_error(
                    "INCOMPLETE_TRACE",
                    "record_finding requires explicit ENTRY and SINK roles in trace "
                    f"step notes; missing: {', '.join(missing_roles)}.",
                )
            vuln_trace = VulnerabilityTrace(
                steps=authoritative_steps,
                summary=(trace or {}).get("summary", ""),
            )
        except Exception as exc:
            return _tool_error(
                "INVALID_TRACE",
                f"Invalid trace ({exc}). Each step needs at least `file` and "
                "`line`; optional `function`, `code_snippet`, `note`.",
            )
        trace_dict = vuln_trace.model_dump()

        # Direct/legacy reporting callers may not use the potential queue. Once
        # a hunt does use it, however, promotion must come from a same-file lead
        # with an explicit security-contract map rather than a sink-only hunch.
        promoted_potential = _completed_invariant_potential(ctx, file, potential_id)
        if (ctx.require_invariant_map or ctx.potentials) and promoted_potential is None:
            return _tool_error(
                "INCOMPLETE_INVARIANT_MAP",
                "Before record_finding, update a potential in this file with its security "
                "boundary, security invariant, attacker inputs, required relationships, "
                "observed checks, and missing checks. Pass potential_id when more than one "
                "lead exists.",
            )

        duplicate = next(
            (f for f in ctx.findings if f.file == file and f.line_number == line_number),
            None,
        )
        if duplicate is not None:
            return _tool_error(
                "DUPLICATE_FINDING",
                f"Finding at {file}:{line_number} was already recorded earlier "
                f"in this session (finding_type={duplicate.finding_type!r}, "
                f"severity={duplicate.severity!r}). Skipping this duplicate "
                "call — if you have new information about a different issue, "
                "record it at a different line instead of re-reporting this one.",
            )

        stable_finding_id = stable_run_id(
            "hunter",
            {
                "run_id": ctx.session_id or "",
                "work_item_id": ctx.work_item_id or "",
                "file": file,
                "line": line_number,
                "type": finding_type,
                "cwe": cwe,
                "description": description,
                "trace": trace_dict,
            },
        )
        finding_metadata = {"stable_finding_id": stable_finding_id}
        if ctx.work_item_id:
            finding_metadata["work_item_id"] = ctx.work_item_id

        finding = Finding(
            # Keep the public legacy identifier shape stable. Evaluation and
            # instrumentation use the deterministic identifier in ``extra``.
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
            crypto_protocol=crypto_protocol or None,
            algorithm=algorithm or None,
            crypto_attack_class=crypto_attack_class or None,
            key_material_exposed=key_material_exposed or None,
            vulnerability_trace=trace_dict,
            extra=finding_metadata,
        )
        ctx.findings.append(finding)
        if promoted_potential is not None:
            ctx.potentials.remove(promoted_potential)
            confirmed = dict(promoted_potential)
            confirmed["status"] = "confirmed"
            confirmed["finding_id"] = finding.id
            ctx.potential_history.append(confirmed)
        # Consume streamed trace evidence only after every validation and
        # duplicate check succeeds. A rejected report must not destroy evidence
        # intended for a later legitimate finding.
        ctx.trace_steps.clear()
        EventBus().emit(
            EventType.FINDING_RECORDED,
            {
                "finding_id": finding.id,
                "stable_finding_id": stable_finding_id,
                "file": file,
                "line_number": line_number,
                "finding_type": finding_type,
                "severity": severity,
                "cwe": cwe,
                "description": description,
                "confidence": confidence,
                "evidence_level": evidence_level,
                "hunter_target": ctx.file_path,
            },
        )
        trace_msg = f", trace={len(trace_dict['steps'])} steps" if trace_dict else ""
        return (
            f"Finding recorded: {finding_type} at {file}:{line_number} "
            f"(severity={severity}, evidence_level={evidence_level}{trace_msg})"
        )

    return [
        NativeToolSpec(
            name="record_trace_step",
            description=(
                "Record one source-backed step in a vulnerability trace from "
                "attacker input to vulnerable sink. The code_snippet must be "
                "copied from a prior source-reading tool result."
            ),
            schema=RecordTraceStepInput.model_json_schema(),
            handler=record_trace_step,
        ),
        NativeToolSpec(
            name="record_finding",
            description="Record a verified or suspected finding into the hunter state.",
            schema=RecordFindingInput.model_json_schema(),
            handler=record_finding,
        ),
    ]
