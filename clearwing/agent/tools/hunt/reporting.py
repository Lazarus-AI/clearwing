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

import uuid

from pydantic import Field

from clearwing.core.events import EventBus, EventType
from clearwing.findings.types import TraceStep, VulnerabilityTrace
from clearwing.llm import NativeToolSpec, ToolInputModel
from clearwing.sourcehunt.instrumentation import stable_run_id
from clearwing.sourcehunt.state import Finding

from .sandbox import HunterContext


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
    finding_type: str
    severity: str
    cwe: str
    description: str
    code_snippet: str = ""
    crash_evidence: str = ""
    poc: str = ""
    confidence: str = "medium"
    evidence_level: str = "suspicion"
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
            return f"ERROR: file '{file}' has not been read yet. Call read_source_file first."
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
        # Echo the full accumulated trace back into the conversation so the
        # growing dataflow path stays part of the message sequence the model
        # reasons over before calling record_finding.
        lines = [f"Trace step {n} recorded. Trace so far ({n} step(s)):"]
        for i, s in enumerate(ctx.trace_steps, 1):
            loc = f"{s.file}:{s.line}"
            fn = f" {s.function}()" if s.function else ""
            note_str = f" — {s.note}" if s.note else ""
            lines.append(f"  {i}. {loc}{fn}{note_str}")
        return "\n".join(lines)

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
            cwe: CWE identifier (e.g. CWE-89, CWE-787, CWE-208).
            description: One- or two-sentence description of the bug.
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
        explicit_steps = trace.get("steps", []) if trace else []
        try:
            authoritative_steps = (
                list(ctx.trace_steps)
                if ctx.trace_steps
                else [TraceStep(**step) for step in explicit_steps]
            )
            if not authoritative_steps:
                return (
                    "ERROR: record_finding requires at least one trace step. "
                    "Call record_trace_step while reading the entry-to-sink path, "
                    "or pass a compatibility trace."
                )
            vuln_trace = VulnerabilityTrace(
                steps=authoritative_steps,
                summary=(trace or {}).get("summary", ""),
            )
        except Exception as exc:
            return (
                f"ERROR: invalid trace ({exc}). Each step needs at least "
                "`file` and `line`; optional `function`, `code_snippet`, `note`."
            )
        trace_dict = vuln_trace.model_dump()
        # Reset only after the authoritative steps are stored on the finding.
        ctx.trace_steps.clear()

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
                "Record one step in a vulnerability trace. Call this AS YOU "
                "READ CODE to build an incremental path from attacker input "
                "to vulnerable sink. The code_snippet MUST be copied from a "
                "prior read_source_file result."
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
