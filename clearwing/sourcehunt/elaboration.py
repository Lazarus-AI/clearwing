"""Stage 1.5: Exploit elaboration — upgrade partial exploits to higher impact.

Two modes:
  - Interactive HITL: researcher guides model to upgrade a partial exploit
  - Autonomous agent: specialized prompt attempts upgrade without human input

The elaboration agent reuses the NativeHunter ReAct loop with deep agent tools
plus a record_elaboration_result tool, matching the AgenticExploiter pattern.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
from pathlib import Path
from typing import Any

from clearwing.llm import AsyncLLMClient, BudgetExceeded, NativeToolSpec

from .exploiter import EXPLOIT_BUDGET_BANDS
from .state import (
    ElaborationResult,
    EvidenceLevel,
    Finding,
    evidence_at_or_above,
)

logger = logging.getLogger(__name__)


# --- Constants ---------------------------------------------------------------

PRIMITIVE_RANK: dict[str, int] = {
    "arbitrary_write": 10,
    "use_after_free": 9,
    "type_confusion": 8,
    "arbitrary_read": 7,
    "bounded_write": 6,
    "bounded_read": 5,
    "info_leak": 4,
    "denial_of_service": 3,
    "logic_error": 2,
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_TARGET_VALUE_PATTERNS: list[tuple[str, int]] = [
    ("kernel/", 3),
    ("drivers/", 3),
    ("net/", 2),
    ("fs/", 2),
    ("crypto/", 2),
    ("security/", 2),
    ("arch/", 2),
]

ELABORATION_AGENT_PROMPT = """\
You have an autonomous PoC for a vulnerability that achieves {current_impact}. \
Your job is to try to upgrade it to a higher-severity exploit.

Current PoC:
{poc_summary}

Primitive available:
{primitive_type}

Target value: {target_class}

{verifier_context}

{shared_findings_context}

Try to achieve, in order of priority:
1. Full sandbox/container escape (if in sandboxed context)
2. Cross-origin/cross-tenant boundary violation
3. Privilege escalation beyond current primitive
4. Remote code execution (if currently local only)

Approach:
1. Understand exactly what the current primitive gives you
2. Survey defenses — and verify whether each actually applies on this path
3. If the primitive alone is not sufficient, query the findings pool for \
complementary primitives (use the query_findings_pool tool)
4. Develop incrementally — get each stage working before combining
5. Use longer timeouts for builds: execute(command="make ...", timeout=600)
6. Call record_elaboration_result when done

If you can upgrade the impact, report the elaborated exploit. If not, report \
why the upgrade isn't feasible — that's valuable triage information too."""


# --- Prompt builder ----------------------------------------------------------


def _build_elaboration_prompt(
    finding: Finding,
    findings_pool: Any = None,
) -> str:
    current_impact = finding.get("exploit_impact") or finding.get("impact") or "unknown"
    poc_summary = (finding.get("exploit") or finding.get("poc") or "none")[:4000]
    primitive = (
        finding.get("exploit_primitive_type")
        or finding.get("primitive_type")
        or "unknown"
    )

    file_path = finding.get("file", "?")
    target_class = "userspace"
    for pattern, _ in _TARGET_VALUE_PATTERNS:
        if pattern in file_path:
            target_class = pattern.rstrip("/")
            break

    verifier_parts = []
    counter = finding.get("verifier_counter_argument")
    if counter:
        verifier_parts.append(f"Verifier counter-argument: {counter}")
    pro = finding.get("verifier_pro_argument")
    if pro:
        verifier_parts.append(f"Verifier pro-argument: {pro}")
    verifier_context = "\n".join(verifier_parts) if verifier_parts else ""

    pool_context = ""
    if findings_pool is not None:
        try:
            summary = findings_pool.summary()
            if summary:
                pool_context = (
                    "Other findings in this project you can chain with:\n"
                    f"{summary}\n\n"
                    "Use query_findings_pool to find complementary primitives."
                )
        except Exception:
            pass

    return ELABORATION_AGENT_PROMPT.format(
        current_impact=current_impact,
        poc_summary=poc_summary,
        primitive_type=primitive,
        target_class=target_class,
        verifier_context=verifier_context,
        shared_findings_context=pool_context,
    )


# --- Elaboration tools -------------------------------------------------------


def build_elaboration_tools(
    ctx: Any,
    finding: Finding,
) -> list[NativeToolSpec]:
    """Build the elaboration agent tool set.

    Inherits all deep agent tools and adds record_elaboration_result.
    """
    from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools

    deep_tools = build_deep_agent_tools(ctx)

    def record_elaboration_result(
        elaborated: bool = False,
        upgraded_impact: str = "",
        upgraded_exploit_code: str = "",
        chained_findings: list | None = None,
        upgrade_path: str = "",
        blocking_mitigations: list | None = None,
        notes: str = "",
    ) -> str:
        ctx.elaboration_result = ElaborationResult(
            original_finding_id=finding.get("id", "unknown"),
            elaborated=bool(elaborated),
            upgraded_impact=upgraded_impact or None,
            upgraded_exploit_code=upgraded_exploit_code or None,
            chained_findings=list(chained_findings or []),
            upgrade_path=upgrade_path,
            blocking_mitigations=list(blocking_mitigations or []),
        )
        status = "UPGRADED" if elaborated else "NOT_UPGRADED"
        return f"Elaboration result recorded: {status} — {upgraded_impact or notes}"

    elab_tool = NativeToolSpec(
        name="record_elaboration_result",
        description=(
            "Record the result of your exploit elaboration attempt. "
            "Call this when you are done — whether you successfully "
            "upgraded the exploit or determined the upgrade isn't feasible."
        ),
        schema={
            "type": "object",
            "properties": {
                "elaborated": {
                    "type": "boolean",
                    "description": "True if you upgraded the exploit to higher impact.",
                },
                "upgraded_impact": {
                    "type": "string",
                    "description": (
                        "New impact if elaborated: code_execution, "
                        "privilege_escalation, sandbox_escape, "
                        "cross_origin_bypass, remote_code_execution."
                    ),
                },
                "upgraded_exploit_code": {
                    "type": "string",
                    "description": "The upgraded exploit script or PoC.",
                },
                "chained_findings": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs of other findings used in the chain.",
                },
                "upgrade_path": {
                    "type": "string",
                    "description": (
                        "Description of the upgrade path attempted "
                        "(e.g., 'heap spray -> cross-origin bypass')."
                    ),
                },
                "blocking_mitigations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Mitigations that prevented the upgrade.",
                },
                "notes": {
                    "type": "string",
                    "description": "Free-form notes about the attempt.",
                },
            },
            "required": ["elaborated"],
        },
        handler=record_elaboration_result,
    )

    return [*deep_tools, elab_tool]


# --- Prioritization ----------------------------------------------------------


def _is_elaboration_eligible(finding: Finding) -> bool:
    if not finding.get("verified", False):
        return False
    if not evidence_at_or_above(
        finding.get("evidence_level", "suspicion"), "crash_reproduced"
    ):
        return False
    return bool(finding.get("exploit_partial")) or bool(finding.get("exploit_success"))


def _severity_rank(finding: Finding) -> int:
    sev = (
        finding.get("severity_verified") or finding.get("severity") or "info"
    ).lower()
    return _SEVERITY_ORDER.get(sev, 0)


def _primitive_rank(finding: Finding) -> int:
    prim = (
        finding.get("exploit_primitive_type")
        or finding.get("primitive_type")
        or ""
    ).lower()
    return PRIMITIVE_RANK.get(prim, 0)


def _target_value(finding: Finding) -> int:
    file_path = finding.get("file", "")
    for pattern, value in _TARGET_VALUE_PATTERNS:
        if pattern in file_path:
            return value
    return 1


def prioritize_for_elaboration(
    verified_findings: list[Finding],
    cap: str | int = "10%",
) -> list[Finding]:
    eligible = [f for f in verified_findings if _is_elaboration_eligible(f)]
    eligible.sort(
        key=lambda f: (_severity_rank(f), _primitive_rank(f), _target_value(f)),
        reverse=True,
    )

    if isinstance(cap, str) and cap.endswith("%"):
        pct = float(cap.rstrip("%")) / 100.0
        max_count = max(1, math.ceil(len(verified_findings) * pct))
    else:
        max_count = int(cap)

    return eligible[:max_count]


# --- Finding loading ---------------------------------------------------------


def load_finding_from_session(
    output_dir: str,
    session_id: str,
    finding_id: str,
) -> Finding | None:
    json_path = Path(output_dir) / session_id / "findings.json"
    if not json_path.exists():
        return None
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    for f_data in data.get("findings", []) + data.get("verified_findings", []):
        fid = f_data.get("id", "") if isinstance(f_data, dict) else ""
        if fid == finding_id:
            return f_data
    return None


def load_session_findings(
    output_dir: str,
    session_id: str,
) -> list[Finding]:
    json_path = Path(output_dir) / session_id / "findings.json"
    if not json_path.exists():
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return data.get("findings", [])


def find_latest_session(output_dir: str) -> str | None:
    out = Path(output_dir)
    if not out.exists():
        return None
    latest_time = 0.0
    latest_session = None
    for manifest in out.rglob("manifest.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            mtime = manifest.stat().st_mtime
            if mtime > latest_time and "session_id" in data:
                latest_time = mtime
                latest_session = data["session_id"]
        except (json.JSONDecodeError, OSError):
            continue
    return latest_session


# --- ElaborationAgent --------------------------------------------------------


def _safe_id(finding_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", finding_id)


class ElaborationAgent:
    """Multi-turn exploit elaboration agent (spec 008).

    Reuses NativeHunter with deep agent tools + elaboration-specific tools.
    Attempts to upgrade a partial exploit to higher impact.
    """

    ELABORATION_GATE: EvidenceLevel = "crash_reproduced"

    def __init__(
        self,
        llm: AsyncLLMClient,
        sandbox_manager: Any = None,
        sandbox_factory: Any = None,
        findings_pool: Any = None,
        budget_band: str = "standard",
        output_dir: str = "",
        project_name: str = "target",
    ):
        self.llm = llm
        self.sandbox_manager = sandbox_manager
        self.sandbox_factory = sandbox_factory
        self.findings_pool = findings_pool
        self.output_dir = output_dir
        self.project_name = project_name
        self._band = EXPLOIT_BUDGET_BANDS[budget_band]

    def is_eligible(self, finding: Finding) -> bool:
        if not finding.get("verified", False):
            return False
        if not evidence_at_or_above(
            finding.get("evidence_level", "suspicion"),
            self.ELABORATION_GATE,
        ):
            return False
        return bool(finding.get("exploit_partial")) or bool(
            finding.get("exploit_success")
        )

    async def aattempt(self, finding: Finding) -> ElaborationResult:
        finding_id = finding.get("id", "unknown")

        if not self.is_eligible(finding):
            return ElaborationResult(
                original_finding_id=finding_id,
                elaborated=False,
                upgrade_path="Skipped — not eligible for elaboration.",
            )

        if self.sandbox_manager is None and self.sandbox_factory is None:
            return ElaborationResult(
                original_finding_id=finding_id,
                elaborated=False,
                upgrade_path="No sandbox available for elaboration.",
            )

        from clearwing.agent.tools.hunt.sandbox import HunterContext
        from clearwing.sourcehunt.hunter import NativeHunter

        sandbox = None
        transcript_dir = None
        if self.output_dir:
            transcript_dir = (
                Path(self.output_dir) / "elaborations" / _safe_id(finding_id)
            )
            transcript_dir.mkdir(parents=True, exist_ok=True)

        try:
            sandbox = self._spawn_sandbox()
            if sandbox is None:
                return ElaborationResult(
                    original_finding_id=finding_id,
                    elaborated=False,
                    upgrade_path="Failed to spawn elaboration sandbox.",
                )

            session_id = f"elaborate-{_safe_id(finding_id)}"
            ctx = HunterContext(
                repo_path="/workspace",
                sandbox=sandbox,
                file_path=finding.get("file"),
                session_id=session_id,
                specialist="elaboration",
                findings_pool=self.findings_pool,
                trajectory_dir=transcript_dir,
            )

            tools = build_elaboration_tools(ctx, finding)
            prompt = _build_elaboration_prompt(
                finding,
                findings_pool=self.findings_pool,
            )

            finding_file = finding.get("file", "?")
            finding_line = finding.get("line_number", "?")
            finding_cwe = finding.get("cwe", "?")
            current_impact = (
                finding.get("exploit_impact") or finding.get("impact") or "unknown"
            )

            hunter = NativeHunter(
                llm=self.llm,
                prompt=prompt,
                tools=tools,
                ctx=ctx,
                max_steps=self._band["max_steps"],
                agent_mode="deep",
                budget_usd=self._band["budget_usd"],
                initial_user_message=(
                    f"Upgrade the exploit for finding {finding_id} — "
                    f"{finding_cwe} at {finding_file}:{finding_line}. "
                    f"Current impact: {current_impact}. "
                    f"Try to achieve higher-severity exploitation."
                ),
            )

            try:
                run_result = await asyncio.wait_for(
                    hunter.arun(),
                    timeout=self._band["timeout_seconds"],
                )
            except asyncio.TimeoutError:
                run_result = None

            transcript_path = ""
            if transcript_dir is not None:
                tp = transcript_dir / "transcript.jsonl"
                if tp.exists():
                    transcript_path = str(tp)

            if ctx.elaboration_result is not None:
                result = ctx.elaboration_result
                result.cost = run_result.cost_usd if run_result else 0.0
                result.transcript_path = transcript_path
                return result

            return ElaborationResult(
                original_finding_id=finding_id,
                elaborated=False,
                upgrade_path=(
                    f"Agent terminated "
                    f"({run_result.stop_reason if run_result else 'timeout'}) "
                    "without recording elaboration result."
                ),
                cost=run_result.cost_usd if run_result else 0.0,
                transcript_path=transcript_path,
            )

        except BudgetExceeded:
            raise
        except Exception as e:
            logger.warning(
                "Elaboration agent error for %s", finding_id, exc_info=True,
            )
            return ElaborationResult(
                original_finding_id=finding_id,
                elaborated=False,
                upgrade_path=f"elaboration error: {e}",
                cost=0.0,
            )
        finally:
            if sandbox is not None:
                try:
                    sandbox.stop()
                except Exception:
                    pass

    def _spawn_sandbox(self):
        if self.sandbox_manager is not None:
            return self.sandbox_manager.spawn(
                writable_workspace=True,
                timeout_seconds=self._band["timeout_seconds"],
            )
        if self.sandbox_factory is not None:
            return self.sandbox_factory()
        return None
