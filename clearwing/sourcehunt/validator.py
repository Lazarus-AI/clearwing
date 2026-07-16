"""Unified 4-axis validator (spec 009).

Replaces the two-stage adversarial verifier + triage agent with a single
stage evaluating: REAL, TRIGGERABLE, IMPACTFUL, GENERAL. The old Verifier
class in verifier.py stays for backward compatibility.

Independence guarantee: the validator sees ONLY the finding report, PoC,
and exploit — never the discovery agent's transcript or reasoning chain.
"""

from __future__ import annotations

import json
import logging
import re
from itertools import islice
from typing import Any, Literal, cast

from pydantic import BaseModel, Field

from clearwing.core.event_payloads import ValidationResultPayload
from clearwing.core.events import EventBus
from clearwing.llm import AsyncLLMClient, BudgetExceeded
from clearwing.llm.native import response_text

from .state import (
    EVIDENCE_LEVELS,
    Axes,
    AxisResult,
    EvidenceLevel,
    Finding,
    ValidatorVerdict,
    evidence_at_or_above,
)

logger = logging.getLogger(__name__)

_LINE_REF_RE = re.compile(r"\blines?\s+(\d+)(?:\s*-\s*(\d+))?")

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --- Prompts -----------------------------------------------------------------


VALIDATOR_SYSTEM_PROMPT = """\
You are an INDEPENDENT VALIDATOR. A discovery agent reported a potential \
vulnerability. You did NOT find this bug. Your job is to determine whether \
it is real and interesting by evaluating four axes.

For each axis, build the STRONGEST possible counter-argument, then decide.

## AXIS 1: REAL
Does this bug actually exist in the code as described? Reproduce the crash \
or behavior if a PoC is provided. Run it. Is the root cause what the report \
claims, or is the analysis wrong?

## AXIS 2: TRIGGERABLE
Can attacker-controlled input reach this code path in a production deployment?
- Is this reachable from any external entry point (network, file parsing, IPC)?
- Do callers enforce invariants that prevent the dangerous input?
- Is the function dead code or only called from test harnesses?

## AXIS 3: IMPACTFUL
Does this cross a meaningful security boundary?
- Privilege escalation, tenant isolation, cross-origin, user boundary, \
kernel/user, sandbox escape?
- Or is it same-origin / same-process with no escalation?
- Is severity proportional to actual impact, or overstated?

## AXIS 4: GENERAL
Is this exploitable in realistic configurations?
- Default configs? Common deployment patterns?
- Or does it require exotic compile flags, deprecated features, unusual setup?

## REPRODUCTION (MANDATORY)
If a PoC is provided, you MUST attempt to reproduce it. Report the exact result.

## OUTPUT — return ONLY this JSON:
{
  "axes": {
    "real": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."},
    "triggerable": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."},
    "impactful": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "...", \
"boundary_crossed": "privilege|tenant|origin|user|kernel|sandbox|none"},
    "general": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."}
  },
  "advance": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_level": "static_corroboration|crash_reproduced|root_cause_explained",
  "pro_argument": "max 200 words — strongest case FOR the vulnerability",
  "counter_argument": "max 200 words — strongest case AGAINST",
  "tie_breaker": "what single piece of evidence resolved it",
  "duplicate_cve": null
}

A finding advances ONLY if all four axes pass, or if REAL + IMPACTFUL pass \
and TRIGGERABLE + GENERAL have confidence >= medium with stated assumptions."""


VALIDATOR_QUICK_PROMPT = """\
You are a quick-pass validator. Check ONLY whether:

1. REAL — does this bug exist in the code as described? If there is a PoC, \
reproduce it.
2. TRIGGERABLE — is this code path reachable from attacker-controlled input \
in a production deployment?

If BOTH pass, the finding advances to full validation. If either fails, reject.

Return ONLY this JSON:
{
  "axes": {
    "real": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."},
    "triggerable": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."}
  },
  "advance": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_level": "static_corroboration|crash_reproduced|root_cause_explained",
  "pro_argument": "one paragraph",
  "counter_argument": "one paragraph",
  "tie_breaker": "what evidence resolved it",
  "duplicate_cve": null
}"""


# --- Enforced structured output schema ---------------------------------------
# The prompts already ask for exactly this JSON; passing it as a schema_model to
# aask_json turns it into a genai-pyo3 response_json_spec so the gateway emits it
# via constrained decoding. That eliminates the "empty first_text / no JSON"
# failure mode reasoning models hit with free-form aask_text. The per-axis value
# is the shared AxisResult (state.py) — used verbatim by the domain verdict too,
# so there is no wire-to-domain axis mapper. This wire container only makes real
# + triggerable required and impactful/general optional (the quick pass omits
# them); the domain Axes container is all-optional to also cover the error case.


class _AxesSchema(BaseModel):
    """The four validation axes.

    real and triggerable are always required. impactful and general are omitted
    on the two-axis quick pass, so they are optional here.
    """

    real: AxisResult = Field(
        description=(
            "Does the bug exist in the code as described? Reproduce the crash "
            "or behavior if a PoC is provided."
        )
    )
    triggerable: AxisResult = Field(
        description=(
            "Can attacker-controlled input reach this code path in a production "
            "deployment, or do callers/entry points prevent it?"
        )
    )
    impactful: AxisResult | None = Field(
        default=None,
        description=(
            "Does the bug cross a meaningful security boundary? Omit on the "
            "quick pass."
        ),
    )
    general: AxisResult | None = Field(
        default=None,
        description=(
            "Is it exploitable in realistic default configurations rather than "
            "exotic setups? Omit on the quick pass."
        ),
    )


class _VerdictSchema(BaseModel):
    """Independent validator verdict for a single reported finding.

    The model produces only the judgment fields below. Domain-owned fields
    (finding_id, the derived severity, raw_response, and the patch-oracle
    results) are supplied by to_verdict, not by the model.
    """

    axes: _AxesSchema = Field(description="Per-axis judgments.")
    advance: bool = Field(
        description=(
            "True only if all provided axes pass, or real + impactful pass and "
            "triggerable + general have confidence >= medium."
        )
    )
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Validated severity of the finding."
    )
    evidence_level: Literal[
        "static_corroboration", "crash_reproduced", "root_cause_explained"
    ] = Field(description="Strength of the evidence gathered during validation.")
    pro_argument: str = Field(
        default="", description="Strongest case FOR the vulnerability."
    )
    counter_argument: str = Field(
        default="", description="Strongest case AGAINST the vulnerability."
    )
    tie_breaker: str = Field(
        default="", description="The single piece of evidence that resolved it."
    )
    duplicate_cve: str | None = Field(
        default=None,
        description="CVE id if this duplicates a known issue, else null.",
    )

    def to_verdict(self, finding_id: str) -> ValidatorVerdict:
        """Map this validated wire object to the domain ValidatorVerdict.

        The LLM only produces judgment fields; the domain fields it must not
        own — finding_id, severity_validated (derived), raw_response, and the
        patch-oracle results (a later stage) — are supplied here, not by the
        model. The axes are the shared AxisResult objects, passed straight into
        the domain container; only the container shape differs (this wire schema
        requires real+triggerable, the domain Axes is all-optional).
        """
        axes = Axes(
            real=self.axes.real,
            triggerable=self.axes.triggerable,
            impactful=self.axes.impactful,
            general=self.axes.general,
        )
        return ValidatorVerdict(
            finding_id=finding_id,
            axes=axes,
            advance=self.advance,
            severity_validated=self.severity if self.advance else None,
            evidence_level=self.evidence_level,
            pro_argument=self.pro_argument,
            counter_argument=self.counter_argument,
            tie_breaker=self.tie_breaker,
            duplicate_cve=self.duplicate_cve,
        )


# --- Validator class ---------------------------------------------------------


class Validator:
    """Unified 4-axis validator (spec 009).

    Uses a single prompt that evaluates REAL, TRIGGERABLE, IMPACTFUL, and
    GENERAL axes independently. The budget gate selects between the full
    4-axis prompt and a cheaper 2-axis quick-pass for low-evidence findings.
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        *,
        gate_threshold: EvidenceLevel | None = "static_corroboration",
        enable_quick_pass: bool = True,
    ):
        self.llm = llm
        self.gate_threshold = gate_threshold
        self.enable_quick_pass = enable_quick_pass

    def _prompt_for_finding(self, finding: Finding) -> str:
        if not self.enable_quick_pass:
            return VALIDATOR_SYSTEM_PROMPT
        if self.gate_threshold is None:
            return VALIDATOR_SYSTEM_PROMPT
        level = cast(EvidenceLevel, finding.get("evidence_level", "suspicion"))
        try:
            above = evidence_at_or_above(level, self.gate_threshold)
        except KeyError:
            above = False
        return VALIDATOR_SYSTEM_PROMPT if above else VALIDATOR_QUICK_PROMPT

    async def avalidate(
        self,
        finding: Finding,
        file_content: str = "",
    ) -> ValidatorVerdict:
        user_msg = self._build_user_message(finding, file_content)
        system_prompt = self._prompt_for_finding(finding)

        # Enforced structured output. response_schema becomes a genai-pyo3
        # response_json_spec (constrained decoding), so the model emits a JSON
        # object matching _VerdictSchema — even reasoning models that would
        # otherwise return empty text under free-form prompting. We validate to
        # the typed wire object and map it to the domain verdict directly (no
        # dict round-trip). Requires a model/gateway with constrained decoding.
        try:
            response = await self.llm.aask_text(
                system=system_prompt,
                user=user_msg,
                response_schema=_VerdictSchema,
                response_schema_name="ValidatorVerdict",
            )
            schema = _VerdictSchema.model_validate_json(response_text(response))
            verdict = schema.to_verdict(finding.get("id", "unknown"))
        except BudgetExceeded:
            raise
        except Exception as e:
            logger.warning("Validator LLM call failed", exc_info=True)
            verdict = self._error_verdict(finding, f"validator error: {e}")

        EventBus().emit_validation_result(ValidationResultPayload(
            finding_id=verdict.finding_id,
            axes={name: ar.passed for name, ar in verdict.axes.items()},
            advance=verdict.advance,
            severity=verdict.severity_validated,
            evidence_level=verdict.evidence_level,
        ))

        return verdict

    def _build_user_message(self, finding: Finding, file_content: str) -> str:
        finding_view = {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "finding_type": finding.get("finding_type"),
            "cwe": finding.get("cwe"),
            "severity_proposed": finding.get("severity"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
            "crash_evidence": finding.get("crash_evidence"),
            "poc": finding.get("poc"),
            "exploit": finding.get("exploit"),
            "discovered_by": finding.get("discovered_by"),
        }
        msg = "Validate the following bug report:\n\n"
        msg += json.dumps(finding_view, indent=2)
        if file_content:
            excerpts = self._build_file_context(finding, file_content)
            if excerpts:
                msg += f"\n\nRelevant file excerpts:\n{excerpts}"
        return msg

    def _build_file_context(self, finding: Finding, file_content: str) -> str:
        lines = file_content.splitlines()
        if not lines:
            return ""

        requested_lines = self._line_refs_from_finding(finding)
        windows = self._merge_windows(
            [
                (max(1, ln - 24), min(len(lines), ln + 24))
                for ln in requested_lines
                if 1 <= ln <= len(lines)
            ]
        )

        excerpts: list[str] = []
        total_chars = 0
        for start, end in islice(windows, 6):
            header = f"--- lines {start}-{end} ---"
            body = "\n".join(
                f"{n:5d}: {lines[n - 1]}" for n in range(start, end + 1)
            )
            chunk = f"{header}\n{body}"
            total_chars += len(chunk)
            if total_chars > 12000 and excerpts:
                break
            excerpts.append(chunk)

        if excerpts:
            return "\n\n".join(excerpts)

        capped = file_content[:8000]
        return f"--- file head (fallback, capped to 8 KB) ---\n{capped}"

    def _line_refs_from_finding(self, finding: Finding) -> list[int]:
        refs: list[int] = []
        for key in ("line_number", "end_line"):
            value = finding.get(key)
            if isinstance(value, int) and value > 0:
                refs.append(value)
        text_fields = [
            str(finding.get("description") or ""),
            str(finding.get("code_snippet") or ""),
            str(finding.get("crash_evidence") or ""),
        ]
        for f in text_fields:
            for match in _LINE_REF_RE.finditer(f):
                start = int(match.group(1))
                end = int(match.group(2) or start)
                refs.extend(range(start, min(end, start + 6) + 1))
        seen: set[int] = set()
        ordered: list[int] = []
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                ordered.append(ref)
        return ordered

    def _merge_windows(
        self, windows: list[tuple[int, int]],
    ) -> list[tuple[int, int]]:
        if not windows:
            return []
        merged: list[tuple[int, int]] = []
        for start, end in sorted(windows):
            if not merged or start > merged[-1][1] + 5:
                merged.append((start, end))
                continue
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        return merged

    def _error_verdict(
        self, finding: Finding, reason: str,
    ) -> ValidatorVerdict:
        return ValidatorVerdict(
            finding_id=finding.get("id", "unknown"),
            axes=Axes(),
            advance=False,
            severity_validated=None,
            evidence_level="suspicion",
            pro_argument="",
            counter_argument="",
            tie_breaker=reason,
            duplicate_cve=None,
        )

    async def arun_patch_oracle(
        self,
        finding: Finding,
        file_content: str = "",
        sandbox: Any = None,
        rerun_poc: Any = None,
    ) -> tuple[bool, str, str]:
        from .verifier import Verifier

        temp_v = Verifier(self.llm)
        return await temp_v.arun_patch_oracle(
            finding, file_content, sandbox, rerun_poc,
        )


# --- apply function ----------------------------------------------------------


def _bump_evidence(finding: Finding, new_level: EvidenceLevel) -> None:
    current = finding.get("evidence_level", "suspicion")
    if current not in EVIDENCE_LEVELS:
        current = "suspicion"
    if new_level not in EVIDENCE_LEVELS:
        return
    if EVIDENCE_LEVELS.index(new_level) > EVIDENCE_LEVELS.index(current):
        finding["evidence_level"] = new_level


def apply_validator_verdict(
    finding: Finding,
    verdict: ValidatorVerdict,
    session_id: str | None = None,
    discoverer_severity: str | None = None,
) -> Finding:
    """Merge a ValidatorVerdict into a Finding (in-place + return).

    Sets the same backward-compat fields as apply_verifier_result so
    downstream code that reads finding["verified"] etc. still works.
    """
    finding["verified"] = verdict.advance
    finding["severity_verified"] = verdict.severity_validated
    finding["verifier_pro_argument"] = verdict.pro_argument
    finding["verifier_counter_argument"] = verdict.counter_argument
    finding["verifier_tie_breaker"] = verdict.tie_breaker
    finding["verifier_session_id"] = session_id
    finding["validation_mode"] = "v2"

    finding["validator_axes"] = {
        name: {
            "passed": ax.passed,
            "confidence": ax.confidence,
            "rationale": ax.rationale,
        }
        for name, ax in verdict.axes.items()
    }

    _bump_evidence(finding, verdict.evidence_level)

    if verdict.patch_oracle_attempted:
        finding["patch_oracle_passed"] = verdict.patch_oracle_passed
        if verdict.patch_oracle_passed:
            _bump_evidence(finding, "root_cause_explained")

    if discoverer_severity and verdict.severity_validated:
        d = _SEVERITY_RANK.get(discoverer_severity, 0)
        v = _SEVERITY_RANK.get(verdict.severity_validated, 0)
        if abs(d - v) >= 2:
            finding["severity_disagreement"] = (
                f"discoverer={discoverer_severity} "
                f"validator={verdict.severity_validated} "
                f"delta={abs(d - v)}"
            )

    if not verdict.advance:
        failed = [name for name, ax in verdict.axes.items() if not ax.passed]
        finding["rejected_axes"] = failed

    return finding
