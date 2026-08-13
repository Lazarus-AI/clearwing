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


VALIDATOR_RETRY_PROMPT = """\
Independently validate the reported vulnerability against the supplied source.
Return the structured verdict immediately. Decide whether it is real, reachable
from attacker input, security-impactful, and realistic in common configurations.
State the strongest case for and against it. Do not omit required fields."""


VALIDATOR_SOURCE_FIRST_PROMPT = """\
You are an independent source-first security validator. The report and trace are
allegations; the supplied current source is authoritative. Verify the complete
causal chain in that source. For REAL, compare the alleged operation and missing
checks with the current code. If a guard, bound, exact-identity check, accounting
update, early return, or other invariant breaks a required step, REAL is false.
Do not affirm a historical bug merely because the report describes it plausibly.

Judge TRIGGERABLE, IMPACTFUL, and GENERAL independently. Optional features,
compile flags, or plausible deployment or environment preconditions reduce
prevalence; they do not alone erase a source-level flaw. Remote memory corruption,
confidentiality loss, authentication bypass, and material resource exhaustion are
security impacts. Reject when the chain is absent, unreachable, non-security-
relevant, or requires implausible conditions. Return the structured verdict."""


VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT = """\
Validate one alleged vulnerability against the supplied current source. The
report is untrusted; current source is authoritative. REAL is false if a guard,
bound, exact-identity check, accounting update, early return, or other invariant
breaks any required causal step. Never affirm a historical flaw against
contradictory current code.

Judge reachability, security impact, and realistic deployment independently.
Optional builds or plausible environment conditions are assumptions, not
automatic rejection. Set advance=true only when REAL and IMPACTFUL pass and
TRIGGERABLE and GENERAL either pass or have medium/high confidence with explicit
assumptions. Otherwise set it false. Return the schema now with concise reasons."""


VALIDATOR_PROMPT_PROFILES = {
    "legacy-v1": VALIDATOR_SYSTEM_PROMPT,
    "source-first-high-recall-v1": VALIDATOR_SOURCE_FIRST_PROMPT,
    "source-first-compact-v2": VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT,
}


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
        prompt_profile: str = "legacy-v1",
        system_prompt: str | None = None,
        max_output_tokens: int | None = None,
        temperature: float | None = None,
    ):
        if prompt_profile not in VALIDATOR_PROMPT_PROFILES:
            choices = ", ".join(sorted(VALIDATOR_PROMPT_PROFILES))
            raise ValueError(
                f"Unknown validator prompt profile {prompt_profile!r}; choose from {choices}"
            )
        if max_output_tokens is not None and max_output_tokens < 1:
            raise ValueError("validator max_output_tokens must be positive")
        if temperature is not None and not 0.0 <= temperature <= 2.0:
            raise ValueError("validator temperature must be between 0 and 2")
        self.llm = llm
        self.gate_threshold = gate_threshold
        self.enable_quick_pass = enable_quick_pass
        self.prompt_profile = prompt_profile
        self.system_prompt = system_prompt
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature

    def _prompt_for_finding(self, finding: Finding) -> str:
        full_prompt = self.system_prompt or VALIDATOR_PROMPT_PROFILES[self.prompt_profile]
        if not self.enable_quick_pass:
            return full_prompt
        if self.gate_threshold is None:
            return full_prompt
        level = cast(EvidenceLevel, finding.get("evidence_level", "suspicion"))
        try:
            above = evidence_at_or_above(level, self.gate_threshold)
        except KeyError:
            above = False
        return full_prompt if above else VALIDATOR_QUICK_PROMPT

    async def avalidate(
        self,
        finding: Finding,
        file_content: str = "",
        source_context: str = "",
    ) -> ValidatorVerdict:
        user_msg = self._build_user_message(finding, file_content, source_context)
        system_prompt = self._prompt_for_finding(finding)

        # Enforced structured output. Some small reasoning models can consume
        # their entire default output budget before emitting the final JSON.
        # Retry once with a much shorter generic instruction and more output
        # headroom; never retry a budget refusal.
        try:
            schema = await self._request_schema(
                system_prompt,
                user_msg,
                max_tokens=self.max_output_tokens,
            )
            verdict = schema.to_verdict(finding.get("id", "unknown"))
        except BudgetExceeded:
            raise
        except Exception as first_error:
            logger.info("Validator response invalid; retrying with compact prompt")
            try:
                schema = await self._request_schema(
                    VALIDATOR_RETRY_PROMPT,
                    user_msg,
                    max_tokens=self.max_output_tokens or 8192,
                )
                verdict = schema.to_verdict(finding.get("id", "unknown"))
            except BudgetExceeded:
                raise
            except Exception as retry_error:
                logger.warning("Validator LLM call failed after retry", exc_info=True)
                verdict = self._error_verdict(
                    finding,
                    f"validator error: {first_error}; retry error: {retry_error}",
                )

        EventBus().emit_validation_result(ValidationResultPayload(
            finding_id=verdict.finding_id,
            axes={name: ar.passed for name, ar in verdict.axes.items()},
            advance=verdict.advance,
            severity=verdict.severity_validated,
            evidence_level=verdict.evidence_level,
        ))

        return verdict

    async def _request_schema(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int | None = None,
    ) -> _VerdictSchema:
        response = await self.llm.aask_text(
            system=system,
            user=user,
            temperature=self.temperature,
            max_tokens=max_tokens,
            response_schema=_VerdictSchema,
            response_schema_name="ValidatorVerdict",
        )
        return cast(
            _VerdictSchema,
            _VerdictSchema.model_validate_json(response_text(response)),
        )

    def _build_user_message(
        self,
        finding: Finding,
        file_content: str,
        source_context: str = "",
    ) -> str:
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
            "vulnerability_trace": finding.get("vulnerability_trace"),
        }
        msg = (
            "Validate the following bug report. Treat vulnerability_trace as the "
            "reporter's alleged source chain: use it to locate the claim, but independently "
            "verify every step against the supplied current source before relying on it.\n\n"
        )
        msg += json.dumps(finding_view, indent=2)
        if file_content:
            excerpts = self._build_file_context(finding, file_content)
            if excerpts:
                msg += f"\n\nRelevant file excerpts:\n{excerpts}"
        if source_context:
            msg += (
                "\n\nIndependently collected current source snapshot. Treat this "
                "source as authoritative and re-check the report's alleged snippets "
                "and mechanism against it:\n"
                f"{source_context[:24000]}"
            )
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
        return cast(
            tuple[bool, str, str],
            await temp_v.arun_patch_oracle(
                finding,
                file_content,
                sandbox,
                rerun_poc,
            ),
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
