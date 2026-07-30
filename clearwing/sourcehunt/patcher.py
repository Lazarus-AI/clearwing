"""Auto-Patch mode — minimal defensive fixes for verified critical/high findings.

Runs after the Exploiter on findings that reached `evidence_level >=
root_cause_explained` and `severity in {critical, high}`. The patcher agent
writes a minimal fix diff, optionally applies it in a sandbox, re-runs the
PoC, and returns a PatchAttempt record. A passed attempt bumps the finding
to `patch_validated`.

**The verify-by-recompile gate is mandatory.** When no sandbox is available
(or no rerun_poc callback is supplied), the patcher operates in "LLM-only"
mode and records `validated=False` — unverified patch suggestions are never
marked as validated.

A candidate patch that PASSES validation is included in the report as a
suggestion. Optionally, `--auto-pr` opens a draft PR via the `gh` CLI.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from clearwing.llm import AsyncLLMClient, BudgetExceeded, extract_json_object
from clearwing.reporting.safety import redact_text, redact_tree

from .state import EvidenceLevel, Finding, evidence_at_or_above

logger = logging.getLogger(__name__)


PATCHER_SYSTEM_PROMPT = """You are writing a PRODUCTION-QUALITY minimal fix for a verified critical or high-severity vulnerability.

Unlike the patch-oracle pass (which writes quick truth-test fixes), this patch MUST be:

1. Correct — actually eliminates the vulnerability, not just the immediate crash.
2. Minimal — smallest change that fixes the bug without touching unrelated code.
3. Defensive — preserves existing behavior for safe inputs.
4. Consistent with the file's existing style (indentation, naming, comment style).
5. Accompanied by a 1-3 sentence commit message explaining the fix.

The fix MUST NOT:
- Add dependencies on new libraries.
- Change the public API.
- Rewrite the function.
- Delete the vulnerable code path entirely (unless it's truly dead).

Return ONLY a JSON object:
{
  "diff": "unified diff text (git-format preferred, or full replacement function if diff is impractical)",
  "commit_message": "one-sentence fix description",
  "explanation": "1-3 sentences explaining why the fix works and what edge cases it handles",
  "confidence": "high|medium|low"
}"""


@dataclass
class PatchAttempt:
    """Result of one auto-patch run on a finding."""

    finding_id: str
    attempted: bool
    validated: bool  # True only if recompile+rerun-PoC confirmed the fix
    diff: str
    commit_message: str
    explanation: str
    confidence: str  # high | medium | low
    notes: str  # free-form (failure reason, etc.)
    raw_response: str = ""


class AutoPatcher:
    """Runs the patcher agent + sandbox verify loop on eligible findings.

    Eligibility gate:
        evidence_level >= root_cause_explained
        severity in {critical, high}
        (severity is verified_severity if set, else the original severity)
    """

    PATCH_GATE: EvidenceLevel = "root_cause_explained"
    _ELIGIBLE_SEVERITIES = {"critical", "high"}

    def __init__(
        self,
        llm: AsyncLLMClient,
        *,
        eligible_severities: set[str] | None = None,
        patch_gate: EvidenceLevel | None = None,
    ):
        self.llm = llm
        self.eligible_severities = eligible_severities or set(self._ELIGIBLE_SEVERITIES)
        self.patch_gate = patch_gate or self.PATCH_GATE

    def is_eligible(self, finding: Finding) -> bool:
        if not finding.get("verified", False):
            return False
        sev = (finding.get("severity_verified") or finding.get("severity") or "").lower()
        if sev not in self.eligible_severities:
            return False
        return evidence_at_or_above(
            cast(EvidenceLevel, finding.get("evidence_level", "suspicion")),
            self.patch_gate,
        )

    async def aattempt(
        self,
        finding: Finding,
        file_content: str = "",
        sandbox: Any = None,
        rerun_poc: Callable | None = None,
    ) -> PatchAttempt:
        """Attempt an auto-patch. Validates ONLY if sandbox + rerun_poc are both provided.

        Args:
            finding: The verified finding to patch.
            file_content: Current source of the file.
            sandbox: Optional SandboxContainer for apply+recompile+rerun.
            rerun_poc: Optional callable
                `(sandbox, finding, candidate_diff) -> still_crashes: bool`.
                Legacy two-argument callbacks remain supported.
        """
        if not self.is_eligible(finding):
            return PatchAttempt(
                finding_id=finding.get("id", "unknown"),
                attempted=False,
                validated=False,
                diff="",
                commit_message="",
                explanation="",
                confidence="low",
                notes=(
                    f"Skipped — evidence_level={finding.get('evidence_level', 'suspicion')}, "
                    f"severity={finding.get('severity_verified') or finding.get('severity')}"
                ),
            )

        user_msg = self._build_user_message(finding, file_content)
        try:
            response = await self.llm.aask_text(system=PATCHER_SYSTEM_PROMPT, user=user_msg)
            content = response.first_text or ""
        except BudgetExceeded:
            raise
        except Exception as e:
            logger.warning("Patcher LLM call failed", exc_info=True)
            return PatchAttempt(
                finding_id=finding.get("id", "unknown"),
                attempted=True,
                validated=False,
                diff="",
                commit_message="",
                explanation="",
                confidence="low",
                notes=f"llm error: {e}",
            )

        parsed = self._parse_response(content)
        if not parsed:
            return PatchAttempt(
                finding_id=finding.get("id", "unknown"),
                attempted=True,
                validated=False,
                diff="",
                commit_message="",
                explanation="",
                confidence="low",
                notes="no JSON in patcher response",
                raw_response=content,
            )

        diff = parsed.get("diff", "")
        commit_message = parsed.get("commit_message", "")
        explanation = parsed.get("explanation", "")
        confidence = (parsed.get("confidence") or "low").lower()

        validated = False
        notes = "llm-only — no sandbox, not validated"
        if sandbox is not None and rerun_poc is not None:
            try:
                sandbox.write_file("/scratch/auto_patch.diff", diff.encode("utf-8"))
                still_crashes = bool(_invoke_rerun_poc(rerun_poc, sandbox, finding, diff))
                if still_crashes:
                    notes = "rejected — crash reproduces with the patch applied"
                else:
                    validated = True
                    notes = "validated — PoC no longer crashes with the patch"
            except Exception as e:
                notes = f"validation error: {e}"

        return PatchAttempt(
            finding_id=finding.get("id", "unknown"),
            attempted=True,
            validated=validated,
            diff=diff,
            commit_message=commit_message,
            explanation=explanation,
            confidence=confidence,
            notes=notes,
            raw_response=content,
        )

    def _build_user_message(self, finding: Finding, file_content: str) -> str:
        view = {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "cwe": finding.get("cwe"),
            "severity": finding.get("severity_verified") or finding.get("severity"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
            "crash_evidence": (finding.get("crash_evidence") or "")[:2000],
            "verifier_pro_argument": finding.get("verifier_pro_argument"),
        }
        msg = "Verified vulnerability:\n\n"
        msg += json.dumps(redact_tree(view), indent=2)
        if file_content:
            msg += f"\n\nCurrent file content (capped to 8 KB):\n{redact_text(file_content)[:8000]}"
        return msg

    def _parse_response(self, content: str) -> dict | None:
        try:
            parsed = extract_json_object(content)
        except ValueError:
            return None
        return parsed


def _invoke_rerun_poc(
    callback: Callable,
    sandbox: Any,
    finding: Finding,
    diff: str,
) -> Any:
    """Pass the candidate diff while preserving legacy two-argument callbacks."""

    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        return callback(sandbox, finding, diff)
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(
        parameter.kind == inspect.Parameter.VAR_POSITIONAL
        for parameter in signature.parameters.values()
    )
    if has_varargs or len(positional) >= 3:
        return callback(sandbox, finding, diff)
    return callback(sandbox, finding)


def apply_patch_attempt(
    finding: Finding,
    attempt: PatchAttempt,
) -> Finding:
    """Merge a PatchAttempt into a Finding.

    Delegates to ``finding.apply_patch_result()`` for the actual mutation
    when *finding* is a Finding dataclass. Falls back to dict-style
    assignment for plain-dict callers. Only validated patches bump the
    evidence level.
    """
    if isinstance(finding, Finding):
        finding.apply_patch_result(
            diff=attempt.diff,
            validated=attempt.validated,
            attempted=attempt.attempted,
        )
    else:
        # Legacy dict path
        finding["auto_patch"] = attempt.diff if attempt.diff else None  # type: ignore[index]
        finding["auto_patch_validated"] = (  # type: ignore[index]
            attempt.validated if attempt.attempted else None
        )
        if attempt.validated:
            from clearwing.findings.types import EVIDENCE_LEVELS as _EL

            current = finding.get("evidence_level", "suspicion")  # type: ignore[union-attr]
            if _EL.index("patch_validated") > _EL.index(current):
                finding["evidence_level"] = "patch_validated"  # type: ignore[index]
    return finding
