"""Independent-context verifier agent for sourcehunt findings.

The verifier takes a single Finding from a hunter and decides whether
it's real. v0.1 uses a non-adversarial prompt; v0.2 turns on the adversarial
mode where the verifier is required to steel-man both sides. v0.3 adds an
optional patch-oracle truth test — write a minimal defensive fix, recompile,
re-run the PoC. If the crash disappears the root cause theory is causally
validated; if it survives, the theory is suspect and should bounce back to
the hunter.

Independence: the verifier never sees the hunter's reasoning messages. Only
the finding dict and the file content. This is enforced at the orchestration
level (the runner builds a fresh agent per finding).
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from .state import EVIDENCE_LEVELS, EvidenceLevel, Finding, evidence_at_or_above

logger = logging.getLogger(__name__)


# --- Verifier prompts -------------------------------------------------------


VERIFIER_SYSTEM_PROMPT_V01 = """You are an independent verifier checking whether a vulnerability report from another agent is real.

You did NOT find this bug. Your job is to confirm or refute it from a fresh perspective. You have access to the project source code and a sandbox.

Please:
1. Reproduce the bug using the provided proof-of-concept (if any).
2. Confirm the crash / behavior is genuine (or refute it).
3. Assess whether this is exploitable in production or just an edge case.
4. Rate severity: critical / high / medium / low / info.
5. Flag if this looks like a duplicate of a known CVE.

Return ONLY a JSON object, no other text:
{
  "is_real": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_level": "static_corroboration|crash_reproduced|root_cause_explained",
  "pro_argument": "one paragraph of why this IS a vulnerability",
  "counter_argument": "",
  "tie_breaker": "what evidence resolved it",
  "duplicate_cve": null
}
"""


PATCH_ORACLE_PROMPT = """You are writing a MINIMAL DEFENSIVE FIX for a verified vulnerability. This is a TRUTH TEST — not a production patch. If your fix eliminates the crash, that confirms the root cause theory. If the crash survives, the theory is suspect.

The fix MUST:
1. Be the smallest diff that could plausibly eliminate the crash.
2. Change ONLY the target file. No cross-file edits.
3. Apply an obvious defensive pattern: widen a bound, add a guard, initialize a default, check for NULL, validate a length.
4. NOT change the function signature.
5. NOT rewrite the function from scratch.
6. NOT delete the vulnerable code path.

You'll be given:
- The verified finding (file, line, description, crash evidence)
- The current source of the file

Return ONLY a JSON object:
{
  "diff": "unified-diff text (or the full new function if a unified diff is impractical)",
  "fix_description": "one sentence — what the fix does and why",
  "confidence": "high|medium|low — how confident that this will stop the crash"
}

Do NOT return anything else."""


# v0.2 turns on adversarial mode — schema unchanged
VERIFIER_SYSTEM_PROMPT_V02 = """You are an independent verifier. A hunter has reported a finding. Your job is NOT to confirm it — your job is to STEEL-MAN BOTH SIDES and determine which is correct.

1. PRO-VULNERABILITY ARGUMENT
   Construct the strongest possible case that this IS a real, exploitable vulnerability. Reproduce the crash if there's a PoC. Identify the root cause precisely. Rate severity assuming the worst plausible exploit.

2. COUNTER-ARGUMENT (steel-manned)
   Construct the strongest possible case that this is NOT a real vulnerability or that severity is overstated. Specifically check:
     a. Is the crash caused by harness misuse (caller never passes these inputs in production)?
     b. Is the code path actually reachable from any real entry point?
     c. Do invariants enforced elsewhere in the codebase neutralize this?
     d. Is the severity overstated? Mitigating context?
     e. Is this a duplicate of a known CVE that's already mitigated?

3. TIE-BREAKER
   What single piece of evidence (a specific call site, a unit test, an invariant in a file you haven't read yet) would resolve the disagreement? GO LOOK FOR IT.

4. VERDICT
   Return ONLY a JSON object:
   {
     "is_real": true|false,
     "severity": "critical|high|medium|low",
     "evidence_level": "crash_reproduced|root_cause_explained",
     "pro_argument": "max 200 words",
     "counter_argument": "max 200 words",
     "tie_breaker": "what evidence resolved it",
     "duplicate_cve": null
   }
"""


# --- Result -----------------------------------------------------------------


@dataclass
class VerifierResult:
    """Output of a single verifier run."""
    finding_id: str
    is_real: bool
    severity_verified: Optional[str]
    evidence_level: EvidenceLevel
    pro_argument: str
    counter_argument: str
    tie_breaker: str
    duplicate_cve: Optional[str]
    raw_response: str = ""
    # v0.3 patch oracle fields
    patch_oracle_attempted: bool = False
    patch_oracle_passed: Optional[bool] = None    # None = not attempted
    patch_oracle_diff: str = ""
    patch_oracle_notes: str = ""


# --- Verifier agent ---------------------------------------------------------


class Verifier:
    """Independent-context verifier for sourcehunt findings.

    v0.1 uses VERIFIER_SYSTEM_PROMPT_V01 (non-adversarial).
    v0.2 flipped to VERIFIER_SYSTEM_PROMPT_V02 (adversarial steel-man).
    v0.4 adds a per-finding budget gate: when `adversarial_threshold` is set,
    the verifier only spends adversarial-prompt budget on findings whose
    evidence level is AT OR ABOVE the threshold. Below the gate, it falls
    back to the cheaper V01 prompt for that one call.

    The output schema is identical in both modes — V01 just leaves the
    counter_argument field empty.
    """

    def __init__(
        self,
        llm: BaseChatModel,
        adversarial: bool = False,
        adversarial_threshold: Optional[str] = "static_corroboration",
    ):
        self.llm = llm
        self.adversarial = adversarial
        # None disables the gate — adversarial runs on every finding when set.
        # The default threshold matches the plan: only spend steel-man budget
        # on findings with at least static corroboration (e.g. a Semgrep hit,
        # SourceAnalyzer regex match, or a hunter-recorded static finding).
        self.adversarial_threshold = adversarial_threshold
        # Keep the "base" prompt for backwards compat — the per-call prompt
        # is selected in verify() based on the gate.
        self._system_prompt = (
            VERIFIER_SYSTEM_PROMPT_V02 if adversarial else VERIFIER_SYSTEM_PROMPT_V01
        )

    def _prompt_for_finding(self, finding: Finding) -> str:
        """Pick the prompt per-finding, respecting the adversarial budget gate."""
        if not self.adversarial:
            return VERIFIER_SYSTEM_PROMPT_V01
        if self.adversarial_threshold is None:
            return VERIFIER_SYSTEM_PROMPT_V02
        level = finding.get("evidence_level", "suspicion")
        try:
            gated = evidence_at_or_above(level, self.adversarial_threshold)
        except KeyError:
            # Unknown evidence level → treat as below the gate (fail cheap)
            gated = False
        return VERIFIER_SYSTEM_PROMPT_V02 if gated else VERIFIER_SYSTEM_PROMPT_V01

    def verify(
        self,
        finding: Finding,
        file_content: str = "",
    ) -> VerifierResult:
        """Run a single verification pass on one finding.

        The verifier sees ONLY the finding dict and (optionally) the file
        content. It does NOT see the hunter's message history — that's the
        independence guarantee.

        Args:
            finding: The hunter's Finding.
            file_content: Optional content of the file the finding lives in.

        Returns:
            A VerifierResult with the structured verdict.
        """
        user_msg = self._build_user_message(finding, file_content)
        system_prompt = self._prompt_for_finding(finding)
        try:
            response = self.llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_msg),
            ])
        except Exception as e:
            logger.warning("Verifier LLM call failed", exc_info=True)
            return VerifierResult(
                finding_id=finding.get("id", "unknown"),
                is_real=False,
                severity_verified=None,
                evidence_level="suspicion",
                pro_argument="",
                counter_argument="",
                tie_breaker=f"verifier error: {e}",
                duplicate_cve=None,
            )

        content = response.content if isinstance(response.content, str) else str(response.content)
        return self._parse_response(finding, content)

    def _build_user_message(self, finding: Finding, file_content: str) -> str:
        # Note: we deliberately do NOT include the hunter's reasoning chain
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
            "discovered_by": finding.get("discovered_by"),
        }
        msg = "Verify the following bug report:\n\n"
        msg += json.dumps(finding_view, indent=2)
        if file_content:
            # Cap to keep the context tight
            capped = file_content[:8000]
            msg += f"\n\nFile content (capped to 8 KB):\n{capped}"
        return msg

    def _parse_response(self, finding: Finding, content: str) -> VerifierResult:
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            logger.warning("Verifier response had no JSON object; got: %s", content[:300])
            return self._error_result(finding, content, "no JSON in response")
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return self._error_result(finding, content, "JSON parse failed")

        is_real = bool(parsed.get("is_real", False))
        severity = parsed.get("severity")
        if severity not in ("critical", "high", "medium", "low", "info", None):
            severity = None
        evidence_level = parsed.get("evidence_level", "suspicion")
        if evidence_level not in EVIDENCE_LEVELS:
            evidence_level = "suspicion"

        return VerifierResult(
            finding_id=finding.get("id", "unknown"),
            is_real=is_real,
            severity_verified=severity if is_real else None,
            evidence_level=evidence_level,  # type: ignore[arg-type]
            pro_argument=str(parsed.get("pro_argument", "")),
            counter_argument=str(parsed.get("counter_argument", "")),
            tie_breaker=str(parsed.get("tie_breaker", "")),
            duplicate_cve=parsed.get("duplicate_cve"),
            raw_response=content,
        )

    def _error_result(
        self,
        finding: Finding,
        raw: str,
        reason: str,
    ) -> VerifierResult:
        return VerifierResult(
            finding_id=finding.get("id", "unknown"),
            is_real=False,
            severity_verified=None,
            evidence_level="suspicion",
            pro_argument="",
            counter_argument="",
            tie_breaker=reason,
            duplicate_cve=None,
            raw_response=raw,
        )

    # --- v0.3 patch oracle -------------------------------------------------

    def run_patch_oracle(
        self,
        finding: Finding,
        file_content: str,
        sandbox=None,
        rerun_poc=None,
    ) -> tuple[bool, str, str]:
        """Write a minimal defensive fix; run it through the oracle.

        Args:
            finding: The verified Finding.
            file_content: Current source of the file (will be used in prompt).
            sandbox: Optional SandboxContainer. If provided, the fix is
                written into the sandbox and rerun_poc is invoked.
            rerun_poc: Optional callable. If provided, called after the fix
                is applied: `rerun_poc(sandbox, finding) -> bool` returning
                True if the original PoC still crashes. If None, the oracle
                is "LLM-only": we take the LLM's confidence score at face value.

        Returns:
            (passed, diff, notes) where:
              passed: True if the fix appears to eliminate the crash.
              diff: The fix diff (or empty string).
              notes: Free-form notes about the attempt.
        """
        user_msg = self._build_patch_oracle_message(finding, file_content)
        try:
            response = self.llm.invoke([
                SystemMessage(content=PATCH_ORACLE_PROMPT),
                HumanMessage(content=user_msg),
            ])
        except Exception as e:
            logger.debug("Patch-oracle LLM call failed", exc_info=True)
            return False, "", f"llm error: {e}"

        content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = self._parse_patch_oracle_response(content)
        if not parsed:
            return False, "", "patch oracle: could not parse response"

        diff = parsed.get("diff", "")
        confidence = parsed.get("confidence", "low").lower()
        description = parsed.get("fix_description", "")

        # If no sandbox, we can only return the LLM's self-reported confidence
        if sandbox is None or rerun_poc is None:
            # High confidence is treated as "passed"; medium/low don't validate
            if confidence == "high":
                return True, diff, f"llm-only oracle, confidence=high: {description}"
            return False, diff, f"llm-only oracle, confidence={confidence}: {description}"

        # Sandbox path: apply the fix, re-run the PoC
        try:
            # The runner is expected to have pre-loaded the sandbox with the
            # original file. We write the patched file and run the PoC callback.
            file_path = finding.get("file", "")
            if not file_path:
                return False, diff, "no file path in finding"
            # Write the patch file into /scratch for reference (apply is caller's job)
            sandbox.write_file(f"/scratch/patch.diff", diff.encode("utf-8"))
            try:
                still_crashes = bool(rerun_poc(sandbox, finding))
            except Exception as e:
                return False, diff, f"rerun_poc failed: {e}"
            if still_crashes:
                return False, diff, "patch oracle: crash survived the fix (theory suspect)"
            return True, diff, f"patch oracle: fix eliminated crash — {description}"
        except Exception as e:
            return False, diff, f"patch oracle error: {e}"

    def _build_patch_oracle_message(self, finding: Finding, file_content: str) -> str:
        view = {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
            "crash_evidence": (finding.get("crash_evidence") or "")[:2000],
            "poc": (finding.get("poc") or "")[:500],
        }
        msg = "Verified finding:\n\n"
        msg += json.dumps(view, indent=2)
        if file_content:
            msg += f"\n\nCurrent file content (capped to 8 KB):\n{file_content[:8000]}"
        return msg

    def _parse_patch_oracle_response(self, content: str) -> Optional[dict]:
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None


def apply_verifier_result(
    finding: Finding,
    result: VerifierResult,
    session_id: Optional[str] = None,
) -> Finding:
    """Merge a VerifierResult into a Finding (in-place + return).

    Accepts either a Finding dataclass or a plain dict — dict subscripting
    works on both via the Finding compat shim.
    """
    finding["verified"] = result.is_real
    finding["severity_verified"] = result.severity_verified
    finding["verifier_pro_argument"] = result.pro_argument
    finding["verifier_counter_argument"] = result.counter_argument
    finding["verifier_tie_breaker"] = result.tie_breaker
    finding["verifier_session_id"] = session_id
    # Bump evidence_level if the verifier confirms a stronger one
    current = finding.get("evidence_level", "suspicion")
    new = result.evidence_level
    if EVIDENCE_LEVELS.index(new) > EVIDENCE_LEVELS.index(current):
        finding["evidence_level"] = new
    # v0.3: patch-oracle outcome
    if result.patch_oracle_attempted:
        finding["patch_oracle_passed"] = result.patch_oracle_passed
        # A passed oracle bumps evidence to root_cause_explained (causally
        # validated — the fix actually killed the crash).
        if result.patch_oracle_passed:
            level = finding.get("evidence_level", "suspicion")
            if EVIDENCE_LEVELS.index("root_cause_explained") > EVIDENCE_LEVELS.index(level):
                finding["evidence_level"] = "root_cause_explained"
    return finding
