"""CVE Retro-Hunt — given a CVE ID + patch, find variants in the target repo.

v0.3 flow:
    1. Fetch the patch diff (from a git commit URL, raw diff file, or
       NVD API reference).
    2. LLM reads the diff and generates a Semgrep rule that captures the
       *fixed* pattern — the anti-pattern the patch removed.
    3. Run the Semgrep rule across the target repo.
    4. Each hit becomes a variant seed: a pre-seeded finding with
       `related_cve` set and a hunter prompt that asks "is this the same
       flaw or a safe usage?"

Uses the existing SemgrepSidecar for rule execution.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from .semgrep_sidecar import SemgrepSidecar
from .state import Finding

logger = logging.getLogger(__name__)


# --- Data classes -----------------------------------------------------------


@dataclass
class RetroHuntResult:
    """Output of one CVE retro-hunt pass."""
    cve_id: str
    patch_source: str                # URL or path
    diff_text: str = ""
    semgrep_rule: str = ""
    rule_description: str = ""
    findings: list[Finding] = field(default_factory=list)
    notes: str = ""


# --- Rule-generation prompt -------------------------------------------------


RULE_GEN_SYSTEM_PROMPT = """You are writing a Semgrep rule that matches the *anti-pattern* a security patch removed.

Given a CVE patch diff, identify what the vulnerable code looked like BEFORE the fix, and produce a Semgrep rule that would have caught it. Do NOT match the post-fix code.

Return ONLY a JSON object:
{
  "rule_id": "retro-hunt-<cve-slug>",
  "description": "one sentence — what the anti-pattern is",
  "languages": ["c", "cpp", ...],
  "pattern": "Semgrep metavariable pattern (or patterns-inside)",
  "severity": "ERROR|WARNING|INFO"
}

Examples:

Input: patch removes memcpy(buf, in, user_len) and replaces with memcpy(buf, in, min(user_len, sizeof(buf)))
Output: {
  "rule_id": "retro-hunt-cve-memcpy",
  "description": "unchecked memcpy length from user-controlled variable",
  "languages": ["c", "cpp"],
  "pattern": "memcpy($DST, $SRC, $LEN)",
  "severity": "ERROR"
}

Return ONLY the JSON."""


# --- Patch fetching --------------------------------------------------------


def fetch_patch_diff(
    source: str,
    repo_path: Optional[str] = None,
) -> str:
    """Fetch a patch diff from a source identifier.

    Supported sources:
        - Local file path: read the file.
        - A git commit SHA (when repo_path is provided): `git show <sha>`.
        - A URL: [Deferred] would require WebFetch in a real deploy.

    Returns the diff text, or raises ValueError on failure.
    """
    if not source:
        raise ValueError("empty patch source")

    # Local file
    if os.path.exists(source):
        return Path(source).read_text(encoding="utf-8", errors="replace")

    # Git SHA + repo
    if repo_path and os.path.isdir(repo_path):
        try:
            proc = subprocess.run(
                ["git", "-C", repo_path, "show", source],
                capture_output=True, text=True, check=False, timeout=30,
            )
            if proc.returncode == 0:
                return proc.stdout
        except Exception:
            pass

    # URL — v0.3 doesn't implement fetch; raise so the caller can handle it
    if source.startswith("http://") or source.startswith("https://"):
        raise ValueError(
            f"URL patch sources are not fetched in v0.3; provide a local "
            f"diff file or a git SHA instead (got {source})"
        )

    raise ValueError(f"could not resolve patch source: {source}")


# --- RetroHunter -----------------------------------------------------------


class RetroHunter:
    """CVE variant-hunter. Pure orchestration on top of Semgrep + an LLM."""

    def __init__(
        self,
        llm: BaseChatModel,
        sidecar: Optional[SemgrepSidecar] = None,
    ):
        self.llm = llm
        self.sidecar = sidecar or SemgrepSidecar()

    def hunt(
        self,
        cve_id: str,
        patch_source: str,
        target_repo_path: str,
        repo_path_for_git_source: Optional[str] = None,
    ) -> RetroHuntResult:
        """Run one retro-hunt pass for a CVE and return the result."""
        result = RetroHuntResult(
            cve_id=cve_id,
            patch_source=patch_source,
        )

        # 1. Fetch the diff
        try:
            diff_text = fetch_patch_diff(patch_source, repo_path_for_git_source)
        except Exception as e:
            result.notes = f"could not fetch patch: {e}"
            return result
        result.diff_text = diff_text[:16000]   # cap for prompt size

        # 2. Generate a Semgrep rule from the diff
        rule_info = self._generate_rule(cve_id, result.diff_text)
        if rule_info is None:
            result.notes = "LLM failed to generate a rule"
            return result
        result.rule_description = rule_info.get("description", "")
        semgrep_rule_yaml = self._format_semgrep_rule(rule_info)
        result.semgrep_rule = semgrep_rule_yaml

        # 3. Run Semgrep with the generated rule
        hits = self._run_rule(semgrep_rule_yaml, target_repo_path)
        result.notes = f"matched {len(hits)} locations"

        # 4. Convert hits into Finding entries with related_cve set
        for hit in hits:
            result.findings.append(self._hit_to_finding(hit, cve_id, rule_info))

        return result

    # --- Internal helpers --------------------------------------------------

    def _generate_rule(self, cve_id: str, diff_text: str) -> Optional[dict]:
        user_msg = f"CVE: {cve_id}\n\nPatch diff:\n\n{diff_text}"
        try:
            response = self.llm.invoke([
                SystemMessage(content=RULE_GEN_SYSTEM_PROMPT),
                HumanMessage(content=user_msg),
            ])
        except Exception:
            logger.debug("Retro-hunt rule-gen LLM call failed", exc_info=True)
            return None
        content = response.content if isinstance(response.content, str) else str(response.content)
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    def _format_semgrep_rule(self, rule_info: dict) -> str:
        """Build a minimal Semgrep rule YAML from the parsed rule_info dict."""
        rule_id = rule_info.get("rule_id", f"retro-hunt-{uuid.uuid4().hex[:6]}")
        description = rule_info.get("description", "")
        pattern = rule_info.get("pattern", "")
        severity = rule_info.get("severity", "WARNING")
        languages = rule_info.get("languages", ["c"])
        if isinstance(languages, str):
            languages = [languages]
        langs_yaml = "\n".join(f"      - {lang}" for lang in languages)
        # Minimal semgrep YAML
        return (
            f"rules:\n"
            f"  - id: {rule_id}\n"
            f"    message: {json.dumps(description)}\n"
            f"    severity: {severity}\n"
            f"    languages:\n{langs_yaml}\n"
            f"    pattern: {json.dumps(pattern)}\n"
        )

    def _run_rule(self, rule_yaml: str, target_repo_path: str) -> list[dict]:
        """Invoke Semgrep with a generated rule and return parsed findings.

        Writes the rule to a temp file and reuses the existing SemgrepSidecar
        machinery (setting its config to the temp file).
        """
        if not self.sidecar.available:
            logger.info("Retro-hunt: Semgrep binary not found; returning empty")
            return []

        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8",
        ) as tf:
            tf.write(rule_yaml)
            tf.flush()
            rule_path = tf.name

        try:
            sidecar = SemgrepSidecar(config=rule_path)
            findings = sidecar.run_scan(target_repo_path)
        finally:
            try:
                os.unlink(rule_path)
            except OSError:
                pass

        return [
            {
                "file": f.file,
                "line": f.line,
                "check_id": f.check_id,
                "message": f.message,
                "severity": f.severity,
                "code_snippet": f.code_snippet,
            }
            for f in findings
        ]

    def _hit_to_finding(
        self,
        hit: dict,
        cve_id: str,
        rule_info: dict,
    ) -> Finding:
        """Turn a Semgrep hit into a Finding with related_cve set."""
        severity = hit.get("severity", "WARNING").lower()
        # Semgrep uses ERROR/WARNING/INFO — map to our scale
        severity_map = {"error": "high", "warning": "medium", "info": "low"}
        mapped_severity = severity_map.get(severity, "medium")

        return Finding(
            id=f"retro-{uuid.uuid4().hex[:8]}",
            file=hit.get("file", ""),
            line_number=int(hit.get("line", 0)),
            finding_type="cve_variant",
            cwe=rule_info.get("cwe", ""),
            severity=mapped_severity,  # type: ignore[arg-type]
            confidence="low",          # hunter must re-verify
            description=(
                f"Possible variant of {cve_id}: "
                f"{rule_info.get('description', '')}. "
                f"Hunter must confirm — Semgrep match only."
            ),
            code_snippet=hit.get("code_snippet", ""),
            evidence_level="static_corroboration",
            discovered_by="retro_hunt",
            related_cve=cve_id,
        )
