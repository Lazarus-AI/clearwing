"""Semgrep sidecar — one static-analysis tool, invoked as a hint source only.

Per the plan: Semgrep findings are NEVER treated as ground truth. They're
injected into hunter prompts as starting hypotheses and feed the per-file
`semgrep_hint` count as a surface-boost signal.

We deliberately don't add CodeQL, Bandit, eslint, etc. — one tool, one
output format, one maintenance burden.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


DEFAULT_SEMGREP_CONFIG = "p/security-audit"
SEMGREP_TIMEOUT_SECONDS = 300


@dataclass
class SemgrepFinding:
    """One Semgrep hit normalized to a simple shape."""

    file: str  # repo-relative path
    line: int
    check_id: str  # e.g. "python.lang.security.audit.dangerous-exec"
    severity: str  # ERROR | WARNING | INFO (we keep semgrep's naming)
    message: str
    code_snippet: str = ""
    cwe: str = ""


class SemgrepSidecar:
    """Wraps the `semgrep` CLI.

    If the binary is not installed, `.available` is False and `.run_scan()`
    returns an empty list. The preprocessor logs a warning in that case.
    """

    def __init__(
        self,
        config: str = DEFAULT_SEMGREP_CONFIG,
        extra_args: list[str] | None = None,
        binary: str = "semgrep",
        timeout_seconds: int | None = None,
        respect_gitignore: bool = False,
    ):
        self.config = config
        self.extra_args = extra_args or []
        self.binary = binary
        self.timeout_seconds = timeout_seconds or SEMGREP_TIMEOUT_SECONDS
        self.respect_gitignore = respect_gitignore

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run_scan(self, repo_path: str) -> list[SemgrepFinding]:
        """Invoke `semgrep --json --config <config> <repo_path>`.

        Returns a list of normalized findings. On any failure, logs and
        returns an empty list — Semgrep is a hint source, not a
        correctness-critical dependency.
        """
        if not self.available:
            logger.debug("Semgrep binary not found; skipping")
            return []

        cmd = [
            self.binary,
            "scan",
            "--json",
            "--config",
            self.config,
            "--quiet",
            "--skip-unknown-extensions",
        ]
        if not self.respect_gitignore:
            cmd.append("--no-git-ignore")  # also scan ignored files — v0.1 choice
        cmd = cmd + self.extra_args + [repo_path]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep scan timed out after %ds", self.timeout_seconds)
            return []
        except FileNotFoundError:
            return []
        except Exception:
            logger.warning("Semgrep scan failed", exc_info=True)
            return []

        # Semgrep exits with rc=1 when there are findings, rc=0 when clean,
        # rc=2+ on error. Don't treat rc=1 as a failure.
        if proc.returncode not in (0, 1):
            logger.warning("Semgrep exited with code %d: %s", proc.returncode, proc.stderr[:500])
            return []

        return self._parse_semgrep_json(proc.stdout, repo_path)

    def _parse_semgrep_json(self, stdout: str, repo_path: str) -> list[SemgrepFinding]:
        """Parse `semgrep --json` output into SemgrepFinding entries."""
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Semgrep output was not JSON")
            return []
        out: list[SemgrepFinding] = []
        results = data.get("results", [])
        for r in results:
            try:
                abs_path = r.get("path", "")
                rel = Path(os.path.relpath(abs_path, repo_path)).as_posix() if abs_path else ""
                start = r.get("start", {})
                line = int(start.get("line", 0))
                extra = r.get("extra", {})
                meta = extra.get("metadata", {})
                # CWE may be a list or a single string
                cwe = meta.get("cwe", "")
                if isinstance(cwe, list):
                    cwe = cwe[0] if cwe else ""
                out.append(
                    SemgrepFinding(
                        file=rel,
                        line=line,
                        check_id=r.get("check_id", ""),
                        severity=(extra.get("severity") or "INFO").upper(),
                        message=extra.get("message", ""),
                        code_snippet=extra.get("lines", "")[:300],
                        cwe=str(cwe),
                    )
                )
            except Exception:
                logger.debug("Failed to parse semgrep result entry", exc_info=True)
                continue
        return out


def finding_to_dict(finding: SemgrepFinding) -> dict:
    """Convert a SemgrepFinding to the plain-dict shape the preprocessor stores."""
    return {
        "file": finding.file,
        "line": finding.line,
        "check_id": finding.check_id,
        "severity": finding.severity,
        "message": finding.message,
        "code_snippet": finding.code_snippet,
        "cwe": finding.cwe,
        "description": finding.message,  # convenience key for prompt formatting
    }
