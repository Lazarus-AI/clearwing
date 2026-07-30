"""Fail-closed remediation policy and unified-diff inspection."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

import yaml  # type: ignore[import-untyped]
from pydantic import ConfigDict, Field

from clearwing.findings.types import EVIDENCE_LEVELS
from clearwing.sourcehunt.paths import resolve_repo_file, safe_repo_relative_path

from .models import FindingSnapshot, PolicyDecision, StrictModel


@dataclass
class DiffSummary:
    touched_files: list[str] = field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0
    creates_or_deletes_files: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def changed_lines(self) -> int:
        return self.added_lines + self.removed_lines


def _diff_path(value: str) -> str | None:
    if value == "/dev/null":
        return None
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return cast(str | None, safe_repo_relative_path(value))


def analyze_unified_diff(diff: str) -> DiffSummary:  # noqa: C901
    """Extract changed paths and size without trusting model-authored headers."""

    summary = DiffSummary()
    touched: set[str] = set()
    old_path: str | None = None
    new_path: str | None = None
    saw_hunk = False

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            old_path = None
            new_path = None
            try:
                parts = shlex.split(line)
            except ValueError:
                summary.errors.append("malformed diff --git header")
                continue
            if len(parts) != 4:
                summary.errors.append("malformed diff --git header")
                continue
            for raw_path in parts[2:]:
                parsed = _diff_path(raw_path)
                if parsed is None:
                    summary.errors.append(f"unsafe diff path: {raw_path}")
                else:
                    touched.add(parsed)
        elif line.startswith("--- "):
            raw_path = line[4:].split("\t", 1)[0].strip()
            old_path = _diff_path(raw_path)
            if raw_path != "/dev/null" and old_path is None:
                summary.errors.append(f"unsafe old path: {raw_path}")
        elif line.startswith("+++ "):
            raw_path = line[4:].split("\t", 1)[0].strip()
            new_path = _diff_path(raw_path)
            if raw_path != "/dev/null" and new_path is None:
                summary.errors.append(f"unsafe new path: {raw_path}")
            if old_path is None or new_path is None:
                summary.creates_or_deletes_files = True
            for parsed in (old_path, new_path):
                if parsed is not None:
                    touched.add(parsed)
        elif line.startswith("@@"):
            saw_hunk = True
        elif saw_hunk and line.startswith("+") and not line.startswith("+++"):
            summary.added_lines += 1
        elif saw_hunk and line.startswith("-") and not line.startswith("---"):
            summary.removed_lines += 1

        if line.startswith(
            (
                "Binary files ",
                "GIT binary patch",
                "rename from ",
                "rename to ",
                "old mode ",
                "new mode ",
                "new file mode ",
                "deleted file mode ",
            )
        ):
            summary.errors.append("binary patches, renames, and mode changes are not supported")

    summary.touched_files = sorted(touched)
    if not saw_hunk:
        summary.errors.append("candidate is not a unified diff with a hunk")
    if not summary.touched_files:
        summary.errors.append("candidate diff has no repository-relative target")
    return summary


class RemediationPolicy(StrictModel):
    """Operator-owned policy; models never decide whether a patch may apply."""

    model_config = ConfigDict(extra="forbid")

    allowed_severities: list[str] = Field(default_factory=lambda: ["critical", "high"])
    allowed_cwes: list[str] = Field(default_factory=list)
    denied_cwes: list[str] = Field(default_factory=list)
    minimum_evidence: str = "root_cause_explained"
    require_verified: bool = True
    target_file_only: bool = True
    forbidden_paths: list[str] = Field(
        default_factory=lambda: [
            ".git/**",
            ".github/workflows/**",
            ".clearwing/**",
            "security-remediation/**",
        ]
    )
    max_files_changed: int = Field(default=1, ge=1, le=100)
    max_changed_lines: int = Field(default=250, ge=1, le=100_000)
    allow_file_creation_or_deletion: Literal[False] = False
    require_clean_target_paths: bool = True
    rollback_on_validation_failure: bool = True
    validation_threshold: float = Field(default=0.80, ge=0.0, le=1.0)
    require_dynamic_validation: bool = False
    kill_switch_env: str = "CLEARWING_REMEDIATION_DISABLED"
    kill_switch_file: str = ".clearwing-remediation-off"

    @classmethod
    def load(cls, path: str | Path | None = None) -> RemediationPolicy:
        if path is None:
            return cls()
        source = Path(path).expanduser()
        payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
        if not isinstance(payload, dict):
            raise ValueError("remediation policy must be a YAML/JSON object")
        return cast(RemediationPolicy, cls.model_validate(payload))

    def sha256(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    def kill_switch_active(self, repo: str | Path) -> bool:
        env_value = os.environ.get(self.kill_switch_env, "").strip().lower()
        if env_value in {"1", "true", "yes", "on"}:
            return True
        sentinel = Path(repo) / self.kill_switch_file
        return sentinel.is_file()

    def pre_generation(self, repo: str | Path, finding: FindingSnapshot) -> PolicyDecision:
        reasons: list[str] = []
        killed = self.kill_switch_active(repo)
        if killed:
            reasons.append("remediation kill switch is active")
        if self.require_verified and not finding.verified:
            reasons.append("finding is not independently verified")
        if finding.severity.lower() not in {item.lower() for item in self.allowed_severities}:
            reasons.append(f"severity {finding.severity!r} is not allowed")
        if self.allowed_cwes and finding.cwe not in self.allowed_cwes:
            reasons.append(f"CWE {finding.cwe or 'unknown'} is not in the allow list")
        if finding.cwe in self.denied_cwes:
            reasons.append(f"CWE {finding.cwe} is denied")
        try:
            current_rank = EVIDENCE_LEVELS.index(finding.evidence_level)
            minimum_rank = EVIDENCE_LEVELS.index(self.minimum_evidence)
            if current_rank < minimum_rank:
                reasons.append(
                    f"evidence {finding.evidence_level!r} is below {self.minimum_evidence!r}"
                )
        except ValueError:
            reasons.append("finding or policy has an unknown evidence level")
        if safe_repo_relative_path(finding.file) is None:
            reasons.append("finding file is not a safe repository-relative path")
        elif resolve_repo_file(repo, finding.file) is None:
            reasons.append("finding file is missing, not regular, or escapes through a symlink")
        if self._forbidden(finding.file):
            reasons.append(f"finding targets forbidden path {finding.file!r}")
        return PolicyDecision(
            phase="pre-generation",
            allowed=not reasons,
            reasons=reasons,
            kill_switch_active=killed,
            policy_sha256=self.sha256(),
        )

    def post_diff(
        self,
        repo: str | Path,
        finding: FindingSnapshot,
        diff: str,
    ) -> tuple[PolicyDecision, DiffSummary]:
        summary = analyze_unified_diff(diff)
        reasons = list(summary.errors)
        killed = self.kill_switch_active(repo)
        if killed:
            reasons.append("remediation kill switch is active")
        if len(summary.touched_files) > self.max_files_changed:
            reasons.append(
                f"diff changes {len(summary.touched_files)} files; maximum is "
                f"{self.max_files_changed}"
            )
        if summary.changed_lines > self.max_changed_lines:
            reasons.append(
                f"diff changes {summary.changed_lines} lines; maximum is {self.max_changed_lines}"
            )
        if summary.creates_or_deletes_files and not self.allow_file_creation_or_deletion:
            reasons.append("file creation and deletion are disabled")
        forbidden = [path for path in summary.touched_files if self._forbidden(path)]
        if forbidden:
            reasons.append(f"diff touches forbidden paths: {', '.join(forbidden)}")
        root = Path(repo).resolve()
        unsafe_targets = []
        for relative in summary.touched_files:
            resolved = resolve_repo_file(root, relative)
            requested = root / relative
            if resolved is None or resolved != requested:
                unsafe_targets.append(relative)
        if unsafe_targets:
            reasons.append(
                "diff targets missing, non-regular, or symlinked files: "
                + ", ".join(unsafe_targets)
            )
        target = safe_repo_relative_path(finding.file)
        if self.target_file_only and target is not None:
            other = [path for path in summary.touched_files if path != target]
            if other:
                reasons.append("diff is not limited to the finding target: " + ", ".join(other))
        decision = PolicyDecision(
            phase="post-diff",
            allowed=not reasons,
            reasons=reasons,
            touched_files=summary.touched_files,
            kill_switch_active=killed,
            policy_sha256=self.sha256(),
        )
        return decision, summary

    def _forbidden(self, path: str) -> bool:
        normalized = (safe_repo_relative_path(path) or path.replace("\\", "/")).lstrip("./")
        for pattern in self.forbidden_paths:
            clean_pattern = pattern.replace("\\", "/").lstrip("./")
            prefix = clean_pattern.removesuffix("/**")
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
            if fnmatch.fnmatchcase(normalized, clean_pattern):
                return True
        return False


def default_policy_document() -> str:
    payload: dict[str, Any] = RemediationPolicy().model_dump(mode="json")
    return cast(str, yaml.safe_dump(payload, sort_keys=False))
