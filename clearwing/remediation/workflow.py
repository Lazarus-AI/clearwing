"""Orchestration for generation, policy, application, validation, and resume."""

from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import uuid
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any, cast

from clearwing.findings.types import EvidenceLevel
from clearwing.llm import AsyncLLMClient
from clearwing.reporting.safety import redact_text
from clearwing.sourcehunt.patcher import AutoPatcher
from clearwing.sourcehunt.paths import resolve_repo_file
from clearwing.sourcehunt.state import Finding

from .models import (
    DynamicValidation,
    FindingSnapshot,
    ProposedFix,
    RemediationDTO,
    RemediationMode,
)
from .panel import RemediationValidationPanel
from .policy import RemediationPolicy
from .store import RemediationStore
from .transaction import PatchTransaction

DynamicValidator = Callable[
    [dict[str, Any], str],
    DynamicValidation | dict[str, Any] | Awaitable[DynamicValidation | dict[str, Any]],
]

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def load_findings(path: str | Path) -> list[dict[str, Any]]:
    """Load a sourcehunt report or a direct JSON finding list."""

    payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    findings: Any
    if isinstance(payload, list):
        findings = payload
    elif isinstance(payload, dict):
        preferred = payload.get("verified_findings")
        findings = (
            preferred if isinstance(preferred, list) and preferred else payload.get("findings")
        )
    else:
        findings = None
    if not isinstance(findings, list):
        raise ValueError("findings input must be a list or a sourcehunt findings.json object")
    return [dict(item) for item in findings if isinstance(item, dict)]


class RemediationWorkflow:
    """One coherent, durable remediation lifecycle for a repository."""

    def __init__(
        self,
        *,
        repo: str | Path,
        store: RemediationStore,
        remediator_llm: AsyncLLMClient,
        validation_panel: RemediationValidationPanel,
        policy: RemediationPolicy | None = None,
        mode: RemediationMode = "report-only",
        dynamic_validator: DynamicValidator | None = None,
        run_id: str | None = None,
    ):
        self.repo = Path(repo).expanduser().resolve()
        self.store = store
        self.policy = policy or RemediationPolicy()
        self.mode = mode
        self.dynamic_validator = dynamic_validator
        self.panel = validation_panel
        self.run_id = run_id or f"rem-{uuid.uuid4().hex[:12]}"
        self.base_git_sha = self._git_sha()
        self.patcher = AutoPatcher(
            remediator_llm,
            eligible_severities={item.lower() for item in self.policy.allowed_severities},
            patch_gate=cast(EvidenceLevel, self.policy.minimum_evidence),
        )

    async def run(
        self,
        findings: Iterable[dict[str, Any]],
        *,
        resume: bool = False,
        top: int | None = None,
        finding_ids: set[str] | None = None,
    ) -> list[RemediationDTO]:
        selected = self._select(findings, top=top, finding_ids=finding_ids)
        results: list[RemediationDTO] = []
        for finding in selected:
            snapshot = FindingSnapshot.from_finding(finding)
            fingerprint = self._fingerprint(snapshot)
            existing = self.store.find_by_fingerprint(fingerprint) if resume else None
            if existing is not None:
                if existing.status == "applied":
                    results.append(await self._resume_applied(existing))
                elif existing.status == "proposed" and self.mode == "apply":
                    existing.mode = "apply"
                    existing.run_id = self.run_id
                    results.append(await self._apply_proposed(existing, finding))
                elif existing.status == "pending" and existing.application.attempted:
                    existing.status = "needs_review"
                    existing.error = (
                        "interrupted during patch application; inspect target hashes and "
                        "encrypted backups before retrying"
                    )
                    self.store.save(existing)
                    results.append(existing)
                else:
                    results.append(existing)
                continue
            dto = RemediationDTO(
                remediation_id=f"rem-{_safe_id(snapshot.id)}-{fingerprint[:10]}",
                run_id=self.run_id,
                mode=self.mode,
                repository=str(self.repo),
                base_git_sha=self.base_git_sha,
                fingerprint=fingerprint,
                finding=snapshot,
            )
            self.store.save(dto)
            results.append(await self._process(dto, finding))
        return results

    async def validate_existing(self, dto: RemediationDTO) -> RemediationDTO:
        """Re-run the independent panel without applying or reverting a patch."""

        prior_status = dto.status
        if dto.proposed_fix is None:
            dto.status = "error"
            dto.error = "DTO has no proposed fix"
            self.store.save(dto)
            return dto
        source = self._read_source(dto.finding)
        dynamic = await self._run_dynamic(dto.finding.model_dump(), dto.proposed_fix.diff)
        dto.validation = await self.panel.validate(
            finding=dto.finding.model_dump(mode="json"),
            fix=dto.proposed_fix,
            checkout_source=source,
            dynamic=dynamic,
            policy_allowed=all(decision.allowed for decision in dto.policy_decisions),
        )
        if prior_status in {"applied", "validated"}:
            dto.status = dto.validation.status
        elif prior_status in {"proposed", "needs_review", "validation_failed"}:
            dto.status = (
                "proposed" if dto.validation.status == "validated" else dto.validation.status
            )
        self.store.save(dto)
        return dto

    async def _process(
        self,
        dto: RemediationDTO,
        finding: dict[str, Any],
    ) -> RemediationDTO:
        try:
            pre = self.policy.pre_generation(self.repo, dto.finding)
            dto.policy_decisions.append(pre)
            if not pre.allowed:
                dto.status = "blocked"
                self.store.save(dto)
                return dto

            source = self._read_source(dto.finding)
            attempt = await self.patcher.aattempt(cast(Finding, finding), file_content=source)
            if not attempt.attempted or not attempt.diff.strip():
                dto.status = "blocked"
                dto.error = redact_text(attempt.notes or "remediator produced no patch")
                self.store.save(dto)
                return dto

            confidence = (
                attempt.confidence if attempt.confidence in {"high", "medium", "low"} else "low"
            )
            dto.proposed_fix = ProposedFix(
                diff=attempt.diff,
                commit_message=attempt.commit_message,
                explanation=attempt.explanation,
                confidence=confidence,  # type: ignore[arg-type]
            )
            post, summary = self.policy.post_diff(self.repo, dto.finding, attempt.diff)
            dto.policy_decisions.append(post)
            dto.proposed_fix.touched_files = summary.touched_files
            if not post.allowed:
                dto.status = "blocked"
                self.store.save(dto)
                return dto

            dynamic = await self._run_dynamic(finding, attempt.diff)
            if self.mode == "report-only":
                dto.validation = await self.panel.validate(
                    finding=dto.finding.model_dump(mode="json"),
                    fix=dto.proposed_fix,
                    checkout_source=source,
                    dynamic=dynamic,
                    policy_allowed=True,
                )
                dto.status = (
                    "proposed" if dto.validation.status == "validated" else dto.validation.status
                )
                self.store.save(dto)
                return dto

            return await self._apply_proposed(dto, finding, dynamic=dynamic)
        except Exception as exc:
            dto.error = redact_text(str(exc))[:1000]
            dto.status = "error"
            self.store.save(dto)
            return dto

    async def _apply_proposed(
        self,
        dto: RemediationDTO,
        finding: dict[str, Any],
        *,
        dynamic: DynamicValidation | None = None,
    ) -> RemediationDTO:
        transaction: PatchTransaction | None = None
        try:
            if dto.proposed_fix is None:
                raise ValueError("DTO has no proposed fix")
            # Re-check finding eligibility, the parsed diff, and the kill switch
            # immediately before mutation.
            pre_apply_gate = self.policy.pre_generation(self.repo, dto.finding)
            dto.policy_decisions.append(pre_apply_gate)
            if not pre_apply_gate.allowed:
                dto.status = "blocked"
                self.store.save(dto)
                return dto
            apply_gate, summary = self.policy.post_diff(
                self.repo,
                dto.finding,
                dto.proposed_fix.diff,
            )
            dto.policy_decisions.append(apply_gate)
            if not apply_gate.allowed:
                dto.status = "blocked"
                self.store.save(dto)
                return dto
            if dynamic is None:
                dynamic = await self._run_dynamic(finding, dto.proposed_fix.diff)

            transaction = PatchTransaction(
                self.repo,
                dto.proposed_fix.diff,
                summary.touched_files,
                require_clean_target_paths=self.policy.require_clean_target_paths,
                expected_git_sha=dto.base_git_sha,
            )
            dto.application = transaction.prepare()
            self.store.store_backups(dto, transaction.before_contents())
            self.store.save(dto)
            dto.application = transaction.apply(dto.application)
            dto.status = "applied"
            self.store.save(dto)

            checkout_source = self._read_source(dto.finding)
            dto.validation = await self.panel.validate(
                finding=dto.finding.model_dump(mode="json"),
                fix=dto.proposed_fix,
                checkout_source=checkout_source,
                dynamic=dynamic,
                policy_allowed=True,
            )
            if dto.validation.status == "validated":
                dto.status = "validated"
            elif self.policy.rollback_on_validation_failure:
                transaction.rollback(dto.application)
                dto.status = "rolled_back"
            else:
                dto.status = dto.validation.status
            self.store.save(dto)
            return dto
        except Exception as exc:
            dto.error = redact_text(str(exc))[:1000]
            if transaction is not None and dto.application.applied:
                try:
                    transaction.rollback(dto.application)
                    dto.status = "rolled_back"
                except Exception as rollback_exc:
                    dto.status = "error"
                    dto.error += "; rollback failed: " + redact_text(str(rollback_exc))[:500]
            else:
                dto.status = "error"
            self.store.save(dto)
            return dto

    async def _resume_applied(self, dto: RemediationDTO) -> RemediationDTO:
        if dto.proposed_fix is None:
            dto.status = "needs_review"
            dto.error = "applied checkpoint has no proposed fix"
            self.store.save(dto)
            return dto
        current_hashes = {
            path: hashlib.sha256((self.repo / path).read_bytes()).hexdigest()
            for path in dto.application.touched_files
            if (self.repo / path).is_file()
        }
        if current_hashes != dto.application.after_sha256:
            dto.status = "needs_review"
            dto.error = "applied target changed after checkpoint; refusing automatic resume"
            self.store.save(dto)
            return dto
        dto = await self.validate_existing(dto)
        if dto.validation is not None and dto.validation.status != "validated":
            if self.policy.rollback_on_validation_failure:
                try:
                    self.store.restore_backups(dto, self.repo)
                    dto.application.applied = False
                    dto.application.rolled_back = True
                    dto.application.notes.append("restored encrypted checkpoint backups")
                    dto.status = "rolled_back"
                except Exception as exc:
                    dto.status = "error"
                    dto.error = "persisted rollback failed: " + redact_text(str(exc))[:500]
                self.store.save(dto)
        return dto

    async def _run_dynamic(
        self,
        finding: dict[str, Any],
        diff: str,
    ) -> DynamicValidation:
        if self.dynamic_validator is None:
            return DynamicValidation()
        try:
            result = self.dynamic_validator(finding, diff)
            if inspect.isawaitable(result):
                result = await result
            if isinstance(result, DynamicValidation):
                return result
            return cast(DynamicValidation, DynamicValidation.model_validate(result))
        except Exception as exc:
            return DynamicValidation(
                attempted=True,
                passed=False,
                notes="dynamic validator error: " + redact_text(str(exc))[:500],
            )

    def _read_source(self, finding: FindingSnapshot) -> str:
        path = resolve_repo_file(self.repo, finding.file)
        if path is None:
            raise ValueError(f"finding source is missing or unsafe: {finding.file!r}")
        return cast(str, path.read_text(encoding="utf-8", errors="replace"))

    def _select(
        self,
        findings: Iterable[dict[str, Any]],
        *,
        top: int | None,
        finding_ids: set[str] | None,
    ) -> list[dict[str, Any]]:
        selected = [
            finding
            for finding in findings
            if not finding_ids or str(finding.get("id", "")) in finding_ids
        ]
        selected.sort(
            key=lambda finding: (
                -_SEVERITY_RANK.get(
                    str(
                        finding.get("severity_verified") or finding.get("severity") or "info"
                    ).lower(),
                    0,
                ),
                str(finding.get("id", "")),
            )
        )
        return selected[:top] if top is not None else selected

    def _fingerprint(self, finding: FindingSnapshot) -> str:
        payload = {
            "repository": str(self.repo),
            "finding": finding.model_dump(mode="json"),
            "base_git_sha": self.base_git_sha,
            "policy_sha256": self.policy.sha256(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def _git_sha(self) -> str | None:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(self.repo),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError(f"not a Git repository: {self.repo}")
        return completed.stdout.strip() or None


def _safe_id(value: str) -> str:
    return "".join(char if char.isalnum() or char in "-_" else "_" for char in value)[:80]
