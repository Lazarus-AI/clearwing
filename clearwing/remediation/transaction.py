"""Rollback-safe host patch application after policy approval."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from clearwing.sourcehunt.paths import resolve_repo_file, safe_repo_relative_path

from .models import ApplicationRecord


class PatchTransactionError(RuntimeError):
    pass


@dataclass
class _Snapshot:
    content: bytes
    mode: int


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class PatchTransaction:
    """Apply one approved diff and retain exact bytes for guarded rollback."""

    def __init__(
        self,
        repo: str | Path,
        diff: str,
        touched_files: list[str],
        *,
        require_clean_target_paths: bool = True,
        expected_git_sha: str | None = None,
    ):
        self.repo = Path(repo).resolve()
        self.diff = diff
        self.touched_files = [self._safe_path(path) for path in touched_files]
        self.require_clean_target_paths = require_clean_target_paths
        self.expected_git_sha = expected_git_sha
        self._before: dict[str, _Snapshot] = {}
        self._after: dict[str, bytes] = {}
        self._prepared = False
        self._applied = False

    def prepare(self) -> ApplicationRecord:
        current_git_sha = self._git_value("rev-parse", "HEAD")
        record = ApplicationRecord(
            attempted=True,
            base_git_sha=current_git_sha,
            touched_files=list(self.touched_files),
        )
        self._assert_git_root()
        if self.expected_git_sha and current_git_sha != self.expected_git_sha:
            raise PatchTransactionError(
                "repository HEAD changed after remediation review: "
                f"expected {self.expected_git_sha}, found {current_git_sha or 'unknown'}"
            )
        if not self.touched_files:
            raise PatchTransactionError("approved patch has no target files")
        if self.require_clean_target_paths:
            status = self._git_value("status", "--porcelain", "--", *self.touched_files)
            if status:
                raise PatchTransactionError(
                    "target paths already contain working-tree changes: "
                    + ", ".join(self.touched_files)
                )

        for relative in self.touched_files:
            path = self.repo / relative
            resolved = resolve_repo_file(self.repo, relative)
            if resolved is None or resolved != path:
                raise PatchTransactionError(
                    f"target is missing, non-regular, or symlinked: {relative}"
                )
            content = path.read_bytes()
            self._before[relative] = _Snapshot(
                content=content,
                mode=stat.S_IMODE(path.stat().st_mode),
            )
            record.before_sha256[relative] = _sha256(content)

        self._prepared = True
        return record

    def before_contents(self) -> dict[str, bytes]:
        if not self._prepared:
            raise PatchTransactionError("transaction has not been prepared")
        return {path: snapshot.content for path, snapshot in self._before.items()}

    def apply(self, record: ApplicationRecord | None = None) -> ApplicationRecord:
        record = record or self.prepare()
        if not self._prepared:
            raise PatchTransactionError("transaction has not been prepared")

        self._git_apply(check=True)
        try:
            self._git_apply(check=False)
            self._applied = True
            for relative in self.touched_files:
                content = (self.repo / relative).read_bytes()
                self._after[relative] = content
                record.after_sha256[relative] = _sha256(content)
                if content == self._before[relative].content:
                    raise PatchTransactionError(f"patch did not change approved target: {relative}")
        except Exception:
            if self._applied:
                self.rollback(record)
            raise

        record.applied = True
        record.notes.append("patch applied after git apply --check")
        return record

    def rollback(self, record: ApplicationRecord) -> None:
        if not self._applied:
            return
        # Verify the complete rollback set before modifying any target.
        for relative in self._before:
            path = self.repo / relative
            current = path.read_bytes() if path.is_file() else b""
            expected = self._after.get(relative)
            if expected is not None and current != expected:
                raise PatchTransactionError(
                    f"refusing rollback because {relative} changed after patch application"
                )
        for relative, snapshot in self._before.items():
            path = self.repo / relative
            path.write_bytes(snapshot.content)
            os.chmod(path, snapshot.mode)
        self._applied = False
        record.applied = False
        record.rolled_back = True
        record.notes.append("restored exact pre-application file snapshots")

    def _safe_path(self, value: str) -> str:
        relative = safe_repo_relative_path(value)
        if relative is None:
            raise PatchTransactionError(f"unsafe patch target: {value!r}")
        return cast(str, relative)

    def _assert_git_root(self) -> None:
        root = self._git_value("rev-parse", "--show-toplevel")
        if not root:
            raise PatchTransactionError("target is not a Git repository")
        if Path(root).resolve() != self.repo:
            raise PatchTransactionError(
                f"repository path must be the Git root ({Path(root).resolve()})"
            )

    def _git_apply(self, *, check: bool) -> None:
        argv = ["git", "apply", "--recount", "--whitespace=error-all"]
        if check:
            argv.append("--check")
        completed = subprocess.run(
            argv,
            cwd=str(self.repo),
            input=self.diff,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[-1000:]
            phase = "check" if check else "apply"
            raise PatchTransactionError(f"git apply {phase} failed: {detail}")

    def _git_value(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(self.repo),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            return ""
        return cast(str, completed.stdout.strip())
