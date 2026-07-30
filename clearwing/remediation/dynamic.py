"""Sandboxed recompile-and-replay validation for proposed patches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clearwing.sandbox.hunter_sandbox import HunterSandbox
from clearwing.sourcehunt.poc_runner import PocRunner

from .models import DynamicValidation


class SandboxPatchValidator:
    """Replay a finding against the candidate diff in a fresh no-network sandbox."""

    def __init__(
        self,
        repo: str | Path,
        *,
        runtime: str | None = None,
        sandbox_manager: Any | None = None,
    ):
        self.repo = Path(repo).expanduser().resolve()
        self.runtime = runtime
        self.manager = sandbox_manager or HunterSandbox(repo_path=str(self.repo))
        self._built = False

    def __call__(self, finding: dict[str, Any], diff: str) -> DynamicValidation:
        if not finding.get("poc"):
            return DynamicValidation(
                attempted=False,
                notes="finding has no PoC input for sandbox replay",
            )
        if not self._built:
            self.manager.build_image()
            self._built = True
        sandbox = self.manager.spawn(runtime=self.runtime)
        try:
            report = PocRunner(sandbox).replay(finding, diff)  # type: ignore[arg-type]
        finally:
            try:
                sandbox.stop()
            except Exception:
                pass
        passed = bool(
            report.get("applied")
            and report.get("compiled")
            and report.get("ran")
            and not report.get("still_crashes", True)
        )
        return DynamicValidation(
            attempted=True,
            passed=passed,
            compiled=bool(report.get("compiled")),
            ran=bool(report.get("ran")),
            still_crashes=bool(report.get("still_crashes", True)),
            notes=str(report.get("notes", "")),
        )

    def close(self) -> None:
        self.manager.cleanup()
