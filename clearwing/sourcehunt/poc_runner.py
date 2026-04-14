"""PoC replay — the sandbox leg of the verify-by-recompile gate.

Given a finding, a candidate diff, and a running SandboxContainer, this
module applies the diff, rebuilds the target, re-runs the PoC input, and
returns True/False for "crash still happens."

This is the load-bearing primitive for:
    - Verifier.run_patch_oracle (v0.3 truth test)
    - AutoPatcher.attempt        (v0.3 mandatory verify-by-recompile gate)

Design constraints:
    - NEVER modify the host repo. The diff is applied inside /scratch, and
      the sandbox is already configured with a read-only /workspace mount.
    - Fail closed: any error during apply/build/run counts as "crash still
      happens" (conservative — don't falsely validate a broken patch).
    - Bounded: every step has a timeout.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from clearwing.sandbox.container import SandboxContainer

from .state import Finding

logger = logging.getLogger(__name__)


# --- Config -----------------------------------------------------------------


@dataclass
class PocRunnerConfig:
    """Timeouts and sanitizer choices for patch replay."""

    apply_timeout_seconds: int = 30
    compile_timeout_seconds: int = 120
    run_timeout_seconds: int = 30
    sanitizers: tuple[str, ...] = ("address", "undefined")
    extra_cflags: str = "-g -O0 -fno-omit-frame-pointer"


# --- PoC runner -------------------------------------------------------------


class PocRunner:
    """Apply a patch, rebuild, and replay a PoC input inside a sandbox.

    Usage:
        runner = PocRunner(sandbox, repo_path_in_sandbox="/workspace")
        still_crashes = runner.replay(finding, candidate_diff)

    Each call is independent — the sandbox is left in an indeterminate state
    after replay, so the caller should spawn a fresh container per finding
    if multiple patches need validating. HunterSandbox.spawn() returns fresh
    containers cheaply.
    """

    def __init__(
        self,
        sandbox: SandboxContainer,
        repo_path_in_sandbox: str = "/workspace",
        config: PocRunnerConfig | None = None,
    ):
        self.sandbox = sandbox
        self.repo_root = repo_path_in_sandbox
        self.config = config or PocRunnerConfig()

    # --- Public API ---------------------------------------------------------

    def replay(
        self,
        finding: Finding,
        candidate_diff: str = "",
    ) -> dict:
        """Apply the candidate diff, rebuild, run the PoC, return a report.

        Returns a dict with keys:
            applied (bool): diff apply succeeded
            compiled (bool): rebuild succeeded
            ran (bool): the PoC replay actually executed
            still_crashes (bool): the original crash still reproduced
            exit_code (int): of the final PoC run
            stderr (str): captured stderr (capped)
            notes (str): short explanation of what happened
        """
        report = {
            "applied": False,
            "compiled": False,
            "ran": False,
            "still_crashes": True,  # conservative default
            "exit_code": -1,
            "stderr": "",
            "notes": "",
        }

        file_rel = finding.get("file", "")
        if not file_rel:
            report["notes"] = "no file path in finding"
            return report

        # 1. If there's no diff, just replay the PoC against the unmodified
        #    source — useful for confirming the finding is currently reachable.
        if candidate_diff.strip():
            applied, apply_note = self._apply_diff(file_rel, candidate_diff)
            report["applied"] = applied
            if not applied:
                report["notes"] = f"apply failed: {apply_note}"
                return report

        # 2. Rebuild the target file
        compiled, binary_path, compile_err = self._recompile(
            file_rel, patched=bool(candidate_diff.strip())
        )
        report["compiled"] = compiled
        if not compiled:
            report["notes"] = f"compile failed: {compile_err[:400]}"
            return report

        # 3. Run the PoC input against the rebuilt binary
        ran, exit_code, stderr = self._run_poc(binary_path, finding)
        report["ran"] = ran
        report["exit_code"] = exit_code
        report["stderr"] = stderr[:4000]
        if not ran:
            report["notes"] = "PoC replay did not execute"
            return report

        report["still_crashes"] = self._still_crashed(finding, exit_code, stderr)
        report["notes"] = (
            "crash reproduced after patch"
            if report["still_crashes"]
            else "PoC no longer crashes after patch"
        )
        return report

    # --- Step 1: diff apply -------------------------------------------------

    def _apply_diff(self, file_rel: str, diff: str) -> tuple[bool, str]:
        """Apply a diff to the target file in a writable copy in /scratch.

        We can't modify /workspace (it's read-only). Instead we copy the
        target file into /scratch/patched/<file_rel>, `patch -p0` the diff,
        and then return the scratch path as the new source location.

        Returns (success, error_message).
        """
        # Write the diff to a scratch file
        diff_bytes = diff.encode("utf-8")
        try:
            self.sandbox.write_file("/scratch/candidate.diff", diff_bytes)
        except Exception as e:
            return False, f"could not write diff: {e}"

        # Copy the workspace file tree under /scratch/patched/ (file-level)
        scratch_dir = f"/scratch/patched/{os.path.dirname(file_rel)}"
        src = f"{self.repo_root}/{file_rel}"
        dst = f"/scratch/patched/{file_rel}"
        mkdir_cmd = ["sh", "-c", f"mkdir -p '{scratch_dir}' && cp '{src}' '{dst}'"]
        result = self.sandbox.exec(mkdir_cmd, timeout=self.config.apply_timeout_seconds)
        if result.exit_code != 0:
            return False, f"could not copy source to scratch: {result.stderr}"

        # Try `patch` first — standard unified-diff apply
        patch_cmd = [
            "sh",
            "-c",
            "cd /scratch/patched && patch -p1 --forward < /scratch/candidate.diff 2>&1",
        ]
        result = self.sandbox.exec(patch_cmd, timeout=self.config.apply_timeout_seconds)
        if result.exit_code == 0:
            return True, ""

        # Fall back to overwriting the file with the full diff contents if the
        # LLM returned a full-function replacement instead of a diff
        if "---" not in diff and "+++" not in diff and "@@" not in diff:
            # Doesn't look like a unified diff — treat as full file replacement
            try:
                self.sandbox.write_file(dst, diff_bytes)
                return True, "applied as full-file replacement"
            except Exception as e:
                return False, f"full-file replacement failed: {e}"

        return False, f"patch -p1 failed: {result.stdout[:400]}"

    # --- Step 2: recompile --------------------------------------------------

    def _recompile(
        self,
        file_rel: str,
        patched: bool,
    ) -> tuple[bool, str, str]:
        """Rebuild the target file with sanitizers.

        Returns (success, binary_path, stderr_on_failure).
        """
        san_flags = ",".join(self.config.sanitizers)
        source_path = f"/scratch/patched/{file_rel}" if patched else f"{self.repo_root}/{file_rel}"
        binary_path = f"/scratch/poc_{os.path.basename(file_rel)}.bin"
        # Build with ASan/UBSan, -g for stack traces, -O0 for accurate line
        # numbers. Include -I /workspace to pick up headers.
        compile_cmd = [
            "sh",
            "-c",
            (
                f"cc -fsanitize={san_flags} {self.config.extra_cflags} "
                f"-I {self.repo_root} -I {self.repo_root}/include "
                f"-o {binary_path} {source_path} 2>&1"
            ),
        ]
        result = self.sandbox.exec(
            compile_cmd,
            timeout=self.config.compile_timeout_seconds,
        )
        if result.exit_code != 0:
            return False, "", result.stdout
        return True, binary_path, ""

    # --- Step 3: run the PoC ------------------------------------------------

    def _run_poc(
        self,
        binary_path: str,
        finding: Finding,
    ) -> tuple[bool, int, str]:
        """Run the binary with the PoC input as stdin.

        Returns (ran_ok, exit_code, stderr_output).
        """
        poc = finding.get("poc") or ""
        stdin_block = poc if poc else ""

        if stdin_block:
            # Pipe the PoC via shell heredoc — quoted to survive shell escaping
            escaped = stdin_block.replace("'", "'\\''")
            cmd = [
                "sh",
                "-c",
                f"printf '%s' '{escaped}' | {binary_path} 2>&1; echo __EXITCODE__$?",
            ]
        else:
            cmd = ["sh", "-c", f"{binary_path} 2>&1; echo __EXITCODE__$?"]

        result = self.sandbox.exec(cmd, timeout=self.config.run_timeout_seconds)
        # Extract the tail exit code from the wrapped output
        output = result.stdout
        rc = result.exit_code
        m = re.search(r"__EXITCODE__(\d+)\s*$", output)
        if m:
            try:
                rc = int(m.group(1))
                output = output[: m.start()].rstrip()
            except ValueError:
                pass
        return True, rc, output

    # --- Step 4: decide --------------------------------------------------

    def _still_crashed(
        self,
        finding: Finding,
        exit_code: int,
        stderr: str,
    ) -> bool:
        """True if the PoC run still exhibits the original crash.

        Heuristic:
        - If the original crash evidence contained a specific sanitizer
          error kind (heap-buffer-overflow, use-after-free, etc.), the new
          run still crashes iff the same error kind appears.
        - Otherwise, any non-zero exit is treated as "still crashed."
        """
        original = (finding.get("crash_evidence") or "").lower()
        # Common sanitizer error kinds to compare
        kinds = [
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
            "global-buffer-overflow",
            "stack-overflow",
            "double-free",
            "invalid-free",
            "alloc-dealloc-mismatch",
            "signed-integer-overflow",
            "runtime error",
            "null deref",
        ]
        original_kind = None
        for k in kinds:
            if k in original:
                original_kind = k
                break

        new_text = stderr.lower()
        if original_kind:
            # Same kind → still crashes. Different kind → we consider the
            # original crash gone (even if a NEW crash appeared, the
            # patch addressed the original theory).
            return original_kind in new_text

        # No specific kind in the original — fall back to exit code
        return exit_code != 0


# --- Convenience factory ----------------------------------------------------


def build_rerun_poc_callback(
    sandbox: SandboxContainer,
    repo_path_in_sandbox: str = "/workspace",
    config: PocRunnerConfig | None = None,
) -> Callable[[Any, Finding, str], bool]:
    """Return a callable `(sandbox, finding) -> still_crashes: bool` suitable
    for passing to Verifier.run_patch_oracle / AutoPatcher.attempt.

    The closure captures the PocRunner — each call is a fresh replay.
    """
    # Note: sandbox argument is ignored here since we captured one at
    # construction time, but the signature matches what the verifier/patcher
    # expects.
    runner = PocRunner(sandbox, repo_path_in_sandbox, config)

    def rerun(_sandbox: Any, finding: Finding, candidate_diff: str = "") -> bool:
        report = runner.replay(finding, candidate_diff)
        return bool(report.get("still_crashes", True))

    return rerun
