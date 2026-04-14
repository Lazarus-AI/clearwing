"""Tests for the PocRunner — the verify-by-recompile sandbox leg.

Uses a FakeSandbox with scripted exec() results so no docker required.
The runner's contract is:
    - fail closed on any error
    - still_crashes reflects whether the ORIGINAL crash kind reappears
    - exit code fallback is used when the original crash has no specific kind
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from clearwing.sandbox.container import ExecResult
from clearwing.sourcehunt.poc_runner import (
    PocRunner,
    PocRunnerConfig,
    build_rerun_poc_callback,
)


class _FakeSandbox:
    """Minimal sandbox stub. Scripts exec() results in order."""

    def __init__(self, exec_results):
        self._results = list(exec_results)
        self._writes: list[tuple[str, bytes]] = []

    def exec(self, cmd, timeout=None, env=None, workdir=None) -> ExecResult:
        if not self._results:
            return ExecResult(exit_code=0, stdout="", stderr="", duration_seconds=0.0)
        return self._results.pop(0)

    def write_file(self, container_path: str, content: bytes) -> None:
        self._writes.append((container_path, content))


def _finding(**kwargs) -> dict:
    base = {
        "id": "f1",
        "file": "src/codec.c",
        "line_number": 9,
        "cwe": "CWE-787",
        "severity": "critical",
        "description": "memcpy overflow",
        "crash_evidence": "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
        "poc": "AAAA",
    }
    base.update(kwargs)
    return base


# --- replay happy path ------------------------------------------------------


class TestReplayPatched:
    def test_patch_kills_crash(self):
        """Apply a diff, rebuild cleanly, run — exit 0 → no more crash."""
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),                        # mkdir && cp
            ExecResult(0, "patching file src/codec.c", "", 0.1),  # patch
            ExecResult(0, "", "", 1.0),                        # cc
            ExecResult(0, "__EXITCODE__0", "", 0.2),           # run — exit 0
        ])
        runner = PocRunner(fake)
        report = runner.replay(_finding(), candidate_diff="--- a/src/codec.c\n+++ b/src/codec.c\n@@ -1 +1 @@\n-bug\n+fix\n")
        assert report["applied"] is True
        assert report["compiled"] is True
        assert report["ran"] is True
        assert report["still_crashes"] is False
        assert "no longer crashes" in report["notes"]

    def test_patch_leaves_crash(self):
        """Apply a diff, rebuild, run — same sanitizer kind reappears."""
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),                        # mkdir && cp
            ExecResult(0, "", "", 0.1),                        # patch
            ExecResult(0, "", "", 1.0),                        # cc
            ExecResult(1, "==2==ERROR: AddressSanitizer: heap-buffer-overflow\n__EXITCODE__1", "", 0.2),  # run — crashes
        ])
        runner = PocRunner(fake)
        report = runner.replay(_finding(), candidate_diff="--- a/x\n+++ b/x\n@@ @@")
        assert report["still_crashes"] is True
        assert "reproduced" in report["notes"]

    def test_different_crash_kind_counts_as_patched(self):
        """If the original was a heap overflow and the new error is use-after-free,
        the patch addressed the original theory → still_crashes=False."""
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),    # mkdir && cp
            ExecResult(0, "", "", 0.1),    # patch
            ExecResult(0, "", "", 1.0),    # cc
            ExecResult(1, "==3==ERROR: AddressSanitizer: use-after-free\n__EXITCODE__1", "", 0.2),
        ])
        runner = PocRunner(fake)
        report = runner.replay(_finding(), candidate_diff="--- a/x\n+++ b/x\n@@ @@")
        assert report["still_crashes"] is False


# --- Failure paths (fail closed) -------------------------------------------


class TestReplayFailsClosed:
    def test_apply_failure_returns_crash(self):
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),              # mkdir && cp
            ExecResult(1, "patch error", "", 0.1),   # patch fails
        ])
        runner = PocRunner(fake)
        report = runner.replay(_finding(), candidate_diff="--- a/x\n+++ b/x\n@@ @@")
        assert report["applied"] is False
        assert report["still_crashes"] is True   # conservative default
        assert "apply failed" in report["notes"]

    def test_compile_failure_returns_crash(self):
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),    # mkdir && cp
            ExecResult(0, "", "", 0.1),    # patch ok
            ExecResult(1, "syntax error", "", 0.1),   # compile fails
        ])
        runner = PocRunner(fake)
        report = runner.replay(_finding(), candidate_diff="--- a/x\n+++ b/x\n@@ @@")
        assert report["compiled"] is False
        assert report["still_crashes"] is True
        assert "compile failed" in report["notes"]

    def test_no_file_path_returns_crash(self):
        runner = PocRunner(_FakeSandbox([]))
        report = runner.replay({"id": "f"}, "anything")
        assert report["still_crashes"] is True
        assert "no file path" in report["notes"]


# --- Unpatched replay -------------------------------------------------------


class TestReplayUnpatched:
    def test_empty_diff_skips_apply(self):
        """When there's no diff, apply step is skipped entirely."""
        fake = _FakeSandbox([
            ExecResult(0, "", "", 1.0),                        # cc
            ExecResult(0, "__EXITCODE__0", "", 0.2),           # run — exit 0
        ])
        runner = PocRunner(fake)
        report = runner.replay(_finding(), candidate_diff="")
        # applied=False is fine because we didn't try to apply anything
        assert report["compiled"] is True
        assert report["ran"] is True
        assert report["still_crashes"] is False


# --- Exit-code fallback (no specific kind in original crash) ---------------


class TestExitCodeFallback:
    def test_no_specific_kind_in_original_uses_exit_code(self):
        # Original crash has generic output — no known sanitizer kind
        f = _finding(crash_evidence="some garbage output")
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),
            ExecResult(0, "", "", 0.1),
            ExecResult(0, "", "", 1.0),
            ExecResult(0, "__EXITCODE__0", "", 0.2),
        ])
        runner = PocRunner(fake)
        report = runner.replay(f, "--- a/x\n+++ b/x\n@@ @@")
        # exit 0 → no crash
        assert report["still_crashes"] is False

    def test_no_specific_kind_nonzero_exit(self):
        f = _finding(crash_evidence="some garbage output")
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),
            ExecResult(0, "", "", 0.1),
            ExecResult(0, "", "", 1.0),
            ExecResult(1, "__EXITCODE__1", "", 0.2),
        ])
        runner = PocRunner(fake)
        report = runner.replay(f, "--- a/x\n+++ b/x\n@@ @@")
        assert report["still_crashes"] is True


# --- Full-file replacement fallback ----------------------------------------


class TestFullFileReplacement:
    def test_non_diff_input_treated_as_full_file(self):
        """If the LLM returns a raw function body (no '---' / '@@' markers),
        the runner writes it as a full-file replacement."""
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),    # mkdir && cp
            # patch step reached but we detect non-diff first; actually
            # we call patch, it fails, then we fall back.
            ExecResult(1, "malformed patch", "", 0.1),
            # compile and run succeed
            ExecResult(0, "", "", 1.0),
            ExecResult(0, "__EXITCODE__0", "", 0.2),
        ])
        runner = PocRunner(fake)
        full_function = "int decode() { return 0; }"
        report = runner.replay(_finding(), candidate_diff=full_function)
        assert report["applied"] is True
        # The fake sandbox captured a write with the full function body
        writes = [w for w in fake._writes if w[0].endswith("/codec.c")]
        assert len(writes) >= 1
        assert b"return 0" in writes[0][1]


# --- build_rerun_poc_callback factory --------------------------------------


class TestBuildRerunPocCallback:
    def test_callback_returns_bool(self):
        fake = _FakeSandbox([
            ExecResult(0, "", "", 0.1),    # mkdir && cp
            ExecResult(0, "", "", 0.1),    # patch
            ExecResult(0, "", "", 1.0),    # cc
            ExecResult(0, "__EXITCODE__0", "", 0.2),    # run ok
        ])
        cb = build_rerun_poc_callback(fake)
        result = cb(fake, _finding(), candidate_diff="--- a/x\n+++ b/x\n@@ @@")
        assert result is False  # crash is gone

    def test_callback_signature_accepts_original_two_args(self):
        """Backwards-compat: the verifier passes (sandbox, finding) — no diff."""
        fake = _FakeSandbox([
            ExecResult(0, "", "", 1.0),               # cc
            ExecResult(0, "__EXITCODE__0", "", 0.2),  # run ok
        ])
        cb = build_rerun_poc_callback(fake)
        # Called without candidate_diff
        result = cb(fake, _finding())
        assert result is False
