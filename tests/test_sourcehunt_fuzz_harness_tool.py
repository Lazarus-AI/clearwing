"""Tests for the un-stubbed fuzz_harness inline @tool.

Uses a FakeSandbox so the tests don't touch docker. Covers:
    - template-mode harness generation for four signature shapes
    - hunter-supplied harness passthrough
    - compile-failure path
    - crash detection via non-zero libFuzzer exit
    - sanitizer_variant dispatch
    - missing-sandbox error path
"""

from __future__ import annotations

from unittest.mock import MagicMock

from clearwing.agent.tools.hunt import (
    HunterContext,
    _default_libfuzzer_template,
    build_hunter_tools,
)
from clearwing.sandbox.container import ExecResult


class _FakeSandbox:
    """Scripted exec() results + write_file capture."""

    def __init__(self, exec_results):
        self._results = list(exec_results)
        self.writes: list[tuple[str, bytes]] = []
        self.stopped = False

    def exec(self, cmd, timeout=None, env=None, workdir=None) -> ExecResult:
        if not self._results:
            return ExecResult(0, "", "", 0.0)
        return self._results.pop(0)

    def write_file(self, path: str, content: bytes) -> None:
        self.writes.append((path, content))

    def stop(self) -> None:
        self.stopped = True


# --- Template generation ---------------------------------------------------


class TestLibFuzzerTemplate:
    def test_native_signature_direct_forward(self):
        src = _default_libfuzzer_template(
            "decode_frame",
            signature="int decode_frame(const uint8_t *data, size_t size)",
        )
        assert "LLVMFuzzerTestOneInput" in src
        assert "extern int decode_frame(const unsigned char *data, size_t size);" in src
        assert "decode_frame(Data, Size);" in src

    def test_empty_signature_defaults_to_native(self):
        """No signature → assume libFuzzer-native shape."""
        src = _default_libfuzzer_template("decode_frame")
        assert "decode_frame(Data, Size);" in src

    def test_const_char_with_size_signature(self):
        src = _default_libfuzzer_template(
            "parse_string",
            signature="int parse_string(const char *s, size_t len)",
        )
        assert "(const char *)Data" in src
        assert "parse_string((const char *)Data, Size);" in src

    def test_nul_terminated_char_signature(self):
        src = _default_libfuzzer_template(
            "parse_url",
            signature="int parse_url(const char *url)",
        )
        # Must NUL-terminate the fuzzer buffer
        assert "malloc(Size + 1)" in src
        assert "buf[Size] = 0;" in src
        assert "parse_url(buf);" in src
        assert "free(buf);" in src

    def test_fallback_writes_to_tempfile(self):
        """Unknown signatures → temp-file fallback."""
        src = _default_libfuzzer_template(
            "load_config",
            signature="int load_config(int flags, void *ctx)",
        )
        assert "mkstemp" in src
        assert "load_config(path);" in src
        assert "unlink(path);" in src

    def test_template_safe_function_name(self):
        """Function names in path templates must be sanitized."""
        src = _default_libfuzzer_template(
            "weird::function",
            signature="int weird::function(int x)",
        )
        # mkstemp path uses a sanitized version of the function name
        assert "weird__function" in src


# --- Tool behaviour: sandbox missing ---------------------------------------


class TestFuzzHarnessNoSandbox:
    def test_returns_error_without_sandbox(self):
        ctx = HunterContext(repo_path="/tmp")
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke(
            {
                "target_function": "decode",
                "duration_seconds": 10,
            }
        )
        assert result["status"] == "no_sandbox"


class TestFuzzHarnessMissingInput:
    def test_no_target_and_no_source_is_error(self):
        ctx = HunterContext(repo_path="/tmp", sandbox=_FakeSandbox([]))
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke({"target_function": "", "harness_source": ""})
        assert result["status"] == "error"


# --- Tool behaviour: template mode happy path -----------------------------


class TestFuzzHarnessTemplateMode:
    def test_clean_run_returns_zero_crashes(self):
        # Scripted exec results: [compile, run]
        fake = _FakeSandbox(
            [
                ExecResult(0, "", "", 1.0),  # compile
                ExecResult(0, "Done 1000 runs", "", 2.0),  # run — no crashes
            ]
        )
        ctx = HunterContext(repo_path="/tmp", sandbox=fake)
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke(
            {
                "target_function": "decode_frame",
                "duration_seconds": 5,
            }
        )
        assert result["status"] == "completed"
        assert result["crashes_found"] == 0
        assert result["crash_evidence"] == ""
        assert result["harness_source_kind"] == "template"
        # Harness file was written before compile
        assert len(fake.writes) == 1
        harness_path, content = fake.writes[0]
        assert harness_path.startswith("/scratch/")
        assert b"LLVMFuzzerTestOneInput" in content

    def test_crashing_run_captures_sanitizer_report(self):
        fake = _FakeSandbox(
            [
                ExecResult(0, "", "", 1.0),  # compile
                # libFuzzer exits 77 on crash per our command args
                ExecResult(
                    77, "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x4000", "", 3.0
                ),
            ]
        )
        ctx = HunterContext(repo_path="/tmp", sandbox=fake)
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke(
            {
                "target_function": "decode",
                "duration_seconds": 10,
            }
        )
        assert result["status"] == "completed"
        assert result["crashes_found"] == 1
        assert "heap-buffer-overflow" in result["crash_evidence"]
        assert "AddressSanitizer" in result["crash_evidence"]

    def test_compile_failure_returns_early(self):
        fake = _FakeSandbox(
            [
                ExecResult(1, "undefined reference", "", 0.5),  # compile failed
            ]
        )
        ctx = HunterContext(repo_path="/tmp", sandbox=fake)
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke({"target_function": "decode"})
        assert result["status"] == "compile_failed"
        assert "undefined reference" in result["stdout"]
        # Only the compile exec was called — no run
        assert len(fake._results) == 0


# --- Tool behaviour: hunter-supplied harness mode --------------------------


class TestFuzzHarnessHunterSupplied:
    def test_hunter_supplied_source_wins(self):
        custom = """
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *D, size_t S) {
    (void)D; (void)S;
    return 0;
}
"""
        fake = _FakeSandbox(
            [
                ExecResult(0, "", "", 1.0),
                ExecResult(0, "", "", 1.0),
            ]
        )
        ctx = HunterContext(repo_path="/tmp", sandbox=fake)
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke(
            {
                "target_function": "ignored",
                "harness_source": custom,
                "duration_seconds": 5,
            }
        )
        assert result["status"] == "completed"
        assert result["harness_source_kind"] == "hunter_supplied"
        # The written harness is the hunter's source, not the template
        _, written = fake.writes[0]
        assert b"(void)D; (void)S;" in written

    def test_hunter_source_can_have_custom_includes(self):
        custom_with_include = """
#include "project_header.h"
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *D, size_t S) { return 0; }
"""
        fake = _FakeSandbox(
            [
                ExecResult(0, "", "", 1.0),
                ExecResult(0, "", "", 1.0),
            ]
        )
        ctx = HunterContext(repo_path="/tmp", sandbox=fake)
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        fuzz.invoke(
            {
                "target_function": "",  # hunter-supplied — doesn't need it
                "harness_source": custom_with_include,
            }
        )
        _, written = fake.writes[0]
        assert b"project_header.h" in written


# --- Sanitizer variant dispatch -------------------------------------------


class TestFuzzHarnessVariantDispatch:
    def test_msan_variant_routes_through_manager(self):
        primary = _FakeSandbox([])  # must not be called
        msan_sandbox = _FakeSandbox(
            [
                ExecResult(0, "", "", 1.0),
                ExecResult(0, "", "", 1.0),
            ]
        )
        manager = MagicMock()
        manager.spawn.return_value = msan_sandbox

        ctx = HunterContext(
            repo_path="/tmp",
            sandbox=primary,
            sandbox_manager=manager,
        )
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke(
            {
                "target_function": "decode",
                "sanitizer_variant": "msan",
                "duration_seconds": 5,
            }
        )
        assert result["status"] == "completed"
        assert result["variant"] == "msan"
        # MSan sandbox received the writes and exec calls
        assert len(msan_sandbox.writes) == 1
        assert primary.writes == []
