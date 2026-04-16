"""Tests for the crash-first Harness Generator.

The generator is the biggest v0.2 addition: it generates libFuzzer harnesses,
compiles them in the sandbox, runs them, and seeds crashes into the hunter
pipeline BEFORE the ReAct hunters start. These tests use mocked LLM and
mocked sandbox so they run fast and don't need docker or gcc.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from clearwing.sandbox.container import ExecResult
from clearwing.sourcehunt.harness_generator import (
    HarnessGenerator,
    HarnessGeneratorConfig,
    HarnessGeneratorResult,
    _guess_target_function,
    _parse_sanitizer_report,
    _strip_markdown_fences,
)
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"


# --- Helpers ---------------------------------------------------------------


def _ft(path: str, absolute_path: str, tags=None, surface=5, language="c") -> dict:
    return {
        "path": path,
        "absolute_path": absolute_path,
        "tags": tags or [],
        "surface": surface,
        "influence": 2,
        "reachability": 3,
        "priority": surface * 0.5 + 0.4 + 0.9,
        "tier": "A",
        "language": language,
        "loc": 30,
        "static_hint": 0,
        "imports_by": 0,
        "defines_constants": False,
        "transitive_callers": 0,
        "semgrep_hint": 0,
        "surface_rationale": "",
        "influence_rationale": "",
        "reachability_rationale": "",
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
    }


def _mock_llm(response_text: str) -> MagicMock:
    llm = MagicMock()
    resp = MagicMock()
    resp.content = response_text
    llm.invoke.return_value = resp
    return llm


class _FakeSandbox:
    """A fake SandboxContainer with scripted exec() responses."""

    def __init__(self, exec_results: list[ExecResult]):
        self._exec_results = list(exec_results)
        self._writes: list[tuple[str, bytes]] = []
        self.stopped = False

    def write_file(self, container_path: str, content: bytes) -> None:
        self._writes.append((container_path, content))

    def exec(self, cmd, timeout=None, env=None, workdir=None) -> ExecResult:
        if not self._exec_results:
            return ExecResult(exit_code=0, stdout="", stderr="", duration_seconds=0)
        return self._exec_results.pop(0)

    def stop(self) -> None:
        self.stopped = True


# --- Eligibility -----------------------------------------------------------


class TestEligibility:
    def test_non_parser_file_skipped(self):
        gen = HarnessGenerator(_mock_llm("int x;"), sandbox_factory=None)
        ft = _ft(
            "util.c",
            str(FIXTURE_C_PROPAGATION / "src/codec_a.c"),
            tags=["memory_unsafe"],
            surface=5,
        )
        eligible = gen._select_eligible([ft])
        assert eligible == []  # no parser/fuzzable tag

    def test_parser_tagged_file_eligible(self):
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=None)
        ft = _ft("decode.c", "/abs/decode.c", tags=["parser"], surface=5)
        eligible = gen._select_eligible([ft])
        assert eligible == [ft]

    def test_fuzzable_tagged_file_eligible(self):
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=None)
        ft = _ft("h.c", "/abs/h.c", tags=["fuzzable"], surface=4)
        eligible = gen._select_eligible([ft])
        assert len(eligible) == 1

    def test_low_surface_skipped(self):
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=None)
        ft = _ft("p.c", "/abs/p.c", tags=["parser"], surface=2)
        assert gen._select_eligible([ft]) == []

    def test_non_c_cpp_skipped(self):
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=None)
        ft = _ft("p.py", "/abs/p.py", tags=["parser"], surface=5, language="python")
        # Only C/C++ in v0.2
        assert gen._select_eligible([ft]) == []

    def test_cpp_allowed(self):
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=None)
        ft = _ft("p.cpp", "/abs/p.cpp", tags=["parser"], surface=5, language="cpp")
        assert gen._select_eligible([ft]) == [ft]


# --- Helpers: target-function guess ----------------------------------------


class TestGuessTargetFunction:
    def test_single_function(self):
        src = """
int decode_frame(const uint8_t *data, size_t len) {
    return 0;
}
"""
        assert _guess_target_function(src) == "decode_frame"

    def test_excludes_main(self):
        src = """
int helper(int x) { return x; }
int main(int argc, char **argv) { return 0; }
"""
        # main is excluded; last non-main function wins
        assert _guess_target_function(src) == "helper"

    def test_empty_source(self):
        assert _guess_target_function("") is None

    def test_multiple_functions_returns_last(self):
        src = """
int first(int a) { return a; }
int second(int b) { return b; }
int third(int c) { return c; }
"""
        assert _guess_target_function(src) == "third"


# --- Helpers: markdown-fence stripping -------------------------------------


class TestStripMarkdownFences:
    def test_fenced_with_c_tag(self):
        content = "```c\nint main() { return 0; }\n```"
        assert _strip_markdown_fences(content) == "int main() { return 0; }"

    def test_fenced_with_cpp_tag(self):
        content = "```cpp\nint f() { return 0; }\n```"
        assert _strip_markdown_fences(content) == "int f() { return 0; }"

    def test_unfenced(self):
        content = "int f() { return 0; }"
        assert _strip_markdown_fences(content) == "int f() { return 0; }"

    def test_leading_whitespace_stripped(self):
        content = "\n\n```c\nint x;\n```\n\n"
        assert _strip_markdown_fences(content) == "int x;"


# --- Helpers: sanitizer report parsing -------------------------------------


class TestParseSanitizerReport:
    def test_asan_header_extracted(self):
        raw = """some noise
INFO: Seed: 42
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xabc
    #0 0x4000 in harness_test /scratch/harness.c:5
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
        report = _parse_sanitizer_report(raw)
        assert "AddressSanitizer" in report
        assert "heap-buffer-overflow" in report

    def test_libfuzzer_header_extracted(self):
        raw = """==1==ERROR: libFuzzer: deadly signal
stack trace..."""
        report = _parse_sanitizer_report(raw)
        assert "libFuzzer" in report

    def test_empty(self):
        assert _parse_sanitizer_report("") == ""


# --- Full _fuzz_one happy-path with a FakeSandbox -------------------------


class TestFuzzOneHappyPath:
    def test_compile_success_and_no_crash(self, tmp_path):
        """Harness compiles and runs cleanly → returns a non-crashed SeededCrash."""
        src_file = tmp_path / "parser.c"
        src_file.write_text(
            """
#include <stdint.h>
int decode(const uint8_t *d, size_t n) {
    (void)d; (void)n;
    return 0;
}
"""
        )
        harness_llm = _mock_llm(
            "#include <stdint.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
            "    return 0;\n"
            "}\n"
        )
        # Script: compile OK, run OK (exit 0)
        fake = _FakeSandbox(
            [
                ExecResult(exit_code=0, stdout="", stderr="", duration_seconds=0.1),  # compile
                ExecResult(exit_code=0, stdout="", stderr="", duration_seconds=5.0),  # run
            ]
        )
        gen = HarnessGenerator(
            harness_llm,
            sandbox_factory=lambda: fake,
            config=HarnessGeneratorConfig(per_harness_duration_seconds=5),
        )
        ft = _ft("parser.c", str(src_file), tags=["parser"], surface=5)
        crash = gen._fuzz_one(ft, str(tmp_path))
        assert crash is not None
        assert crash.crashed is False
        assert crash.file == "parser.c"
        assert fake.stopped is True

    def test_crash_captured(self, tmp_path):
        """Harness run exits non-zero → crash report parsed."""
        src_file = tmp_path / "parser.c"
        src_file.write_text("int decode(const unsigned char *d, unsigned n) { return 0; }\n")
        harness_llm = _mock_llm(
            "int LLVMFuzzerTestOneInput(const uint8_t *D, size_t S) { return 0; }"
        )
        # Script: compile OK, run crashes with ASan report
        crash_stdout = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 in decode\n"
        fake = _FakeSandbox(
            [
                ExecResult(exit_code=0, stdout="", stderr="", duration_seconds=0.1),
                ExecResult(exit_code=1, stdout=crash_stdout, stderr="", duration_seconds=2.0),
            ]
        )
        gen = HarnessGenerator(
            harness_llm,
            sandbox_factory=lambda: fake,
            config=HarnessGeneratorConfig(per_harness_duration_seconds=5),
        )
        ft = _ft("parser.c", str(src_file), tags=["parser"], surface=5)
        crash = gen._fuzz_one(ft, str(tmp_path))
        assert crash is not None
        assert crash.crashed is True
        assert "heap-buffer-overflow" in crash.report

    def test_compile_failure_returns_none(self, tmp_path):
        src_file = tmp_path / "parser.c"
        src_file.write_text("int decode(unsigned char *d, int n) { return *d; }\n")
        harness_llm = _mock_llm(
            "int LLVMFuzzerTestOneInput(const uint8_t *D, size_t S) { return 0; }"
        )
        fake = _FakeSandbox(
            [
                # Compile fails
                ExecResult(exit_code=1, stdout="syntax error", stderr="", duration_seconds=0.1),
            ]
        )
        gen = HarnessGenerator(harness_llm, sandbox_factory=lambda: fake)
        ft = _ft("parser.c", str(src_file), tags=["parser"], surface=5)
        crash = gen._fuzz_one(ft, str(tmp_path))
        assert crash is None  # no crash to seed
        assert fake.stopped is True

    def test_no_target_function_returns_none(self, tmp_path):
        """If the file has no guessable function, skip it."""
        src_file = tmp_path / "empty.c"
        src_file.write_text("// only a comment\n")
        fake = _FakeSandbox([])
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=lambda: fake)
        ft = _ft("empty.c", str(src_file), tags=["parser"], surface=5)
        crash = gen._fuzz_one(ft, str(tmp_path))
        assert crash is None

    def test_no_sandbox_factory_returns_none(self, tmp_path):
        gen = HarnessGenerator(_mock_llm("x"), sandbox_factory=None)
        ft = _ft("parser.c", str(tmp_path / "parser.c"), tags=["parser"])
        crash = gen._fuzz_one(ft, str(tmp_path))
        assert crash is None


# --- run() top-level orchestration -----------------------------------------


class TestRunTopLevel:
    def test_run_on_empty_list(self):
        gen = HarnessGenerator(_mock_llm(""), sandbox_factory=None)
        result = gen.run([], "/tmp")
        assert isinstance(result, HarnessGeneratorResult)
        assert result.seeded_crashes == []
        assert result.harnesses_generated == 0

    def test_run_counts_crashes(self, tmp_path):
        src_file = tmp_path / "parser.c"
        src_file.write_text("int decode(const unsigned char *d, unsigned n) { return 0; }\n")

        call_count = {"n": 0}

        def sandbox_factory():
            # First call: clean run; second call: crashing run
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _FakeSandbox(
                    [
                        ExecResult(0, "", "", 0.1),  # compile
                        ExecResult(0, "", "", 2.0),  # run
                    ]
                )
            return _FakeSandbox(
                [
                    ExecResult(0, "", "", 0.1),
                    ExecResult(1, "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n", "", 2.0),
                ]
            )

        gen = HarnessGenerator(
            _mock_llm("int LLVMFuzzerTestOneInput(const uint8_t *D, size_t S) { return 0; }"),
            sandbox_factory=sandbox_factory,
            config=HarnessGeneratorConfig(max_parallel=1),
        )
        files = [
            _ft("parser_a.c", str(src_file), tags=["parser"], surface=5),
            _ft("parser_b.c", str(src_file), tags=["parser"], surface=5),
        ]
        result = gen.run(files, str(tmp_path))
        assert result.harnesses_generated == 2
        assert result.harnesses_crashed == 1
        assert len(result.seeded_crashes) == 1


# --- HuntPoolConfig plumbing -----------------------------------------------


class TestHuntPoolSeededCrashPlumbing:
    """Verify the seeded_crashes_by_file lookup flows through to hunter builds."""

    def test_pool_passes_seeded_crash_to_hunter(self):
        """HuntPoolConfig.seeded_crashes_by_file → build_hunter_agent seeded_crash."""
        ft = _ft("parser.c", "/abs/parser.c", tags=["parser"], surface=5)
        llm = MagicMock()
        llm.bind_tools.return_value = MagicMock()

        cfg = HuntPoolConfig(
            files=[ft],
            repo_path="/tmp",
            llm=llm,
            seeded_crashes_by_file={
                "parser.c": {"report": "ASan: heap-buffer-overflow", "target_function": "decode"}
            },
            semgrep_hints_by_file={
                "parser.c": [{"line": 5, "description": "suspicious memcpy"}],
            },
        )
        pool = HunterPool(cfg)

        with patch("clearwing.sourcehunt.hunter.build_hunter_agent") as mock_build:
            mock_build.return_value = (MagicMock(), MagicMock(session_id="s1"))
            pool._build_hunter_for_file(ft, sandbox=None)
            kwargs = mock_build.call_args.kwargs
            assert kwargs["seeded_crash"]["report"] == "ASan: heap-buffer-overflow"
            assert kwargs["semgrep_hints"][0]["line"] == 5
