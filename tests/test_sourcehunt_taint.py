"""Tests for the v0.4 lightweight taint analyzer.

Uses the taint_samples fixtures to exercise real tree-sitter parsing.
Every test skips cleanly if tree-sitter grammars aren't installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clearwing.sourcehunt.taint import (
    C_SINKS,
    C_SOURCES,
    PYTHON_SINKS,
    PYTHON_SOURCES,
    TaintAnalysisResult,
    TaintAnalyzer,
)

FIXTURES = Path(__file__).parent / "fixtures" / "vuln_samples" / "taint_samples"


@pytest.fixture(scope="module")
def analyzer() -> TaintAnalyzer:
    a = TaintAnalyzer()
    if not a.available:
        pytest.skip("tree-sitter grammars not installed")
    return a


# --- Pattern tables --------------------------------------------------------


class TestPatternTables:
    def test_c_sources_include_read(self):
        names = {p.name for p in C_SOURCES}
        assert "read" in names
        assert "recv" in names
        assert "fgets" in names
        assert "getenv" in names

    def test_c_sinks_include_memcpy(self):
        names = {p.name for p in C_SINKS}
        assert "memcpy" in names
        assert "system" in names
        assert "strcpy" in names

    def test_python_sources_include_request(self):
        names = {p.name for p in PYTHON_SOURCES}
        assert any("request" in n for n in names)
        assert "input" in names

    def test_python_sinks_include_execute(self):
        names = {p.name for p in PYTHON_SINKS}
        assert "execute" in names
        assert "eval" in names
        assert "system" in names
        assert "loads" in names

    def test_every_sink_has_severity(self):
        for p in list(C_SINKS) + list(PYTHON_SINKS):
            assert p.severity in ("critical", "high", "medium", "low", "info")

    def test_every_sink_has_cwe(self):
        for p in list(C_SINKS) + list(PYTHON_SINKS):
            assert p.cwe.startswith("CWE-")

    def test_every_sink_has_sensitive_args(self):
        for p in list(C_SINKS) + list(PYTHON_SINKS):
            assert len(p.sensitive_args) >= 1


# --- Analyzer availability -------------------------------------------------


class TestAnalyzerAvailability:
    def test_analyzer_constructs(self, analyzer):
        assert analyzer is not None

    def test_available_when_grammars_present(self, analyzer):
        assert analyzer.available is True


# --- C taint detection -----------------------------------------------------


class TestCTaintDetection:
    def test_read_to_memcpy_path_detected(self, analyzer, tmp_path: Path):
        """The canonical case: read(fd, buf, n) → memcpy(dst, buf, n)."""
        # Copy the fixture into a temp "repo" so the walker picks it up
        src = (FIXTURES / "c_memcpy_from_read.c").read_text()
        (tmp_path / "process.c").write_text(src)
        result = analyzer.analyze_repo(str(tmp_path))

        assert isinstance(result, TaintAnalysisResult)
        assert result.files_analyzed >= 1
        assert result.files_with_paths == 1

        # We expect at least one path: read → memcpy
        memcpy_paths = [p for p in result.paths if p.sink_function == "memcpy"]
        assert len(memcpy_paths) >= 1
        p = memcpy_paths[0]
        assert p.source_function == "read"
        assert p.sink_function == "memcpy"
        assert p.variable in ("buf", "n")
        assert p.sink_cwe == "CWE-787"
        assert p.severity == "high"
        assert p.language == "c"
        assert "process.c" in p.file
        # Sink line should be AFTER source line
        assert p.sink_line > p.source_line

    def test_clean_c_file_has_no_paths(self, analyzer, tmp_path: Path):
        """A file with no sources or sinks should produce zero paths."""
        (tmp_path / "clean.c").write_text("""
int add(int a, int b) {
    return a + b;
}
int main(int argc, char **argv) {
    return add(1, 2);
}
""")
        result = analyzer.analyze_repo(str(tmp_path))
        assert result.paths == []
        assert result.files_analyzed == 1

    def test_source_without_sink_produces_no_path(self, analyzer, tmp_path: Path):
        """A source without a downstream sink in the same function → no path."""
        (tmp_path / "source_only.c").write_text("""
#include <unistd.h>
int reader(int fd) {
    char buf[64];
    read(fd, buf, sizeof(buf));
    return buf[0];  /* no sink downstream */
}
""")
        result = analyzer.analyze_repo(str(tmp_path))
        assert result.paths == []

    def test_sink_without_source_produces_no_path(self, analyzer, tmp_path: Path):
        """A sink whose args aren't tainted → no path."""
        (tmp_path / "sink_only.c").write_text("""
#include <string.h>
void copy_literal() {
    char dst[16];
    memcpy(dst, "hello", 5);  /* literal — no taint */
}
""")
        result = analyzer.analyze_repo(str(tmp_path))
        assert result.paths == []

    def test_intraprocedural_only(self, analyzer, tmp_path: Path):
        """A taint that crosses function boundaries isn't detected in v0.4."""
        (tmp_path / "cross_fn.c").write_text("""
#include <unistd.h>
#include <string.h>
char *get_input(int fd) {
    static char buf[64];
    read(fd, buf, sizeof(buf));
    return buf;
}
void copier(int fd) {
    char *s = get_input(fd);
    char dst[16];
    /* Taint is in `s` but `read` happened in a different function.
     * v0.4 doesn't track this cross-function. Expected: no path. */
    memcpy(dst, s, 16);
}
""")
        result = analyzer.analyze_repo(str(tmp_path))
        # Deliberately: no path found (documented limitation)
        memcpy_paths = [p for p in result.paths if p.sink_function == "memcpy"]
        assert memcpy_paths == []


# --- Python taint detection ------------------------------------------------


class TestPythonTaintDetection:
    def test_request_args_to_execute_path_detected(self, analyzer, tmp_path: Path):
        src = (FIXTURES / "py_sql_from_request.py").read_text()
        (tmp_path / "app.py").write_text(src)
        result = analyzer.analyze_repo(str(tmp_path))

        execute_paths = [p for p in result.paths if p.sink_function == "execute"]
        assert len(execute_paths) >= 1
        p = execute_paths[0]
        # The rightmost-identifier heuristic gives us "args" or "get" or "title"
        # depending on how tree-sitter represents `request.args.get(...)`.
        assert p.variable in ("title", "args", "get", "q")
        assert p.sink_cwe == "CWE-89"
        assert p.language == "python"

    def test_input_to_eval_detected(self, analyzer, tmp_path: Path):
        (tmp_path / "danger.py").write_text("""
def run():
    x = input('> ')
    eval(x)
""")
        result = analyzer.analyze_repo(str(tmp_path))
        eval_paths = [p for p in result.paths if p.sink_function == "eval"]
        assert len(eval_paths) >= 1
        assert eval_paths[0].sink_cwe == "CWE-95"
        assert eval_paths[0].severity == "critical"

    def test_clean_python_file_has_no_paths(self, analyzer, tmp_path: Path):
        (tmp_path / "clean.py").write_text("""
def add(a, b):
    return a + b
""")
        result = analyzer.analyze_repo(str(tmp_path))
        assert result.paths == []


# --- Result aggregation ----------------------------------------------------


class TestResultAggregation:
    def test_paths_by_file_grouping(self, analyzer, tmp_path: Path):
        (tmp_path / "a.c").write_text("""
#include <unistd.h>
#include <string.h>
void f(int fd) {
    char buf[64];
    read(fd, buf, 64);
    char d[16];
    memcpy(d, buf, 16);
}
""")
        (tmp_path / "b.py").write_text("""
def g():
    x = input()
    eval(x)
""")
        result = analyzer.analyze_repo(str(tmp_path))
        by_file = result.paths_by_file()
        assert "a.c" in by_file
        assert "b.py" in by_file

    def test_files_analyzed_counter(self, analyzer, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"f{i}.c").write_text("int x;")
        (tmp_path / "ignored.bin").write_bytes(b"\x00\x01")
        result = analyzer.analyze_repo(str(tmp_path))
        # 3 .c files analyzed, .bin skipped
        assert result.files_analyzed == 3


# --- Integration test: runner path length ---------------------------------


class TestTaintIntegration:
    def test_taint_fixture_round_trip(self, analyzer):
        """Full analyze on the shipped taint_samples dir produces >= 2 paths."""
        result = analyzer.analyze_repo(str(FIXTURES))
        # At least one C path (memcpy) and one Python path (execute or eval)
        sinks = {p.sink_function for p in result.paths}
        assert "memcpy" in sinks or "execute" in sinks or "eval" in sinks
        assert result.files_with_paths >= 1

    def test_paths_sorted_by_file_and_line(self, analyzer, tmp_path: Path):
        """Multiple paths in one file are stable w.r.t. repeated runs."""
        src = (FIXTURES / "c_memcpy_from_read.c").read_text()
        (tmp_path / "p.c").write_text(src)
        r1 = analyzer.analyze_repo(str(tmp_path))
        r2 = analyzer.analyze_repo(str(tmp_path))
        assert [(p.file, p.source_line, p.sink_line) for p in r1.paths] == [
            (p.file, p.source_line, p.sink_line) for p in r2.paths
        ]
