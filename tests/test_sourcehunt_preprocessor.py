"""Unit tests for the sourcehunt preprocessor.

Exercises the v0.1 path: clone (or local-path), enumerate, static pre-scan,
file tagging, imports_by counting. Verifies v0.2 seams (callgraph,
semgrep_findings, fuzz_corpora) are present and default to None/empty.
"""

from __future__ import annotations

from pathlib import Path
import os
import tempfile

import pytest

from clearwing.analysis.source_analyzer import SourceAnalyzer
from clearwing.sourcehunt.preprocessor import (
    Preprocessor,
    PreprocessResult,
    _file_defines_constants,
    _tag_file,
)

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"
FIXTURE_PY_SQLI = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"


# --- File tagger heuristics --------------------------------------------------


class TestFileTagger:
    def test_c_file_tagged_memory_unsafe(self):
        tags = _tag_file("src/codec_a.c", "int main() {}\n")
        assert "memory_unsafe" in tags

    def test_h_file_tagged_memory_unsafe(self):
        tags = _tag_file("include/codec_limits.h", "#define X 1\n")
        assert "memory_unsafe" in tags

    def test_python_file_not_memory_unsafe(self):
        tags = _tag_file("app.py", "print('hi')\n")
        assert "memory_unsafe" not in tags

    def test_parser_filename(self):
        tags = _tag_file("src/parse_input.c", "int parse() {}\n")
        assert "parser" in tags

    def test_decoder_filename(self):
        tags = _tag_file("codecs/decode_h264.c", "void decode() {}\n")
        assert "parser" in tags

    def test_crypto_dir(self):
        tags = _tag_file("crypto/aes.c", "void aes() {}\n")
        assert "crypto" in tags

    def test_crypto_filename(self):
        tags = _tag_file("hash_md5.c", "void md5() {}\n")
        assert "crypto" in tags

    def test_auth_boundary_dir(self):
        tags = _tag_file("auth/login.py", "def login(): pass\n")
        assert "auth_boundary" in tags

    def test_auth_filename(self):
        tags = _tag_file("session_token.py", "TOKEN = 'x'\n")
        assert "auth_boundary" in tags

    def test_syscall_filename(self):
        tags = _tag_file("driver/ioctl_handler.c", "int handle() {}\n")
        assert "syscall_entry" in tags

    def test_fuzzable_signature(self):
        content = """
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    return 0;
}
"""
        tags = _tag_file("harness.c", content)
        assert "fuzzable" in tags

    def test_non_fuzzable_signature(self):
        tags = _tag_file("util.c", "int helper() { return 0; }\n")
        assert "fuzzable" not in tags

    def test_tags_are_a_list(self):
        # Multi-tag: parser + memory_unsafe
        tags = _tag_file("src/parse_input.c", "int parse() {}\n")
        assert isinstance(tags, list)
        assert "parser" in tags and "memory_unsafe" in tags


# --- defines_constants heuristic ---------------------------------------------


class TestDefinesConstants:
    def test_c_define(self):
        assert _file_defines_constants("#define MAX 256\n", "c")

    def test_c_no_define(self):
        assert not _file_defines_constants("int main() { return 0; }\n", "c")

    def test_python_caps_constant(self):
        assert _file_defines_constants("MAX_RETRIES = 3\n", "python")

    def test_python_lowercase_not_a_constant(self):
        assert not _file_defines_constants("counter = 0\n", "python")

    def test_rust_const(self):
        assert _file_defines_constants("const MAX_BYTES: usize = 256;\n", "rust")

    def test_go_const(self):
        assert _file_defines_constants("const MAX_BYTES = 256\n", "go")

    def test_unknown_language_returns_false(self):
        assert not _file_defines_constants("foo bar\n", "haskell")


# --- Preprocessor.run on local fixture ---------------------------------------


class TestPreprocessorRun:
    def test_local_path_c_propagation_fixture(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        assert isinstance(result, PreprocessResult)
        assert result.repo_path == str(FIXTURE_C_PROPAGATION.resolve())
        # 4 source files: codec_a.c, codec_b.c, codec_c.c, codec_limits.h
        assert result.file_count == 4

    def test_file_targets_have_required_fields(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        for ft in result.file_targets:
            assert "path" in ft
            assert "absolute_path" in ft
            assert "language" in ft
            assert "loc" in ft
            assert "tags" in ft
            assert "static_hint" in ft
            assert "imports_by" in ft
            assert "defines_constants" in ft
            # v0.1 defaults
            assert ft["reachability"] == 3
            assert ft["surface"] == 0  # ranker fills
            assert ft["influence"] == 0
            # v0.2 seams present with safe defaults
            assert ft["semgrep_hint"] == 0
            assert ft["transitive_callers"] == 0
            assert ft["fuzz_harness_path"] is None

    def test_respect_gitignore_filters_file_targets_and_static_findings(self, tmp_path):
        (tmp_path / ".gitignore").write_text(".next/\n")
        (tmp_path / ".next" / "server").mkdir(parents=True)
        (tmp_path / ".next" / "server" / "webpack.js").write_text("eval(userCode);\n")
        (tmp_path / "src.js").write_text("eval(userCode);\n")

        pp = Preprocessor(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            respect_gitignore=True,
        )
        result = pp.run()

        assert [ft["path"] for ft in result.file_targets] == ["src.js"]
        assert [Path(f.file_path).name for f in result.static_findings] == ["src.js"]

    def test_codec_limits_h_tagged_memory_unsafe(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        header = next(ft for ft in result.file_targets if ft["path"].endswith("codec_limits.h"))
        assert "memory_unsafe" in header["tags"]
        assert header["defines_constants"] is True

    def test_codec_limits_h_imports_by_counts_three(self):
        """The header is included by three .c files; imports_by should be 3."""
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        header = next(ft for ft in result.file_targets if ft["path"].endswith("codec_limits.h"))
        assert header["imports_by"] == 3

    def test_codec_a_imports_by_zero(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        codec_a = next(ft for ft in result.file_targets if ft["path"].endswith("codec_a.c"))
        # No file imports codec_a.c
        assert codec_a["imports_by"] == 0

    def test_python_sqli_fixture_tagged(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
        )
        result = pp.run()
        assert result.file_count >= 1
        app = next(ft for ft in result.file_targets if ft["path"].endswith("app.py"))
        assert app["language"] == "python"
        assert app["static_hint"] >= 1  # SourceAnalyzer regex catches the f-string

    def test_v02_seams_default_to_empty(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        assert result.callgraph is None
        assert result.semgrep_findings == []
        assert result.fuzz_corpora == []

    def test_v02_flags_accepted_without_error(self):
        """Future-compat: passing all v0.2 flags should not error."""
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            build_callgraph=True,
            run_semgrep=True,
            propagate_reachability=True,
            ingest_fuzz_corpora=True,
        )
        result = pp.run()
        # v0.2: callgraph is populated (tree-sitter was installed)
        # v0.2: semgrep and fuzz corpus still no-op
        assert result.callgraph is not None
        assert result.semgrep_findings == []
        assert result.fuzz_corpora == []

    def test_language_summary(self):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        summary = result.language_summary
        assert summary.get("c", 0) == 4  # codec_a/b/c.c plus codec_limits.h

    def test_git_clone_repo_survives_through_run(self, monkeypatch):
        """Regression: keep clone-owner analyzer alive during run().

        If run() replaces the analyzer instance after clone(), the temporary
        clone directory is deleted early and file enumeration drops to zero.
        """

        def fake_clone(self, git_url: str, branch: str = "main") -> str:
            tmp = tempfile.TemporaryDirectory(prefix="clearwing-test-clone-")
            repo = Path(tmp.name)
            (repo / "demo.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            self._temp_dir = tmp
            self.repo_path = str(repo)
            return str(repo)

        monkeypatch.setattr(SourceAnalyzer, "clone", fake_clone)

        pp = Preprocessor(repo_url="https://example.com/repo.git")
        result = pp.run()
        assert result.file_count >= 1


class TestImportsByBatched:
    """Regression coverage for the batched imports_by fix (run-334 timeout).

    The hot path must walk the repo ONCE and read each file's head at most
    once, instead of once per source target (O(S*R) -> O(R) file reads),
    while preserving the exact basename-substring counting semantics of the
    legacy per-target `_count_imports_by` (including duplicate-basename
    behavior, the max_imports_by_files cap, and self-exclusion).
    """

    def test_imports_by_walks_repo_once_and_reads_each_file_once(self, tmp_path, monkeypatch):
        """Scaling regression: instrument os.walk and open to prove the
        batched pass does NOT walk/read once per source target.

        With N=8 source files the legacy per-target path did N fresh walks and
        N*R file reads for imports_by; the batched path does 1 walk and R reads.
        """
        import builtins

        n = 8
        for i in range(n):
            (tmp_path / f"mod_{i}.py").write_text(
                f"import mod_{(i + 1) % n}\n", encoding="utf-8"
            )
        # A non-source referencer that still mentions a module name; it must be
        # walked/read exactly once, same as every other repo file.
        (tmp_path / "README.md").write_text("import mod_0\n", encoding="utf-8")

        walk_count = 0
        real_walk = os.walk

        def counting_walk(top, *a, **k):
            nonlocal walk_count
            walk_count += 1
            yield from real_walk(top, *a, **k)

        monkeypatch.setattr("os.walk", counting_walk)

        open_count = 0
        real_open = builtins.open
        root = str(tmp_path)

        def counting_open(path, *a, **k):
            nonlocal open_count
            if str(path).startswith(root):
                open_count += 1
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", counting_open)

        pp = Preprocessor(repo_url=str(tmp_path), local_path=str(tmp_path))
        result = pp.run()

        # Legacy per-target path: >= n walks just for imports_by (one per
        # target). Batched path: exactly one imports_by walk. Total walks stay
        # a small constant and must NOT scale with source-file count.
        assert walk_count < n, (
            f"expected imports_by to walk the repo once, not once per target; "
            f"walk_count={walk_count} >= n={n} (O(S) walk regression)"
        )
        # Legacy path opened each repo file once per source target for
        # imports_by (n*R reads). Batched path reads each repo file once.
        # Total opens must stay O(R), not O(S*R).
        assert open_count < n * 4, (
            f"expected each repo file read at most once for imports_by; "
            f"open_count={open_count} suggests per-target re-reading "
            f"(n={n})"
        )
        # Sanity: the run still produced targets with imports_by populated.
        assert result.file_count == n
        assert any(ft["imports_by"] >= 0 for ft in result.file_targets)

    def test_duplicate_basenames_get_same_imports_by(self, tmp_path):
        """Two source files sharing a basename must receive the same imports_by
        count (the number of repo files importing that basename), each
        excluding only itself."""
        (tmp_path / "x").mkdir()
        (tmp_path / "y").mkdir()
        (tmp_path / "x" / "dup.py").write_text("def f(): pass\n", encoding="utf-8")
        (tmp_path / "y" / "dup.py").write_text("def g(): pass\n", encoding="utf-8")
        (tmp_path / "r1.py").write_text("import dup\n", encoding="utf-8")
        (tmp_path / "r2.py").write_text("from dup import f\n", encoding="utf-8")
        (tmp_path / "r3.py").write_text("import dup\n", encoding="utf-8")

        pp = Preprocessor(repo_url=str(tmp_path), local_path=str(tmp_path))
        result = pp.run()

        dups = [ft for ft in result.file_targets if Path(ft["path"]).name == "dup.py"]
        assert len(dups) == 2
        counts = {ft["absolute_path"]: ft["imports_by"] for ft in dups}
        # Neither dup.py self-imports, so both see the same three importers.
        assert set(counts.values()) == {3}, (
            f"duplicate basenames should share imports_by=3; got {counts}"
        )

    def test_max_imports_by_files_zero_disables_imports_by(self, tmp_path):
        """budget=0 must yield imports_by=0 for every target (cap preserved)."""
        (tmp_path / "header.h").write_text("#define X 1\n", encoding="utf-8")
        (tmp_path / "a.c").write_text(
            '#include "header.h"\nint main(void){return 0;}\n', encoding="utf-8"
        )
        (tmp_path / "b.c").write_text(
            '#include "header.h"\nint main(void){return 0;}\n', encoding="utf-8"
        )

        pp = Preprocessor(
            repo_url=str(tmp_path), local_path=str(tmp_path), max_imports_by_files=0
        )
        result = pp.run()
        for ft in result.file_targets:
            assert ft["imports_by"] == 0

    def test_python_import_resolution(self, tmp_path):
        """Python `from pkg.util import u` and `import util` both count as
        importers of util.py (stem match with word boundary)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "util.py").write_text("def u(): pass\n", encoding="utf-8")
        (tmp_path / "app.py").write_text(
            "from pkg.util import u\nimport util\n", encoding="utf-8"
        )
        (tmp_path / "other.py").write_text("import util\n", encoding="utf-8")

        pp = Preprocessor(repo_url=str(tmp_path), local_path=str(tmp_path))
        result = pp.run()
        util = next(ft for ft in result.file_targets if ft["path"].endswith("util.py"))
        assert util["imports_by"] == 2, (
            f"util.py should have 2 importers (app.py, other.py); got {util['imports_by']}"
        )

    def test_cpp_include_resolution(self, tmp_path):
        """C++ #include "x.hpp" counts as an importer of x.hpp (basename)."""
        (tmp_path / "limits.hpp").write_text("#pragma once\nstruct X {};\n", encoding="utf-8")
        (tmp_path / "a.cpp").write_text(
            '#include "limits.hpp"\nint main(){}\n', encoding="utf-8"
        )
        (tmp_path / "b.cpp").write_text(
            '#include "limits.hpp"\nint main(){}\n', encoding="utf-8"
        )

        pp = Preprocessor(repo_url=str(tmp_path), local_path=str(tmp_path))
        result = pp.run()
        hpp = next(ft for ft in result.file_targets if ft["path"].endswith("limits.hpp"))
        assert hpp["language"] == "cpp"
        assert hpp["imports_by"] == 2, (
            f"limits.hpp should have 2 importers (a.cpp, b.cpp); got {hpp['imports_by']}"
        )


class TestPreprocessorErrorPaths:
    def test_missing_local_path_raises(self):
        with pytest.raises(ValueError, match="local_path does not exist"):
            Preprocessor(
                repo_url="dummy",
                local_path="/nonexistent/path/xyz",
            ).run()

    def test_invalid_repo_url_raises(self):
        with pytest.raises(ValueError, match="neither a git URL nor"):
            Preprocessor(repo_url="not-a-real-thing").run()


class TestIsGitUrl:
    def test_https(self):
        assert Preprocessor._is_git_url("https://github.com/foo/bar")

    def test_http(self):
        assert Preprocessor._is_git_url("http://gitlab.local/foo")

    def test_ssh(self):
        assert Preprocessor._is_git_url("git@github.com:foo/bar.git")

    def test_dot_git(self):
        assert Preprocessor._is_git_url("foo.git")

    def test_local_path_not_git(self):
        assert not Preprocessor._is_git_url("/tmp/some/dir")
