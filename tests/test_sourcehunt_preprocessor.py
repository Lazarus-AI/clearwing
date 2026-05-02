"""Unit tests for the sourcehunt preprocessor.

Exercises the v0.1 path: clone (or local-path), enumerate, static pre-scan,
file tagging, imports_by counting. Verifies v0.2 seams (callgraph,
semgrep_findings, fuzz_corpora) are present and default to None/empty.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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
