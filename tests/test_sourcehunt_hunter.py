"""Unit tests for the sourcehunt hunter agent factory.

These tests verify:
- v0.1 always selects specialist="general" except for Tier C → "propagation"
- The hunter graph compiles with mocked LLM + mocked sandbox
- Tier C hunters get the narrower propagation auditor tool set
- Tier A/B hunters get the full tool set
- record_finding appends to ctx.findings
- seeded_crash and semgrep_hints parameters are accepted
- Hunter tools work in test mode (host file I/O fallback) with no sandbox
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.agent.tools.hunt.hunter_tools import (
    HunterContext,
    _grep_python_fallback,
    _normalize_path,
    _parse_rg_output,
    _parse_sanitizer_report,
    build_hunter_tools,
    build_propagation_auditor_tools,
)
from clearwing.sourcehunt.hunter import (
    GENERAL_HUNTER_PROMPT,
    PROPAGATION_AUDIT_PROMPT,
    _build_hunter_prompt,
    _build_propagation_prompt,
    _choose_specialist,
    build_hunter_agent,
)


FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"


def _make_file_target(path: str, tier: str = "B", **kwargs) -> dict:
    return {
        "path": path,
        "absolute_path": str(FIXTURE_C_PROPAGATION / path),
        "tier": tier,
        "language": kwargs.get("language", "c"),
        "loc": kwargs.get("loc", 50),
        "tags": kwargs.get("tags", []),
        "imports_by": kwargs.get("imports_by", 0),
        "surface": kwargs.get("surface", 4),
        "influence": kwargs.get("influence", 2),
        "reachability": 3,
        "priority": 3.3,
        "static_hint": 0,
        "semgrep_hint": 0,
        "defines_constants": False,
        "transitive_callers": 0,
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
        "surface_rationale": "",
        "influence_rationale": "",
        "reachability_rationale": "",
    }


# --- Specialist routing -----------------------------------------------------


class TestSpecialistRouting:
    """v0.2: _choose_specialist routes by file tags."""

    def test_memory_unsafe_tag_picks_memory_safety(self):
        ft = _make_file_target("foo.c", tags=["memory_unsafe"])
        assert _choose_specialist(ft) == "memory_safety"

    def test_parser_tag_picks_memory_safety(self):
        # Parsers are where memory-safety bugs live
        ft = _make_file_target("decode.c", tags=["parser"])
        assert _choose_specialist(ft) == "memory_safety"

    def test_fuzzable_tag_picks_memory_safety(self):
        ft = _make_file_target("harness.c", tags=["fuzzable"])
        assert _choose_specialist(ft) == "memory_safety"

    def test_auth_boundary_tag_picks_logic_auth(self):
        ft = _make_file_target("auth.py", tags=["auth_boundary"])
        assert _choose_specialist(ft) == "logic_auth"

    def test_crypto_tag_in_python_picks_logic_auth(self):
        """Python crypto glue routes to logic_auth — protocol-level bugs."""
        ft = _make_file_target("hmac.py", tags=["crypto"], language="python")
        assert _choose_specialist(ft) == "logic_auth"

    def test_crypto_tag_in_c_picks_crypto_primitive(self):
        """v0.4: C/C++/Rust crypto files route to the primitive specialist."""
        ft = _make_file_target("hmac.c", tags=["crypto"], language="c")
        assert _choose_specialist(ft) == "crypto_primitive"

    def test_crypto_primitive_wins_over_memory_safety(self):
        """v0.4: a C crypto file with memory_unsafe tag still routes to
        crypto_primitive — the crypto specialist covers constant-time and
        primitive-level concerns that the memory specialist doesn't."""
        ft = _make_file_target(
            "aes.c",
            tags=["memory_unsafe", "crypto"],
            language="c",
        )
        assert _choose_specialist(ft) == "crypto_primitive"

    def test_untagged_file_falls_back_to_general(self):
        ft = _make_file_target("main.py", tags=[])
        assert _choose_specialist(ft) == "general"

    def test_syscall_entry_tag_picks_kernel_syscall(self):
        ft = _make_file_target("drivers/ioctl.c", tags=["syscall_entry"])
        assert _choose_specialist(ft) == "kernel_syscall"

    def test_kernel_syscall_wins_over_memory_unsafe(self):
        """syscall_entry is more specific than memory_unsafe."""
        ft = _make_file_target(
            "drivers/driver.c",
            tags=["syscall_entry", "memory_unsafe"],
        )
        assert _choose_specialist(ft) == "kernel_syscall"

    def test_crypto_primitive_for_c_crypto_code(self):
        ft = _make_file_target("aes.c", tags=["crypto"], language="c")
        assert _choose_specialist(ft) == "crypto_primitive"

    def test_crypto_primitive_for_rust_crypto_code(self):
        ft = _make_file_target(
            "src/crypto/sha256.rs",
            tags=["crypto"],
            language="rust",
        )
        assert _choose_specialist(ft) == "crypto_primitive"

    def test_crypto_in_python_routes_to_logic_auth(self):
        """Python crypto glue goes to logic_auth, not the primitive specialist."""
        ft = _make_file_target(
            "auth/jwt_handler.py",
            tags=["crypto", "auth_boundary"],
            language="python",
        )
        assert _choose_specialist(ft) == "logic_auth"

    def test_web_framework_python_views(self):
        ft = _make_file_target(
            "app/views/user.py",
            tags=[],
            language="python",
        )
        assert _choose_specialist(ft) == "web_framework"

    def test_web_framework_node_routes(self):
        ft = _make_file_target(
            "src/routes/api.js",
            tags=[],
            language="javascript",
        )
        assert _choose_specialist(ft) == "web_framework"

    def test_web_framework_ruby_controllers(self):
        ft = _make_file_target(
            "app/controllers/sessions_controller.rb",
            tags=[],
            language="ruby",
        )
        assert _choose_specialist(ft) == "web_framework"

    def test_non_web_python_path_falls_through(self):
        """A Python file NOT in a views/routes dir doesn't get web_framework."""
        ft = _make_file_target("lib/util.py", tags=[], language="python")
        assert _choose_specialist(ft) == "general"

    def test_irrelevant_tag_falls_back_to_general(self):
        # parser-less, auth-less, crypto-less → general
        ft = _make_file_target("misc.txt", tags=[])
        assert _choose_specialist(ft) == "general"


# --- Prompt builders --------------------------------------------------------


class TestPromptBuilders:
    def test_general_prompt_includes_file_metadata(self):
        ft = _make_file_target("src/codec_a.c", tags=["memory_unsafe", "parser"])
        prompt = _build_hunter_prompt(ft, "test_project", None, None)
        assert "src/codec_a.c" in prompt
        assert "c" in prompt
        assert "memory_unsafe" in prompt and "parser" in prompt
        assert "test_project" in prompt
        # Phrase must mention severity and evidence_level (from the prompt template)
        assert "evidence_level" in prompt

    def test_general_prompt_with_seeded_crash(self):
        ft = _make_file_target("foo.c")
        crash = {"report": "==12345==ERROR: AddressSanitizer: heap-buffer-overflow"}
        prompt = _build_hunter_prompt(ft, "p", crash, None)
        assert "fuzz harness produced this crash" in prompt
        assert "heap-buffer-overflow" in prompt

    def test_general_prompt_with_semgrep_hints(self):
        ft = _make_file_target("foo.c")
        hints = [
            {"line": 42, "description": "Possible buffer overflow"},
            {"line": 100, "description": "Format string vulnerability"},
        ]
        prompt = _build_hunter_prompt(ft, "p", None, hints)
        assert "Static analysis hints" in prompt
        assert "line 42" in prompt
        assert "Format string" in prompt

    def test_propagation_prompt_for_header_file(self):
        ft = _make_file_target("include/codec_limits.h", tier="C", imports_by=50)
        prompt = _build_propagation_prompt(ft)
        assert "PROPAGATION RISK" in prompt
        assert "codec_limits.h" in prompt
        assert "50" in prompt   # imports_by
        # Must enumerate the 5 specific question categories
        assert "BUFFER SIZE ADEQUACY" in prompt
        assert "SENTINEL" in prompt
        assert "TRUNCATION" in prompt
        assert "UNSAFE DEFAULTS" in prompt

    def test_memory_safety_specialist_prompt(self):
        ft = _make_file_target("codec.c", tags=["memory_unsafe"])
        prompt = _build_hunter_prompt(ft, "p", None, None, specialist="memory_safety")
        assert "MEMORY SAFETY specialist" in prompt
        assert "LENGTH vs ALLOCATION" in prompt
        assert "SIGNED / UNSIGNED" in prompt
        assert "WIDTH TRUNCATION" in prompt
        assert "MEMCPY BOUNDS" in prompt
        assert "USE-AFTER-FREE" in prompt

    def test_logic_auth_specialist_prompt(self):
        ft = _make_file_target("auth.py", tags=["auth_boundary"])
        prompt = _build_hunter_prompt(ft, "p", None, None, specialist="logic_auth")
        assert "LOGIC / AUTH specialist" in prompt
        assert "BOOLEAN DEFAULTS" in prompt
        assert "COMPARISON SEMANTICS" in prompt
        assert "TRUST PROPAGATION" in prompt
        assert "FAIL-OPEN" in prompt
        assert "TOCTOU" in prompt

    def test_unknown_specialist_falls_back_to_general(self):
        ft = _make_file_target("main.py", tags=[])
        prompt = _build_hunter_prompt(ft, "p", None, None, specialist="made_up")
        # Should fall back to general (no specialist-specific header)
        assert "MEMORY SAFETY specialist" not in prompt
        assert "LOGIC / AUTH specialist" not in prompt

    def test_kernel_syscall_specialist_prompt(self):
        ft = _make_file_target("driver.c", tags=["syscall_entry"])
        prompt = _build_hunter_prompt(ft, "p", None, None, specialist="kernel_syscall")
        assert "KERNEL / SYSCALL specialist" in prompt
        assert "copy_from_user" in prompt
        assert "IOCTL HANDLER" in prompt
        assert "REFERENCE COUNTING" in prompt

    def test_crypto_primitive_specialist_prompt(self):
        ft = _make_file_target("aes.c", tags=["crypto"])
        prompt = _build_hunter_prompt(ft, "p", None, None, specialist="crypto_primitive")
        assert "CRYPTOGRAPHIC PRIMITIVE specialist" in prompt
        assert "TIMING SIDE CHANNELS" in prompt
        assert "IV / NONCE REUSE" in prompt
        assert "constant-time" in prompt

    def test_web_framework_specialist_prompt(self):
        ft = _make_file_target("app/views.py", tags=[])
        prompt = _build_hunter_prompt(ft, "p", None, None, specialist="web_framework")
        assert "WEB FRAMEWORK specialist" in prompt
        assert "SQL injection" in prompt
        assert "SERVER-SIDE REQUEST FORGERY" in prompt
        assert "CSRF" in prompt
        assert "mass assignment" in prompt.lower()


# --- build_hunter_agent -----------------------------------------------------


class TestBuildHunterAgent:
    def test_tier_b_untagged_file_uses_general(self):
        llm = MagicMock()
        bound = MagicMock()
        llm.bind_tools.return_value = bound
        bound.invoke = MagicMock(return_value=MagicMock(content="ok", tool_calls=[]))

        # Empty tags → general specialist
        ft = _make_file_target("src/main.py", tier="B", tags=[], language="python")
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path=str(FIXTURE_C_PROPAGATION),
            sandbox=None,
            llm=llm,
            session_id="test-session",
        )
        assert graph is not None
        assert ctx.specialist == "general"
        # Full tool set (9 tools) was bound
        bind_args = llm.bind_tools.call_args[0][0]
        tool_names = {t.name for t in bind_args}
        assert tool_names == {
            "read_source_file", "list_source_tree", "grep_source", "find_callers",
            "compile_file", "run_with_sanitizer", "write_test_case",
            "fuzz_harness", "record_finding",
        }

    def test_tier_b_memory_unsafe_routes_to_memory_safety(self):
        llm = MagicMock()
        llm.bind_tools.return_value = MagicMock()
        ft = _make_file_target("src/codec_a.c", tier="B", tags=["memory_unsafe", "parser"])
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path=str(FIXTURE_C_PROPAGATION),
            sandbox=None,
            llm=llm,
            session_id="s1",
        )
        assert ctx.specialist == "memory_safety"

    def test_tier_b_auth_boundary_routes_to_logic_auth(self):
        llm = MagicMock()
        llm.bind_tools.return_value = MagicMock()
        ft = _make_file_target("auth.py", tier="B", tags=["auth_boundary"], language="python")
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path=str(FIXTURE_C_PROPAGATION),
            sandbox=None,
            llm=llm,
            session_id="s1",
        )
        assert ctx.specialist == "logic_auth"

    def test_tier_c_uses_propagation_auditor_tools(self):
        llm = MagicMock()
        bound = MagicMock()
        llm.bind_tools.return_value = bound
        bound.invoke = MagicMock(return_value=MagicMock(content="ok", tool_calls=[]))

        ft = _make_file_target("include/codec_limits.h", tier="C")
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path=str(FIXTURE_C_PROPAGATION),
            sandbox=None,
            llm=llm,
            session_id="test-session",
        )
        assert ctx.specialist == "propagation"
        # Narrower tool set: no compile/run/write_test_case/fuzz
        bind_args = llm.bind_tools.call_args[0][0]
        tool_names = {t.name for t in bind_args}
        assert tool_names == {
            "read_source_file", "list_source_tree", "grep_source", "find_callers",
            "record_finding",
        }
        assert "compile_file" not in tool_names
        assert "run_with_sanitizer" not in tool_names

    def test_explicit_specialist_override(self):
        llm = MagicMock()
        llm.bind_tools.return_value = MagicMock()
        ft = _make_file_target("foo.c", tier="B")
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path=str(FIXTURE_C_PROPAGATION),
            sandbox=None,
            llm=llm,
            session_id="s1",
            specialist="propagation",
        )
        assert ctx.specialist == "propagation"

    def test_v02_seam_seeded_crash_param_accepted(self):
        llm = MagicMock()
        llm.bind_tools.return_value = MagicMock()
        ft = _make_file_target("foo.c")
        # The v0.2 seed parameters are accepted in v0.1 — they just don't
        # do anything if the prompt template doesn't reference them
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path=str(FIXTURE_C_PROPAGATION),
            sandbox=None,
            llm=llm,
            session_id="s1",
            seeded_crash={"report": "ASan: heap-buffer-overflow"},
            semgrep_hints=[{"line": 1, "description": "x"}],
            variant_seed={"original": "ignored in v0.1"},
        )
        assert ctx.seeded_crash is not None


# --- Hunter tools (host fallback paths) -------------------------------------


class TestHunterToolsHostFallback:
    """When sandbox=None the tools use host file I/O — exercised in tests."""

    def test_read_source_file(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        read = next(t for t in tools if t.name == "read_source_file")
        out = read.invoke({"path": "include/codec_limits.h"})
        assert "MAX_FRAME_BYTES" in out

    def test_read_source_file_path_traversal_blocked(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        read = next(t for t in tools if t.name == "read_source_file")
        out = read.invoke({"path": "../../../etc/passwd"})
        assert "Error" in out

    def test_list_source_tree(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        ls = next(t for t in tools if t.name == "list_source_tree")
        listing = ls.invoke({"dir_path": "."})
        # Should include all 4 source files (codec_a.c, codec_b.c, codec_c.c, codec_limits.h)
        assert any("codec_a.c" in entry for entry in listing)
        assert any("codec_limits.h" in entry for entry in listing)

    def test_grep_source_python_fallback(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        grep = next(t for t in tools if t.name == "grep_source")
        matches = grep.invoke({"pattern": "MAX_FRAME_BYTES", "path": "."})
        assert isinstance(matches, list)
        assert len(matches) >= 4   # 1 in header + 3 in codec files
        # Each match has the right shape
        for m in matches:
            assert "file" in m
            assert "line_number" in m
            assert "matched_text" in m

    def test_find_callers_wraps_grep(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        callers = next(t for t in tools if t.name == "find_callers")
        matches = callers.invoke({"symbol": "MAX_FRAME_BYTES"})
        assert len(matches) >= 4

    def test_compile_file_without_sandbox_returns_error(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        compile_tool = next(t for t in tools if t.name == "compile_file")
        result = compile_tool.invoke({"file_path": "src/codec_a.c"})
        assert result["success"] is False
        assert "no sandbox" in result.get("error", "").lower()

    def test_run_with_sanitizer_without_sandbox_returns_error(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        run = next(t for t in tools if t.name == "run_with_sanitizer")
        result = run.invoke({"binary": "/scratch/x"})
        assert result["crashed"] is False

    def test_write_test_case_basename_only(self):
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        write = next(t for t in tools if t.name == "write_test_case")
        # Path with slash → rejected by basename validation before sandbox check
        out = write.invoke({"filename": "../etc/passwd", "content": "x"})
        assert "basename" in out.lower()
        # Filename starting with "." → also rejected by the validation
        out = write.invoke({"filename": ".hidden", "content": "x"})
        assert "basename" in out.lower()
        # Valid basename with no sandbox → returns the no-sandbox error
        out = write.invoke({"filename": "poc.bin", "content": "AAAA"})
        assert "no sandbox" in out.lower()

    def test_fuzz_harness_without_sandbox_returns_no_sandbox(self):
        """v0.4: fuzz_harness is fully implemented but still requires a sandbox."""
        ctx = HunterContext(repo_path=str(FIXTURE_C_PROPAGATION))
        tools = build_hunter_tools(ctx)
        fuzz = next(t for t in tools if t.name == "fuzz_harness")
        result = fuzz.invoke({"target_function": "decode_frame_a"})
        assert result["status"] == "no_sandbox"


# --- record_finding appends to ctx ------------------------------------------


class TestRecordFinding:
    def test_append_to_findings(self):
        ctx = HunterContext(
            repo_path=str(FIXTURE_C_PROPAGATION),
            session_id="sess-123",
            specialist="general",
        )
        tools = build_hunter_tools(ctx)
        record = next(t for t in tools if t.name == "record_finding")
        msg = record.invoke({
            "file": "src/codec_a.c",
            "line_number": 9,
            "finding_type": "memory_safety",
            "severity": "critical",
            "cwe": "CWE-787",
            "description": "memcpy with unchecked length",
            "code_snippet": "memcpy(frame, input, input_len);",
            "evidence_level": "static_corroboration",
        })
        assert "Finding recorded" in msg
        assert len(ctx.findings) == 1
        f = ctx.findings[0]
        assert f["file"] == "src/codec_a.c"
        assert f["line_number"] == 9
        assert f["severity"] == "critical"
        assert f["evidence_level"] == "static_corroboration"
        assert f["discovered_by"] == "hunter:general"
        assert f["seeded_from_crash"] is False
        assert f["hunter_session_id"] == "sess-123"
        assert f["id"].startswith("hunter-")

    def test_seeded_from_crash_flag(self):
        ctx = HunterContext(
            repo_path=str(FIXTURE_C_PROPAGATION),
            seeded_crash={"report": "asan"},
            specialist="memory_safety",
        )
        tools = build_hunter_tools(ctx)
        record = next(t for t in tools if t.name == "record_finding")
        record.invoke({
            "file": "x.c", "line_number": 1, "finding_type": "uaf",
            "severity": "high", "cwe": "CWE-416", "description": "y",
        })
        assert ctx.findings[0]["seeded_from_crash"] is True
        assert ctx.findings[0]["discovered_by"] == "hunter:memory_safety"


# --- Sanitizer / rg parsing helpers -----------------------------------------


class TestSanitizerParser:
    def test_parses_asan_header(self):
        stderr = """some warmup text
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234
    #0 0x4000 in main /workspace/foo.c:42
    #1 0x4100 in __libc_start_main
==12345==SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
        report = _parse_sanitizer_report(stderr)
        assert "AddressSanitizer" in report
        assert "heap-buffer-overflow" in report

    def test_no_sanitizer_just_returns_first_lines(self):
        stderr = "regular error\nline two\nline three\n"
        report = _parse_sanitizer_report(stderr)
        assert "regular error" in report

    def test_empty_stderr_returns_empty(self):
        assert _parse_sanitizer_report("") == ""


class TestRgOutputParser:
    def test_basic_rg_output(self):
        stdout = (
            "/workspace/foo.c:42:    int x = 1;\n"
            "/workspace/bar.c:7:#define X 2\n"
        )
        matches = _parse_rg_output(stdout)
        assert len(matches) == 2
        assert matches[0]["file"] == "foo.c"
        assert matches[0]["line_number"] == 42
        assert matches[1]["file"] == "bar.c"
        assert matches[1]["line_number"] == 7

    def test_caps_at_100(self):
        stdout = "\n".join(f"/a:{i}:line" for i in range(150))
        matches = _parse_rg_output(stdout)
        assert len(matches) == 100


class TestNormalizePath:
    def test_strips_leading_slash(self):
        rel = _normalize_path("/tmp/repo", "/foo/bar")
        # The function turns absolute-looking paths into repo-relative
        assert not rel.startswith("/")

    def test_traversal_raises(self):
        with pytest.raises(ValueError, match="escapes repo"):
            _normalize_path("/tmp/repo", "../../../etc/passwd")

    def test_clean_rel_path(self):
        rel = _normalize_path("/tmp/repo", "src/foo.c")
        assert rel == "src/foo.c"
