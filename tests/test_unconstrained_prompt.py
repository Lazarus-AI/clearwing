"""Tests for unconstrained prompt mode (spec 002)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.hunter import (
    DISCOVERY_PROMPT,
    EXPLOIT_EXTENSION,
    HUNTER_EXECUTION_RULES,
    MITIGATION_REASONING,
    SELF_CHECK,
    _build_unconstrained_prompt,
    build_hunter_agent,
)
from clearwing.sourcehunt.state import FileTarget


def _make_file_target(
    path: str = "src/main.c",
    tier: str = "B",
    tags: list[str] | None = None,
    language: str = "c",
) -> FileTarget:
    return {
        "path": path,
        "absolute_path": f"/repo/{path}",
        "language": language,
        "loc": 100,
        "tags": tags or [],
        "tier": tier,
        "surface": 3,
        "influence": 2,
        "reachability": 3,
        "priority": 2.5,
    }


class TestBuildUnconstrainedPrompt:
    def test_no_execution_rules(self):
        ft = _make_file_target()
        prompt = _build_unconstrained_prompt(ft, "test-project", None, None)
        assert "Execution rules:" not in prompt
        assert "By step 3" not in prompt

    def test_has_self_check(self):
        ft = _make_file_target()
        prompt = _build_unconstrained_prompt(ft, "test-project", None, None)
        assert "Before you record a finding" in prompt
        assert "attacker would actually trigger" in prompt

    def test_has_file_and_project(self):
        ft = _make_file_target("lib/parser.c")
        prompt = _build_unconstrained_prompt(ft, "my-project", None, None)
        assert "lib/parser.c" in prompt
        assert "my-project" in prompt

    def test_exploit_mode_appends_extension_and_mitigation(self):
        ft = _make_file_target()
        prompt = _build_unconstrained_prompt(
            ft, "test-project", None, None, exploit_mode=True
        )
        assert "please write exploits" in prompt
        assert "defensive mitigation" in prompt
        assert "int32_t[] gets no canary" in prompt

    def test_no_exploit_mode_omits_extension(self):
        ft = _make_file_target()
        prompt = _build_unconstrained_prompt(
            ft, "test-project", None, None, exploit_mode=False
        )
        assert "please write exploits" not in prompt
        assert "defensive mitigation" not in prompt

    def test_campaign_hint_formatted(self):
        ft = _make_file_target()
        prompt = _build_unconstrained_prompt(
            ft, "test-project", None, None,
            campaign_hint="bugs reachable from unauthenticated remote input",
        )
        assert "bugs reachable from unauthenticated remote input" in prompt
        assert "particularly interested" in prompt

    def test_no_campaign_hint(self):
        ft = _make_file_target()
        prompt = _build_unconstrained_prompt(ft, "test-project", None, None)
        assert "particularly interested" not in prompt

    def test_seeded_crash_included(self):
        ft = _make_file_target()
        crash = {"report": "ASan: heap-buffer-overflow in parse_header"}
        prompt = _build_unconstrained_prompt(ft, "test-project", crash, None)
        assert "heap-buffer-overflow" in prompt
        assert "crash BEFORE you started" in prompt

    def test_semgrep_hints_included(self):
        ft = _make_file_target()
        hints = [
            {"line": 42, "description": "potential buffer overflow"},
            {"line": 99, "description": "unchecked return value"},
        ]
        prompt = _build_unconstrained_prompt(ft, "test-project", None, hints)
        assert "line 42" in prompt
        assert "potential buffer overflow" in prompt
        assert "Static analysis hints" in prompt

    def test_all_options_combined(self):
        ft = _make_file_target()
        crash = {"report": "UBSan: signed-integer-overflow"}
        hints = [{"line": 10, "description": "width truncation"}]
        prompt = _build_unconstrained_prompt(
            ft, "test-project", crash, hints,
            campaign_hint="integer overflow bugs",
            exploit_mode=True,
        )
        assert "signed-integer-overflow" in prompt
        assert "width truncation" in prompt
        assert "integer overflow bugs" in prompt
        assert "please write exploits" in prompt
        assert "Before you record a finding" in prompt


class TestBuildHunterAgentPromptMode:
    def test_unconstrained_deep_uses_discovery_prompt(self):
        llm = MagicMock()
        ft = _make_file_target(tags=["memory_unsafe", "parser"])
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            agent_mode="deep",
            prompt_mode="unconstrained",
        )
        assert "Please find a security vulnerability" in hunter.prompt
        assert "Execution rules:" not in hunter.prompt
        assert ctx.specialist == "unconstrained"
        tool_names = {t.name for t in hunter.tools}
        assert "execute" in tool_names
        assert hunter.max_steps == 500

    def test_unconstrained_constrained_uses_discovery_prompt_with_9_tools(self):
        llm = MagicMock()
        ft = _make_file_target(tags=["memory_unsafe"])
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            agent_mode="constrained",
            prompt_mode="unconstrained",
        )
        assert "Please find a security vulnerability" in hunter.prompt
        assert "Execution rules:" not in hunter.prompt
        assert ctx.specialist == "unconstrained"
        tool_names = {t.name for t in hunter.tools}
        assert "read_source_file" in tool_names
        assert "compile_file" in tool_names
        assert hunter.max_steps == 20

    def test_specialist_mode_uses_specialist_prompt(self):
        llm = MagicMock()
        ft = _make_file_target(tags=["memory_unsafe", "parser"])
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            agent_mode="constrained",
            prompt_mode="specialist",
        )
        assert "MEMORY SAFETY specialist" in hunter.prompt
        assert "Execution rules:" in hunter.prompt
        assert ctx.specialist == "memory_safety"

    def test_specialist_mode_deep_uses_deep_specialist_prompt(self):
        llm = MagicMock()
        ft = _make_file_target(tags=["memory_unsafe"])
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            agent_mode="deep",
            prompt_mode="specialist",
        )
        assert "memory corruption" in hunter.prompt
        assert ctx.specialist == "memory_safety"
        tool_names = {t.name for t in hunter.tools}
        assert "execute" in tool_names

    def test_propagation_ignores_prompt_mode(self):
        llm = MagicMock()
        ft = _make_file_target(tier="C")
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            prompt_mode="unconstrained",
        )
        assert ctx.specialist == "propagation"
        assert "PROPAGATION RISK" in hunter.prompt
        tool_names = {t.name for t in hunter.tools}
        assert "compile_file" not in tool_names

    def test_unconstrained_with_exploit_mode(self):
        llm = MagicMock()
        ft = _make_file_target()
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            prompt_mode="unconstrained",
            exploit_mode=True,
        )
        assert "please write exploits" in hunter.prompt
        assert "defensive mitigation" in hunter.prompt

    def test_unconstrained_with_campaign_hint(self):
        llm = MagicMock()
        ft = _make_file_target()
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
            prompt_mode="unconstrained",
            campaign_hint="logic bugs in the authentication path",
        )
        assert "logic bugs in the authentication path" in hunter.prompt

    def test_default_prompt_mode_is_unconstrained(self):
        llm = MagicMock()
        ft = _make_file_target()
        hunter, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp/repo",
            sandbox=None,
            llm=llm,
            session_id="s1",
        )
        assert "Please find a security vulnerability" in hunter.prompt
        assert ctx.specialist == "unconstrained"
