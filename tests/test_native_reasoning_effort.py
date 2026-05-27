"""Tests for the reasoning_effort auto-detection added to AsyncLLMClient.

See: docs/specs/2026-05-27-clearwing-reasoning-effort-patch-design.md
"""

import pytest

from clearwing.llm.native import (
    AsyncLLMClient,
    _REASONING_EFFORT_UNSUPPORTED_PATTERNS,
    _REASONING_EFFORT_OVERRIDE_ALLOW,
)


class TestAutoResolveReasoningEffort:
    """Layer 1: model-name-based denylist."""

    def test_groq_llama_3_3_resolves_to_none(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("llama-3.3-70b-versatile")
        assert result is None

    def test_match_is_case_insensitive(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("Llama-3-70B-INSTRUCT")
        assert result is None

    def test_openai_gpt_4o_keeps_medium(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("gpt-4o")
        assert result == "medium"

    def test_openai_o1_keeps_medium(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("o1-preview")
        assert result == "medium"

    def test_deepseek_r1_keeps_medium(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("deepseek-r1")
        assert result == "medium"

    def test_mistral_resolves_to_none(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("mistral-large-2407")
        assert result is None

    def test_mixtral_resolves_to_none(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("mixtral-8x7b-instruct")
        assert result is None

    def test_qwen2_resolves_to_none(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("qwen2.5-72b-instruct")
        assert result is None

    def test_gemma_resolves_to_none(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("gemma-2-27b-it")
        assert result is None

    def test_unknown_model_keeps_medium(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("some-future-model-2030")
        assert result == "medium"

    def test_constants_are_exported(self):
        """Sanity check: the public surface for the denylist is the two module-level constants."""
        assert isinstance(_REASONING_EFFORT_UNSUPPORTED_PATTERNS, tuple)
        assert "llama-3" in _REASONING_EFFORT_UNSUPPORTED_PATTERNS
        assert isinstance(_REASONING_EFFORT_OVERRIDE_ALLOW, frozenset)
