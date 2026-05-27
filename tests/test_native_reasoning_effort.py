"""Tests for the reasoning_effort auto-detection added to AsyncLLMClient.

Covers Layer 1 (model-name denylist + sentinel-default constructor) and
Layer 2 (retry-on-400 fallback in achat / achat_stream).
"""

import asyncio
from unittest.mock import patch

import pytest

from clearwing.llm.native import (
    _REASONING_EFFORT_OVERRIDE_ALLOW,
    _REASONING_EFFORT_UNSUPPORTED_PATTERNS,
    AsyncLLMClient,
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


class TestConstructorAutoBehavior:
    """Layer 1, wired into __init__.

    These tests verify that with the new sentinel default ('auto'), the
    constructor calls _auto_resolve_reasoning_effort and stores the result.
    Explicit values (including None and "medium") must pass through untouched.
    """

    def _kwargs(self, **overrides):
        """Minimal kwargs to satisfy AsyncLLMClient.__init__."""
        base = dict(
            model_name="llama-3.3-70b-versatile",
            provider_name="openai_compat",
            api_key="sk-test",
        )
        base.update(overrides)
        return base

    def test_default_for_groq_llama_resolves_to_none(self):
        client = AsyncLLMClient(**self._kwargs(model_name="llama-3.3-70b-versatile"))
        assert client.reasoning_effort is None

    def test_default_for_gpt_4o_resolves_to_medium(self):
        client = AsyncLLMClient(**self._kwargs(model_name="gpt-4o"))
        assert client.reasoning_effort == "medium"

    def test_explicit_medium_passes_through_on_denylist_model(self):
        client = AsyncLLMClient(
            **self._kwargs(
                model_name="llama-3.3-70b-versatile",
                reasoning_effort="medium",
            )
        )
        assert client.reasoning_effort == "medium"

    def test_explicit_none_passes_through_on_allowed_model(self):
        client = AsyncLLMClient(**self._kwargs(model_name="gpt-4o", reasoning_effort=None))
        assert client.reasoning_effort is None

    def test_explicit_high_passes_through(self):
        client = AsyncLLMClient(**self._kwargs(model_name="o1-preview", reasoning_effort="high"))
        assert client.reasoning_effort == "high"


class TestIsUnsupportedReasoningEffortError:
    """Layer 2 helper: classifying the exception so we only retry the right ones."""

    def test_matches_real_groq_400_body(self):
        # Verbatim from the original session log
        exc = RuntimeError(
            "Web stream error for model 'llama-3.3-70b-versatile (adapter: OpenAI)'. "
            "Status: 400 Bad Request. "
            'Body: {"error":{"message":"`reasoning_effort` is not supported with '
            'this model","type":"invalid_request_error","code":"unknown_parameter"}}'
        )
        assert AsyncLLMClient._is_unsupported_reasoning_effort_error(exc) is True

    def test_matches_unsupported_word_without_400(self):
        exc = RuntimeError("reasoning_effort: unsupported parameter")
        assert AsyncLLMClient._is_unsupported_reasoning_effort_error(exc) is True

    def test_rejects_429_rate_limit(self):
        exc = RuntimeError("Status: 429 Too Many Requests. rate limit exceeded")
        assert AsyncLLMClient._is_unsupported_reasoning_effort_error(exc) is False

    def test_rejects_400_for_other_param(self):
        exc = RuntimeError("Status: 400 Bad Request. unknown parameter 'frobnicator'")
        assert AsyncLLMClient._is_unsupported_reasoning_effort_error(exc) is False

    def test_rejects_500_server_error(self):
        exc = RuntimeError("Status: 500 Internal Server Error")
        assert AsyncLLMClient._is_unsupported_reasoning_effort_error(exc) is False

    def test_rejects_non_400_message_mentioning_param(self):
        # Defensive: a stringified exception that mentions reasoning_effort but
        # isn't actually a 400 or "unsupported" message
        exc = RuntimeError("reasoning_effort defaulted to medium for unknown model")
        assert AsyncLLMClient._is_unsupported_reasoning_effort_error(exc) is False


class TestRebuildOptionsWithoutReasoning:
    """Layer 2 helper: reconstruct ChatOptions with reasoning_effort dropped."""

    def test_drops_reasoning_effort_preserves_everything_else(self):
        from genai_pyo3 import ChatOptions

        original = ChatOptions(
            temperature=0.7,
            max_tokens=2048,
            capture_content=True,
            capture_usage=True,
            capture_tool_calls=True,
            capture_reasoning_content=True,
            normalize_reasoning_content=True,
            reasoning_effort="medium",
        )

        rebuilt = AsyncLLMClient._rebuild_options_without_reasoning(original)

        assert rebuilt.reasoning_effort is None
        assert rebuilt.temperature == 0.7
        assert rebuilt.max_tokens == 2048
        assert rebuilt.capture_content is True
        assert rebuilt.capture_usage is True
        assert rebuilt.capture_tool_calls is True
        assert rebuilt.capture_reasoning_content is True
        assert rebuilt.normalize_reasoning_content is True


class TestAchatRetryOnUnsupportedReasoning:
    """Layer 2 in the non-streaming path: catch the 400, retry once, mutate state."""

    def _make_client(self):
        # Pass explicit reasoning_effort="medium" to bypass auto-detection,
        # so we can prove the retry path runs even when Layer 1 didn't catch it.
        return AsyncLLMClient(
            model_name="some-future-model-2030",
            provider_name="openai_compat",
            api_key="sk-test",
            reasoning_effort="medium",
        )

    def test_retries_once_and_mutates_self(self):
        client = self._make_client()
        first_exc = RuntimeError(
            "Status: 400 Bad Request. "
            'Body: {"error":{"message":"`reasoning_effort` is not supported"}}'
        )
        success_response = object()  # Sentinel — we don't assert its shape

        # Replace the private call helper. _achat_with_provider_policy is the
        # narrowest seam: raises on first call, returns on second.
        call_log: list[str] = []

        async def fake_policy(self_, client_obj, request, options):
            call_log.append("called")
            if len(call_log) == 1:
                raise first_exc
            assert options.reasoning_effort is None, "Second call must drop reasoning_effort"
            return success_response

        with (
            patch.object(
                AsyncLLMClient,
                "_achat_with_provider_policy",
                new=fake_policy,
            ),
            patch.object(
                AsyncLLMClient,
                "_build_client",
                new=lambda self, cls: object(),
            ),
        ):
            result = asyncio.run(client.achat(messages=[], system=None, tools=None))

        assert result is success_response
        assert len(call_log) == 2, "Retry should have happened exactly once"
        assert client.reasoning_effort is None, (
            "Instance state must be mutated so future calls skip the param"
        )

    def test_unrelated_runtime_error_propagates(self):
        client = self._make_client()
        unrelated = RuntimeError("Status: 500 Internal Server Error")

        async def always_raise(self_, client_obj, request, options):
            raise unrelated

        with (
            patch.object(
                AsyncLLMClient,
                "_achat_with_provider_policy",
                new=always_raise,
            ),
            patch.object(
                AsyncLLMClient,
                "_build_client",
                new=lambda self, cls: object(),
            ),
        ):
            with pytest.raises(RuntimeError) as exc_info:
                asyncio.run(client.achat(messages=[], system=None, tools=None))

        assert exc_info.value is unrelated
        assert client.reasoning_effort == "medium", (
            "Instance state must not be touched on unrelated errors"
        )


class TestAchatStreamRetryOnUnsupportedReasoning:
    """Same Layer 2 behavior, on the streaming path."""

    def _make_client(self):
        return AsyncLLMClient(
            model_name="some-future-model-2030",
            provider_name="openai_compat",
            api_key="sk-test",
            reasoning_effort="medium",
        )

    def test_streaming_path_retries_once(self):
        client = self._make_client()
        first_exc = RuntimeError(
            "Status: 400 Bad Request. "
            'Body: {"error":{"message":"`reasoning_effort` is not supported"}}'
        )
        success_end = object()
        on_text = lambda chunk: None  # noqa: E731

        call_log: list[str] = []

        class FakeEvent:
            content = None
            end = success_end

        async def fake_stream(model_name, request, options):
            call_log.append("called")
            if len(call_log) == 1:
                raise first_exc
            assert options.reasoning_effort is None, (
                "Second streaming call must drop reasoning_effort"
            )

            async def gen():
                yield FakeEvent()

            return gen()

        fake_client = type(
            "FakeClient",
            (),
            {"astream_chat": staticmethod(fake_stream)},
        )()

        with patch.object(
            AsyncLLMClient,
            "_build_client",
            new=lambda self, cls: fake_client,
        ):
            result = asyncio.run(
                client.achat_stream(
                    messages=[],
                    system=None,
                    tools=None,
                    on_text_delta=on_text,
                )
            )

        assert result is success_end
        assert len(call_log) == 2
        assert client.reasoning_effort is None
