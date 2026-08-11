"""Tests for the reasoning_effort auto-detection added to AsyncLLMClient.

Covers Layer 1 (model-name denylist + sentinel-default constructor) and
Layer 2 (retry-on-400 fallback in achat / achat_stream).
"""

import asyncio
from unittest.mock import patch

import pytest
from genai_pyo3 import ChatResponse

from clearwing.llm.budget import BudgetExceeded
from clearwing.llm.native import (
    _REASONING_EFFORT_OVERRIDE_ALLOW,
    _REASONING_EFFORT_UNSUPPORTED_PATTERNS,
    _TRUNCATION_RETRY_ESCALATION,
    AsyncLLMClient,
    _looks_truncated,
)


class _FakeUsage:
    def __init__(self, prompt_tokens: int = 10, completion_tokens: int = 0):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens
        self.prompt_tokens_details = None


class _FakeResponse:
    """Stand-in for genai_pyo3.ChatResponse (which is Rust-backed and can't have
    its usage set from Python) — carries just the attributes the achat/settle
    path reads."""

    provider_model_name = "fake-model"
    reasoning_content = None

    def __init__(self, *, completion_tokens: int, tool_calls=None, text: str = "ok"):
        self.usage = _FakeUsage(completion_tokens=completion_tokens)
        self.tool_calls = tool_calls or []
        self._text = text

    @property
    def first_text(self) -> str:
        return self._text


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

    def test_deepseek_v4_flash_resolves_to_low(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("deepseek-v4-flash")
        assert result == "low"

    def test_deepseek_v4_flash_match_is_case_insensitive(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("DeepSeek-V4-Flash")
        assert result == "low"

    @pytest.mark.parametrize(
        "model_name",
        [
            "qwen3.8-27b",
            "Qwen3.8-32B-Instruct",
            "qwen/qwen3.8-27b",
        ],
    )
    def test_qwen3_8_variants_resolve_to_low(self, model_name):
        assert AsyncLLMClient._auto_resolve_reasoning_effort(model_name) == "low"

    def test_kimi_k3_uses_supported_high_effort(self):
        result = AsyncLLMClient._auto_resolve_reasoning_effort("kimi-k3")
        assert result == "high"

    @pytest.mark.parametrize("model", ["k3", "k3-256k"])
    def test_kimi_code_k3_uses_supported_high_effort(self, model):
        result = AsyncLLMClient._auto_resolve_reasoning_effort(model)
        assert result == "high"

    @pytest.mark.parametrize("model", ["kimi-for-coding", "kimi-for-coding-highspeed"])
    def test_kimi_code_k2_7_omits_reasoning_effort(self, model):
        result = AsyncLLMClient._auto_resolve_reasoning_effort(model)
        assert result is None

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


class TestTimeoutRetryPolicy:
    def test_timeout_retries_once_then_raises(self):
        client = AsyncLLMClient(
            model_name="test-model",
            provider_name="openai_compat",
            api_key="sk-test",
            rate_limit_max_retries=6,
            timeout_max_retries=1,
        )
        calls = 0

        async def always_times_out():
            nonlocal calls
            calls += 1
            raise RuntimeError("request timeout")

        async def no_sleep(_delay):
            return None

        with patch("clearwing.llm.native.asyncio.sleep", new=no_sleep):
            with pytest.raises(RuntimeError, match="request timeout"):
                asyncio.run(client._with_retries(always_times_out))

        assert calls == 2


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
        success_response = ChatResponse(content=[{"text": "ok"}])

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

        # A minimal stand-in for genai's StreamEnd (captured_* fields);
        # achat_stream rebuilds a ChatResponse from it via
        # _chat_response_from_stream_end.
        class _FakeStreamEnd:
            captured_content = [{"text": "streamed-ok"}]
            captured_reasoning_content = None
            captured_response_id = None
            captured_usage = None

        success_end = _FakeStreamEnd()
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

        # achat_stream now returns a real ChatResponse rebuilt from the
        # StreamEnd (not the raw end object), so assert on its content.
        assert result.first_text == "streamed-ok"
        assert len(call_log) == 2
        assert client.reasoning_effort is None


class TestLooksTruncated:
    """The truncation proxy: completion_tokens reached the applied cap."""

    def test_at_cap_is_truncated(self):
        resp = _FakeResponse(completion_tokens=4096)
        assert _looks_truncated(resp, 4096) is True

    def test_over_cap_is_truncated(self):
        resp = _FakeResponse(completion_tokens=5000)
        assert _looks_truncated(resp, 4096) is True

    def test_under_cap_is_not_truncated(self):
        resp = _FakeResponse(completion_tokens=100)
        assert _looks_truncated(resp, 4096) is False

    def test_no_cap_is_never_truncated(self):
        resp = _FakeResponse(completion_tokens=999999)
        assert _looks_truncated(resp, None) is False


class TestAchatTruncationRetry:
    """achat detects a capped, tool-call-less response and retries once."""

    def _make_client(self):
        # No spend ledger → reservation is None and max_tokens flows straight
        # from the caller, so we control the applied cap directly.
        return AsyncLLMClient(
            model_name="deepseek-v4-flash",
            provider_name="openai_compat",
            api_key="sk-test",
        )

    def _run(self, client, fake_policy, *, max_tokens):
        with (
            patch.object(AsyncLLMClient, "_achat_with_provider_policy", new=fake_policy),
            patch.object(AsyncLLMClient, "_build_client", new=lambda self, cls: object()),
        ):
            return asyncio.run(
                client.achat(messages=[], system=None, tools=None, max_tokens=max_tokens)
            )

    def test_retries_once_with_escalated_cap(self):
        client = self._make_client()
        caps: list = []

        async def fake_policy(self_, client_obj, request, options):
            caps.append(options.max_tokens)
            if len(caps) == 1:
                # Truncation fingerprint: at cap, no tool call, no text.
                return _FakeResponse(completion_tokens=100, tool_calls=[], text="")
            return _FakeResponse(completion_tokens=50, tool_calls=[], text="done")

        result = self._run(client, fake_policy, max_tokens=100)

        assert caps == [100, 100 * _TRUNCATION_RETRY_ESCALATION]
        assert result.usage.completion_tokens == 50

    def test_no_retry_when_text_present_even_at_cap(self):
        """A text-bearing answer at the cap (e.g. ranker JSON on a tight budget)
        is a real answer, not a truncation — must NOT retry."""
        client = self._make_client()
        caps: list = []

        async def fake_policy(self_, client_obj, request, options):
            caps.append(options.max_tokens)
            return _FakeResponse(completion_tokens=100, tool_calls=[], text='{"results": []}')

        result = self._run(client, fake_policy, max_tokens=100)

        assert caps == [100]
        assert result.first_text == '{"results": []}'

    def test_no_retry_when_tool_calls_present(self):
        client = self._make_client()
        caps: list = []

        async def fake_policy(self_, client_obj, request, options):
            caps.append(options.max_tokens)
            # At cap, but a tool call means the turn did useful work.
            return _FakeResponse(completion_tokens=100, tool_calls=[object()])

        result = self._run(client, fake_policy, max_tokens=100)

        assert caps == [100]
        assert result.tool_calls

    def test_no_retry_when_under_cap(self):
        client = self._make_client()
        caps: list = []

        async def fake_policy(self_, client_obj, request, options):
            caps.append(options.max_tokens)
            return _FakeResponse(completion_tokens=50, tool_calls=[])

        self._run(client, fake_policy, max_tokens=100)

        assert caps == [100]

    def test_only_one_retry_even_if_still_truncated(self):
        client = self._make_client()
        caps: list = []

        async def fake_policy(self_, client_obj, request, options):
            caps.append(options.max_tokens)
            # Always truncated at whatever cap was applied → would loop forever
            # if the single-retry guard were missing.
            return _FakeResponse(completion_tokens=options.max_tokens, tool_calls=[], text="")

        self._run(client, fake_policy, max_tokens=100)

        assert caps == [100, 100 * _TRUNCATION_RETRY_ESCALATION]

    def test_budget_exceeded_on_retry_returns_truncated_response(self):
        client = self._make_client()
        caps: list = []
        first = _FakeResponse(completion_tokens=100, tool_calls=[], text="")

        async def fake_policy(self_, client_obj, request, options):
            caps.append(options.max_tokens)
            if len(caps) == 1:
                return first
            raise BudgetExceeded("no budget for the escalated retry")

        result = self._run(client, fake_policy, max_tokens=100)

        assert caps == [100, 100 * _TRUNCATION_RETRY_ESCALATION]
        assert result is first

    def test_streaming_retries_once_with_escalated_cap(self):
        client = self._make_client()
        caps: list = []

        class FakeEvent:
            content = None
            end = object()

        async def fake_stream(model_name, request, options):
            caps.append(options.max_tokens)

            async def gen():
                yield FakeEvent()

            return gen()

        fake_client = type("FakeClient", (), {"astream_chat": staticmethod(fake_stream)})()
        responses = [
            _FakeResponse(completion_tokens=100, tool_calls=[], text=""),  # truncated
            _FakeResponse(completion_tokens=50, tool_calls=[], text="ok"),  # under cap
        ]

        def fake_from_end(self_, end):
            return responses.pop(0)

        with (
            patch.object(AsyncLLMClient, "_build_client", new=lambda self, cls: fake_client),
            patch.object(AsyncLLMClient, "_chat_response_from_stream_end", new=fake_from_end),
        ):
            result = asyncio.run(
                client.achat_stream(
                    messages=[],
                    system=None,
                    tools=None,
                    on_text_delta=lambda chunk: None,
                    max_tokens=100,
                )
            )

        assert caps == [100, 100 * _TRUNCATION_RETRY_ESCALATION]
        assert result.usage.completion_tokens == 50
