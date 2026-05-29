"""Regression test: drop `reasoning_effort` and retry when a model rejects the
legacy thinking request param.

Current Anthropic Opus models (4.7/4.8) 400 with '"thinking.type.enabled" is
not supported for this model. Use "thinking.type.adaptive" and
"output_config.effort" ...' because genai-pyo3 serializes reasoning_effort
into the legacy thinking shape. The client must detect this, stop sending the
param, and retry. Pure-logic test — no network, no real provider.
"""

from __future__ import annotations

from clearwing.llm.native import AsyncLLMClient

_THINKING_400 = Exception(
    'Status: 400 Bad Request Body: {"type":"error","error":{"type":'
    '"invalid_request_error","message":"\\"thinking.type.enabled\\" is not '
    'supported for this model. Use \\"thinking.type.adaptive\\" and '
    '\\"output_config.effort\\" to control thinking behavior."}}'
)


def _client(reasoning_effort="medium") -> AsyncLLMClient:
    return AsyncLLMClient(
        model_name="claude-opus-4-8",
        provider_name="anthropic",
        api_key="test-key",
        reasoning_effort=reasoning_effort,
    )


def test_detects_thinking_unsupported_error():
    c = _client()
    assert c._is_thinking_unsupported_error(_THINKING_400)
    assert not c._is_thinking_unsupported_error(Exception("429 too many requests"))
    assert not c._is_thinking_unsupported_error(Exception("500 internal error"))


def test_handle_latches_and_suppresses_effort():
    c = _client()
    assert c._effective_reasoning_effort() == "medium"

    assert c._handle_thinking_unsupported(_THINKING_400) is True
    assert c._thinking_unsupported is True
    assert c._effective_reasoning_effort() is None
    # Idempotent: a second occurrence doesn't request another retry.
    assert c._handle_thinking_unsupported(_THINKING_400) is False


def test_handle_ignores_unrelated_errors():
    c = _client()
    assert c._handle_thinking_unsupported(Exception("500 internal error")) is False
    assert c._thinking_unsupported is False
    assert c._effective_reasoning_effort() == "medium"


def test_no_retry_when_effort_already_disabled():
    c = _client(reasoning_effort=None)
    # Nothing to drop, so there's no point retrying.
    assert c._handle_thinking_unsupported(_THINKING_400) is False
