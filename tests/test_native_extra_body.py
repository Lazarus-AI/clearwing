"""Tests for the unified extra_body handling added to AsyncLLMClient.

The registered model params (notably Qwen's ``enable_thinking=False``) must be
applied at runtime on EVERY call path. AsyncLLMClient resolves ``extra_body``
once in ``__init__`` — a model-family default (Qwen3 thinking disabled) deep-
merged with any explicitly configured extra_body — and sends it on every
ChatOptions it builds, so operate / sourcehunt / ranker / hunter stay
consistent.
"""

from genai_pyo3 import ChatOptions

from clearwing.llm.native import (
    AsyncLLMClient,
    _merge_extra_body,
    _model_thinking_extra_body,
)

QWEN_DISABLE = {"chat_template_kwargs": {"enable_thinking": False}}


def _client(model: str, extra_body: dict | None = None) -> AsyncLLMClient:
    return AsyncLLMClient(
        model_name=model,
        provider_name="openai",
        api_key="x",
        base_url="http://sakura-vllm:8000/v1",
        extra_body=extra_body,
    )


def test_qwen_family_disables_thinking() -> None:
    for model in ("qwen3.8-27b", "qwen3.8-27b-lambdalabs", "Qwen3-Coder"):
        assert _model_thinking_extra_body(model) == QWEN_DISABLE
        assert _client(model).extra_body == QWEN_DISABLE


def test_non_qwen_models_send_no_extra_body() -> None:
    for model in ("claude-opus-4-6", "glm-5.3", "z-ai/glm-5.3", "gpt-4o"):
        assert _model_thinking_extra_body(model) is None
        assert _client(model).extra_body is None


def test_configured_extra_body_deep_merges_over_family_default() -> None:
    client = _client("qwen3.8-27b", extra_body={"chat_template_kwargs": {"top_k": 20}})
    # family default (enable_thinking) preserved AND the configured key added
    assert client.extra_body == {"chat_template_kwargs": {"enable_thinking": False, "top_k": 20}}


def test_merge_helper_edges() -> None:
    assert _merge_extra_body(None, None) is None
    assert _merge_extra_body(None, {"a": 1}) == {"a": 1}
    assert _merge_extra_body({"a": 1}, None) == {"a": 1}
    # override wins on scalar collisions
    assert _merge_extra_body({"a": 1}, {"a": 2}) == {"a": 2}


def test_rebuild_without_reasoning_preserves_extra_body() -> None:
    original = ChatOptions(
        temperature=0.0,
        reasoning_effort="medium",
        extra_body=QWEN_DISABLE,
    )
    rebuilt = AsyncLLMClient._rebuild_options_without_reasoning(original)
    assert rebuilt.reasoning_effort is None
    # extra_body survives the reasoning-effort rebuild (JSON round-trip)
    assert original.extra_body_json == rebuilt.extra_body_json
    assert rebuilt.extra_body_json is not None
    assert "enable_thinking" in rebuilt.extra_body_json
