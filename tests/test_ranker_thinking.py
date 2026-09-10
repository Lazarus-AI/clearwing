"""Ranker-only Qwen thinking switch (hunter path must stay untouched)."""

from __future__ import annotations

from genai_pyo3 import ChatMessage, ChatOptions, ChatRequest

from clearwing.llm.native import AsyncLLMClient, _merge_extra_body
from clearwing.sourcehunt.config import parse_runtime_tuning_policy
from clearwing.sourcehunt.ranker import RankerConfig


def test_ranker_extra_body_disables_thinking_by_default():
    assert RankerConfig().llm_extra_body() == {
        "chat_template_kwargs": {"enable_thinking": False}
    }


def test_ranker_extra_body_can_reenable_thinking():
    assert RankerConfig(enable_thinking=True).llm_extra_body() == {
        "chat_template_kwargs": {"enable_thinking": True}
    }


def test_parse_runtime_tuning_defaults_ranker_thinking_off():
    policy = parse_runtime_tuning_policy({"ok": True, "policy": {}})
    assert policy.sourcehunt.ranker.enable_thinking is False


def test_parse_runtime_tuning_can_restore_ranker_thinking():
    policy = parse_runtime_tuning_policy(
        {"policy": {"sourcehunt": {"ranker": {"enable_thinking": True}}}}
    )
    assert policy.sourcehunt.ranker.enable_thinking is True


def test_merge_extra_body_keeps_top_k_and_thinking_kwargs():
    merged = _merge_extra_body(
        {"top_k": 20},
        {"chat_template_kwargs": {"enable_thinking": False}},
    )
    assert merged == {
        "top_k": 20,
        "chat_template_kwargs": {"enable_thinking": False},
    }


def test_hunter_openai_body_has_no_thinking_kwargs_by_default():
    client = AsyncLLMClient(
        model_name="Qwen3.8-27B-NVFP4",
        provider_name="openai_compat",
        api_key="dummy",
        base_url="https://example.test/v1",
        reasoning_effort="medium",
    )
    request = ChatRequest(messages=[ChatMessage("user", "hunt")])
    options = ChatOptions(reasoning_effort=client.reasoning_effort)
    body = client._openai_chat_request_body(request, options, stream=True)
    assert "chat_template_kwargs" not in body
    assert body["reasoning_effort"] == "medium"


def test_ranker_openai_body_sends_enable_thinking_false():
    client = AsyncLLMClient(
        model_name="Qwen3.8-27B-NVFP4",
        provider_name="openai_compat",
        api_key="dummy",
        base_url="https://example.test/v1",
        reasoning_effort="medium",
    )
    request = ChatRequest(messages=[ChatMessage("user", "rank")])
    extra = RankerConfig().llm_extra_body()
    options = ChatOptions(
        reasoning_effort=client.reasoning_effort,
        extra_body=extra,
    )
    body = client._openai_chat_request_body(request, options, stream=False)
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert body["reasoning_effort"] == "medium"
