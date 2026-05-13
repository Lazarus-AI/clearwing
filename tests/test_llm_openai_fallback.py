from __future__ import annotations

import json

import pytest
from genai_pyo3 import ChatMessage, ChatOptions, ChatRequest, ChatResponse, JsonSpec, Tool

from clearwing.llm.native import AsyncLLMClient


def test_openai_fallback_request_body_includes_system_tools_and_json_schema():
    client = AsyncLLMClient(
        model_name="UnCut",
        provider_name="openai",
        api_key="dummy",
        base_url="https://example.test/v1",
    )
    request = ChatRequest(
        messages=[ChatMessage("user", "hi")],
        system="system prompt",
        tools=[Tool("lookup", "Look up a value", json.dumps({"type": "object"}))],
    )
    options = ChatOptions(
        max_tokens=128,
        temperature=0,
        capture_usage=True,
        reasoning_effort="medium",
        response_json_spec=JsonSpec(
            "Answer",
            json.dumps({"type": "object", "properties": {"answer": {"type": "string"}}}),
            "Structured answer",
        ),
    )

    body = client._openai_chat_request_body(request, options, stream=True)

    assert body["model"] == "UnCut"
    assert body["stream"] is True
    assert body["stream_options"] == {"include_usage": True}
    assert body["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "hi"},
    ]
    assert body["tools"][0]["function"]["name"] == "lookup"
    assert body["reasoning_effort"] == "medium"
    assert body["response_format"]["type"] == "json_schema"


def test_openai_fallback_parses_reasoning_content_usage_and_tool_calls():
    client = AsyncLLMClient(
        model_name="UnCut",
        provider_name="openai",
        api_key="dummy",
        base_url="https://example.test/v1",
    )
    payload = {
        "model": "UnCut",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "visible answer",
                    "reasoning_content": "private reasoning",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "lookup",
                                "arguments": json.dumps({"q": "abc"}),
                            },
                        }
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8},
    }

    response = client._chat_response_from_openai_payload(payload)

    assert response.first_text == "visible answer"
    assert response.reasoning_content == "private reasoning"
    assert response.usage.prompt_tokens == 3
    [tool_call] = response.tool_calls
    assert tool_call.call_id == "call_1"
    assert tool_call.fn_name == "lookup"
    assert tool_call.fn_arguments == {"q": "abc"}


@pytest.mark.asyncio
async def test_achat_falls_back_when_native_openai_streaming_transport_fails(monkeypatch):
    class FailingClient:
        async def achat_via_stream(self, *_args, **_kwargs):
            raise RuntimeError("Web stream error for model")

    async def fallback(self, request, options, *, on_text_delta=None):
        assert request.messages()[0].content == "hello"
        assert options.capture_content is True
        assert on_text_delta is None
        return ChatResponse(content=[{"text": "fallback ok"}])

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, _cls: FailingClient())
    monkeypatch.setattr(AsyncLLMClient, "_openai_chat_http_fallback", fallback)
    client = AsyncLLMClient(
        model_name="UnCut",
        provider_name="openai",
        api_key="dummy",
        base_url="https://example.test/v1",
    )

    response = await client.achat(messages=[ChatMessage("user", "hello")])

    assert response.first_text == "fallback ok"


@pytest.mark.asyncio
async def test_achat_stream_falls_back_and_preserves_delta_callback(monkeypatch):
    class FailingClient:
        async def astream_chat(self, *_args, **_kwargs):
            raise RuntimeError("Web stream error for model")

    async def fallback(self, request, options, *, on_text_delta=None):
        assert request.messages()[0].content == "hello"
        assert on_text_delta is not None
        on_text_delta("fall")
        on_text_delta("back")
        return ChatResponse(content=[{"text": "fallback"}])

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, _cls: FailingClient())
    monkeypatch.setattr(AsyncLLMClient, "_openai_chat_http_fallback", fallback)
    client = AsyncLLMClient(
        model_name="UnCut",
        provider_name="openai",
        api_key="dummy",
        base_url="https://example.test/v1",
    )
    deltas: list[str] = []

    response = await client.achat_stream(
        messages=[ChatMessage("user", "hello")],
        on_text_delta=deltas.append,
    )

    assert response.first_text == "fallback"
    assert deltas == ["fall", "back"]
