from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
from genai_pyo3 import ChatMessage, ChatOptions, ChatRequest, ChatResponse, JsonSpec, Tool, Usage

from clearwing.llm.budget import SpendLedger
from clearwing.llm.native import AsyncLLMClient


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    monkeypatch.setattr(
        AsyncLLMClient, "_build_client", Mock(side_effect=AssertionError("native network blocked"))
    )
    monkeypatch.setattr(
        aiohttp, "ClientSession", Mock(side_effect=AssertionError("HTTP network blocked"))
    )


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
    assert "max_tokens" not in body
    assert "max_completion_tokens" not in body
    assert "max_output_tokens" not in body


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
async def test_achat_falls_back_when_native_openai_transport_fails(monkeypatch):
    class FailingClient:
        async def achat(self, *_args, **_kwargs):
            raise RuntimeError("Web call failed: connection refused")

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
        rate_limit_max_retries=0,
    )

    response = await client.achat(messages=[ChatMessage("user", "hello")])

    assert response.first_text == "fallback ok"


@pytest.mark.asyncio
async def test_achat_stream_falls_back_and_preserves_delta_callback(monkeypatch):
    class FailingClient:
        async def astream_chat(self, *_args, **_kwargs):
            raise RuntimeError("Web call failed: connection refused")

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
        rate_limit_max_retries=0,
    )
    deltas: list[str] = []

    response = await client.achat_stream(
        messages=[ChatMessage("user", "hello")],
        on_text_delta=deltas.append,
    )

    assert response.first_text == "fallback"
    assert deltas == ["fall", "back"]


@pytest.mark.asyncio
@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("enforcing", [False, True])
@pytest.mark.parametrize("error", ["response body interrupted", "connection refused", "HTTP 429"])
async def test_failed_fallback_stream_never_replays_request(
    monkeypatch, tmp_path, partial, enforcing, error
):
    requests = []

    class Response:
        status = 200

        @property
        def content(self):
            async def chunks():
                if partial:
                    yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n'
                raise aiohttp.ClientPayloadError(error)

            return chunks()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class Session:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        def post(self, url, **kwargs):
            requests.append(kwargs["json"])
            assert len(requests) == 1, "accepted stream must not trigger a second billable POST"
            return Response()

    monkeypatch.setattr(aiohttp, "ClientSession", Session)
    client = AsyncLLMClient(
        model_name="fixture-model",
        provider_name="openai",
        api_key="dummy",
        base_url="https://example.test/v1",
        rate_limit_max_retries=0,
    )
    native = SimpleNamespace(astream_chat=AsyncMock(side_effect=RuntimeError("connection refused")))
    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda *_: native)
    ledger = make_ledger(tmp_path, enforcing)
    client = client.with_spend_ledger(ledger, stage="test")
    deltas = []
    with pytest.raises(RuntimeError, match=error) as failure:
        await client.achat_stream(
            messages=[ChatMessage("user", "hello")],
            max_tokens=2,
            on_text_delta=deltas.append,
        )
    assert isinstance(failure.value.__cause__, aiohttp.ClientPayloadError)
    assert native.astream_chat.await_count == 1
    assert len(requests) == 1
    assert requests[0]["stream"] is True
    assert deltas == (["partial"] if partial else [])
    assert ledger.spent_usd == (2.0 if enforcing else 0.0)
    assert ledger.snapshot()["reserved_usd"] == 0
    assert ledger._records[-1]["status"] == "ambiguous_failure"


@pytest.mark.asyncio
@pytest.mark.parametrize("enforcing", [False, True])
@pytest.mark.parametrize("error", ["connection refused", "HTTP 429"])
async def test_unbilled_stream_retry_settles_only_success(monkeypatch, tmp_path, enforcing, error):
    async def events():
        yield SimpleNamespace(content="ok", end=object())

    response = ChatResponse(
        content=[{"text": "ok"}], usage=Usage(prompt_tokens=0, completion_tokens=1, total_tokens=1)
    )
    native = SimpleNamespace(astream_chat=AsyncMock(side_effect=[RuntimeError(error), events()]))
    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda *_: native)
    monkeypatch.setattr(AsyncLLMClient, "_chat_response_from_stream_end", lambda *_: response)
    ledger = make_ledger(tmp_path, enforcing)
    client = AsyncLLMClient(
        model_name="fixture-model",
        provider_name="openai",
        api_key="dummy",
        rate_limit_max_retries=1,
    ).with_spend_ledger(ledger, stage="test")
    monkeypatch.setattr(client, "_retry_delay_seconds", lambda *_: 0)
    deltas = []
    result = await client.achat_stream(
        messages=[ChatMessage("user", "hello")],
        max_tokens=2,
        on_text_delta=deltas.append,
    )
    assert result is response
    assert deltas == ["ok"]
    assert native.astream_chat.await_count == 2
    assert ledger.spent_usd == 1.0
    assert ledger.snapshot()["reserved_usd"] == 0


def make_ledger(tmp_path, enforcing):
    return SpendLedger(
        limit_usd=10.0 if enforcing else 0.0,
        session_id="stream-test",
        repo_url="/tmp/repo",
        output_dir=tmp_path,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("enforcing", [False, True])
@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize(
    "error", ["connection reset", "connection refused", "HTTP 429", "eof", "callback"]
)
async def test_accepted_native_stream_never_replays(
    monkeypatch, tmp_path, enforcing, partial, error
):
    async def events():
        if partial:
            yield SimpleNamespace(content="partial", end=None)
        if error != "eof":
            raise RuntimeError(error)

    native = SimpleNamespace(astream_chat=AsyncMock(side_effect=lambda *_: events()))
    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda *_: native)
    fallback = AsyncMock(side_effect=AssertionError("must not replay"))
    monkeypatch.setattr(AsyncLLMClient, "_openai_chat_http_fallback", fallback)
    ledger = make_ledger(tmp_path, enforcing)
    client = AsyncLLMClient(
        model_name="fixture-model",
        provider_name="openai",
        api_key="dummy",
        base_url="https://example.test/v1",
    ).with_spend_ledger(ledger, stage="test")
    deltas = []

    def callback(text):
        deltas.append(text)
        if error == "callback":
            raise RuntimeError("HTTP 400 unsupported reasoning_effort")

    with pytest.raises(RuntimeError):
        await client.achat_stream(
            messages=[ChatMessage("user", "hello")],
            max_tokens=2,
            on_text_delta=callback,
        )
    assert native.astream_chat.await_count == 1
    fallback.assert_not_awaited()
    assert deltas == (["partial"] if partial else [])
    assert ledger.spent_usd == (2.0 if enforcing else 0.0)
    assert ledger.snapshot()["reserved_usd"] == 0
    assert ledger._records[-1]["status"] == "ambiguous_failure"


@pytest.mark.asyncio
@pytest.mark.parametrize("enforcing", [False, True])
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "error,unbilled",
    [
        ("connection refused", True),
        ("HTTP 429", True),
        ("error sending request", False),
        ("connection reset", False),
        ("timeout", False),
        ("Web stream error", False),
    ],
)
async def test_dispatch_failure_retry_and_accounting(
    monkeypatch, tmp_path, enforcing, streaming, error, unbilled
):
    operation = AsyncMock(side_effect=RuntimeError(error))
    native = SimpleNamespace(astream_chat=operation, achat=operation)
    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda *_: native)
    ledger = make_ledger(tmp_path, enforcing)
    client = AsyncLLMClient(
        model_name="fixture-model",
        provider_name="openai",
        api_key="dummy",
        rate_limit_max_retries=1,
    ).with_spend_ledger(ledger, stage="test")
    monkeypatch.setattr(client, "_retry_delay_seconds", lambda *_: 0)
    call = client.achat_stream if streaming else client.achat
    kwargs = {"on_text_delta": Mock()} if streaming else {}
    with pytest.raises(RuntimeError, match=error):
        await call(messages=[ChatMessage("user", "hello")], max_tokens=2, **kwargs)
    assert operation.await_count == (2 if unbilled else 1)
    assert ledger.spent_usd == (2.0 if enforcing and not unbilled else 0.0)
    assert ledger.snapshot()["reserved_usd"] == 0
    assert ledger._records[-1]["status"] == ("rejected" if unbilled else "ambiguous_failure")
