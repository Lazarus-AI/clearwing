from __future__ import annotations

import asyncio
import json
import socket
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from genai_pyo3 import ChatMessage

from clearwing.llm.budget import SpendLedger
from clearwing.llm.native import AsyncLLMClient


@pytest.fixture(autouse=True)
def bypass_proxies(monkeypatch):
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")


@asynccontextmanager
async def loopback_server(handler):
    application = web.Application()
    application.router.add_post("/v1/chat/completions", handler)
    runner = web.AppRunner(application)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.setblocking(False)
        port = listener.getsockname()[1]
        await runner.setup()
        await web.SockSite(runner, listener).start()
        yield f"http://127.0.0.1:{port}/v1/"
    finally:
        await runner.cleanup()
        listener.close()


def loopback_client(base_url, tmp_path, enforcing, transport, monkeypatch):
    ledger = SpendLedger(
        limit_usd=10.0 if enforcing else 0.0,
        session_id="loopback-stream",
        repo_url=str(tmp_path),
        output_dir=tmp_path,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
    )
    client = AsyncLLMClient(
        model_name="fixture-model",
        provider_name="openai",
        api_key="loopback-only",
        base_url=base_url,
        rate_limit_max_retries=1 if transport == "native" else 0,
    ).with_spend_ledger(ledger, stage="test")
    monkeypatch.setattr(client, "_retry_delay_seconds", lambda *_: 0)
    if transport == "fallback":
        native = SimpleNamespace(
            astream_chat=AsyncMock(side_effect=RuntimeError("connection refused"))
        )
        monkeypatch.setattr(client, "_build_client", lambda *_: native)
    return client, ledger


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["native", "fallback"])
@pytest.mark.parametrize("enforcing", [False, True])
@pytest.mark.parametrize("ending", ["disconnect", "eof", "callback"])
async def test_accepted_loopback_stream_is_not_replayed(
    monkeypatch, tmp_path, transport, enforcing, ending
):
    posts = []
    deltas = []
    delta_received = asyncio.Event()

    async def handler(request):
        posts.append(await request.json())
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        chunk = {"choices": [{"index": 0, "delta": {"content": "partial"}}]}
        await response.write(f"data: {json.dumps(chunk)}\n\n".encode())
        await asyncio.wait_for(delta_received.wait(), timeout=5)
        if ending == "disconnect":
            request.transport.abort()
        else:
            await response.write_eof()
        return response

    def on_delta(text):
        deltas.append(text)
        delta_received.set()
        if ending == "callback":
            raise RuntimeError(
                "Web stream error for model 'fixture-model (adapter: OpenAI)'.\n"
                "Cause: HTTP error.\nStatus: 429 Too Many Requests"
            )

    async with loopback_server(handler) as base_url:
        client, ledger = loopback_client(base_url, tmp_path, enforcing, transport, monkeypatch)
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(
                client.achat_stream(
                    messages=[ChatMessage("user", "hello")],
                    max_tokens=2,
                    on_text_delta=on_delta,
                ),
                timeout=10,
            )

    assert len(posts) == 1
    assert posts[0]["stream"] is True
    assert deltas == ["partial"]
    assert ledger.spent_usd == (2.0 if enforcing else 0.0)
    assert ledger.snapshot()["reserved_usd"] == 0
    assert ledger._records[-1]["status"] == "ambiguous_failure"


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["native", "fallback"])
@pytest.mark.parametrize("enforcing", [False, True])
@pytest.mark.parametrize("status", [401, 429])
async def test_loopback_http_rejection_is_unbilled(
    monkeypatch, tmp_path, transport, enforcing, status
):
    posts = []
    deltas = []

    async def handler(request):
        posts.append(await request.json())
        return web.json_response(
            {"error": {"message": "rejected before generation"}}, status=status
        )

    async with loopback_server(handler) as base_url:
        client, ledger = loopback_client(base_url, tmp_path, enforcing, transport, monkeypatch)
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(
                client.achat_stream(
                    messages=[ChatMessage("user", "hello")],
                    max_tokens=2,
                    on_text_delta=deltas.append,
                ),
                timeout=10,
            )

    assert len(posts) == (2 if transport == "native" and status == 429 else 1)
    assert all(post["stream"] is True for post in posts)
    assert deltas == []
    assert ledger.spent_usd == 0
    assert ledger.snapshot()["reserved_usd"] == 0
    assert ledger._records[-1]["status"] == "rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["native", "fallback"])
@pytest.mark.parametrize("enforcing", [False, True])
async def test_completed_loopback_stream_settles_usage(monkeypatch, tmp_path, transport, enforcing):
    posts = []
    deltas = []

    async def handler(request):
        posts.append(await request.json())
        if transport == "native" and len(posts) == 1:
            return web.json_response({"error": {"message": "rate limited"}}, status=429)
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        chunks = [
            {"choices": [{"index": 0, "delta": {"content": "ok"}}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            {
                "choices": [],
                "usage": {"prompt_tokens": 0, "completion_tokens": 1, "total_tokens": 1},
            },
        ]
        for chunk in chunks:
            await response.write(f"data: {json.dumps(chunk)}\n\n".encode())
        await response.write(b"data: [DONE]\n\n")
        await response.write_eof()
        return response

    async with loopback_server(handler) as base_url:
        client, ledger = loopback_client(base_url, tmp_path, enforcing, transport, monkeypatch)
        response = await asyncio.wait_for(
            client.achat_stream(
                messages=[ChatMessage("user", "hello")],
                max_tokens=2,
                on_text_delta=deltas.append,
            ),
            timeout=10,
        )

    assert len(posts) == (2 if transport == "native" else 1)
    assert all(post["stream"] is True for post in posts)
    assert deltas == ["ok"]
    assert response.first_text == "ok"
    assert ledger.spent_usd == 1.0
    assert ledger.snapshot()["reserved_usd"] == 0
    assert ledger._records[-1]["status"] == "succeeded"
