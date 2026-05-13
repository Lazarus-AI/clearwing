from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import aiohttp
from genai_pyo3 import (
    ChatMessage,
    ChatOptions,
    ChatRequest,
    ChatResponse,
    Client,
    JsonSpec,
    Tool,
    Usage,
)
from pydantic import BaseModel, RootModel

logger = logging.getLogger(__name__)


def _run_coro_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("Synchronous wrapper called from a running event loop")


def response_text(response: ChatResponse) -> str:
    """Coalesce a :class:`ChatResponse`'s text segments into a single string.

    Prefers ``first_text()`` when it is non-empty; falls back to joining
    every non-empty segment in ``texts()``. Returns ``""`` when the
    response carries no text at all (e.g. a pure tool-call response).
    """
    first = response.first_text
    if first:
        return first
    return "\n".join(segment for segment in response.texts if segment)


def _is_root_model_type(schema_model: type[BaseModel]) -> bool:
    return issubclass(schema_model, RootModel)


def _validate_schema_response(schema_model: type[BaseModel], text: str) -> BaseModel:
    try:
        return schema_model.model_validate_json(text)
    except Exception:
        parsed_json = json.loads(text)
        if isinstance(parsed_json, list) and "results" in schema_model.model_fields:
            return schema_model.model_validate({"results": parsed_json})
        raise


@dataclass(slots=True)
class NativeToolSpec:
    name: str
    description: str
    schema: dict[str, Any]
    handler: Any

    async def ainvoke(self, arguments: dict[str, Any]) -> Any:
        if asyncio.iscoroutinefunction(self.handler):
            return await self.handler(**arguments)
        return await asyncio.to_thread(self.handler, **arguments)

    def invoke(self, arguments: dict[str, Any] | None = None) -> Any:
        return _run_coro_sync(self.ainvoke(arguments or {}))

    @property
    def input_schema(self) -> dict[str, Any]:
        return self.schema


class AsyncLLMClient:
    """Native async wrapper around genai-pyo3 for sourcehunt/runtime use.

    This intentionally bypasses LangChain's message/result model and exposes
    only the pieces Clearwing actually needs: text, tool calls, usage, and
    bounded concurrency.
    """

    def __init__(
        self,
        *,
        model_name: str,
        provider_name: str,
        api_key: str,
        base_url: str | None = None,
        max_concurrency: int = 4,
        default_system: str = "You are a helpful assistant.",
        rate_limit_max_retries: int = 6,
        rate_limit_initial_backoff_seconds: float = 1.0,
        rate_limit_max_backoff_seconds: float = 60.0,
        reasoning_effort: str | None = "medium",
    ) -> None:
        self.model_name = model_name
        self.provider_name = provider_name
        self.api_key = api_key
        self.base_url = base_url
        self._default_headers: dict[str, str] | None = None

        # `openai_codex` is clearwing's label for the OAuth-authenticated
        # Responses API (the ChatGPT "Codex CLI" flow). It's not a distinct
        # rust-genai adapter — it *is* the openai_resp adapter plus three
        # extra request headers (`chatgpt-account-id`, `OpenAI-Beta`,
        # `originator`) and a proxy base_url. Resolve the OAuth token and
        # account-id once here; from this point on the Client behaves
        # exactly like any other openai_resp Client.
        #
        # Token refresh happens once at construction. If the token expires
        # during a long-running AsyncLLMClient instance, subsequent calls
        # will fail until the instance is rebuilt — accepted tradeoff for
        # avoiding per-call refresh overhead.
        if provider_name == "openai_codex":
            from clearwing.providers.openai_oauth import (
                OPENAI_CODEX_DEFAULT_BASE_URL,
                ensure_fresh_openai_oauth_credentials,
                extract_account_id,
            )

            try:
                creds = ensure_fresh_openai_oauth_credentials()
                self.api_key = creds.access
            except Exception:
                if not self.api_key:
                    raise

            if not self.api_key:
                raise RuntimeError(
                    "Missing OpenAI OAuth access token. "
                    "Run: `clearwing setup --provider openai-oauth`"
                )

            account_id = extract_account_id(self.api_key)
            if not account_id:
                raise RuntimeError(
                    "OpenAI OAuth access token is missing the ChatGPT account id."
                )

            # rust-genai's openai_resp adapter joins "responses" onto the
            # base_url, so set base to `.../codex/` and let it produce
            # `.../codex/responses`.
            if not self.base_url:
                self.base_url = f"{OPENAI_CODEX_DEFAULT_BASE_URL}/codex/"
            elif not self.base_url.rstrip("/").endswith("/codex"):
                self.base_url = self.base_url.rstrip("/") + "/codex/"
            self._default_headers = {
                "ChatGPT-Account-ID": account_id,
                "originator": "codex_cli_rs",
                "User-Agent": "codex_cli_rs/0.0.0 (clearwing)",
            }

        if provider_name == "anthropic_oauth":
            from clearwing.providers.openai_oauth import (
                anthropic_oauth_headers,
                ensure_fresh_anthropic_oauth_credentials,
            )

            try:
                creds = ensure_fresh_anthropic_oauth_credentials()
                self.api_key = creds.token
            except Exception:
                if not self.api_key:
                    raise

            if not self.api_key:
                raise RuntimeError(
                    "Missing Anthropic OAuth token. "
                    "Run: `clearwing setup --provider anthropic-oauth`"
                )

            self._default_headers = anthropic_oauth_headers(self.api_key)
            self._anthropic_oauth_url = "https://api.anthropic.com/v1/messages"

        self.default_system = default_system
        # `reasoning_effort` controls how much reasoning the provider
        # runs (for models that support it). "medium" is a sensible
        # default — higher for deeper-reasoning tasks, "none"/None to
        # opt out entirely. Accepted values: "none" | "minimal" | "low"
        # | "medium" | "high" | "xhigh" | "max" | "budget:<n>".
        self.reasoning_effort = reasoning_effort
        self.rate_limit_max_retries = max(0, rate_limit_max_retries)
        self.rate_limit_initial_backoff_seconds = max(0.1, rate_limit_initial_backoff_seconds)
        self.rate_limit_max_backoff_seconds = max(
            self.rate_limit_initial_backoff_seconds,
            rate_limit_max_backoff_seconds,
        )
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def achat(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None = None,
        tools: list[NativeToolSpec] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_schema: type[BaseModel] | None = None,
        response_schema_name: str | None = None,
        response_schema_description: str | None = None,
    ) -> ChatResponse:
        request_tools = None
        if tools:
            request_tools = [
                Tool(
                    tool.name,
                    tool.description,
                    json.dumps(tool.schema),
                )
                for tool in tools
            ]

        request = ChatRequest(
            messages=list(messages),
            system=system or self.default_system,
            tools=request_tools,
        )
        options = ChatOptions(
            temperature=temperature,
            max_tokens=max_tokens,
            capture_content=True,
            capture_usage=True,
            capture_tool_calls=True,
            # Ask genai-pyo3 to surface the provider's reasoning output
            # (OpenAI Responses `reasoning.summary`, Anthropic thinking
            # blocks, etc.). `normalize_reasoning_content` unifies the
            # varied provider shapes into ChatResponse.reasoning_content,
            # so hunter transcripts see a single string regardless of
            # backend.
            capture_reasoning_content=True,
            normalize_reasoning_content=True,
            reasoning_effort=self.reasoning_effort,
            response_json_spec=(
                _json_spec_from_model(
                    response_schema,
                    name=response_schema_name,
                    description=response_schema_description,
                )
                if response_schema is not None
                else None
            ),
        )

        async with self._semaphore:
            client = self._build_client(Client)
            response = await self._with_rate_limit_retries(
                lambda: self._achat_with_provider_policy(client, request, options)
            )
        return response

    async def achat_stream(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None = None,
        tools: list[NativeToolSpec] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        on_text_delta: Callable[[str], None] | None = None,
    ) -> ChatResponse:
        """Like ``achat`` but streams text deltas via *on_text_delta*.

        Uses genai-pyo3's native ``astream_chat``. Falls back to
        non-streaming ``achat`` when no callback is given.
        """
        if on_text_delta is None:
            return await self.achat(
                messages=messages,
                system=system,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        request_tools = None
        if tools:
            request_tools = [
                Tool(tool.name, tool.description, json.dumps(tool.schema)) for tool in tools
            ]
        request = ChatRequest(
            messages=list(messages),
            system=system or self.default_system,
            tools=request_tools,
        )
        options = ChatOptions(
            temperature=temperature,
            max_tokens=max_tokens,
            capture_content=True,
            capture_usage=True,
            capture_tool_calls=True,
            capture_reasoning_content=True,
            normalize_reasoning_content=True,
            reasoning_effort=self.reasoning_effort,
        )

        async with self._semaphore:
            if self.provider_name == "openai_codex":
                return await self._codex_responses_via_aiohttp(
                    request, options, on_text_delta=on_text_delta
                )

            client = self._build_client(Client)
            try:
                stream = await client.astream_chat(self.model_name, request, options)
                async for event in stream:
                    if event.content:
                        on_text_delta(event.content)
                    if event.end is not None:
                        return event.end
            except Exception as exc:
                if not self._should_try_openai_http_fallback(exc):
                    raise
                logger.debug(
                    "Native OpenAI async stream failed for model=%s base_url=%s; "
                    "falling back to aiohttp chat/completions: %s",
                    self.model_name,
                    self.base_url,
                    exc,
                )
                return await self._openai_chat_http_fallback(
                    request, options, on_text_delta=on_text_delta
                )
        # Fallback if stream ends without an end event
        return await self.achat(
            messages=messages,
            system=system,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def chat(self, **kwargs: Any) -> ChatResponse:
        return _run_coro_sync(self.achat(**kwargs))

    async def aask_text(
        self,
        *,
        system: str,
        user: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_schema: type[BaseModel] | None = None,
        response_schema_name: str | None = None,
        response_schema_description: str | None = None,
    ) -> ChatResponse:
        return await self.achat(
            messages=[ChatMessage("user", user)],
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
            response_schema=response_schema,
            response_schema_name=response_schema_name,
            response_schema_description=response_schema_description,
        )

    async def aask_json(
        self,
        *,
        system: str,
        user: str,
        expect: str = "object",
        temperature: float | None = None,
        max_tokens: int | None = None,
        schema_model: type[BaseModel] | None = None,
        schema_name: str | None = None,
        schema_description: str | None = None,
    ) -> tuple[Any, ChatResponse]:
        response = await self.aask_text(
            system=system,
            user=user,
            temperature=temperature,
            max_tokens=max_tokens,
            response_schema=schema_model,
            response_schema_name=schema_name,
            response_schema_description=schema_description,
        )
        text = response_text(response)
        if schema_model is not None:
            parsed_model = _validate_schema_response(schema_model, text)
            if _is_root_model_type(schema_model):
                return parsed_model.root, response
            return parsed_model.model_dump(), response
        if expect == "array":
            return extract_json_array(text), response
        return extract_json_object(text), response

    def _build_client(self, client_cls):
        # anthropic_oauth bypasses the normal auth resolver entirely —
        # with_request_override sends only our explicit headers (Bearer
        # token + beta flags), avoiding the ANTHROPIC_API_KEY env lookup.
        if self.provider_name == "anthropic_oauth":
            return client_cls.with_request_override(
                "anthropic",
                self._anthropic_oauth_url,
                self._default_headers or {},
            )

        # openai_codex is not a rust-genai adapter — it's the openai_resp
        # adapter plus the extra headers __init__ stashed on
        # `self._default_headers`. Map the name here so genai-pyo3's
        # adapter-kind validator accepts it.
        rust_provider = (
            "openai_resp" if self.provider_name == "openai_codex" else self.provider_name
        )
        default_headers = self._default_headers
        base_url = self.base_url
        if base_url:
            base_url = base_url if base_url.endswith("/") else f"{base_url}/"
            if self.api_key:
                return client_cls.with_api_key_and_base_url(
                    rust_provider,
                    self.api_key,
                    base_url,
                    default_headers=default_headers,
                )
            return client_cls.with_base_url(
                rust_provider, base_url, default_headers=default_headers
            )
        if self.api_key:
            return client_cls.with_api_key(
                rust_provider, self.api_key, default_headers=default_headers
            )
        raise RuntimeError(
            f"Cannot build LLM client for model={self.model_name} "
            f"provider={self.provider_name}: no API key or base URL configured. "
            f"Run `clearwing setup` or set ANTHROPIC_API_KEY / CLEARWING_BASE_URL."
        )

    async def _achat_with_provider_policy(
        self,
        client: Client,
        request: ChatRequest,
        options: ChatOptions,
    ) -> ChatResponse:
        # openai_codex (ChatGPT OAuth) requires aiohttp: genai-pyo3's
        # reqwest/HTTP2 transport gets 404'd by Cloudflare's edge proxy.
        if self.provider_name == "openai_codex":
            return await self._codex_responses_via_aiohttp(request, options)

        # Always go through `achat_via_stream`: it streams internally and
        # returns a fully-collected ChatResponse, so callers never see
        # chunk events. Necessary for backends that require `stream=true`
        # on the wire (our local openai_resp gateway, OpenAI's Responses
        # API with certain models), harmless for everyone else — every
        # adapter genai-pyo3 supports speaks SSE. Some OpenAI-compatible
        # gateways are only compatible at the JSON shape level and fail on
        # reqwest/HTTP2/SSE details, so OpenAI chat-completions gets an
        # aiohttp fallback below.
        try:
            return await client.achat_via_stream(self.model_name, request, options)
        except Exception as exc:
            if not self._should_try_openai_http_fallback(exc):
                raise
            logger.debug(
                "Native OpenAI streaming transport failed for model=%s base_url=%s; "
                "falling back to aiohttp chat/completions: %s",
                self.model_name,
                self.base_url,
                exc,
            )
            return await self._openai_chat_http_fallback(request, options)

    async def _codex_responses_via_aiohttp(
        self,
        request: ChatRequest,
        options: ChatOptions,
        *,
        on_text_delta: Callable[[str], None] | None = None,
    ) -> ChatResponse:
        """OpenAI Codex Responses API transport using aiohttp.

        genai-pyo3's reqwest/HTTP2 transport is 404'd by Cloudflare's
        edge proxy in front of chatgpt.com. This method speaks the
        Responses API wire format over HTTP/1.1 via aiohttp.
        """
        input_msgs: list[dict[str, Any]] = []
        for msg in request.messages():
            if msg.role == "tool":
                input_msgs.append({
                    "type": "function_call_output",
                    "call_id": msg.tool_response_call_id or "",
                    "output": msg.content or "",
                })
            elif msg.role == "assistant" and msg.tool_calls:
                input_msgs.append({"role": "assistant", "content": msg.content or ""})
                for call in msg.tool_calls:
                    input_msgs.append({
                        "type": "function_call",
                        "call_id": call.call_id,
                        "name": call.fn_name,
                        "arguments": json.dumps(call.fn_arguments) if isinstance(call.fn_arguments, dict) else (call.fn_arguments or "{}"),
                    })
            else:
                input_msgs.append({"role": msg.role, "content": msg.content or ""})

        body: dict[str, Any] = {
            "model": self.model_name,
            "instructions": request.system or self.default_system or "",
            "input": input_msgs,
            "stream": True,
            "store": False,
        }
        if options.temperature is not None:
            body["temperature"] = options.temperature
        if options.max_tokens is not None:
            body["max_output_tokens"] = options.max_tokens
        if options.reasoning_effort:
            body["reasoning"] = {"effort": options.reasoning_effort, "summary": "detailed"}
        if request.tools:
            body["tools"] = [self._responses_api_tool_body(tool) for tool in request.tools]
        if options.response_json_spec is not None:
            body["text"] = {"format": self._responses_api_text_format(options.response_json_spec)}

        base = self.base_url or "https://chatgpt.com/backend-api"
        if not base.rstrip("/").endswith("/codex"):
            base = base.rstrip("/") + "/codex"
        url = urljoin(
            base if base.endswith("/") else f"{base}/",
            "responses",
        )
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self._default_headers:
            headers.update(self._default_headers)

        timeout = aiohttp.ClientTimeout(total=600, sock_connect=30, sock_read=300)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=body, headers=headers) as resp:
                if resp.status >= 400:
                    detail = (await resp.text())[:1000]
                    raise RuntimeError(
                        f"Codex Responses API failed with HTTP {resp.status}: {detail}"
                    )
                return await self._collect_codex_sse_response(resp, on_text_delta)

    async def _collect_codex_sse_response(
        self,
        resp: aiohttp.ClientResponse,
        on_text_delta: Callable[[str], None] | None,
    ) -> ChatResponse:
        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        tool_call_parts: dict[int, dict[str, Any]] = {}
        usage: dict[str, Any] | None = None
        provider_model = self.model_name

        async for raw_line in resp.content:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")

            if etype == "response.output_text.delta":
                delta = event.get("delta", "")
                if delta:
                    content_parts.append(delta)
                    if on_text_delta:
                        on_text_delta(delta)

            elif etype == "response.reasoning.delta":
                delta = event.get("delta", "")
                if delta:
                    reasoning_parts.append(delta)

            elif etype == "response.function_call_arguments.delta":
                idx = event.get("output_index", 0)
                acc = tool_call_parts.setdefault(idx, {"arguments": ""})
                acc["arguments"] += event.get("delta", "")
                if event.get("call_id"):
                    acc["id"] = event["call_id"]
                if event.get("name"):
                    acc["name"] = event["name"]

            elif etype == "response.output_item.done":
                item = event.get("item", {})
                if item.get("type") == "function_call":
                    idx = event.get("output_index", 0)
                    acc = tool_call_parts.setdefault(idx, {"arguments": ""})
                    acc.setdefault("id", item.get("call_id", ""))
                    acc.setdefault("name", item.get("name", ""))
                    if item.get("arguments"):
                        acc["arguments"] = item["arguments"]

            elif etype == "response.completed":
                r = event.get("response", {})
                provider_model = r.get("model") or provider_model
                usage = r.get("usage")

        text = "".join(content_parts)
        reasoning = "".join(reasoning_parts) or None
        tool_calls = self._finalize_openai_tool_calls(tool_call_parts)

        return self._chat_response_from_parts(
            text=text,
            reasoning_content=reasoning,
            tool_calls=tool_calls,
            usage=usage,
            provider_model=provider_model,
        )

    def _should_try_openai_http_fallback(self, exc: Exception) -> bool:
        if self.provider_name != "openai" or not self.base_url:
            return False

        text = str(exc).lower()
        return (
            "web stream error" in text
            or "web call failed" in text
            or "error sending request" in text
            or "http2" in text
            or "http/2" in text
            or "stream" in text
            or "reqwest error" in text
        )

    async def _openai_chat_http_fallback(
        self,
        request: ChatRequest,
        options: ChatOptions,
        *,
        on_text_delta: Callable[[str], None] | None = None,
    ) -> ChatResponse:
        """Fallback OpenAI chat-completions transport using aiohttp.

        This keeps Clearwing usable with OpenAI-compatible gateways that are
        correct enough for ordinary HTTP/1.1 clients but brittle with
        reqwest/HTTP2/SSE streaming. The fallback still returns genai-pyo3's
        ChatResponse so callers do not need provider-specific branches.
        """
        body = self._openai_chat_request_body(request, options, stream=on_text_delta is not None)
        headers = {
            "accept": "text/event-stream" if body.get("stream") else "application/json",
            "content-type": "application/json",
            "user-agent": "clearwing (aiohttp openai fallback)",
        }
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        if self._default_headers:
            headers.update(self._default_headers)

        url = urljoin(
            self.base_url if self.base_url.endswith("/") else f"{self.base_url}/",
            "chat/completions",
        )
        timeout = aiohttp.ClientTimeout(total=600, sock_connect=30, sock_read=300)
        if body.get("stream"):
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=body, headers=headers) as resp:
                    if resp.status >= 400:
                        detail = (await resp.text())[:1000]
                        raise RuntimeError(
                            f"OpenAI-compatible fallback failed with HTTP {resp.status}: {detail}"
                        )
                    try:
                        return await self._collect_openai_sse_response(resp, on_text_delta)
                    except Exception:
                        logger.debug(
                            "OpenAI-compatible SSE fallback failed; retrying without streaming",
                            exc_info=True,
                        )

        body = self._openai_chat_request_body(request, options, stream=False)
        headers["accept"] = "application/json"
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=body, headers=headers) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    raise RuntimeError(
                        f"OpenAI-compatible fallback failed with HTTP {resp.status}: {text[:1000]}"
                    )
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        f"OpenAI-compatible fallback returned non-JSON response: {text[:1000]}"
                    ) from exc
        response = self._chat_response_from_openai_payload(payload)
        if on_text_delta:
            visible = response.first_text or ""
            if visible:
                on_text_delta(visible)
        return response

    def _openai_chat_request_body(
        self,
        request: ChatRequest,
        options: ChatOptions,
        *,
        stream: bool,
    ) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        for message in request.messages():
            messages.append(self._openai_message_body(message))

        body: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": stream,
        }
        if stream and options.capture_usage:
            body["stream_options"] = {"include_usage": True}
        if options.temperature is not None:
            body["temperature"] = options.temperature
        if options.top_p is not None:
            body["top_p"] = options.top_p
        if options.max_tokens is not None:
            body["max_tokens"] = options.max_tokens
        if options.stop_sequences:
            body["stop"] = list(options.stop_sequences)
        if options.seed is not None:
            body["seed"] = options.seed
        if options.reasoning_effort:
            body["reasoning_effort"] = options.reasoning_effort
        if request.tools:
            body["tools"] = [self._openai_tool_body(tool) for tool in request.tools]
        if options.response_json_spec is not None:
            body["response_format"] = self._openai_response_format(options.response_json_spec)
        elif options.response_json_mode:
            body["response_format"] = {"type": options.response_json_mode}
        return body

    def _openai_message_body(self, message: ChatMessage) -> dict[str, Any]:
        body: dict[str, Any] = {"role": message.role, "content": message.content}
        if message.tool_response_call_id:
            body["tool_call_id"] = message.tool_response_call_id
        if message.tool_calls:
            body["tool_calls"] = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {
                        "name": call.fn_name,
                        "arguments": json.dumps(call.fn_arguments),
                    },
                }
                for call in message.tool_calls
            ]
        return body

    def _openai_tool_body(self, tool: Tool) -> dict[str, Any]:
        try:
            parameters = json.loads(tool.schema_json or "{}")
        except json.JSONDecodeError:
            parameters = {"type": "object", "properties": {}}
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": parameters,
            },
        }

    def _openai_response_format(self, spec: JsonSpec) -> dict[str, Any]:
        try:
            schema = json.loads(spec.schema_json)
        except json.JSONDecodeError:
            schema = {"type": "object"}
        json_schema: dict[str, Any] = {"name": spec.name, "schema": schema}
        if spec.description:
            json_schema["description"] = spec.description
        return {"type": "json_schema", "json_schema": json_schema}

    def _responses_api_text_format(self, spec: JsonSpec) -> dict[str, Any]:
        """Build the Responses API `text.format` object.

        The Responses API puts `name` at the top level of the format
        object, unlike Chat Completions which nests it inside
        `json_schema`.
        """
        try:
            schema = json.loads(spec.schema_json)
        except json.JSONDecodeError:
            schema = {"type": "object"}
        fmt: dict[str, Any] = {
            "type": "json_schema",
            "name": spec.name,
            "schema": schema,
        }
        if spec.description:
            fmt["description"] = spec.description
        return fmt

    def _responses_api_tool_body(self, tool: Tool) -> dict[str, Any]:
        """Build tool definition for the Responses API.

        The Responses API puts name/description/parameters at the top level,
        unlike Chat Completions which nests them inside a ``function`` key.
        """
        try:
            parameters = json.loads(tool.schema_json or "{}")
        except json.JSONDecodeError:
            parameters = {"type": "object", "properties": {}}
        return {
            "type": "function",
            "name": tool.name,
            "description": tool.description or "",
            "parameters": parameters,
        }

    async def _collect_openai_sse_response(
        self,
        resp: aiohttp.ClientResponse,
        on_text_delta: Callable[[str], None] | None,
    ) -> ChatResponse:
        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        tool_call_parts: dict[int, dict[str, Any]] = {}
        usage: dict[str, Any] | None = None
        provider_model = self.model_name

        async for raw_line in resp.content:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                logger.debug("Skipping malformed OpenAI SSE chunk: %r", data)
                continue

            provider_model = chunk.get("model") or provider_model
            if chunk.get("usage"):
                usage = chunk["usage"]
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                text = delta.get("content")
                if text:
                    content_parts.append(text)
                    if on_text_delta:
                        on_text_delta(text)
                reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                if reasoning:
                    reasoning_parts.append(reasoning)
                self._merge_openai_tool_call_deltas(tool_call_parts, delta.get("tool_calls"))

        return self._chat_response_from_parts(
            text="".join(content_parts),
            reasoning_content="".join(reasoning_parts) or None,
            tool_calls=self._finalize_openai_tool_calls(tool_call_parts),
            usage=usage,
            provider_model=provider_model,
        )

    def _chat_response_from_openai_payload(self, payload: dict[str, Any]) -> ChatResponse:
        choice = (payload.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        text = self._extract_openai_message_text(message.get("content"))
        reasoning_content = message.get("reasoning_content") or message.get("reasoning")
        tool_calls = self._openai_tool_calls_from_message(message.get("tool_calls") or [])
        return self._chat_response_from_parts(
            text=text,
            reasoning_content=reasoning_content,
            tool_calls=tool_calls,
            usage=payload.get("usage"),
            provider_model=payload.get("model") or self.model_name,
        )

    def _extract_openai_message_text(self, content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str):
                        parts.append(text)
            return "".join(parts)
        return str(content)

    def _openai_tool_calls_from_message(self, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        parsed: list[dict[str, Any]] = []
        for call in tool_calls:
            fn = call.get("function") or {}
            parsed.append(
                {
                    "call_id": call.get("id") or "",
                    "fn_name": fn.get("name") or call.get("name") or "",
                    "fn_arguments": self._parse_openai_tool_arguments(
                        fn.get("arguments") if "arguments" in fn else call.get("arguments")
                    ),
                }
            )
        return parsed

    def _merge_openai_tool_call_deltas(
        self,
        tool_call_parts: dict[int, dict[str, Any]],
        deltas: list[dict[str, Any]] | None,
    ) -> None:
        for delta in deltas or []:
            index = int(delta.get("index") or 0)
            acc = tool_call_parts.setdefault(index, {"arguments": ""})
            if delta.get("id"):
                acc["id"] = delta["id"]
            fn = delta.get("function") or {}
            if fn.get("name"):
                acc["name"] = fn["name"]
            if fn.get("arguments"):
                acc["arguments"] += fn["arguments"]

    def _finalize_openai_tool_calls(
        self,
        tool_call_parts: dict[int, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            {
                "call_id": part.get("id") or "",
                "fn_name": part.get("name") or "",
                "fn_arguments": self._parse_openai_tool_arguments(part.get("arguments")),
            }
            for _, part in sorted(tool_call_parts.items())
        ]

    def _parse_openai_tool_arguments(self, value: Any) -> Any:
        if value is None:
            return {}
        if isinstance(value, str):
            if not value:
                return {}
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value

    def _chat_response_from_parts(
        self,
        *,
        text: str,
        reasoning_content: str | None,
        tool_calls: list[dict[str, Any]],
        usage: dict[str, Any] | None,
        provider_model: str,
    ) -> ChatResponse:
        content: list[dict[str, Any]] = []
        if text:
            content.append({"text": text})
        for call in tool_calls:
            if call["call_id"] and call["fn_name"]:
                content.append({"tool_call": call})
        return ChatResponse(
            content=content or None,
            reasoning_content=reasoning_content,
            model_adapter_kind="openai",
            model_name=self.model_name,
            provider_model_adapter_kind="openai",
            provider_model_name=provider_model,
            usage=self._usage_from_openai_payload(usage),
        )

    def _usage_from_openai_payload(self, usage: dict[str, Any] | None) -> Usage:
        usage = usage or {}
        return Usage(
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"),
        )

    async def _with_rate_limit_retries(self, op) -> ChatResponse:
        attempt = 0
        while True:
            try:
                return await op()
            except Exception as exc:
                if not self._is_rate_limit_error(exc) or attempt >= self.rate_limit_max_retries:
                    raise

                delay = self._retry_delay_seconds(exc, attempt)
                attempt += 1
                logger.warning(
                    "LLM call rate-limited for model=%s provider=%s; retrying in %.2fs (attempt %d/%d): %s",
                    self.model_name,
                    self.provider_name,
                    delay,
                    attempt,
                    self.rate_limit_max_retries,
                    exc,
                )
                await asyncio.sleep(delay)

    def _is_rate_limit_error(self, exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            " 429" in text
            or text.startswith("429")
            or "status code 429" in text
            or "too many requests" in text
            or "rate limit" in text
            or "ratelimit" in text
        )

    def _retry_delay_seconds(self, exc: Exception, attempt: int) -> float:
        retry_after = self._parse_retry_after_seconds(str(exc))
        if retry_after is not None:
            base_delay = retry_after
        else:
            base_delay = min(
                self.rate_limit_initial_backoff_seconds * (2**attempt),
                self.rate_limit_max_backoff_seconds,
            )

        jitter = min(1.0, base_delay * 0.2) * random.random()
        return min(base_delay + jitter, self.rate_limit_max_backoff_seconds)

    def _parse_retry_after_seconds(self, text: str) -> float | None:
        patterns = [
            r"retry[- ]after[:=]?\s*([0-9]+(?:\.[0-9]+)?)",
            r"try again in\s*([0-9]+(?:\.[0-9]+)?)s",
            r"wait\s*([0-9]+(?:\.[0-9]+)?)s",
        ]
        lowered = text.lower()
        for pattern in patterns:
            match = re.search(pattern, lowered)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    return None
        return None


def extract_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise ValueError("response did not contain a JSON object")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("response JSON was not an object")
    return parsed


def extract_json_array(text: str) -> list[Any]:
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        raise ValueError("response did not contain a JSON array")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, list):
        raise ValueError("response JSON was not an array")
    return parsed


def _json_spec_from_model(
    schema_model: type[BaseModel],
    *,
    name: str | None = None,
    description: str | None = None,
) -> JsonSpec:
    schema = schema_model.model_json_schema()
    return JsonSpec(
        name=name or _schema_name_for_model(schema_model),
        schema_json=json.dumps(schema),
        description=description,
    )


def _schema_name_for_model(schema_model: type[BaseModel]) -> str:
    raw_name = getattr(schema_model, "__name__", "response_schema")
    normalized = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_name).strip("_")
    return normalized or "response_schema"
