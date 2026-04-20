from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

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
    first = response.first_text()
    if first:
        return first
    return "\n".join(segment for segment in response.texts() if segment)


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

        if self.provider_name == "openai_codex":
            async with self._semaphore:
                return await self._with_rate_limit_retries(
                    lambda: self._achat_openai_codex(
                        messages=list(messages),
                        system=system or self.default_system,
                        tools=tools or None,
                    )
                )

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
            client = self._build_client(Client)
            stream = await client.astream_chat(self.model_name, request, options)
            async for event in stream:
                if event.content:
                    on_text_delta(event.content)
                if event.end is not None:
                    return event.end
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
        base_url = self.base_url
        if base_url:
            base_url = base_url if base_url.endswith("/") else f"{base_url}/"
            if self.api_key:
                return client_cls.with_api_key_and_base_url(
                    self.provider_name,
                    self.api_key,
                    base_url,
                )
            return client_cls.with_base_url(self.provider_name, base_url)
        if self.api_key:
            return client_cls.with_api_key(self.provider_name, self.api_key)
        return client_cls()

    async def _achat_with_provider_policy(
        self,
        client: Client,
        request: ChatRequest,
        options: ChatOptions,
    ) -> ChatResponse:
        # Always go through `achat_via_stream`: it streams internally and
        # returns a fully-collected ChatResponse, so callers never see
        # chunk events. Necessary for backends that require `stream=true`
        # on the wire (our local openai_resp gateway, OpenAI's Responses
        # API with certain models), harmless for everyone else — every
        # adapter genai-pyo3 supports speaks SSE.
        return await client.achat_via_stream(self.model_name, request, options)

    async def _achat_openai_codex(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None,
        tools: list[NativeToolSpec] | None,
    ) -> ChatResponse:
        from clearwing.providers.openai_oauth import (
            OPENAI_CODEX_DEFAULT_BASE_URL,
            ensure_fresh_openai_oauth_credentials,
            extract_account_id,
        )

        access_token = self.api_key
        try:
            creds = await asyncio.to_thread(ensure_fresh_openai_oauth_credentials)
            access_token = creds.access
        except Exception:
            if not access_token:
                raise

        if not access_token:
            raise RuntimeError(
                "Missing OpenAI OAuth access token. Run: `clearwing setup --provider openai-oauth`"
            )

        account_id = extract_account_id(access_token)
        if not account_id:
            raise RuntimeError("OpenAI OAuth access token is missing the ChatGPT account id.")

        result = await _openai_codex_responses_chat(
            model=self.model_name,
            base_url=self.base_url or OPENAI_CODEX_DEFAULT_BASE_URL,
            access_token=access_token,
            account_id=account_id,
            messages=messages,
            system=system,
            tools=tools,
        )
        content: list[dict[str, Any]] = []
        if result["content"]:
            content.append({"text": result["content"]})
        for call in result["tool_calls"]:
            args = call.get("arguments") or {}
            args_json = json.dumps(args)
            content.append(
                {
                    "tool_call": {
                        "call_id": call.get("id") or "",
                        "fn_name": call.get("name") or "",
                        "fn_arguments": args,
                        "fn_arguments_json": args_json,
                    }
                }
            )

        usage_data = result.get("usage") or {}
        prompt_tokens = _int_or_none(
            usage_data.get("input_tokens") or usage_data.get("prompt_tokens")
        )
        completion_tokens = _int_or_none(
            usage_data.get("output_tokens") or usage_data.get("completion_tokens")
        )
        total_tokens = _int_or_none(usage_data.get("total_tokens"))
        if total_tokens is None and (prompt_tokens is not None or completion_tokens is not None):
            total_tokens = (prompt_tokens or 0) + (completion_tokens or 0)
        return ChatResponse(
            content=content,
            usage=Usage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            ),
            model_name=self.model_name,
            provider_model_name=self.model_name,
            model_adapter_kind="openai_codex",
            provider_model_adapter_kind="openai_codex",
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


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _resolve_codex_responses_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/codex/responses"):
        return normalized
    if normalized.endswith("/codex"):
        return f"{normalized}/responses"
    return f"{normalized}/codex/responses"


def _native_tools_to_responses(tools: list[NativeToolSpec] | None) -> list[dict[str, Any]]:
    if not tools:
        return []
    return [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.schema or {"type": "object", "properties": {}},
        }
        for tool in tools
    ]


def _messages_to_codex_input(
    messages: list[ChatMessage],
) -> list[dict[str, Any]]:
    input_items: list[dict[str, Any]] = []
    for message in messages:
        role = str(getattr(message, "role", "") or "")
        content = str(getattr(message, "content", "") or "")

        if role == "system":
            continue
        if role == "user":
            input_items.append(
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": content}],
                }
            )
            continue
        if role == "assistant":
            if content:
                input_items.append(
                    {
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": content}],
                    }
                )
            for call in getattr(message, "tool_calls", None) or []:
                call_id = str(getattr(call, "call_id", "") or "")
                name = str(getattr(call, "fn_name", "") or "")
                args_json = str(getattr(call, "fn_arguments_json", "") or "")
                if not args_json:
                    args_json = json.dumps(getattr(call, "fn_arguments", {}) or {})
                input_items.append(
                    {
                        "type": "function_call",
                        "call_id": call_id,
                        "name": name,
                        "arguments": args_json,
                    }
                )
            continue
        if role == "tool":
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": str(getattr(message, "tool_response_call_id", "") or ""),
                    "output": content,
                }
            )
            continue

        input_items.append(
            {
                "role": "user",
                "content": [{"type": "input_text", "text": content}],
            }
        )
    return input_items


async def _iter_sse_json(response: aiohttp.ClientResponse):
    data_lines: list[str] = []

    def emit_buffer() -> dict[str, Any] | None:
        data = "\n".join(data_lines).strip()
        if not data or data == "[DONE]":
            return None
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            return None
        return obj if isinstance(obj, dict) else None

    while not response.content.at_eof():
        raw = await response.content.readline()
        if not raw:
            break
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
            continue
        if line.strip():
            continue
        if not data_lines:
            continue
        obj = emit_buffer()
        data_lines = []
        if obj is not None:
            yield obj
    if data_lines:
        obj = emit_buffer()
        if obj is not None:
            yield obj


async def _openai_codex_responses_chat(
    *,
    model: str,
    base_url: str,
    access_token: str,
    account_id: str,
    messages: list[ChatMessage],
    system: str | None,
    tools: list[NativeToolSpec] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "store": False,
        "stream": True,
        "input": _messages_to_codex_input(messages),
        "text": {"verbosity": "medium"},
        "include": ["reasoning.encrypted_content"],
    }
    if system:
        payload["instructions"] = system
    response_tools = _native_tools_to_responses(tools)
    if response_tools:
        payload["tools"] = response_tools
        payload["tool_choice"] = "auto"
        payload["parallel_tool_calls"] = True

    headers = {
        "Authorization": f"Bearer {access_token}",
        "chatgpt-account-id": account_id,
        "OpenAI-Beta": "responses=experimental",
        "originator": "pi",
        "accept": "text/event-stream",
        "content-type": "application/json",
        "user-agent": "clearwing (python)",
    }

    timeout = aiohttp.ClientTimeout(total=None, connect=30, sock_read=120)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            _resolve_codex_responses_url(base_url),
            headers=headers,
            json=payload,
        ) as resp:
            if resp.status < 200 or resp.status >= 300:
                text = await resp.text()
                raise RuntimeError(f"OpenAI OAuth request failed: HTTP {resp.status}: {text}")

            content_parts: list[str] = []
            tool_calls: list[dict[str, Any]] = []
            current_fc: dict[str, Any] | None = None
            usage: dict[str, Any] = {}

            async for event in _iter_sse_json(resp):
                event_type = event.get("type")

                if event_type == "response.output_text.delta":
                    delta = event.get("delta", "")
                    if isinstance(delta, str) and delta:
                        content_parts.append(delta)
                    continue

                if event_type == "response.output_item.added":
                    item = event.get("item") or {}
                    if isinstance(item, dict) and item.get("type") == "function_call":
                        current_fc = {
                            "call_id": item.get("call_id"),
                            "name": item.get("name"),
                            "args_buf": item.get("arguments") or "",
                        }
                    continue

                if event_type == "response.function_call_arguments.delta":
                    if current_fc is not None:
                        delta = event.get("delta", "")
                        if isinstance(delta, str) and delta:
                            current_fc["args_buf"] = (current_fc.get("args_buf") or "") + delta
                    continue

                if event_type == "response.function_call_arguments.done":
                    if current_fc is not None:
                        args = event.get("arguments", "")
                        if isinstance(args, str) and args:
                            current_fc["args_buf"] = args
                    continue

                if event_type == "response.output_item.done":
                    item = event.get("item") or {}
                    if not isinstance(item, dict) or item.get("type") != "function_call":
                        continue
                    call_id = item.get("call_id") or (current_fc or {}).get("call_id")
                    name = item.get("name") or (current_fc or {}).get("name")
                    args_str = item.get("arguments") or (current_fc or {}).get("args_buf") or ""
                    try:
                        args = (
                            json.loads(args_str) if isinstance(args_str, str) and args_str else {}
                        )
                    except json.JSONDecodeError:
                        logger.debug("Failed to parse tool arguments: %r", str(args_str)[:200])
                        args = {}
                    tool_calls.append(
                        {
                            "id": call_id,
                            "name": name or "",
                            "arguments": args,
                        }
                    )
                    current_fc = None
                    continue

                if event_type in {"response.done", "response.completed"}:
                    response_obj = event.get("response")
                    if isinstance(response_obj, dict) and isinstance(
                        response_obj.get("usage"), dict
                    ):
                        usage = response_obj["usage"]
                    break

                if event_type in {"error", "response.failed"}:
                    message = (
                        event.get("message")
                        or (event.get("error") or {}).get("message")
                        or "OpenAI OAuth request failed"
                    )
                    raise RuntimeError(str(message))

    return {
        "content": "".join(content_parts),
        "tool_calls": tool_calls,
        "usage": usage,
    }
