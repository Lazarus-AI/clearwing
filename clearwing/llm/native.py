from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from genai_pyo3 import (
    ChatMessage,
    ChatOptions,
    ChatRequest,
    ChatResponse,
    Client,
    JsonSpec,
    Tool,
)
from pydantic import BaseModel, RootModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# reasoning_effort auto-detection
# ---------------------------------------------------------------------------
#
# `reasoning_effort` is an OpenAI-reasoning-only parameter. Most non-OpenAI
# OpenAI-compat endpoints reject it with HTTP 400 when the configured model is
# not reasoning-capable. We default to omitting it for models we know reject
# it, while preserving the current "medium" default for everything else.
#
# Match semantics: case-insensitive substring against the model name. First
# match wins. Order is not significant.

_REASONING_EFFORT_UNSUPPORTED_PATTERNS: tuple[str, ...] = (
    "llama-3",
    "llama-4",
    "mistral",
    "mixtral",
    "qwen2",
    "gemma",
)

# Explicit re-enable list for model names that contain an unsupported pattern
# above but actually *do* support reasoning_effort (e.g. reasoning-tuned
# variants of denylisted model families). Intentionally empty today; populate
# as such models ship.
_REASONING_EFFORT_OVERRIDE_ALLOW: frozenset[str] = frozenset()


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

    @staticmethod
    def _auto_resolve_reasoning_effort(model_name: str) -> str | None:
        """Return the effective reasoning_effort for *model_name*.

        Returns ``None`` (i.e. omit the parameter) when the model name matches
        a pattern in :data:`_REASONING_EFFORT_UNSUPPORTED_PATTERNS` and is not
        in :data:`_REASONING_EFFORT_OVERRIDE_ALLOW`. Returns ``"medium"``
        otherwise (the previous default for all callers).
        """
        lower = model_name.lower()
        if lower in _REASONING_EFFORT_OVERRIDE_ALLOW:
            return "medium"
        for pattern in _REASONING_EFFORT_UNSUPPORTED_PATTERNS:
            if pattern in lower:
                logger.info(
                    "reasoning_effort=None: model %r matches non-reasoning pattern %r",
                    model_name,
                    pattern,
                )
                return None
        return "medium"

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
            # `.../codex/responses`. Matches the path the hand-rolled
            # aiohttp version used to hit.
            self.base_url = self.base_url or f"{OPENAI_CODEX_DEFAULT_BASE_URL}/codex/"
            self._default_headers = {
                "chatgpt-account-id": account_id,
                "OpenAI-Beta": "responses=experimental",
                "originator": "pi",
                "user-agent": "clearwing (python)",
            }

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

