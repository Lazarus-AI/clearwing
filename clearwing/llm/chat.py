from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from genai_pyo3 import ChatResponse

from clearwing.llm.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    _coerce_chat_messages,
    _message_to_chat_message,
    _normalize_role,
    extract_text_content,
)
from clearwing.llm.native import AsyncLLMClient

# Re-exported for backwards compatibility: these message types and helpers used
# to live in this module. They now live in ``clearwing.llm.messages`` so they
# survive the eventual deletion of ``ChatModel`` (Stage 4), but importers that
# still reach for ``clearwing.llm.chat`` keep working.
__all__ = [
    "AIMessage",
    "BaseMessage",
    "ChatModel",
    "HumanMessage",
    "SystemMessage",
    "ToolMessage",
    "extract_text_content",
]

# Silence "imported but unused" for the compat re-exports that this module does
# not itself reference.
_ = (HumanMessage, ToolMessage, _message_to_chat_message, _normalize_role)


class ChatModel:
    def __init__(
        self,
        *,
        model_name: str,
        api_key: str,
        provider_name: str,
        base_url: str | None = None,
        default_system: str = "You are a helpful assistant.",
        bound_tools: Sequence[Any] | None = None,
        tool_choice: str | None = None,
    ) -> None:
        self.model_name = model_name
        self.api_key = api_key
        self.provider_name = provider_name
        self.base_url = base_url
        self.default_system = default_system
        self.bound_tools = list(bound_tools or [])
        self.tool_choice = tool_choice
        self._client = AsyncLLMClient(
            model_name=model_name,
            api_key=api_key,
            provider_name=provider_name,
            base_url=base_url,
            default_system=default_system,
        )

    @property
    def client(self) -> AsyncLLMClient:
        return self._client

    def bind_tools(
        self,
        tools: Sequence[Any],
        *,
        tool_choice: str | None = None,
        **_: Any,
    ) -> ChatModel:
        from clearwing.agent.tooling import ensure_agent_tool

        native_tools = [ensure_agent_tool(tool) for tool in tools]
        return ChatModel(
            model_name=self.model_name,
            api_key=self.api_key,
            provider_name=self.provider_name,
            base_url=self.base_url,
            default_system=self.default_system,
            bound_tools=native_tools,
            tool_choice=tool_choice or self.tool_choice,
        )

    def invoke(self, messages: Any) -> AIMessage:
        system, chat_messages = _coerce_chat_messages(messages)
        response = self._client.chat(
            messages=chat_messages,
            system=system or self.default_system,
            tools=self.bound_tools or None,
        )
        return AIMessage(
            content=response.first_text or "",
            tool_calls=[
                {
                    "id": tool_call.call_id,
                    "name": tool_call.fn_name,
                    "args": tool_call.fn_arguments,
                    "type": "tool_call",
                }
                for tool_call in response.tool_calls
            ],
            response_metadata={
                "usage": {
                    "input_tokens": response.usage.prompt_tokens or 0,
                    "output_tokens": response.usage.completion_tokens or 0,
                    "total_tokens": response.usage.total_tokens or 0,
                },
                "model": response.provider_model_name or self.model_name,
            },
        )

    async def aask_text(self, **kwargs: Any) -> ChatResponse:
        """Delegate to the underlying native client's ``aask_text``.

        Gives ChatModel the same text-ask surface as AsyncLLMClient, so callers
        holding either type share one API (and returns a ``ChatResponse``, not
        an ``AIMessage`` like ``ainvoke``).
        """
        return await self._client.aask_text(**kwargs)

    async def aask_json(self, **kwargs: Any) -> tuple[Any, ChatResponse]:
        """Delegate to the underlying native client's ``aask_json``."""
        return await self._client.aask_json(**kwargs)

    async def ainvoke(self, messages: Any, on_text_delta: Callable[[str], None] | None = None) -> AIMessage:
        system, chat_messages = _coerce_chat_messages(messages)
        if on_text_delta is not None:
            response = await self._client.achat_stream(
                messages=chat_messages,
                system=system or self.default_system,
                tools=self.bound_tools or None,
                on_text_delta=on_text_delta,
            )
        else:
            response = await self._client.achat(
                messages=chat_messages,
                system=system or self.default_system,
                tools=self.bound_tools or None,
            )
        return AIMessage(
            content=response.first_text or "",
            tool_calls=[
                {
                    "id": tool_call.call_id,
                    "name": tool_call.fn_name,
                    "args": tool_call.fn_arguments,
                    "type": "tool_call",
                }
                for tool_call in response.tool_calls
            ],
            response_metadata={
                "usage": {
                    "input_tokens": response.usage.prompt_tokens or 0,
                    "output_tokens": response.usage.completion_tokens or 0,
                    "total_tokens": response.usage.total_tokens or 0,
                },
                "model": response.provider_model_name or self.model_name,
            },
        )
