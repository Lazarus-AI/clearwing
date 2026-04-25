from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from genai_pyo3 import ChatMessage

from clearwing.llm.native import AsyncLLMClient


def extract_text_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type in {"text", "text-plain"}:
                text = item.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
            elif item_type == "reasoning":
                reasoning = item.get("reasoning")
                if isinstance(reasoning, str) and reasoning:
                    parts.append(reasoning)
        return "\n".join(part for part in parts if part)
    return str(content)


@dataclass(slots=True)
class BaseMessage:
    content: Any
    name: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_id: str | None = None
    role: str = field(init=False, default="user")
    type: str = field(init=False, default="base")

    @property
    def text(self) -> str:
        return extract_text_content(self.content)


@dataclass(slots=True)
class HumanMessage(BaseMessage):
    role: str = field(init=False, default="user")
    type: str = field(init=False, default="human")


@dataclass(slots=True)
class SystemMessage(BaseMessage):
    role: str = field(init=False, default="system")
    type: str = field(init=False, default="system")


@dataclass(slots=True)
class AIMessage:
    content: Any
    name: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_id: str | None = None
    response_metadata: dict[str, Any] = field(default_factory=dict)
    type: str = field(init=False, default="ai")

    @property
    def text(self) -> str:
        return extract_text_content(self.content)


@dataclass(slots=True)
class ToolMessage(BaseMessage):
    role: str = field(init=False, default="tool")
    type: str = field(init=False, default="tool")


def _normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized in {"human", "user"}:
        return "user"
    if normalized in {"system"}:
        return "system"
    if normalized in {"ai", "assistant"}:
        return "assistant"
    if normalized in {"tool"}:
        return "tool"
    return normalized or "user"


def _message_to_chat_message(message: Any) -> tuple[str | None, ChatMessage | None]:
    if isinstance(message, str):
        return None, ChatMessage.from_python(message)

    if isinstance(message, ChatMessage):
        if message.role == "system":
            return message.content, None
        return None, message

    if isinstance(message, dict):
        role = _normalize_role(str(message.get("role", "user")))
        content = extract_text_content(message.get("content", ""))
        if role == "system":
            return content, None
        normalized = dict(message)
        normalized["role"] = role
        normalized["content"] = content
        return None, ChatMessage.from_python(normalized)

    if isinstance(message, AIMessage):
        return None, ChatMessage.from_python(
            {
                "role": "assistant",
                "content": message.text,
                "tool_calls": message.tool_calls,
            }
        )

    role = _normalize_role(getattr(message, "role", getattr(message, "type", "user")))
    content = extract_text_content(getattr(message, "content", message))
    if role == "system":
        return content, None
    payload = {
        "role": role,
        "content": content,
        "tool_response_call_id": getattr(
            message,
            "tool_response_call_id",
            getattr(message, "tool_call_id", None),
        ),
        "tool_calls": getattr(message, "tool_calls", []),
    }
    return None, ChatMessage.from_python(payload)


def _coerce_chat_messages(messages: Any) -> tuple[str | None, list[ChatMessage]]:
    if isinstance(messages, str | AIMessage | ChatMessage | dict):
        messages = [messages]

    system_parts: list[str] = []
    chat_messages: list[ChatMessage] = []
    for message in messages or []:
        system_text, chat_message = _message_to_chat_message(message)
        if system_text:
            system_parts.append(system_text)
        if chat_message is not None:
            chat_messages.append(chat_message)

    system = "\n\n".join(part for part in system_parts if part).strip() or None
    return system, chat_messages


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
            content=response.first_text() or "",
            tool_calls=[
                {
                    "id": tool_call.call_id,
                    "name": tool_call.fn_name,
                    "args": tool_call.fn_arguments,
                    "type": "tool_call",
                }
                for tool_call in response.tool_calls()
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
            content=response.first_text() or "",
            tool_calls=[
                {
                    "id": tool_call.call_id,
                    "name": tool_call.fn_name,
                    "args": tool_call.fn_arguments,
                    "type": "tool_call",
                }
                for tool_call in response.tool_calls()
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
