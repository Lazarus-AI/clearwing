"""Protocol types for the agent runtime.

These structural (duck-typed) protocols replace the ``Any`` annotations that
previously appeared in :class:`NativeAgentGraph`, giving mypy something
concrete to check at the call-site without coupling the runtime to a
single concrete LLM implementation.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from genai_pyo3 import ChatMessage, ChatResponse

from clearwing.llm.native import NativeToolSpec


@runtime_checkable
class LLMInvokable(Protocol):
    """The native LLM surface the runtime drives.

    The runtime holds an :class:`~clearwing.llm.native.AsyncLLMClient` and
    threads a pre-built tool list through each call. This protocol captures the
    two methods it uses — ``achat`` and its streaming sibling ``achat_stream`` —
    without coupling the runtime to the concrete client class.
    """

    async def achat(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None = ...,
        tools: list[NativeToolSpec] | None = ...,
    ) -> ChatResponse: ...

    async def achat_stream(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None = ...,
        tools: list[NativeToolSpec] | None = ...,
        on_text_delta: Any | None = ...,
    ) -> ChatResponse: ...


class SystemPromptFactory(Protocol):
    """Callable that builds a system prompt from the current agent state."""

    def __call__(self, state: dict[str, Any]) -> str: ...


class StateUpdater(Protocol):
    """Callable that returns extra state keys after a tool runs."""

    def __call__(
        self, tool_name: str, data: Any, state: dict[str, Any]
    ) -> dict[str, Any]: ...


class KnowledgeGraphPopulator(Protocol):
    """Callable that feeds tool results into the knowledge graph."""

    def __call__(
        self, kg: Any, tool_name: str, content: str, state: dict[str, Any]
    ) -> dict[str, Any]: ...
