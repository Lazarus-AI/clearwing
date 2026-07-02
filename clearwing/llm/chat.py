"""Back-compat re-export shim for the message model.

The ``ChatModel`` LangChain-compat facade that used to live here has been
removed; every caller now uses the native
:class:`~clearwing.llm.native.AsyncLLMClient` directly. The message dataclasses
and coercion helpers now live in :mod:`clearwing.llm.messages`; this module
re-exports them so importers that still reach for ``clearwing.llm.chat`` keep
working.
"""

from __future__ import annotations

from clearwing.llm.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    extract_text_content,
)

__all__ = [
    "AIMessage",
    "BaseMessage",
    "HumanMessage",
    "SystemMessage",
    "ToolMessage",
    "extract_text_content",
]
