"""Context window summarizer for long-running penetration testing sessions."""

from __future__ import annotations

import re
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

# Patterns that indicate a captured flag — these messages must never be dropped.
_FLAG_PATTERNS = re.compile(r"(flag\{[^}]*\}|FLAG\{[^}]*\}|HTB\{[^}]*\}|CTF\{[^}]*\})", re.IGNORECASE)

_SUMMARIZE_PROMPT = (
    "Summarize these penetration testing findings concisely, preserving: "
    "discovered ports, services, vulnerabilities, exploit results, and any flags found."
)


class ContextSummarizer:
    """Decides when and how to compress the message history."""

    # ------------------------------------------------------------------
    # Token estimation
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_tokens(messages: list) -> int:
        """Rough token count — ~4 characters per token."""
        total_chars = 0
        for msg in messages:
            content = msg.content if hasattr(msg, "content") else str(msg)
            total_chars += len(content)
        return total_chars // 4

    def should_summarize(self, messages: list, max_tokens: int = 150_000) -> bool:
        """Return True when the estimated token count exceeds 80% of *max_tokens*."""
        return self._estimate_tokens(messages) > int(max_tokens * 0.8)

    # ------------------------------------------------------------------
    # Summarisation
    # ------------------------------------------------------------------

    async def summarize(self, messages: list, llm: Any) -> list:
        """Compress the oldest 70% of messages via *llm*, keeping the newest 30%.

        Messages that contain flag patterns are always preserved verbatim.
        """
        if not messages:
            return messages

        total = len(messages)
        split_idx = int(total * 0.7)

        old_messages = messages[:split_idx]
        recent_messages = messages[split_idx:]

        # Pull out flag-bearing messages from the old batch so they survive.
        flag_messages: list = []
        to_summarize: list = []

        for msg in old_messages:
            content = msg.content if hasattr(msg, "content") else str(msg)
            if _FLAG_PATTERNS.search(content):
                flag_messages.append(msg)
            else:
                to_summarize.append(msg)

        # Build the text block to hand to the LLM.
        text_block = "\n\n".join(
            f"[{type(m).__name__}]: {m.content}" for m in to_summarize if hasattr(m, "content")
        )

        summary_input = [
            HumanMessage(content=f"{_SUMMARIZE_PROMPT}\n\n---\n\n{text_block}"),
        ]

        summary_response = await llm.ainvoke(summary_input)
        summary_text = (
            summary_response.content
            if hasattr(summary_response, "content")
            else str(summary_response)
        )

        # Reconstruct the message list.
        result: list = [
            SystemMessage(content=f"[Session Summary]\n{summary_text}"),
        ]
        result.extend(flag_messages)
        result.extend(recent_messages)

        return result
