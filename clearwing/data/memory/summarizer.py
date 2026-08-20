"""Context window summarizer for long-running penetration testing sessions."""

from __future__ import annotations

import logging
import re
from typing import Any

from clearwing.llm import ChatMessage

logger = logging.getLogger(__name__)

_FLAG_PATTERNS = re.compile(
    r"(flag\{[^}]*\}|FLAG\{[^}]*\}|HTB\{[^}]*\}|CTF\{[^}]*\})", re.IGNORECASE
)

_SUMMARIZE_PROMPT = (
    "Summarize these penetration testing findings concisely, preserving: "
    "discovered ports, services, vulnerabilities, exploit results, and any flags found."
)


class ContextSummarizer:
    """Compresses message history, keeping tool calls and flags verbatim."""

    @staticmethod
    def _estimate_tokens(messages: list) -> int:
        total_chars = 0
        for msg in messages:
            content = getattr(msg, "content", None) or str(msg)
            total_chars += len(content)
            for tc in getattr(msg, "tool_calls", None) or []:
                total_chars += len(getattr(tc, "fn_arguments_json", None) or "")
        return total_chars // 4

    def should_summarize(self, messages: list, max_tokens: int = 150_000) -> bool:
        return self._estimate_tokens(messages) > int(max_tokens * 0.8)

    async def summarize(self, messages: list, llm: Any) -> list:
        """Compress oldest 70%, keeping tool calls/results and flags verbatim.

        Returns [summary, ...preserved, ...recent_messages].
        """
        if not messages:
            return messages

        total = len(messages)
        split_idx = int(total * 0.7)
        old_messages = messages[:split_idx]
        recent_messages = messages[split_idx:]

        preserved: list = []
        to_summarize: list = []

        for msg in old_messages:
            content = getattr(msg, "content", None) or ""
            if (
                _FLAG_PATTERNS.search(content)
                or getattr(msg, "tool_calls", None)
                or getattr(msg, "tool_response_call_id", None)
            ):
                preserved.append(msg)
            else:
                to_summarize.append(msg)

        text_block = "\n\n".join(
            f"[{getattr(m, 'role', 'msg')}]: {getattr(m, 'content', '')}"
            for m in to_summarize
            if getattr(m, "content", None)
        )

        from clearwing.llm.native import response_text

        summary_response = await llm.aask_text(
            system=_SUMMARIZE_PROMPT,
            user=text_block,
        )
        summary_text = response_text(summary_response)

        summary = ChatMessage("system", f"[Session Summary]\n{summary_text}")
        result: list = [summary, *preserved, *recent_messages]

        logger.info(
            "context summarizer: %d msgs → %d (preserved=%d, recent=%d)",
            total, len(result), len(preserved), len(recent_messages),
        )
        return result
