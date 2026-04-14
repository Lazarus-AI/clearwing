"""Streaming LLM output parser with flag detection."""

from __future__ import annotations

import re

from clearwing.core.events import EventBus, EventType

# Flag detection patterns
FLAG_PATTERNS = [
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"FLAG\{[^}]+\}"),
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"CTF\{[^}]+\}"),
    re.compile(r"[A-Fa-f0-9]{32}"),  # MD5-like hash
]


class StreamingParser:
    """Parse streaming LLM output for tool calls and flags."""

    def __init__(self):
        self._buffer = ""
        self._bus = EventBus()

    def feed(self, chunk: str) -> None:
        """Process a chunk of streaming output."""
        self._buffer += chunk
        self._check_flags(chunk)

    def _check_flags(self, text: str) -> None:
        for pattern in FLAG_PATTERNS:
            for match in pattern.finditer(text):
                self._bus.emit_flag(match.group(), "Detected in output")

    def reset(self) -> None:
        self._buffer = ""
