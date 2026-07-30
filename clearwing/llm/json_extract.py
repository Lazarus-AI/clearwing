"""Robust extraction of structured JSON from model responses.

Models occasionally wrap JSON in prose or Markdown fences, include braces in
string values, or emit a regex/Windows path with an invalid JSON backslash.
Greedy regular expressions cannot distinguish those cases.  This module uses a
bounded, string-aware scanner and keeps the public object/array helpers strict
about the type they return.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from typing import Any

logger = logging.getLogger(__name__)

_MAX_INPUT_CHARS = 5_000_000
_FENCED_BLOCK = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_VALID_ESCAPES = frozenset('"\\/bfnrtu')


def _candidate_regions(text: str) -> Iterator[str]:
    """Yield likely JSON regions, preferring fenced content without relying on it."""

    stripped = text.strip()
    whole_fence = _FENCED_BLOCK.fullmatch(stripped)
    seen: set[str] = set()
    if whole_fence is not None:
        candidate = whole_fence.group(1)
        seen.add(candidate)
        yield candidate
    for match in _FENCED_BLOCK.finditer(text):
        candidate = match.group(1)
        if candidate not in seen:
            seen.add(candidate)
            yield candidate
    if text not in seen:
        yield text


def _balanced_json_span(text: str, start: int) -> str | None:
    """Return the balanced object/array beginning at *start*, if complete."""

    opening = text[start]
    if opening not in "{[":
        return None
    stack = [opening]
    in_string = False
    escaped = False
    pairs = {"}": "{", "]": "["}

    for index in range(start + 1, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "{[":
            stack.append(char)
        elif char in "}]":
            if not stack or stack[-1] != pairs[char]:
                return None
            stack.pop()
            if not stack:
                return text[start : index + 1]
    return None


def _repair_string_escapes(value: str) -> str:
    """Double invalid backslashes inside JSON strings, leaving syntax alone."""

    output: list[str] = []
    in_string = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == '"':
            in_string = not in_string
            output.append(char)
            index += 1
            continue
        if in_string and char == "\\":
            following = value[index + 1] if index + 1 < len(value) else ""
            if following in _VALID_ESCAPES:
                output.extend((char, following))
                index += 2
                continue
            output.append("\\\\")
            index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _decode(span: str) -> Any:
    try:
        return json.loads(span)
    except json.JSONDecodeError as original:
        repaired = _repair_string_escapes(span)
        if repaired == span:
            raise
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            raise original from None


def _extract(text: str, expected_type: type[dict] | type[list]) -> dict[str, Any] | list[Any]:
    if not isinstance(text, str):
        raise TypeError("model response must be text")
    if len(text) > _MAX_INPUT_CHARS:
        logger.warning(
            "Model response is %d characters; JSON scan is capped at %d",
            len(text),
            _MAX_INPUT_CHARS,
        )
        text = text[:_MAX_INPUT_CHARS]

    last_error: json.JSONDecodeError | None = None
    for candidate in _candidate_regions(text):
        index = 0
        while index < len(candidate):
            if candidate[index] not in "{[":
                index += 1
                continue
            span = _balanced_json_span(candidate, index)
            if span is None:
                index += 1
                continue
            try:
                decoded = _decode(span)
            except json.JSONDecodeError as exc:
                last_error = exc
                index += max(1, len(span))
                continue
            if isinstance(decoded, expected_type):
                return decoded
            index += max(1, len(span))

    kind = "object" if expected_type is dict else "array"
    if last_error is not None:
        raise ValueError(f"response did not contain a valid JSON {kind}") from last_error
    raise ValueError(f"response did not contain a JSON {kind}")


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first valid JSON object from a bounded model response."""

    value = _extract(text, dict)
    return value  # type: ignore[return-value]


def extract_json_array(text: str) -> list[Any]:
    """Extract the first valid JSON array from a bounded model response."""

    value = _extract(text, list)
    return value  # type: ignore[return-value]
