"""Output-boundary redaction and safe Markdown rendering helpers.

Security findings routinely contain source snippets, banners, model prose, and
operator-controlled labels.  Treat all of them as untrusted at serialization
time: redact likely credentials/PII and neutralize report-structure injection.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PAN_CANDIDATE = re.compile(r"(?<![0-9A-Za-z])(?:\d[\s-]?){12,18}\d(?![0-9A-Za-z])")
_SSN = re.compile(r"(?<!\d)(\d{3})[-.\t \u00a0](\d{2})[-.\t \u00a0](\d{4})(?!\d)")
_PRIVATE_KEY = re.compile(
    r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}"
)

_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS-KEY", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("GITHUB-TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("SLACK-TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b")),
    ("STRIPE-KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("GOOGLE-API-KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)
_AUTHORIZATION = re.compile(
    r"(?i)\b(?P<scheme>Bearer|Basic)\s+(?P<value>[A-Za-z0-9+/=._-]{8,})"
)
_URL_PASSWORD = re.compile(
    r"(?i)\b(?P<prefix>[a-z][a-z0-9+.\-]*://[^\s:/@]+:)(?P<password>[^\s/@]{1,256})@"
)
_GENERIC_SECRET = re.compile(
    r"(?i)\b(?P<key>password|passwd|pwd|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)"
    r"(?P<separator>\s*['\"`]?\s*[:=]\s*)(?P<quote>['\"`]?)"
    r"(?P<value>[^\s'\"`,;]{6,256})(?P=quote)"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:\$\{?[A-Z0-9_.]+}?|%[A-Z0-9_]+%|<[^>]+>|\*{3,}|x{3,}|"
    r"\[?redacted(?:-[a-z0-9-]+)?]?|null|none|changeme|placeholder|example)$"
)


def _luhn(number: str) -> bool:
    total = 0
    parity = len(number) % 2
    for index, char in enumerate(number):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _known_card_network(number: str) -> bool:
    length = len(number)
    first = int(number[0])
    first_two = int(number[:2])
    first_three = int(number[:3])
    first_four = int(number[:4])
    return bool(
        (first == 4 and 13 <= length <= 19)
        or (length == 15 and first_two in {34, 37})
        or (length == 16 and (51 <= first_two <= 55 or 2221 <= first_four <= 2720))
        or (16 <= length <= 19 and (first_four == 6011 or first_two == 65 or 644 <= first_three <= 649))
        or (16 <= length <= 19 and 3528 <= first_four <= 3589)
    )


def _valid_ssn(match: re.Match[str]) -> bool:
    area, group, serial = (int(match.group(i)) for i in range(1, 4))
    return area not in {0, 666} and group != 0 and serial != 0


def redact_text(text: str) -> str:
    """Mask likely credentials, private keys, payment cards, and SSNs."""

    if not text:
        return text
    value = text.replace("\x00", "")
    value = _PRIVATE_KEY.sub("[REDACTED-PRIVATE-KEY]", value)
    for label, pattern in _TOKEN_PATTERNS:
        value = pattern.sub(f"[REDACTED-{label}]", value)

    def redact_auth(match: re.Match[str]) -> str:
        token = match.group("value")
        if token.isalpha():
            return match.group(0)
        return f"{match.group('scheme')} [REDACTED-AUTHORIZATION]"

    value = _AUTHORIZATION.sub(redact_auth, value)
    value = _URL_PASSWORD.sub(
        lambda match: f"{match.group('prefix')}[REDACTED-URL-PASSWORD]@",
        value,
    )

    def redact_secret(match: re.Match[str]) -> str:
        secret = match.group("value").rstrip(").}]!?>") or match.group("value")
        if _PLACEHOLDER.fullmatch(secret):
            return match.group(0)
        suffix = match.group("value")[len(secret) :]
        return (
            f"{match.group('key')}{match.group('separator')}"
            f"{match.group('quote')}[REDACTED-SECRET]{match.group('quote')}{suffix}"
        )

    value = _GENERIC_SECRET.sub(redact_secret, value)

    def redact_pan(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if _known_card_network(digits) and _luhn(digits):
            return "[REDACTED-PAN]"
        return match.group(0)

    value = _PAN_CANDIDATE.sub(redact_pan, value)
    value = _SSN.sub(
        lambda match: "[REDACTED-SSN]" if _valid_ssn(match) else match.group(0),
        value,
    )
    return value


def redact_tree(value: Any) -> Any:
    """Return a redacted JSON-compatible copy without mutating the source."""

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return redact_tree(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {key: redact_tree(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_tree(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _single_line(value: object) -> str:
    text = _CONTROL_CHARS.sub("", str(value))
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ")


def markdown_inline(value: object) -> str:
    """Render untrusted content as inert single-line Markdown text."""

    text = _single_line(value)
    replacements = {
        "\\": "\\\\",
        "`": "\\`",
        "*": "\\*",
        "_": "\\_",
        "[": "\\[",
        "]": "\\]",
        "|": "\\|",
        "#": "\\#",
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
    }
    return "".join(replacements.get(char, char) for char in text)


def markdown_code_span(value: object) -> str:
    """Render an untrusted path or identifier in a non-breakout code span."""

    text = _single_line(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(1, longest + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def markdown_fenced_code(value: object, language: str = "") -> str:
    """Render a code block using a fence longer than any run in the content."""

    text = _CONTROL_CHARS.sub("", str(value)).replace("\r\n", "\n").replace("\r", "\n")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    safe_language = re.sub(r"[^A-Za-z0-9_+.-]", "", language)
    return f"{fence}{safe_language}\n{text}\n{fence}"


def markdown_table_cell(value: object) -> str:
    """Escape an untrusted value for a single Markdown table cell."""

    return markdown_inline(value)
