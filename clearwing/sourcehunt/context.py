"""Bounded, deterministic context assembly for SourceHunt hunters."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from clearwing.llm import ChatMessage, NativeToolSpec

from .optimization import ContextProfile

_CHECKPOINT_PREFIX = "[SourceHunt durable checkpoint]"


def _content(message: ChatMessage) -> str:
    return str(getattr(message, "content", None) or "")


def _clip(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _value(item: Any, name: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def estimate_messages_tokens(messages: list[ChatMessage]) -> int:
    """Cheap, provider-independent estimate suitable for deterministic policy."""

    total_chars = 0
    for message in messages:
        total_chars += len(str(getattr(message, "role", ""))) + len(_content(message))
        total_chars += len(str(getattr(message, "tool_response_call_id", "") or ""))
        for tool_call in getattr(message, "tool_calls", None) or []:
            total_chars += len(str(getattr(tool_call, "fn_name", "") or ""))
            total_chars += len(str(getattr(tool_call, "fn_arguments_json", "") or ""))
    return max(1, total_chars // 4)


def estimate_request_tokens(
    messages: list[ChatMessage],
    *,
    system: str,
    tools: list[NativeToolSpec],
) -> int:
    static_chars = len(system)
    for tool in tools:
        static_chars += len(tool.name) + len(tool.description)
        static_chars += len(json.dumps(tool.schema, sort_keys=True, separators=(",", ":")))
    return estimate_messages_tokens(messages) + static_chars // 4


def compact_tool_specs(tools: list[NativeToolSpec]) -> list[NativeToolSpec]:
    """Remove provider-facing schema prose while preserving callable contracts."""

    def compact_schema(value: Any) -> Any:
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if key == "title":
                    continue
                if key == "description":
                    result[key] = _clip(child, 120)
                else:
                    result[key] = compact_schema(child)
            return result
        if isinstance(value, list):
            return [compact_schema(item) for item in value]
        return value

    return [
        NativeToolSpec(
            name=tool.name,
            description=_clip(tool.description, 160),
            schema=compact_schema(tool.schema),
            handler=tool.handler,
        )
        for tool in tools
    ]


def durable_checkpoint(ctx: Any, *, max_chars: int) -> str:
    """Render tool-maintained investigation state without an extra model call."""

    candidates = []
    for candidate_id in sorted(ctx.candidates):
        candidate = ctx.candidates[candidate_id]
        candidates.append(
            {
                "id": _clip(candidate.get("candidate_id", candidate_id), 24),
                "status": _clip(candidate.get("status"), 20),
                "location": _clip(
                    f"{candidate.get('file', '')}:{candidate.get('line', 0) or '?'}", 180
                ),
                "hypothesis": _clip(candidate.get("hypothesis"), 360),
                "attacker_control": _clip(candidate.get("attacker_control"), 220),
                "invariant": _clip(candidate.get("invariant"), 220),
                "effect": _clip(candidate.get("effect"), 220),
                "counterargument": _clip(candidate.get("counterargument"), 300),
                "evidence": _clip(candidate.get("evidence"), 360),
                "next_check": _clip(candidate.get("next_check"), 260),
            }
        )

    trace = []
    for index, step in enumerate(ctx.trace_steps, start=1):
        trace.append(
            {
                "step": index,
                "location": _clip(
                    f"{_value(step, 'file')}:{_value(step, 'line', 0) or '?'}", 180
                ),
                "function": _clip(_value(step, "function"), 120),
                "code": _clip(_value(step, "code_snippet"), 320),
                "note": _clip(_value(step, "note"), 280),
            }
        )

    payload = {
        "target": str(ctx.file_path or "unknown"),
        "source_windows_ranked": bool(ctx.source_windows_ranked),
        "ranked_windows_read": sorted(ctx.source_windows_read),
        "state_packets_read": sorted(ctx.state_packets_read),
        "value_domains": [ctx.value_domains[name] for name in sorted(ctx.value_domains)],
        "domain_consequences": [
            ctx.domain_consequences[name] for name in sorted(ctx.domain_consequences)
        ],
        "candidates": candidates,
        "trace": trace,
        "findings_recorded": len(ctx.findings),
    }
    active_next_checks = [
        candidate["next_check"]
        for candidate in candidates
        if candidate["status"] in {"pending", "investigating", "validated"}
        and candidate["next_check"]
    ]
    payload["continue"] = (
        f"Do not rerank. Resolve this next: {active_next_checks[0]}"
        if active_next_checks
        else "Do not rerank. Continue with one unread ranked window or form a candidate."
    )
    rendered = _CHECKPOINT_PREFIX + "\n" + json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(rendered) <= max_chars:
        return rendered

    # Active state and the newest rejected/trace evidence are most actionable.
    active = [item for item in candidates if item["status"] != "rejected"]
    rejected = [item for item in candidates if item["status"] == "rejected"]
    payload["candidates"] = active + rejected[-4:]
    payload["trace"] = trace[:2] + trace[-6:] if len(trace) > 8 else trace
    rendered = _CHECKPOINT_PREFIX + "\n" + json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _clip(rendered, max_chars)


def _protocol_groups(messages: list[ChatMessage]) -> list[list[ChatMessage]]:
    """Group assistant calls with all matching tool results."""

    groups: list[list[ChatMessage]] = []
    index = 0
    while index < len(messages):
        message = messages[index]
        if getattr(message, "role", "") != "assistant":
            groups.append([message])
            index += 1
            continue
        group = [message]
        expected = len(getattr(message, "tool_calls", None) or [])
        index += 1
        while expected > 0 and index < len(messages):
            next_message = messages[index]
            if getattr(next_message, "role", "") != "tool":
                break
            group.append(next_message)
            expected -= 1
            index += 1
        groups.append(group)
    return groups


@dataclass
class ContextCompaction:
    messages: list[ChatMessage]
    before_tokens: int
    after_tokens: int
    dropped_messages: int


class SourceHuntContextManager:
    """Apply a versioned context policy to a hunter transcript."""

    def __init__(self, profile: ContextProfile, ctx: Any) -> None:
        self.profile = profile
        self.ctx = ctx

    def should_compact(
        self,
        messages: list[ChatMessage],
        *,
        system: str,
        tools: list[NativeToolSpec],
    ) -> bool:
        return (
            self.profile.strategy != "legacy"
            and estimate_request_tokens(messages, system=system, tools=tools)
            >= self.profile.compact_at_tokens
        )

    def compact(
        self,
        messages: list[ChatMessage],
        *,
        system: str,
        tools: list[NativeToolSpec],
    ) -> ContextCompaction:
        before = estimate_request_tokens(messages, system=system, tools=tools)
        checkpoint = ChatMessage(
            "system",
            durable_checkpoint(self.ctx, max_chars=self.profile.checkpoint_chars),
        )
        initial = next(
            (
                message
                for message in messages
                if getattr(message, "role", "") == "user"
                and not _content(message).startswith(_CHECKPOINT_PREFIX)
            ),
            None,
        )
        eligible = [
            message
            for message in messages
            if message is not initial and not _content(message).startswith(_CHECKPOINT_PREFIX)
        ]
        groups = _protocol_groups(eligible)
        base = ([initial] if initial is not None else []) + [checkpoint]
        static_tokens = estimate_request_tokens(base, system=system, tools=tools)
        remaining = max(0, self.profile.compact_to_tokens - static_tokens)
        recent: list[list[ChatMessage]] = []
        used = 0
        for group in reversed(groups):
            if len(recent) >= self.profile.recent_protocol_groups:
                break
            group_tokens = estimate_messages_tokens(group)
            if recent and used + group_tokens > remaining:
                break
            if not recent or group_tokens <= remaining:
                recent.append(group)
                used += group_tokens
        recent.reverse()
        compacted = [*base, *(message for group in recent for message in group)]
        after = estimate_request_tokens(compacted, system=system, tools=tools)
        return ContextCompaction(
            messages=compacted,
            before_tokens=before,
            after_tokens=after,
            dropped_messages=max(0, len(messages) - len(compacted)),
        )


__all__ = [
    "ContextCompaction",
    "SourceHuntContextManager",
    "compact_tool_specs",
    "durable_checkpoint",
    "estimate_messages_tokens",
    "estimate_request_tokens",
]
