"""Unit tests for ``_mark_cache_prefix`` (prompt-caching breakpoint placement).

These pin the invariants that keep the caching hint provably equivalent to the
model: exactly one breakpoint on the last message, no stale markers, and — the
regression that a benchmark run surfaced — no loss of the ``reasoning_content``
that pairs with an assistant turn's ``thought_signature`` (Anthropic rejects a
thinking block whose signature has no matching reasoning value).
"""

from __future__ import annotations

from genai_pyo3 import ChatMessage

from clearwing.llm.native import _mark_cache_prefix


def test_disabled_is_passthrough_no_markers():
    msgs = [ChatMessage("user", "a"), ChatMessage("assistant", "b")]
    out = _mark_cache_prefix(msgs, False)
    assert [m.content for m in out] == ["a", "b"]
    assert all(m.cache_control is None for m in out)


def test_enabled_marks_only_last():
    msgs = [ChatMessage("user", "a"), ChatMessage("assistant", "b")]
    out = _mark_cache_prefix(msgs, True)
    assert out[0].cache_control is None
    assert out[-1].cache_control == "ephemeral"


def test_marker_rolls_forward_and_clears_stale():
    # Simulate the hunter reusing one growing list across turns.
    msgs = [ChatMessage("user", "a")]
    _mark_cache_prefix(msgs, True)
    assert msgs[-1].cache_control == "ephemeral"

    # Next turn: history grows; the old marker must move to the new last msg.
    msgs.append(ChatMessage("assistant", "b"))
    _mark_cache_prefix(msgs, True)
    assert msgs[0].cache_control is None  # stale marker cleared
    assert msgs[-1].cache_control == "ephemeral"
    # Never more than one breakpoint.
    assert sum(1 for m in msgs if m.cache_control) == 1


def test_marks_in_place_without_rebuilding():
    # The regression: reconstructing the message dropped the reasoning value
    # that pairs with an assistant turn's thought_signature -> Anthropic 400
    # ("thinking blocks require one reasoning value per thought signature").
    # The fix mutates only cache_control on the SAME object, so every other
    # field (reasoning_content, thought_signatures, content, ...) is preserved
    # by construction. Asserting identity is the strongest guarantee of that.
    m = ChatMessage("assistant", "analysis", thought_signatures=["sig-1"])
    out = _mark_cache_prefix([m], True)
    marked = out[-1]
    assert marked is m  # same object — mutated in place, not rebuilt
    assert marked.cache_control == "ephemeral"
    assert marked.thought_signatures == ["sig-1"]
    assert marked.content == "analysis"


def test_preserves_tool_calls_and_response_id():
    from genai_pyo3 import ToolCall

    tc = [ToolCall("call-1", "read_file", "{}")]
    m = ChatMessage("assistant", "x", tool_calls=tc)
    out = _mark_cache_prefix([m], True)
    assert out[-1].tool_calls and out[-1].tool_calls[0].call_id == "call-1"
    assert out[-1].cache_control == "ephemeral"


def test_empty_list_is_safe():
    assert _mark_cache_prefix([], True) == []
