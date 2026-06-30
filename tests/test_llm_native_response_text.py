"""Compatibility tests for clearwing.llm.native.response_text."""

from __future__ import annotations

from clearwing.llm.native import response_text


class _MethodStyleResponse:
    def first_text(self):  # pragma: no cover - shape test
        return ""

    def texts(self):  # pragma: no cover - shape test
        return ["alpha", "", "beta"]


class _PropertyStyleResponse:
    first_text = "hello"
    texts = ["ignored"]


def test_response_text_accepts_method_style_response():
    assert response_text(_MethodStyleResponse()) == "alpha\nbeta"


def test_response_text_accepts_property_style_response():
    assert response_text(_PropertyStyleResponse()) == "hello"
