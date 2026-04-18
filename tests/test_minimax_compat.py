"""Tests for MiniMax M2.7 compatibility: think-tag stripping and catalog entry."""

from __future__ import annotations

from clearwing.llm.native import strip_think_tags, extract_json_object
from clearwing.providers.catalog import preset_by_key
from clearwing.providers.env import _default_openai_compat_model


class TestStripThinkTags:
    def test_no_tags(self):
        assert strip_think_tags("Hello, world!") == "Hello, world!"

    def test_simple_think_block(self):
        text = "<think>Let me think about this...</think>\nHere is the answer."
        assert strip_think_tags(text) == "Here is the answer."

    def test_multiline_think_block(self):
        text = (
            "<think>\nI need to consider:\n1. First thing\n"
            "2. Second thing\n</think>\n\nThe result is 42."
        )
        assert strip_think_tags(text) == "The result is 42."

    def test_think_block_with_json_inside(self):
        text = (
            '<think>\nI need to structure this like {"key": "value"} format.\n'
            'The result should have {"results": []} with entries.\n</think>\n\n'
            '{"results": [{"file": "foo.py", "score": 0.8}]}'
        )
        result = strip_think_tags(text)
        assert result == '{"results": [{"file": "foo.py", "score": 0.8}]}'

    def test_preserves_content_without_tags(self):
        text = '{"results": [{"file": "bar.py"}]}'
        assert strip_think_tags(text) == text

    def test_empty_think_block(self):
        assert strip_think_tags("<think></think>answer") == "answer"

    def test_multiple_think_blocks(self):
        text = "<think>first</think>hello <think>second</think>world"
        assert strip_think_tags(text) == "hello world"

    def test_empty_string(self):
        assert strip_think_tags("") == ""

    def test_only_think_block(self):
        assert strip_think_tags("<think>just thinking</think>") == ""


class TestResponseTextWithThinkTags:
    def test_json_extraction_after_think_strip(self):
        raw = (
            "<think>\nLet me analyze these files...\n"
            'Should I use {"results": []}?\n</think>\n\n'
            '{"results": [{"file": "a.py", "score": 0.9}]}'
        )
        cleaned = strip_think_tags(raw)
        parsed = extract_json_object(cleaned)
        assert parsed["results"][0]["file"] == "a.py"


class TestMiniMaxCatalog:
    def test_preset_exists(self):
        preset = preset_by_key("minimax")
        assert preset is not None
        assert preset.default_base_url == "https://api.minimax.io/v1"
        assert preset.default_model == "MiniMax-M2.7"
        assert preset.api_key_env_var == "MINIMAX_API_KEY"

    def test_alt_models(self):
        preset = preset_by_key("minimax")
        assert "MiniMax-M2.7-highspeed" in preset.alt_models


class TestMiniMaxDefaultModel:
    def test_minimax_io_url(self):
        assert _default_openai_compat_model("https://api.minimax.io/v1") == "MiniMax-M2.7"
