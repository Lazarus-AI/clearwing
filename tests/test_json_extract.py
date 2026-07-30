from __future__ import annotations

import pytest

from clearwing.llm import extract_json_array, extract_json_object


def test_extract_object_ignores_braces_inside_strings() -> None:
    payload = extract_json_object('prefix {"text": "literal } and {", "items": [1, 2]} suffix')
    assert payload == {"text": "literal } and {", "items": [1, 2]}


def test_extract_array_after_non_json_fence() -> None:
    response = '```python\nprint("not json")\n```\nResult: [{"id": 1}]'
    assert extract_json_array(response) == [{"id": 1}]


def test_extract_whole_fence_with_backticks_in_json_string() -> None:
    response = '```json\n{"snippet": "```c\\nint main(void);\\n```"}\n```'
    assert extract_json_object(response)["snippet"].startswith("```c")


def test_extract_repairs_invalid_backslashes_in_string_values() -> None:
    payload = extract_json_object(r'{"regex": "\d+", "path": "C:\Users\demo"}')
    assert payload == {"regex": r"\d+", "path": r"C:\Users\demo"}


def test_extract_skips_invalid_opener_before_valid_payload() -> None:
    assert extract_json_object('bad { prose, then {"ok": true}') == {"ok": True}


def test_object_and_array_helpers_enforce_top_level_type() -> None:
    with pytest.raises(ValueError, match="object"):
        extract_json_object("[1, 2, 3]")
    with pytest.raises(ValueError, match="array"):
        extract_json_array('{"items": [1, 2, 3]}')
