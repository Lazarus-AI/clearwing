"""Regression test: structured-output JSON schemas must not carry numeric-range
keywords that Anthropic's validator rejects.

Current Anthropic models 400 with "For 'integer' type, properties maximum,
minimum are not supported" when a structured-output schema contains
minimum/maximum (which Pydantic emits from Field(ge=, le=)). This killed the
sourcehunt ranker (RankedFileScore uses 1..5 scores). Pure-logic test — no
network, no real provider.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from clearwing.llm.native import _json_spec_from_model


class _Scored(BaseModel):
    path: str
    surface: int = Field(ge=1, le=5)
    influence: int = Field(ge=1, le=5)


def test_json_spec_strips_numeric_range_keywords():
    spec = _json_spec_from_model(_Scored, name="scored")
    schema = json.loads(spec.schema_json)
    props = schema["properties"]
    for field in ("surface", "influence"):
        assert "minimum" not in props[field]
        assert "maximum" not in props[field]
    # Non-range structure is preserved.
    assert props["surface"]["type"] == "integer"
    assert props["path"]["type"] == "string"


def test_json_spec_strips_nested_and_array_bounds():
    class Inner(BaseModel):
        n: int = Field(ge=0, le=10)

    class Outer(BaseModel):
        items: list[Inner]

    blob = _json_spec_from_model(Outer, name="outer").schema_json
    assert "minimum" not in blob
    assert "maximum" not in blob
