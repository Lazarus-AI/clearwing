"""The ranker's structured-output schema must be acceptable to Anthropic.

Anthropic's structured-output validator uses constrained decoding and 400s with
"For 'integer' type, properties maximum, minimum are not supported" when a
schema carries numeric-range keywords. Pydantic emits those from
Field(ge=, le=), so RankedFileScore's 1..5 scores must instead be expressed as
a Literal (-> {"type": "integer", "enum": [...]}), which the validator supports
and enforces. These are pure-logic tests — no network, no real provider.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from clearwing.llm.native import _json_spec_from_model
from clearwing.sourcehunt.ranker import RankedFileScore

_RANGE_KEYWORDS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf")


def test_score_fields_serialize_as_enum_not_range() -> None:
    # Exercise the real wire path (model -> JsonSpec), not just model_json_schema.
    schema = json.loads(_json_spec_from_model(RankedFileScore, name="ranked").schema_json)
    props = schema["properties"]
    for field in ("surface", "influence"):
        node = props[field]
        assert node["enum"] == [1, 2, 3, 4, 5]
        assert node["type"] == "integer"
        assert not any(kw in node for kw in _RANGE_KEYWORDS)


def test_no_range_keywords_anywhere_in_schema() -> None:
    blob = _json_spec_from_model(RankedFileScore, name="ranked").schema_json
    for kw in _RANGE_KEYWORDS:
        assert kw not in blob


def test_pydantic_still_enforces_the_1_to_5_range() -> None:
    ok = RankedFileScore(
        path="x.c", surface=5, influence=1, surface_rationale="r", influence_rationale="r"
    )
    assert ok.surface == 5 and ok.influence == 1

    for bad in (0, 6):
        with pytest.raises(ValidationError):
            RankedFileScore(
                path="x.c",
                surface=bad,
                influence=3,
                surface_rationale="r",
                influence_rationale="r",
            )
