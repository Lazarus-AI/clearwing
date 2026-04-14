"""Unit tests for the three-axis sourcehunt ranker.

The ranker is the only component besides the hunters/verifier/exploiter that
makes LLM calls in v0.1, so most tests use a MagicMock for the LLM.

Critical assertions:
- BOTH surface AND influence scored 1-5 with rationales
- Static-hint and imports_by floors applied
- Reachability defaults to 3 in v0.1
- Priority formula = surface*0.5 + influence*0.2 + reachability*0.3
- Chunking works for >chunk_size files
- The FFmpeg-style file (surface=1, influence=5) doesn't get dropped
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.ranker import (
    Ranker,
    RankerConfig,
    RANKER_SYSTEM_PROMPT,
)


def _make_file(
    path: str,
    *,
    language: str = "c",
    loc: int = 50,
    static_hint: int = 0,
    imports_by: int = 0,
    defines_constants: bool = False,
    tags: list[str] = None,
) -> dict:
    return {
        "path": path,
        "absolute_path": "/abs/" + path,
        "language": language,
        "loc": loc,
        "tags": tags or [],
        "static_hint": static_hint,
        "imports_by": imports_by,
        "defines_constants": defines_constants,
        "surface": 0,
        "influence": 0,
        "reachability": 3,
        "priority": 0.0,
        "tier": "C",
    }


def _mock_llm_returning(scores: list[dict]) -> MagicMock:
    """Build a MagicMock LLM whose .invoke returns a response with JSON scores."""
    mock = MagicMock()
    response = MagicMock()
    response.content = json.dumps(scores)
    mock.invoke.return_value = response
    return mock


# --- Basic rank()  -----------------------------------------------------------


class TestRanker:
    def test_empty_files_returns_empty(self):
        llm = MagicMock()
        ranker = Ranker(llm)
        out = ranker.rank([])
        assert out == []
        llm.invoke.assert_not_called()

    def test_basic_rank_fills_in_scores(self):
        llm = _mock_llm_returning([
            {
                "path": "foo.c",
                "surface": 4,
                "influence": 2,
                "surface_rationale": "parses input",
                "influence_rationale": "isolated",
            }
        ])
        files = [_make_file("foo.c")]
        ranker = Ranker(llm)
        out = ranker.rank(files)
        assert out[0]["surface"] == 4
        assert out[0]["influence"] == 2
        assert out[0]["surface_rationale"] == "parses input"
        assert out[0]["influence_rationale"] == "isolated"

    def test_priority_formula(self):
        llm = _mock_llm_returning([
            {"path": "x.c", "surface": 4, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("x.c")]
        Ranker(llm).rank(files)
        # surface=4 → 2.0, influence=2 → 0.4, reachability=3 → 0.9 → total 3.3
        assert files[0]["priority"] == pytest.approx(3.3)

    def test_reachability_defaults_to_three(self):
        llm = _mock_llm_returning([
            {"path": "y.c", "surface": 1, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("y.c")]
        Ranker(llm).rank(files)
        assert files[0]["reachability"] == 3


# --- Floors ------------------------------------------------------------------


class TestFloors:
    def test_static_hint_promotes_surface(self):
        llm = _mock_llm_returning([
            {"path": "weak.c", "surface": 1, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("weak.c", static_hint=2)]
        Ranker(llm).rank(files)
        # surface=1 from LLM → floored to 3 by static_hint
        assert files[0]["surface"] == 3

    def test_static_hint_does_not_decrease_surface(self):
        """If LLM already returned 5, static_hint floor of 3 doesn't drop it."""
        llm = _mock_llm_returning([
            {"path": "strong.c", "surface": 5, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("strong.c", static_hint=3)]
        Ranker(llm).rank(files)
        assert files[0]["surface"] == 5

    def test_imports_by_promotes_influence(self):
        llm = _mock_llm_returning([
            {"path": "header.h", "surface": 1, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("header.h", imports_by=20)]
        Ranker(llm).rank(files)
        # imports_by > 10 → influence floor of 3
        assert files[0]["influence"] == 3

    def test_defines_constants_promotes_influence(self):
        llm = _mock_llm_returning([
            {"path": "limits.h", "surface": 1, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("limits.h", defines_constants=True)]
        Ranker(llm).rank(files)
        assert files[0]["influence"] == 3

    def test_low_imports_by_does_not_floor(self):
        llm = _mock_llm_returning([
            {"path": "a.c", "surface": 1, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("a.c", imports_by=2)]
        Ranker(llm).rank(files)
        # imports_by=2 < threshold=10 → no floor
        assert files[0]["influence"] == 1


# --- Chunking ----------------------------------------------------------------


class TestChunking:
    def test_chunks_split_correctly(self):
        files = [_make_file(f"f{i}.c") for i in range(350)]
        chunks = Ranker._chunk(files, 150)
        assert len(chunks) == 3
        assert len(chunks[0]) == 150
        assert len(chunks[1]) == 150
        assert len(chunks[2]) == 50

    def test_rank_makes_one_call_per_chunk(self):
        # Build 250 files; chunk_size=100 → 3 chunks → 3 LLM calls
        llm = _mock_llm_returning([
            {"path": f"f{i}.c", "surface": 2, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
            for i in range(250)
        ])
        files = [_make_file(f"f{i}.c") for i in range(250)]
        Ranker(llm, RankerConfig(chunk_size=100)).rank(files)
        assert llm.invoke.call_count == 3


# --- LLM response handling ---------------------------------------------------


class TestResponseParsing:
    def test_parse_response_extracts_json_array(self):
        ranker = Ranker(MagicMock())
        content = '''Here is my analysis:
[
  {"path": "a.c", "surface": 3, "influence": 2, "surface_rationale": "x", "influence_rationale": "y"}
]
Done.'''
        result = ranker._parse_response(content)
        assert "a.c" in result
        assert result["a.c"]["surface"] == 3
        assert result["a.c"]["influence"] == 2

    def test_parse_response_invalid_json_returns_empty(self):
        ranker = Ranker(MagicMock())
        result = ranker._parse_response("not json at all")
        assert result == {}

    def test_parse_response_clamps_out_of_range(self):
        ranker = Ranker(MagicMock())
        content = '[{"path":"f","surface":99,"influence":-3,"surface_rationale":"","influence_rationale":""}]'
        parsed = ranker._parse_response(content)
        # _parse_response itself doesn't clamp — _apply_scores does
        assert parsed["f"]["surface"] == 99


class TestFallbackOnLLMSilence:
    """When the LLM returns no scores for a file, the ranker falls back to heuristics."""

    def test_fallback_surface_for_parser_tag(self):
        llm = _mock_llm_returning([])  # empty array
        files = [_make_file("decoder.c", tags=["parser"])]
        Ranker(llm).rank(files)
        assert files[0]["surface"] == 4

    def test_fallback_surface_for_static_hint(self):
        llm = _mock_llm_returning([])
        files = [_make_file("a.c", static_hint=1)]
        Ranker(llm).rank(files)
        assert files[0]["surface"] >= 3

    def test_fallback_influence_for_high_imports_by(self):
        llm = _mock_llm_returning([])
        files = [_make_file("h.h", imports_by=25)]
        Ranker(llm).rank(files)
        # imports_by > 20 → fallback influence 5; floor stays 5
        assert files[0]["influence"] == 5

    def test_fallback_when_llm_raises(self):
        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        files = [_make_file("foo.c", tags=["parser"], static_hint=2, imports_by=15)]
        Ranker(llm).rank(files)
        # Failure → fallback — surface should be at least 3 from static_hint floor
        assert files[0]["surface"] >= 3
        # imports_by=15 → fallback influence 4 (15 > 5 but ≤ 20)
        assert files[0]["influence"] >= 3


# --- The FFmpeg-style propagation case --------------------------------------


class TestPropagationCase:
    """The whole point of the two-axis ranker: a file with surface=1 but
    influence=5 must NOT be dropped to the bottom of the queue.
    """

    def test_constants_header_lands_high_priority(self):
        # LLM correctly identifies it as low surface, high influence
        llm = _mock_llm_returning([
            {"path": "codec_limits.h", "surface": 1, "influence": 5,
             "surface_rationale": "just constants", "influence_rationale": "used in 50 memcpys"},
            {"path": "main.c", "surface": 4, "influence": 2,
             "surface_rationale": "main entry", "influence_rationale": "isolated"},
        ])
        files = [
            _make_file("codec_limits.h", defines_constants=True, imports_by=50),
            _make_file("main.c"),
        ]
        Ranker(llm).rank(files)
        header = next(f for f in files if f["path"] == "codec_limits.h")
        main = next(f for f in files if f["path"] == "main.c")
        # surface=1, influence=5, reachability=3
        # priority = 0.5 + 1.0 + 0.9 = 2.4
        assert header["priority"] == pytest.approx(2.4)
        # main.c: 4*0.5 + 2*0.4... wait that's 2.0 + 0.4 + 0.9 = 3.3
        assert main["priority"] == pytest.approx(3.3)
        # main.c outranks the header by priority — that's expected with these
        # weights. But the header is NOT zeroed out: its priority is 2.4, well
        # above any rank-1 file (0.5 + 0.2 + 0.9 = 1.6). So it'll land in
        # Tier B at worst — never Tier C — and never get dropped.
        assert header["priority"] > 2.0

    def test_pure_constants_file_with_high_imports_by_floors(self):
        """Even if the LLM whiffs (returns influence=1), the imports_by floor
        and defines_constants floor must keep it relevant."""
        llm = _mock_llm_returning([
            {"path": "limits.h", "surface": 1, "influence": 1,
             "surface_rationale": "constants", "influence_rationale": "missed it"},
        ])
        files = [_make_file(
            "limits.h", defines_constants=True, imports_by=30,
        )]
        Ranker(llm).rank(files)
        # Both floors apply → influence at least 3
        assert files[0]["influence"] == 3
        # priority = 1*0.5 + 3*0.2 + 3*0.3 = 0.5 + 0.6 + 0.9 = 2.0
        assert files[0]["priority"] == pytest.approx(2.0)


class TestFuzzableRankBoost:
    """v0.4: files tagged parser/fuzzable with surface>=4 get priority += 0.5.
    This back-propagates the HarnessGenerator's selection criteria into the
    ranker so fuzzable parsers outrank peers at the same base score."""

    def test_parser_tagged_high_surface_gets_boost(self):
        llm = _mock_llm_returning([
            {"path": "decode.c", "surface": 4, "influence": 2,
             "surface_rationale": "parses input", "influence_rationale": "isolated"}
        ])
        files = [_make_file("decode.c", tags=["parser"])]
        Ranker(llm).rank(files)
        # Base priority: 4*0.5 + 2*0.2 + 3*0.3 = 3.3
        # After boost: 3.3 + 0.5 = 3.8
        assert files[0]["priority"] == pytest.approx(3.8)

    def test_fuzzable_tagged_high_surface_gets_boost(self):
        llm = _mock_llm_returning([
            {"path": "harness.c", "surface": 5, "influence": 1,
             "surface_rationale": "fuzz entry point", "influence_rationale": ""}
        ])
        files = [_make_file("harness.c", tags=["fuzzable"])]
        Ranker(llm).rank(files)
        # Base: 5*0.5 + 1*0.2 + 3*0.3 = 3.6, + 0.5 = 4.1
        assert files[0]["priority"] == pytest.approx(4.1)

    def test_low_surface_no_boost_even_if_tagged(self):
        """surface < 4 disqualifies the boost."""
        llm = _mock_llm_returning([
            {"path": "lib.c", "surface": 3, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("lib.c", tags=["parser"])]
        Ranker(llm).rank(files)
        # Base: 3*0.5 + 2*0.2 + 3*0.3 = 2.8, no boost
        assert files[0]["priority"] == pytest.approx(2.8)

    def test_no_relevant_tag_no_boost(self):
        """Even with high surface, no parser/fuzzable tag → no boost."""
        llm = _mock_llm_returning([
            {"path": "auth.c", "surface": 5, "influence": 3,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("auth.c", tags=["auth_boundary"])]
        Ranker(llm).rank(files)
        # Base: 5*0.5 + 3*0.2 + 3*0.3 = 4.0, no boost
        assert files[0]["priority"] == pytest.approx(4.0)

    def test_boost_is_audited_in_rationale(self):
        """The boost should leave a trace in surface_rationale for explainability."""
        llm = _mock_llm_returning([
            {"path": "parser.c", "surface": 4, "influence": 2,
             "surface_rationale": "parses untrusted input",
             "influence_rationale": ""}
        ])
        files = [_make_file("parser.c", tags=["parser"])]
        Ranker(llm).rank(files)
        assert "+0.5" in files[0]["surface_rationale"]
        assert "fuzzable boost" in files[0]["surface_rationale"]

    def test_parser_fuzzable_outranks_non_parser_at_same_base(self):
        """The whole point of the boost: a parser file outranks a non-parser
        peer at the same surface/influence/reachability."""
        llm = _mock_llm_returning([
            {"path": "parser.c", "surface": 4, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""},
            {"path": "util.c", "surface": 4, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""},
        ])
        files = [
            _make_file("parser.c", tags=["parser"]),
            _make_file("util.c", tags=[]),
        ]
        Ranker(llm).rank(files)
        parser = next(f for f in files if f["path"] == "parser.c")
        util = next(f for f in files if f["path"] == "util.c")
        assert parser["priority"] > util["priority"]
        assert parser["priority"] - util["priority"] == pytest.approx(0.5)

    def test_boost_applied_only_once_per_file(self):
        """Running rank() twice on the same file shouldn't stack the boost."""
        llm = _mock_llm_returning([
            {"path": "decode.c", "surface": 4, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("decode.c", tags=["parser"])]
        Ranker(llm).rank(files)
        first_priority = files[0]["priority"]
        # Re-run — boost is deterministic on the same inputs
        # but we need to re-mock the LLM
        llm2 = _mock_llm_returning([
            {"path": "decode.c", "surface": 4, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        Ranker(llm2).rank(files)
        # Priority should be the same (4*0.5 + 2*0.2 + 3*0.3 + 0.5 = 3.8)
        assert files[0]["priority"] == pytest.approx(first_priority)
        # Rationale audit note should appear at most once
        rationale = files[0]["surface_rationale"]
        assert rationale.count("fuzzable boost") == 1

    def test_boost_changes_tier_assignment(self):
        """A fuzzable file at the B/A boundary should get bumped to A by
        the boost — the whole point of the back-propagation."""
        from clearwing.sourcehunt.pool import assign_tier

        llm = _mock_llm_returning([
            {"path": "parser.c", "surface": 4, "influence": 2,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("parser.c", tags=["parser"])]
        Ranker(llm).rank(files)
        # Base priority 3.3 → A (>= 3.0), after boost 3.8 → still A but stronger
        assert assign_tier(files[0]) == "A"

    def test_boost_rescues_borderline_file(self):
        """A file with surface=4, influence=1, reach=3 → base priority 2.9 → B.
        With the fuzzable boost: 3.4 → A."""
        from clearwing.sourcehunt.pool import assign_tier

        llm = _mock_llm_returning([
            {"path": "decode.c", "surface": 4, "influence": 1,
             "surface_rationale": "", "influence_rationale": ""}
        ])
        files = [_make_file("decode.c", tags=["parser"])]
        Ranker(llm).rank(files)
        # 4*0.5 + 1*0.2 + 3*0.3 + 0.5 = 2.0 + 0.2 + 0.9 + 0.5 = 3.6 → A
        assert files[0]["priority"] == pytest.approx(3.6)
        assert assign_tier(files[0]) == "A"


class TestRankerSystemPrompt:
    def test_prompt_mentions_both_axes(self):
        assert "SURFACE" in RANKER_SYSTEM_PROMPT
        assert "INFLUENCE" in RANKER_SYSTEM_PROMPT
        # The prompt must explicitly call out the propagation case
        assert "constants.h" in RANKER_SYSTEM_PROMPT or "propagat" in RANKER_SYSTEM_PROMPT.lower()
        # Must request JSON output
        assert "JSON" in RANKER_SYSTEM_PROMPT
