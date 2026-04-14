"""Tests for the v0.3 Variant Hunter Loop.

The variant loop compounds finding density within a single run by turning
each verified finding into a search pattern and re-feeding matches as
suspicion-level variant findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from clearwing.sourcehunt.variant_loop import (
    VariantLoop,
    VariantLoopConfig,
    VariantLoopResult,
    VariantPattern,
    VariantPatternGenerator,
    VariantSearcher,
)

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"


def _mock_llm(payload: dict) -> MagicMock:
    llm = MagicMock()
    response = MagicMock()
    response.content = json.dumps(payload)
    llm.invoke.return_value = response
    return llm


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "cwe": "CWE-787",
        "severity": "high",
        "description": "memcpy overflow",
        "code_snippet": "memcpy(frame, input, input_len);",
        "evidence_level": "crash_reproduced",
    }
    base.update(kwargs)
    return base


# --- VariantPatternGenerator -----------------------------------------------


class TestVariantPatternGenerator:
    def test_basic_generation(self):
        llm = _mock_llm(
            {
                "grep_regex": r"memcpy\s*\([^)]*len[^)]*\)",
                "semantic_description": "memcpy with length variable",
            }
        )
        gen = VariantPatternGenerator(llm)
        pattern = gen.generate(_make_finding())
        assert pattern is not None
        assert "memcpy" in pattern.grep_regex
        assert "memcpy" in pattern.semantic_description

    def test_invalid_response_returns_none(self):
        llm = MagicMock()
        resp = MagicMock()
        resp.content = "no json here"
        llm.invoke.return_value = resp
        gen = VariantPatternGenerator(llm)
        assert gen.generate(_make_finding()) is None

    def test_llm_exception_returns_none(self):
        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        gen = VariantPatternGenerator(llm)
        assert gen.generate(_make_finding()) is None


# --- VariantSearcher --------------------------------------------------------


class TestVariantSearcher:
    def test_search_finds_memcpy_matches(self):
        """The c_propagation fixture has memcpy calls in 3 codec files."""
        searcher = VariantSearcher()
        pattern = VariantPattern(
            grep_regex=r"memcpy",
            semantic_description="memcpy call",
        )
        # Source finding is on codec_a.c:9 — searcher should skip that exact line
        source = _make_finding(file="src/codec_a.c", line_number=9, id="origin")
        matches = searcher.search(str(FIXTURE_C_PROPAGATION), pattern, source)
        # Expect memcpy in codec_b.c and codec_c.c (at least — not codec_a.c:9)
        match_files = {m.file for m in matches}
        assert "src/codec_b.c" in match_files
        assert "src/codec_c.c" in match_files
        # codec_a.c:9 (the source) is excluded
        for m in matches:
            assert not (m.file == "src/codec_a.c" and m.line_number == 9)

    def test_search_invalid_regex_returns_empty(self):
        searcher = VariantSearcher()
        pattern = VariantPattern(
            grep_regex=r"[invalid(",
            semantic_description="broken regex",
        )
        assert searcher.search(str(FIXTURE_C_PROPAGATION), pattern, _make_finding()) == []

    def test_search_empty_regex_returns_empty(self):
        searcher = VariantSearcher()
        pattern = VariantPattern(grep_regex="", semantic_description="empty")
        assert searcher.search(str(FIXTURE_C_PROPAGATION), pattern, _make_finding()) == []

    def test_search_respects_max_per_pattern(self):
        """The searcher caps matches per pattern to keep results sane."""
        searcher = VariantSearcher()
        searcher.MAX_MATCHES_PER_PATTERN = 2  # tiny cap for the test
        pattern = VariantPattern(grep_regex=r".", semantic_description="all")
        matches = searcher.search(str(FIXTURE_C_PROPAGATION), pattern, _make_finding())
        assert len(matches) <= 2


# --- VariantLoop orchestration ---------------------------------------------


class TestVariantLoop:
    def test_run_once_generates_seeds(self):
        llm = _mock_llm(
            {
                "grep_regex": r"memcpy",
                "semantic_description": "memcpy variant",
            }
        )
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))
        verified = [_make_finding(file="src/codec_a.c", line_number=9)]
        result = loop.run_once(verified, str(FIXTURE_C_PROPAGATION))

        assert isinstance(result, VariantLoopResult)
        assert result.patterns_generated == 1
        assert result.matches_found >= 2  # codec_b and codec_c
        assert result.iterations == 1
        for seed in result.seeds:
            assert seed.original_finding["id"] == "hunter-abc"
            assert "A similar pattern" in seed.message
            assert seed.match.source_finding_id == "hunter-abc"

    def test_run_once_respects_already_seen(self):
        """Locations in already_seen_locations should not generate seeds."""
        llm = _mock_llm(
            {
                "grep_regex": r"memcpy",
                "semantic_description": "memcpy variant",
            }
        )
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))

        # Pre-claim codec_b.c lines 6-10
        already_seen = {("src/codec_b.c", i) for i in range(1, 15)}
        result = loop.run_once(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
            already_seen_locations=already_seen,
        )
        for seed in result.seeds:
            assert seed.match.file != "src/codec_b.c"

    def test_run_once_with_no_verified_findings(self):
        llm = _mock_llm({"grep_regex": "x", "semantic_description": "x"})
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))
        result = loop.run_once([], str(FIXTURE_C_PROPAGATION))
        assert result.seeds == []
        assert result.patterns_generated == 0

    def test_run_once_caps_matches_per_finding(self):
        llm = _mock_llm({"grep_regex": r".", "semantic_description": "any"})
        config = VariantLoopConfig(max_variants_per_finding=2)
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm), config=config)
        result = loop.run_once(
            [_make_finding()],
            str(FIXTURE_C_PROPAGATION),
        )
        # Each verified finding contributes at most `max_variants_per_finding` seeds
        assert len(result.seeds) <= 2

    def test_pattern_gen_failure_is_per_finding(self):
        """If pattern generation fails for one finding, others still run."""
        llm = MagicMock()
        llm.invoke.side_effect = [
            Exception("rate limited"),  # first finding fails
            _mock_llm_response(
                {"grep_regex": "memcpy", "semantic_description": "ok"}
            ),  # second succeeds
        ]
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))
        result = loop.run_once(
            [
                _make_finding(id="f1", file="src/codec_a.c", line_number=9),
                _make_finding(id="f2", file="src/codec_b.c", line_number=5),
            ],
            str(FIXTURE_C_PROPAGATION),
        )
        # Only one pattern generated (the second succeeded)
        assert result.patterns_generated == 1


def _mock_llm_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.content = json.dumps(payload)
    return resp


# --- Runner integration ----------------------------------------------------


class TestMultiIterationDriver:
    """v0.4: VariantLoop.run() drives multiple iterations until fixpoint."""

    def test_run_single_iteration_when_no_seeds_found(self):
        """If the first pass finds nothing, the loop terminates after 1 iteration."""
        # Regex doesn't match anything in the fixture
        llm = _mock_llm(
            {
                "grep_regex": "xyzzy_never_matches",
                "semantic_description": "nothing",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=5),
        )
        result = loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
        )
        # 1 iteration, fixpoint reached
        assert result.iterations == 1
        assert result.seeds == []
        # Pattern was generated once
        assert result.patterns_generated == 1

    def test_run_stops_after_empty_iteration(self):
        """Second iteration produces no new seeds → loop stops at 2."""
        # Already-seen dict grows each iteration; once the regex exhausts
        # everything new, the next pass returns zero seeds.
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=5),
        )
        result = loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
        )
        # First pass finds variants; second pass finds nothing (already_seen
        # now includes them). Stops at 2.
        assert result.iterations == 2
        assert result.matches_found >= 2  # from the first pass

    def test_run_respects_max_iterations_cap(self):
        """max_iterations hard-cap the loop."""
        llm = MagicMock()
        # Return a pattern that always matches something
        response = MagicMock()
        response.content = json.dumps(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        llm.invoke.return_value = response

        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(
                max_iterations=1,
                stop_on_empty_iteration=False,  # force the cap to matter
            ),
        )
        result = loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
        )
        assert result.iterations == 1

    def test_run_with_reverify_callback_compounds(self):
        """When reverify_callback returns new findings, the next pass uses them."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=3),
        )

        # reverify_callback turns seeds into "verified" findings with new IDs
        reverify_calls = []

        def reverify(seeds):
            reverify_calls.append(len(seeds))
            # Return a new finding at a fresh file so the NEXT pass can look
            # for variants of the NEW finding rather than the original.
            return [
                _make_finding(
                    id=f"reverified-{len(reverify_calls)}",
                    file="src/codec_b.c",
                    line_number=100 + len(reverify_calls),
                )
            ]

        loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
            reverify_callback=reverify,
        )
        # At least one reverify call (the first iteration found seeds)
        assert len(reverify_calls) >= 1

    def test_run_reverify_callback_empty_result_stops_loop(self):
        """If reverify returns [], the next iteration has no input → stop."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=5),
        )

        def reverify(seeds):
            return []  # nothing survived re-verification

        result = loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
            reverify_callback=reverify,
        )
        # The first pass generated a pattern; reverify returned [] so the
        # loop stopped after 1 iteration.
        assert result.iterations == 1

    def test_run_per_iteration_callback_fires(self):
        """per_iteration_callback should fire after each run_once pass."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "x",
            }
        )
        callback_calls = []
        config = VariantLoopConfig(
            max_iterations=2,
            stop_on_empty_iteration=False,
            per_iteration_callback=lambda r: callback_calls.append(r),
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=config,
        )
        loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
        )
        assert len(callback_calls) == 2
        # Each callback receives a VariantLoopResult
        for r in callback_calls:
            assert isinstance(r, VariantLoopResult)

    def test_run_aggregates_seeds_across_iterations(self):
        """The returned VariantLoopResult sums seeds across passes."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "x",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=3),
        )
        result = loop.run(
            [_make_finding(file="src/codec_a.c", line_number=9)],
            str(FIXTURE_C_PROPAGATION),
        )
        # Total patterns_generated should equal iterations (one per pass)
        assert result.patterns_generated == result.iterations


class TestRunnerVariantLoopIntegration:
    def test_runner_initializes_with_variant_loop_enabled(self, tmp_path):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            enable_variant_loop=True,
        )
        assert runner.enable_variant_loop is True

    def test_variant_loop_can_be_disabled(self, tmp_path):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner = SourceHuntRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            enable_variant_loop=False,
        )
        assert runner.enable_variant_loop is False
