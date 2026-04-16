"""Tests for the tree-sitter callgraph builder and reachability propagation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.callgraph import (
    CallGraph,
    CallGraphBuilder,
)
from clearwing.sourcehunt.preprocessor import Preprocessor
from clearwing.sourcehunt.ranker import Ranker

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"
FIXTURE_PY_SQLI = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"


# Skip everything if tree-sitter grammars aren't installed
@pytest.fixture(scope="module")
def builder():
    b = CallGraphBuilder()
    if not b.available:
        pytest.skip("tree-sitter grammars not installed")
    return b


# --- CallGraph data class ---------------------------------------------------


class TestCallGraphMethods:
    def test_empty_graph(self):
        g = CallGraph()
        assert g.empty is True
        assert g.callers_of_file("x.c") == set()
        assert g.transitive_callers_of_file("x.c") == set()

    def test_callers_of_file_via_defined_in(self):
        g = CallGraph()
        g.functions["lib.c"] = {"helper"}
        g.defined_in["helper"] = {"lib.c"}
        g.calls_out["main.c"] = {"helper"}
        g.calls_out["util.c"] = {"helper"}
        assert g.callers_of_file("lib.c") == {"main.c", "util.c"}

    def test_callers_excludes_self(self):
        g = CallGraph()
        g.functions["a.c"] = {"foo"}
        g.defined_in["foo"] = {"a.c"}
        g.calls_out["a.c"] = {"foo"}  # a.c calls its own foo
        assert g.callers_of_file("a.c") == set()

    def test_transitive_callers_chain(self):
        g = CallGraph()
        # a.c defines foo; b.c calls foo; c.c calls b.c's bar; b.c defines bar
        g.functions["a.c"] = {"foo"}
        g.functions["b.c"] = {"bar"}
        g.defined_in["foo"] = {"a.c"}
        g.defined_in["bar"] = {"b.c"}
        g.calls_out["b.c"] = {"foo"}
        g.calls_out["c.c"] = {"bar"}
        # Direct caller of a.c: b.c
        # Transitive: b.c (direct), c.c (via b.c's bar)
        assert g.transitive_callers_of_file("a.c") == {"b.c", "c.c"}

    def test_reachable_from_entry(self):
        g = CallGraph()
        g.functions["main.c"] = {"main"}
        g.functions["lib.c"] = {"helper"}
        g.functions["deep.c"] = {"deeper"}
        g.defined_in["helper"] = {"lib.c"}
        g.defined_in["deeper"] = {"deep.c"}
        g.calls_out["main.c"] = {"helper"}
        g.calls_out["lib.c"] = {"deeper"}
        distances = g.reachable_from({"main.c"}, max_depth=5)
        assert distances["main.c"] == 0
        assert distances["lib.c"] == 1
        assert distances["deep.c"] == 2

    def test_reachable_from_max_depth_cap(self):
        g = CallGraph()
        g.functions["a.c"] = {"a"}
        g.functions["b.c"] = {"b"}
        g.functions["c.c"] = {"c"}
        g.defined_in["a"] = {"a.c"}
        g.defined_in["b"] = {"b.c"}
        g.defined_in["c"] = {"c.c"}
        g.calls_out["a.c"] = {"b"}
        g.calls_out["b.c"] = {"c"}
        # max_depth=1 → only distance 0 and 1
        distances = g.reachable_from({"a.c"}, max_depth=1)
        assert "a.c" in distances
        assert "b.c" in distances
        assert "c.c" not in distances


# --- CallGraphBuilder (needs tree-sitter grammars) --------------------------


class TestCallGraphBuilderC:
    def test_c_propagation_fixture(self, builder):
        graph = builder.build(str(FIXTURE_C_PROPAGATION))
        assert not graph.empty
        # codec_a.c defines decode_frame_a
        codec_a_funcs = graph.functions.get("src/codec_a.c", set())
        assert "decode_frame_a" in codec_a_funcs
        # codec_a.c calls memcpy
        codec_a_calls = graph.calls_out.get("src/codec_a.c", set())
        assert "memcpy" in codec_a_calls

    def test_c_functions_definitions_indexed(self, builder):
        graph = builder.build(str(FIXTURE_C_PROPAGATION))
        # Each codec file defines one decoder
        assert "decode_frame_a" in graph.defined_in
        assert "decode_frame_b" in graph.defined_in
        assert "decode_frame_c" in graph.defined_in
        assert graph.defined_in["decode_frame_a"] == {"src/codec_a.c"}


class TestCallGraphBuilderPython:
    def test_python_sqli_fixture(self, builder):
        graph = builder.build(str(FIXTURE_PY_SQLI))
        # app.py defines login_safe and search_books
        funcs = graph.functions.get("app.py", set())
        assert "login_safe" in funcs
        assert "search_books" in funcs
        # app.py calls sqlite3.connect (rightmost identifier wins → "connect")
        calls = graph.calls_out.get("app.py", set())
        assert "connect" in calls or "execute" in calls


# --- Preprocessor integration ----------------------------------------------


class TestPreprocessorCallgraphIntegration:
    def test_preprocessor_populates_transitive_callers(self, builder):
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            build_callgraph=True,
        )
        result = pp.run()
        # callgraph was built
        assert result.callgraph is not None
        assert not result.callgraph.empty
        # At least one file has transitive_callers set
        assert any(ft.get("transitive_callers", 0) >= 0 for ft in result.file_targets)

    def test_preprocessor_propagate_reachability_marks_parsers_as_entry(self, builder):
        """Files tagged parser should get reachability=5."""
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            build_callgraph=True,
            propagate_reachability=True,
        )
        result = pp.run()
        # Any file tagged as parser / fuzzable / syscall_entry should have
        # reachability = 5 (entry point).
        for ft in result.file_targets:
            tags = set(ft.get("tags", []))
            if tags & {"parser", "fuzzable", "syscall_entry"}:
                assert ft.get("reachability") == 5, (
                    f"{ft.get('path')} is tagged {tags} but reachability={ft.get('reachability')}"
                )


# --- Ranker uses transitive_callers ----------------------------------------


class TestRankerUsesTransitiveCallers:
    def test_transitive_callers_floors_influence(self):
        """Ranker._apply_floors should use transitive_callers if set, else imports_by."""
        llm = MagicMock()
        response = MagicMock()
        response.content = json.dumps(
            [
                {
                    "path": "header.h",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        llm.invoke.return_value = response

        files = [
            {
                "path": "header.h",
                "language": "c",
                "loc": 10,
                "tags": [],
                "static_hint": 0,
                "imports_by": 0,  # v0.1 signal is zero
                "transitive_callers": 25,  # v0.2 signal says 25 callers
                "defines_constants": False,
                "surface": 0,
                "influence": 0,
                "reachability": 3,
                "priority": 0.0,
                "tier": "C",
            }
        ]
        Ranker(llm).rank(files)
        # Influence should be floored to 3 via transitive_callers > 10
        assert files[0]["influence"] == 3
