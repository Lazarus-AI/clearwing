"""Future-compat tests pinning v0.2/v0.3 seams in the v0.1 schema.

These tests assert that the v0.1 types and APIs accept v0.2/v0.3 fields
and parameters without erroring. v0.1 code paths ignore them, but the
schema must accept them so future phases land as feature additions, not
refactors.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.findings.types import Finding
from clearwing.sourcehunt.preprocessor import Preprocessor
from clearwing.sourcehunt.state import (
    EVIDENCE_LEVELS,
    FileTarget,
    SourceHuntState,
)


FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"


# --- FileTarget v0.2 fields exist as TypedDict members ---------------------


class TestFileTargetSchema:
    def test_filetarget_accepts_callgraph_fields(self):
        ft: FileTarget = {
            "path": "x.c",
            "absolute_path": "/abs/x.c",
            "language": "c",
            "loc": 100,
            "tags": [],
            "static_hint": 0,
            "imports_by": 0,
            "defines_constants": False,
            "surface": 4,
            "influence": 2,
            "reachability": 3,
            "priority": 3.3,
            "tier": "B",
            "surface_rationale": "",
            "influence_rationale": "",
            "reachability_rationale": "",
            # v0.2 fields — these MUST be accepted by the schema
            "transitive_callers": 42,
            "semgrep_hint": 5,
            "has_fuzz_entry_point": True,
            "fuzz_harness_path": "/scratch/harness.c",
        }
        assert ft["transitive_callers"] == 42
        assert ft["semgrep_hint"] == 5
        assert ft["has_fuzz_entry_point"] is True
        assert ft["fuzz_harness_path"] == "/scratch/harness.c"

    def test_filetarget_v01_defaults_are_safe(self):
        """A FileTarget built with only v0.1 fields is still valid."""
        ft: FileTarget = {
            "path": "x.c",
            "absolute_path": "/abs/x.c",
            "language": "c",
            "loc": 100,
            "tags": [],
            "static_hint": 0,
            "imports_by": 0,
            "defines_constants": False,
            "surface": 4,
            "influence": 2,
            "reachability": 3,
            "priority": 3.3,
            "tier": "B",
            "surface_rationale": "",
            "influence_rationale": "",
            "reachability_rationale": "",
            "semgrep_hint": 0,
            "transitive_callers": 0,
            "has_fuzz_entry_point": False,
            "fuzz_harness_path": None,
        }
        assert ft["transitive_callers"] == 0


class TestSourceFindingSchema:
    def test_sourcefinding_accepts_v02_v03_fields(self):
        sf: Finding = {
            "id": "x",
            "file": "f.c",
            "line_number": 1,
            "end_line": None,
            "finding_type": "memory_safety",
            "cwe": "CWE-787",
            "severity": "high",
            "confidence": "high",
            "description": "x",
            "code_snippet": "",
            "crash_evidence": None,
            "poc": None,
            "evidence_level": "crash_reproduced",
            "discovered_by": "hunter:memory_safety",
            "related_finding_id": None,
            "related_cve": None,
            "seeded_from_crash": False,
            "verified": True,
            "severity_verified": "critical",
            # v0.2 adversarial verifier fields
            "verifier_pro_argument": "strong",
            "verifier_counter_argument": "weak",
            "verifier_tie_breaker": "tests show it",
            # v0.3 patch oracle / auto-patch fields
            "patch_oracle_passed": True,
            "auto_patch": "diff --git ...",
            "auto_patch_validated": True,
            "exploit": None,
            "exploit_success": None,
            "hunter_session_id": "s1",
            "verifier_session_id": "v1",
        }
        assert sf["verifier_counter_argument"] == "weak"
        assert sf["patch_oracle_passed"] is True
        assert sf["auto_patch_validated"] is True

    def test_sourcefinding_evidence_level_must_be_in_ladder(self):
        for level in EVIDENCE_LEVELS:
            sf: Finding = {"id": "x", "evidence_level": level}
            assert sf["evidence_level"] == level


class TestSourceHuntStateSchema:
    def test_state_has_v02_v03_seams(self):
        from langchain_core.messages import HumanMessage
        state: SourceHuntState = {
            "messages": [HumanMessage(content="hunt")],
            "repo_url": "x",
            "repo_path": "/x",
            "branch": "main",
            "files": [],
            "files_scanned": [],
            "current_file": None,
            # v0.2 seams
            "callgraph": {"node": "data"},
            "semgrep_findings": [{"hint": 1}],
            "fuzz_corpora": [{"name": "corpus"}],
            "seeded_crashes": [{"file": "x.c", "report": "asan"}],
            "findings": [],
            "verified_findings": [],
            # v0.3 seams
            "variant_seeds": [{"original": "id"}],
            "exploited_findings": [],
            "patch_attempts": [{"finding_id": "x", "validated": True}],
            "budget_usd": 10.0,
            "spent_usd": 0.0,
            "spent_per_tier": {"A": 0.0, "B": 0.0, "C": 0.0},
            "total_tokens": 0,
            "phase": "hunt",
            "session_id": "s1",
            "flags_found": [],
        }
        assert state["callgraph"] == {"node": "data"}
        assert state["seeded_crashes"][0]["report"] == "asan"
        assert state["variant_seeds"][0]["original"] == "id"


# --- Preprocessor v0.2 flags accepted but no-op ----------------------------


class TestPreprocessorV02Flags:
    def test_all_v02_flags_accepted(self, tmp_path):
        # Create a minimal repo
        (tmp_path / "main.py").write_text("def hi():\n    print('hi')\n")
        pp = Preprocessor(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            build_callgraph=True,
            run_semgrep=True,
            propagate_reachability=True,
            ingest_fuzz_corpora=True,
        )
        result = pp.run()
        # v0.2: callgraph is now built (if tree-sitter is installed)
        # v0.2 seams still no-op: semgrep and fuzz_corpora stay empty
        assert result is not None
        assert result.semgrep_findings == []
        assert result.fuzz_corpora == []
        # callgraph may or may not be None depending on whether tree-sitter
        # grammars are available in this environment


# --- Hunter / pool v0.2 parameters accepted --------------------------------


class TestHunterAcceptsV02Seams:
    def test_build_hunter_agent_accepts_seeded_crash_and_hints(self):
        from clearwing.sourcehunt.hunter import build_hunter_agent

        llm = MagicMock()
        llm.bind_tools.return_value = MagicMock()
        ft: FileTarget = {
            "path": "foo.c",
            "absolute_path": "/abs/foo.c",
            "language": "c",
            "loc": 50,
            "tags": [],
            "tier": "B",
            "surface": 3, "influence": 2, "reachability": 3, "priority": 2.5,
        }
        graph, ctx = build_hunter_agent(
            file_target=ft,
            repo_path="/tmp",
            sandbox=None,
            llm=llm,
            session_id="s1",
            seeded_crash={"report": "asan"},
            semgrep_hints=[{"line": 1, "description": "x"}],
            variant_seed={"original_finding_id": "f1"},
        )
        assert graph is not None
        assert ctx.seeded_crash == {"report": "asan"}


class TestPoolAcceptsV02Sandbox:
    def test_huntpool_config_accepts_sandbox_factory(self):
        from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig

        def factory():
            return MagicMock()

        cfg = HuntPoolConfig(
            files=[],
            repo_path="/tmp",
            sandbox_factory=factory,
        )
        pool = HunterPool(cfg)
        assert pool.config.sandbox_factory is factory


class TestRunnerAcceptsV02Seams:
    def test_runner_accepts_sandbox_factory(self, tmp_path):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        def sandbox_factory():
            return MagicMock()

        runner = SourceHuntRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            sandbox_factory=sandbox_factory,
        )
        assert runner.sandbox_factory is sandbox_factory
