"""Unit tests for the sourcehunt elaboration module (spec 008).

Critical assertions:
- Eligibility: requires verified + exploit attempt (partial or successful)
- Prioritization: severity > primitive quality > target value
- Cap: percentage and absolute counts work correctly
- ElaborationResult: defaults, full construction, serialization
- ElaborationAgent: no-sandbox graceful skip, eligibility gate
- record_elaboration_result tool: sets ctx.elaboration_result
- Finding loading: round-trip from JSON
- Pipeline: elaboration creates new findings, doesn't remove originals
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import asdict
from unittest.mock import MagicMock

from clearwing.sourcehunt.elaboration import (
    ElaborationAgent,
    _build_elaboration_prompt,
    build_elaboration_tools,
    find_latest_session,
    load_finding_from_session,
    load_session_findings,
    prioritize_for_elaboration,
)
from clearwing.sourcehunt.state import ElaborationResult


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "finding_type": "memory_safety",
        "cwe": "CWE-787",
        "severity": "high",
        "verified": True,
        "evidence_level": "crash_reproduced",
        "description": "memcpy overflow",
        "code_snippet": "memcpy(frame, input, input_len);",
        "crash_evidence": "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        "poc": "AAAA...300...AAAA",
        "exploit_success": True,
        "exploit_partial": False,
        "exploit_impact": "denial_of_service",
        "exploit_primitive_type": "bounded_write",
    }
    base.update(kwargs)
    return base


# --- ElaborationResult -------------------------------------------------------


class TestElaborationResult:
    def test_defaults(self):
        r = ElaborationResult(original_finding_id="x", elaborated=False)
        assert r.upgraded_impact is None
        assert r.upgraded_exploit_code is None
        assert r.chained_findings == []
        assert r.upgrade_path == ""
        assert r.blocking_mitigations == []
        assert r.human_guided is False
        assert r.cost == 0.0
        assert r.transcript_path == ""

    def test_full_construction(self):
        r = ElaborationResult(
            original_finding_id="x",
            elaborated=True,
            upgraded_impact="code_execution",
            upgraded_exploit_code="python3 exploit.py",
            chained_findings=["f-1", "f-2"],
            upgrade_path="heap spray -> ROP chain",
            blocking_mitigations=[],
            human_guided=True,
            cost=12.5,
            transcript_path="/tmp/transcript.jsonl",
        )
        assert r.elaborated is True
        assert r.upgraded_impact == "code_execution"
        assert r.chained_findings == ["f-1", "f-2"]
        assert r.human_guided is True

    def test_serializable(self):
        r = ElaborationResult(
            original_finding_id="x",
            elaborated=True,
            upgraded_impact="code_execution",
        )
        d = asdict(r)
        serialized = json.dumps(d)
        assert "code_execution" in serialized
        roundtrip = json.loads(serialized)
        assert roundtrip["elaborated"] is True


# --- Eligibility gate --------------------------------------------------------


class TestElaborationEligibility:
    def test_unverified_not_eligible(self):
        ae = ElaborationAgent(MagicMock())
        f = _make_finding(verified=False)
        assert ae.is_eligible(f) is False

    def test_no_exploit_not_eligible(self):
        ae = ElaborationAgent(MagicMock())
        f = _make_finding(exploit_partial=False, exploit_success=False)
        assert ae.is_eligible(f) is False

    def test_partial_exploit_eligible(self):
        ae = ElaborationAgent(MagicMock())
        f = _make_finding(exploit_partial=True, exploit_success=False)
        assert ae.is_eligible(f) is True

    def test_successful_exploit_eligible(self):
        ae = ElaborationAgent(MagicMock())
        f = _make_finding(exploit_success=True)
        assert ae.is_eligible(f) is True

    def test_low_evidence_not_eligible(self):
        ae = ElaborationAgent(MagicMock())
        f = _make_finding(evidence_level="suspicion")
        assert ae.is_eligible(f) is False


# --- Prioritization ----------------------------------------------------------


class TestPrioritization:
    def test_sort_by_severity_then_primitive(self):
        findings = [
            _make_finding(id="f1", severity="medium", exploit_primitive_type="bounded_write"),
            _make_finding(id="f2", severity="critical", exploit_primitive_type="arbitrary_write"),
            _make_finding(id="f3", severity="critical", exploit_primitive_type="info_leak"),
            _make_finding(id="f4", severity="high", exploit_primitive_type="use_after_free"),
        ]
        result = prioritize_for_elaboration(findings, cap=10)
        ids = [f["id"] for f in result]
        assert ids[0] == "f2"  # critical + arbitrary_write
        assert ids[1] == "f3"  # critical + info_leak
        assert ids[2] == "f4"  # high + use_after_free
        assert ids[3] == "f1"  # medium + bounded_write

    def test_cap_percentage(self):
        findings = [_make_finding(id=f"f{i}") for i in range(20)]
        result = prioritize_for_elaboration(findings, cap="10%")
        assert len(result) == max(1, math.ceil(20 * 0.10))

    def test_cap_absolute(self):
        findings = [_make_finding(id=f"f{i}") for i in range(20)]
        result = prioritize_for_elaboration(findings, cap=3)
        assert len(result) == 3

    def test_zero_eligible(self):
        findings = [_make_finding(verified=False)]
        result = prioritize_for_elaboration(findings, cap="10%")
        assert result == []

    def test_target_value_tiebreak(self):
        findings = [
            _make_finding(
                id="userspace",
                severity="critical",
                exploit_primitive_type="arbitrary_write",
                file="src/main.c",
            ),
            _make_finding(
                id="kernel",
                severity="critical",
                exploit_primitive_type="arbitrary_write",
                file="kernel/mm/slub.c",
            ),
        ]
        result = prioritize_for_elaboration(findings, cap=10)
        assert result[0]["id"] == "kernel"


# --- ElaborationAgent --------------------------------------------------------


class TestElaborationAgentNoSandbox:
    def test_no_sandbox_returns_not_attempted(self):
        import asyncio

        ae = ElaborationAgent(
            MagicMock(),
            sandbox_manager=None,
            sandbox_factory=None,
        )
        result = asyncio.run(ae.aattempt(_make_finding()))
        assert result.elaborated is False
        assert "No sandbox" in result.upgrade_path

    def test_ineligible_returns_not_attempted(self):
        import asyncio

        ae = ElaborationAgent(MagicMock())
        f = _make_finding(verified=False)
        result = asyncio.run(ae.aattempt(f))
        assert result.elaborated is False
        assert "not eligible" in result.upgrade_path

    def test_budget_bands_inherited(self):
        ae = ElaborationAgent(MagicMock(), budget_band="deep")
        assert ae._band["budget_usd"] == 200.0
        assert ae._band["timeout_seconds"] == 14400
        assert ae._band["max_steps"] == 2000


# --- Elaboration tools -------------------------------------------------------


class TestElaborationTools:
    def test_tools_include_record(self):
        from clearwing.agent.tools.hunt.sandbox import HunterContext

        ctx = HunterContext(repo_path="/tmp", file_path="src/main.c")
        finding = _make_finding()
        tools = build_elaboration_tools(ctx, finding)
        tool_names = [t.name for t in tools]
        assert "record_elaboration_result" in tool_names
        assert "execute" in tool_names
        assert "read_file" in tool_names

    def test_sets_ctx_elaboration_result(self):
        from clearwing.agent.tools.hunt.sandbox import HunterContext

        ctx = HunterContext(repo_path="/tmp", file_path="src/main.c")
        finding = _make_finding()
        tools = build_elaboration_tools(ctx, finding)
        record_tool = next(t for t in tools if t.name == "record_elaboration_result")

        result_str = record_tool.invoke(
            {
                "elaborated": True,
                "upgraded_impact": "code_execution",
                "upgraded_exploit_code": "python3 exploit.py",
                "upgrade_path": "heap spray -> ROP",
            }
        )
        assert "UPGRADED" in result_str
        assert ctx.elaboration_result is not None
        assert ctx.elaboration_result.elaborated is True
        assert ctx.elaboration_result.upgraded_impact == "code_execution"

    def test_partial_elaboration(self):
        from clearwing.agent.tools.hunt.sandbox import HunterContext

        ctx = HunterContext(repo_path="/tmp", file_path="src/main.c")
        finding = _make_finding()
        tools = build_elaboration_tools(ctx, finding)
        record_tool = next(t for t in tools if t.name == "record_elaboration_result")

        result_str = record_tool.invoke(
            {
                "elaborated": False,
                "blocking_mitigations": ["CFI", "KASLR"],
                "upgrade_path": "tried arbitrary write -> code exec",
            }
        )
        assert "NOT_UPGRADED" in result_str
        assert ctx.elaboration_result.elaborated is False
        assert ctx.elaboration_result.blocking_mitigations == ["CFI", "KASLR"]

    def test_successful_elaboration(self):
        from clearwing.agent.tools.hunt.sandbox import HunterContext

        ctx = HunterContext(repo_path="/tmp", file_path="src/main.c")
        finding = _make_finding()
        tools = build_elaboration_tools(ctx, finding)
        record_tool = next(t for t in tools if t.name == "record_elaboration_result")

        record_tool.invoke(
            {
                "elaborated": True,
                "upgraded_impact": "sandbox_escape",
                "chained_findings": ["f-info-leak"],
            }
        )
        assert ctx.elaboration_result.elaborated is True
        assert ctx.elaboration_result.upgraded_impact == "sandbox_escape"
        assert ctx.elaboration_result.chained_findings == ["f-info-leak"]


# --- Finding loading ---------------------------------------------------------


class TestFindingLoading:
    def test_load_finding_from_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = os.path.join(tmpdir, "session-001")
            os.makedirs(session_dir)
            findings = [_make_finding(id="f-target"), _make_finding(id="f-other")]
            with open(os.path.join(session_dir, "findings.json"), "w") as f:
                json.dump({"findings": findings, "verified_findings": []}, f)

            result = load_finding_from_session(tmpdir, "session-001", "f-target")
            assert result is not None
            assert result["id"] == "f-target"

    def test_missing_session_returns_none(self):
        result = load_finding_from_session("/nonexistent", "no-session", "f-1")
        assert result is None

    def test_missing_finding_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = os.path.join(tmpdir, "session-001")
            os.makedirs(session_dir)
            with open(os.path.join(session_dir, "findings.json"), "w") as f:
                json.dump({"findings": [_make_finding(id="f-other")]}, f)

            result = load_finding_from_session(tmpdir, "session-001", "f-missing")
            assert result is None

    def test_load_session_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = os.path.join(tmpdir, "session-001")
            os.makedirs(session_dir)
            findings = [_make_finding(id="f1"), _make_finding(id="f2")]
            with open(os.path.join(session_dir, "findings.json"), "w") as f:
                json.dump({"findings": findings}, f)

            result = load_session_findings(tmpdir, "session-001")
            assert len(result) == 2

    def test_find_latest_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for sid in ["session-001", "session-002"]:
                session_dir = os.path.join(tmpdir, sid)
                os.makedirs(session_dir)
                with open(os.path.join(session_dir, "manifest.json"), "w") as f:
                    json.dump({"session_id": sid}, f)

            result = find_latest_session(tmpdir)
            assert result in ("session-001", "session-002")

    def test_find_latest_session_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_latest_session(tmpdir)
            assert result is None


# --- Prompt builder ----------------------------------------------------------


class TestElaborationPrompt:
    def test_prompt_has_primitive_and_impact(self):
        f = _make_finding(
            exploit_impact="denial_of_service",
            exploit_primitive_type="bounded_write",
        )
        prompt = _build_elaboration_prompt(f)
        assert "denial_of_service" in prompt
        assert "bounded_write" in prompt

    def test_prompt_pool_context_included(self):
        mock_pool = MagicMock()
        mock_pool.summary.return_value = "3 findings: 1 arbitrary_read, 2 bounded_write"
        f = _make_finding()
        prompt = _build_elaboration_prompt(f, findings_pool=mock_pool)
        assert "arbitrary_read" in prompt
        assert "query_findings_pool" in prompt

    def test_prompt_pool_context_absent_without_pool(self):
        f = _make_finding()
        prompt = _build_elaboration_prompt(f, findings_pool=None)
        assert "Other findings" not in prompt

    def test_prompt_verifier_context(self):
        f = _make_finding(
            verifier_counter_argument="Stack canary protects this path",
            verifier_pro_argument="Input reaches memcpy unchecked",
        )
        prompt = _build_elaboration_prompt(f)
        assert "Stack canary" in prompt
        assert "memcpy unchecked" in prompt

    def test_prompt_target_class_kernel(self):
        f = _make_finding(file="kernel/mm/slub.c")
        prompt = _build_elaboration_prompt(f)
        assert "kernel" in prompt.lower()


# --- Pipeline integration (runner) -------------------------------------------


class TestRunnerElaboration:
    def test_elaboration_disabled_by_default(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        r = SourceHuntRunner(repo_url="test", depth="standard")
        assert r.enable_elaboration is False

    def test_elaboration_enabled_with_flag(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        r = SourceHuntRunner(
            repo_url="test",
            depth="standard",
            enable_elaboration=True,
        )
        assert r.enable_elaboration is True

    def test_apply_elaboration_creates_new_finding(self):
        from clearwing.sourcehunt.runner import _apply_elaboration

        finding = _make_finding(id="original-123")
        elab_result = ElaborationResult(
            original_finding_id="original-123",
            elaborated=True,
            upgraded_impact="code_execution",
            upgraded_exploit_code="python3 exploit.py",
            chained_findings=["f-info-leak"],
            upgrade_path="heap spray -> ROP chain",
        )
        new_finding = _apply_elaboration(finding, elab_result)
        repeated = _apply_elaboration(finding, elab_result)
        assert new_finding["id"].startswith("elab-")
        assert len(new_finding["id"]) == len("elab-") + 8
        assert repeated["id"] != new_finding["id"]
        assert repeated["stable_finding_id"] == new_finding["stable_finding_id"]
        assert len(new_finding["stable_finding_id"]) == len("elab-") + 16
        assert new_finding["related_finding_id"] == "original-123"
        assert new_finding["severity"] == "critical"
        assert new_finding["severity_verified"] == "critical"
        assert new_finding["evidence_level"] == "exploit_demonstrated"
        assert new_finding["discovered_by"] == "elaboration_agent"
        assert new_finding["exploit"] == "python3 exploit.py"
        assert new_finding["elaboration_upgrade_path"] == "heap spray -> ROP chain"
        # Original finding unchanged
        assert finding["id"] == "original-123"

    def test_apply_elaboration_preserves_original(self):
        from clearwing.sourcehunt.runner import _apply_elaboration

        finding = _make_finding(id="original-456", severity="high")
        elab_result = ElaborationResult(
            original_finding_id="original-456",
            elaborated=True,
            upgraded_impact="privilege_escalation",
        )
        new_finding = _apply_elaboration(finding, elab_result)
        # Original is unmodified
        assert finding["severity"] == "high"
        assert finding["id"] == "original-456"
        # New finding is separate
        assert new_finding["id"] != "original-456"
        assert new_finding["severity_verified"] == "critical"
