"""Prompt/scaffold optimization seams and benchmark leakage guards."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from genai_pyo3 import ChatMessage, ToolCall, Usage

from clearwing.agent.tools.hunt.candidates import build_candidate_tools
from clearwing.agent.tools.hunt.reporting import build_reporting_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.agent.tools.hunt.windows import rank_source_windows
from clearwing.eval.sourcehunt import GroundTruthManifest
from clearwing.sourcehunt.context import SourceHuntContextManager, estimate_request_tokens
from clearwing.sourcehunt.hunter import build_hunter_agent
from clearwing.sourcehunt.optimization import (
    GENERIC_DISCOVERY_V1,
    get_context_profile,
    get_prompt_bundle,
    get_scaffold_profile,
    lint_prompt_candidate,
    redact_benchmark_terms,
    require_generic_prompt,
)
from clearwing.sourcehunt.static_signals import (
    is_production_source_path,
    score_source_security_signals,
)


def _target(path: str = "src/parser.c") -> dict:
    return {
        "path": path,
        "tier": "B",
        "language": "c",
        "loc": 100,
        "tags": ["parser", "memory_unsafe"],
        "imports_by": 0,
    }


def test_generic_prompt_template_passes_full_manifest_leakage_lint() -> None:
    manifest = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")

    require_generic_prompt(GENERIC_DISCOVERY_V1, manifest=manifest)


def test_leakage_linter_rejects_answer_bearing_prompt() -> None:
    manifest = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")
    case = manifest.cases[0]
    candidate = (
        f"Audit {case.repository} and {case.ground_truth.target_files[0]} "
        f"at {case.vulnerable_commit}. "
        f"Look for {case.ground_truth.expected_mechanisms[0]} and CWE-787."
    )

    leaks = lint_prompt_candidate(candidate, manifest=manifest)

    categories = {leak.category for leak in leaks}
    assert {"repository", "commit", "target_file", "mechanism", "expected_cwe"} <= categories
    with pytest.raises(ValueError, match="leaks benchmark answers"):
        require_generic_prompt(candidate, manifest=manifest)

    redacted = redact_benchmark_terms(candidate, manifest)
    assert not lint_prompt_candidate(redacted, manifest=manifest)


def test_generic_bundle_excludes_historical_solution_context() -> None:
    hunter, ctx = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="generic",
        prompt_mode="specialist",
        prompt_bundle="generic-security-v1",
        seed_context="CVE-2099-99999 known_solution_symbol",
    )

    assert ctx.specialist == "generic"
    assert "ORIENT" in hunter.prompt
    assert "CHALLENGE" in hunter.prompt
    assert "CVE-2099-99999" not in hunter.prompt
    assert "known_solution_symbol" not in hunter.prompt
    assert "SENTINEL / COUNTER COLLISIONS" not in hunter.prompt


def test_minimal_linear_scaffold_reduces_constrained_tool_surface() -> None:
    hunter, _ = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="minimal",
        prompt_bundle="generic-security-v1",
        scaffold_profile="minimal-linear-v1",
    )

    assert {tool.name for tool in hunter.tools} == {
        "read_source_file",
        "grep_source",
        "record_trace_step",
        "record_finding",
    }
    assert "READ -> CANDIDATES -> INVESTIGATE -> CHALLENGE -> SUBMIT" in hunter.prompt


def test_minimal_linear_scaffold_reduces_deep_tool_surface() -> None:
    hunter, _ = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="minimal-deep",
        agent_mode="deep",
        prompt_bundle="generic-security-v1",
        scaffold_profile="minimal-linear-v1",
    )

    assert {tool.name for tool in hunter.tools} == {
        "execute",
        "read_file",
        "record_trace_step",
        "record_finding",
    }


def test_hunter_step_override_bounds_deep_optimization_runs() -> None:
    hunter, _ = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="bounded-deep",
        agent_mode="deep",
        prompt_bundle="generic-security-v1",
        scaffold_profile="minimal-linear-v1",
        max_steps_override=40,
    )

    assert hunter.max_steps == 40


def test_candidate_ledger_scaffold_persists_explicit_hypotheses() -> None:
    hunter, ctx = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="candidate-ledger",
        prompt_bundle="generic-security-v1",
        scaffold_profile="candidate-ledger-v1",
    )
    tools = {tool.name: tool for tool in hunter.tools}

    output = tools["record_candidate"].invoke(
        {
            "candidate_id": "C1",
            "status": "investigating",
            "file": "src/parser.c",
            "line": 42,
            "hypothesis": "unchecked length may exceed an allocation",
            "attacker_control": "packet length",
            "invariant": "copy length stays within the destination",
            "effect": "out-of-bounds write",
            "counterargument": "a caller may cap the length",
            "next_check": "inspect all callers for a dominating cap",
            "evidence": "allocation and copy use different expressions",
        }
    )

    assert set(tools) == {
        "read_source_file",
        "grep_source",
        "record_candidate",
        "record_trace_step",
        "record_finding",
    }
    assert ctx.candidates["C1"]["next_check"] == "inspect all callers for a dominating cap"
    assert "Active queue (1)" in output
    assert "Do not sweep the file sequentially" in hunter.prompt


def test_candidate_ledger_closure_is_a_versioned_runtime_treatment() -> None:
    hunter, _ = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="candidate-ledger-closure",
        prompt_bundle="generic-security-v1",
        scaffold_profile="candidate-ledger-closure-v1",
    )

    assert {tool.name for tool in hunter.tools} == {
        "read_source_file",
        "grep_source",
        "record_candidate",
        "record_trace_step",
        "record_finding",
    }
    assert hunter.closing_steps == 3
    assert "Budget closure" not in hunter.prompt


def test_candidate_ledger_source_retry_is_a_versioned_runtime_treatment() -> None:
    hunter, _ = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="candidate-ledger-source-retry",
        prompt_bundle="generic-security-v1",
        scaffold_profile="candidate-ledger-source-retry-v1",
    )

    assert hunter.initial_source_action_retries == 1
    assert "No source tool ran" not in hunter.prompt


def test_candidate_ledger_active_submission_gate_is_versioned() -> None:
    hunter, ctx = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="candidate-ledger-source-retry-active",
        prompt_bundle="generic-security-v1",
        scaffold_profile="candidate-ledger-source-retry-active-v1",
    )

    assert hunter.initial_source_action_retries == 1
    assert ctx.require_active_candidate_before_finding is True
    assert "No source tool ran" not in hunter.prompt


def test_generic_source_window_ranker_prioritizes_diverse_risky_regions() -> None:
    lines = ["int harmless = 0;" for _ in range(220)]
    lines[19] = "char *buf = malloc(user_len);"
    lines[109] = "state->generation = ++global_generation;"
    lines[189] = "memcpy(dst, packet, packet_len);"

    windows = rank_source_windows("\n".join(lines), max_windows=3, window_lines=40)

    assert [window["anchor_line"] for window in windows] == [190, 20, 110]
    assert {signal for window in windows for signal in window["signals"]} >= {
        "memory_operation",
        "allocation_lifetime",
        "representation_transition",
    }


def test_file_signal_score_caps_repetition_and_rewards_category_coverage() -> None:
    repeated = "\n".join("memcpy(dst, src, len);" for _ in range(100))
    diverse = """
    packet = read_input();
    if (packet_size + offset > buffer_len) return -1;
    dst[index] = (uint16_t)packet[value];
    memset(state, -1, sizeof(*state));
    free(state);
    """

    repeated_score = score_source_security_signals(repeated)
    diverse_score = score_source_security_signals(diverse)

    assert diverse_score.score > repeated_score.score
    assert diverse_score.diversity > repeated_score.diversity
    assert repeated_score.counts["memory_operation"] == 100


def test_production_source_filter_is_repository_independent() -> None:
    assert is_production_source_path("src/codec/decode.c") is True
    assert is_production_source_path("docs/examples/decode.c") is False
    assert is_production_source_path("tools/target_decoder_fuzzer.c") is False


def test_window_ledger_requires_ranked_windows_before_candidates() -> None:
    hunter, ctx = build_hunter_agent(
        file_target=_target("src/codec_a.c"),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="window-ledger",
        prompt_bundle="generic-security-v1",
        scaffold_profile="window-ledger-v1",
    )
    tools = {tool.name: tool for tool in hunter.tools}

    result = tools["rank_source_windows"].invoke(
        {"path": "src/codec_a.c", "max_windows": 4, "window_lines": 40}
    )

    assert set(tools) == {
        "rank_source_windows",
        "read_source_file",
        "grep_source",
        "record_candidate",
        "record_trace_step",
        "record_finding",
    }
    assert ctx.source_windows_ranked is True
    assert result["path"] == "src/codec_a.c"
    assert hunter.require_source_windows is True


def test_guided_window_ledger_reads_ranked_windows_without_line_translation() -> None:
    hunter, ctx = build_hunter_agent(
        file_target=_target("src/codec_a.c"),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="guided-window-ledger",
        prompt_bundle="generic-security-v1",
        scaffold_profile="guided-window-ledger-v1",
        context_profile="compact-small-model-v1",
    )
    tools = {tool.name: tool for tool in hunter.tools}

    plan = tools["rank_source_windows"].invoke(
        {"path": "src/codec_a.c", "max_windows": 4, "window_lines": 40}
    )
    first = tools["read_ranked_window"].invoke({"window_id": "W1"})
    repeated_plan = tools["rank_source_windows"].invoke({"path": "src/codec_a.c"})

    assert plan["windows"][0]["window_id"] == "W1"
    assert "src/codec_a.c:" in first
    assert ctx.source_windows_read == {"W1"}
    assert "already exists" in repeated_plan["instruction"]
    assert hunter.ranked_windows_before_candidate == 3


def test_state_interaction_packet_connects_generic_state_roles(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    header = tmp_path / "src" / "target.h"
    source.parent.mkdir()
    source.write_text(
        """
        #include "target.h"
        void reset(Context *ctx) { memset(ctx->slot_state, -1, sizeof(ctx->slot_state)); }
        void update(Context *ctx, int i) { ctx->slot_state[i] = ctx->generation; }
        int check(Context *ctx, int i) { return ctx->slot_state[i] == 0xFFFF; }
        void consume(Context *ctx, int i, char *dst, const char *src) {
            int use_neighbor = ctx->slot_state[i] == 0xFFFF;
            char *selected = ctx->borders[i - 1];
            if (use_neighbor) {
                memcpy(selected, src, 8);
            }
        }
        void advance(Context *ctx) { ctx->generation = ++global_generation; }
        """,
        encoding="utf-8",
    )
    header.write_text(
        """
        typedef struct Context {
            uint16_t slot_state[64];
            int generation;
        } Context;
        """,
        encoding="utf-8",
    )
    hunter, ctx = build_hunter_agent(
        file_target=_target("src/target.c"),
        repo_path=str(tmp_path),
        sandbox=None,
        llm=MagicMock(),
        session_id="state-interactions",
        prompt_bundle="generic-security-v1",
        scaffold_profile="state-interaction-ledger-v1",
        context_profile="compact-small-model-v1",
    )
    tools = {tool.name: tool for tool in hunter.tools}

    plan = tools["rank_source_windows"].invoke(
        {"path": "src/target.c", "max_windows": 3, "window_lines": 20}
    )
    tools["read_ranked_window"].invoke({"window_id": "W1"})
    packet = tools["read_state_interactions"].invoke({"window_id": "W1"})

    assert set(tools) == {
        "rank_source_windows",
        "read_ranked_window",
        "read_state_interactions",
        "read_domain_consequences",
        "record_value_domain",
        "record_domain_consequence",
        "record_domain_proof",
        "read_source_file",
        "grep_source",
        "record_candidate",
        "record_trace_step",
        "record_finding",
    }
    assert plan["windows"][0]["window_id"] == "W1"
    assert "Primary state: slot_state" in packet
    assert "uint16_t slot_state[64]" in packet
    assert "slot_state[i] = ctx->generation" in packet
    assert "slot_state[i] == 0xFFFF" in packet
    assert "generation = ++global_generation" in packet
    assert ctx.value_domain_plans["D1"]["producer_tokens"] == ["generation"]
    tools["record_value_domain"].invoke(
        {
            "domain_id": "D1",
            "guard": "none observed",
            "assessment": "overlap_possible",
            "evidence": "the producer reaches storage and storage reserves 0xFFFF",
            "next_check": "check whether generation can equal 0xFFFF",
        }
    )
    consequence_packet = tools["read_domain_consequences"].invoke({"domain_id": "D1"})
    assert "Derived branch-to-effect chains:" in consequence_packet
    assert "use_neighbor" in consequence_packet
    assert "memcpy(selected, src, 8)" in consequence_packet
    assert {"use_neighbor", "memcpy", "selected"} <= set(
        ctx.domain_consequence_plans["D1"]["impact_tokens"]
    )
    assert ctx.domain_consequence_plans["D1"]["boundary_facts"] == [
        {"line": 8, "token": "i", "expression": "i - 1"}
    ]
    tools["record_candidate"].invoke(
        {
            "candidate_id": "C1",
            "status": "investigating",
            "file": "src/target.c",
            "line": 5,
            "hypothesis": "slot_state can store a generation that aliases reserved state",
            "attacker_control": "input-driven generation advances",
            "invariant": "slot_state live generations differ from distinguished values",
            "effect": "the changed branch reaches a boundary memory effect",
            "counterargument": "a producer guard may exclude the value",
            "next_check": "resolve the four domain proof obligations",
            "evidence": "slot_state and generation interact across the packet",
        }
    )
    proof = tools["record_domain_proof"].invoke(
        {
            "domain_id": "D1",
            "candidate_id": "C1",
            "attacker_reaches_producer": True,
            "producer_reaches_distinguished": True,
            "changed_branch_reaches_effect": True,
            "boundary_effect_unguarded": True,
            "evidence": "src/target.c:5, src/target.c:6, src/target.c:7, src/target.c:8",
            "counterevidence": "none observed",
        }
    )

    assert "validated C1" in proof
    assert ctx.candidates["C1"]["status"] == "validated"
    assert [step.note for step in ctx.trace_steps] == [
        "source",
        "state sink",
        "condition",
        "effect sink",
    ]
    finding = tools["record_finding"].invoke(
        {
            "candidate_id": "C1",
            "file": "src/target.c",
            "line_number": 8,
            "finding_type": "memory_safety",
            "severity": "high",
            "description": "A validated state-domain collision reaches a boundary memory effect.",
            "evidence_level": "static_corroboration",
        }
    )
    assert "Finding recorded" in finding
    assert [step["note"] for step in ctx.findings[0].vulnerability_trace["steps"]] == [
        "source",
        "state sink",
        "condition",
        "effect sink",
    ]
    assert ctx.state_packets_read == {"W1"}
    assert hunter.state_packets_before_candidate == 1


def test_proof_refinement_is_on_demand_and_obligation_specific(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    source.parent.mkdir()
    source.write_text(
        """
        int produce(Context *ctx) { return ++ctx->generation; }
        int dispatch(Context *ctx) { return produce(ctx); }
        int parse(Context *ctx, int count) {
            for (int i = 0; i < count; i++) {
                dispatch(ctx);
            }
            return 0;
        }
        """,
        encoding="utf-8",
    )
    hunter, ctx = build_hunter_agent(
        file_target=_target("src/target.c"),
        repo_path=str(tmp_path),
        sandbox=None,
        llm=MagicMock(),
        session_id="refinement",
        prompt_bundle="generic-security-v1",
        scaffold_profile="proof-refinement-ledger-v1",
        context_profile="compact-small-model-v1",
    )
    ctx.value_domains["D1"] = {
        "domain_id": "D1",
        "target_path": "src/target.c",
        "trace_facts": [
            {
                "role": "source",
                "file": "src/target.c",
                "line": 2,
                "code_snippet": "return ++ctx->generation;",
            }
        ],
    }
    ctx.domain_consequence_plans["D1"] = {"trace_facts": [], "boundary_facts": []}
    tools = {tool.name: tool for tool in hunter.tools}

    before_proof = tools["read_domain_proof_refinement"].invoke(
        {"domain_id": "D1", "obligation": "attacker_reaches_producer"}
    )
    assert "call record_domain_proof" in before_proof

    ctx.domain_proof_obligations["D1"] = ["attacker_reaches_producer"]
    wrong_obligation = tools["read_domain_proof_refinement"].invoke(
        {"domain_id": "D1", "obligation": "changed_branch_reaches_effect"}
    )
    packet = tools["read_domain_proof_refinement"].invoke(
        {"domain_id": "D1", "obligation": "attacker_reaches_producer"}
    )
    repeated = tools["read_domain_proof_refinement"].invoke(
        {"domain_id": "D1", "obligation": "attacker_reaches_producer"}
    )

    assert "refine only a recorded unresolved obligation" in wrong_obligation
    assert "Proof refinement for attacker_reaches_producer" in packet
    assert "for (int i = 0; i < count; i++)" in packet
    assert "dispatch(ctx)" in packet
    assert len(packet) < 1_200
    assert "already read" in repeated
    assert ctx.domain_refinement_pending_proof == {"D1"}


def test_refinement_schema_is_hidden_until_proof_records_a_gap() -> None:
    hunter, ctx = build_hunter_agent(
        file_target=_target(),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="refinement-schema",
        prompt_bundle="generic-security-v1",
        scaffold_profile="proof-refinement-ledger-v1",
        context_profile="compact-small-model-v1",
    )

    assert "read_domain_proof_refinement" not in {
        tool.name for tool in hunter._request_tools()
    }
    ctx.domain_proof_obligations["D1"] = ["attacker_reaches_producer"]
    assert "read_domain_proof_refinement" in {
        tool.name for tool in hunter._request_tools()
    }


def test_value_domain_closure_requires_producer_bound_and_distinguished_value(
    tmp_path,
) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    ctx.value_domain_plans["D1"] = {
        "stored_state": "slot_state",
        "producer_state": "generation",
        "producer_tokens": ["generation", "global_generation"],
        "blocking_guard_locations": ["src/target.c:9"],
        "distinguished_tokens": ["0xFFFF"],
    }
    ctx.domain_consequence_plans["D1"] = {"domain_id": "D1"}
    tools = {tool.name: tool for tool in build_candidate_tools(ctx)}

    opened = tools["record_value_domain"].invoke(
        {
            "domain_id": "D1",
            "guard": "none observed",
            "assessment": "overlap_possible",
            "evidence": "producer reaches storage and storage reserves 0xFFFF",
            "next_check": "check whether generation can equal 0xFFFF",
        }
    )
    consequence = tools["record_domain_consequence"].invoke(
        {
            "domain_id": "D1",
            "branch_effect": "reserved-state branch accepts a live value",
            "state_effect": "live state is misclassified",
            "security_effect": "memory access uses the wrong neighbor state",
            "assessment": "security_effect_possible",
            "evidence": "consumer branch and downstream memory operation",
            "next_check": "trace generation reaching 0xFFFF",
        }
    )

    unrelated = tools["record_value_domain"].invoke(
        {
            "domain_id": "D1",
            "guard": "allocation size bounds all table indexes",
            "assessment": "overlap_blocked",
            "evidence": "the allocation is in bounds and generation would need 0xFFFF",
            "next_check": "none",
        }
    )
    premature_benign = tools["record_domain_consequence"].invoke(
        {
            "domain_id": "D1",
            "branch_effect": "table indexes are in bounds",
            "state_effect": "allocation is large enough",
            "security_effect": "none",
            "assessment": "benign",
            "evidence": "allocation calculation and maximum index",
            "next_check": "none",
        }
    )
    practical_limit = tools["record_value_domain"].invoke(
        {
            "domain_id": "D1",
            "guard": "generation needs 65535 increments after each reset, which is impractical",
            "assessment": "overlap_blocked",
            "evidence": "generation would need to reach distinguished value 0xFFFF",
            "next_check": "none",
        }
    )

    assert "overlap_possible" in opened
    assert "security_effect_possible" in consequence
    assert "must constrain the extracted producer chain" in unrelated
    assert "requires an extracted source guard" in practical_limit
    assert "cannot be marked benign" in premature_benign
    assert ctx.value_domains["D1"]["assessment"] == "overlap_possible"
    assert ctx.domain_consequences["D1"]["assessment"] == "security_effect_possible"

    closed = tools["record_value_domain"].invoke(
        {
            "domain_id": "D1",
            "guard": "src/target.c:9 rejects when global_generation >= 0xFFFF",
            "assessment": "disjoint",
            "evidence": (
                "src/target.c:9 returns before assignment and prevents generation from taking "
                "distinguished value 0xFFFF"
            ),
            "next_check": "confirm the guard dominates the transfer",
        }
    )

    assert "disjoint" in closed
    assert ctx.value_domains["D1"]["assessment"] == "disjoint"


def test_candidate_domain_matching_ignores_unresolved_placeholders() -> None:
    ctx = HunterContext(repo_path="/repo")
    ctx.value_domains["D1"] = {
        "stored_state": "interim",
        "producer_state": "unknown",
        "producer_tokens": [],
        "distinguished_tokens": [],
        "assessment": "overlap_possible",
    }
    ctx.domain_consequences["D1"] = {"assessment": "security_effect_possible"}
    tools = {tool.name: tool for tool in build_candidate_tools(ctx)}

    result = tools["record_candidate"].invoke(
        {
            "candidate_id": "C1",
            "status": "investigating",
            "file": "src/decoder.c",
            "hypothesis": "interim samples may cross the allocated block boundary",
            "invariant": "interim remains within its allocation",
            "evidence": "the copy length and allocation use different bounds",
        }
    )

    assert "Candidate C1 saved" in result
    assert ctx.domain_candidate_ids == {"D1": "C1"}
    assert "unknown" not in ctx.candidates["C1"]["next_check"]


def test_domain_proof_requires_guard_reassessment_and_all_obligations(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    ctx.enable_domain_proof_refinement = True
    ctx.value_domains["D1"] = {
        "domain_id": "D1",
        "stored_state": "slot_state",
        "producer_state": "generation",
        "assessment": "overlap_possible",
        "blocking_guard_locations": ["src/target.c:9"],
        "trace_facts": [],
    }
    ctx.domain_consequence_plans["D1"] = {
        "domain_id": "D1",
        "boundary_facts": [{"line": 12, "token": "i", "expression": "i - 1"}],
        "trace_facts": [],
    }
    ctx.domain_candidate_ids["D1"] = "C1"
    ctx.candidates["C1"] = {"candidate_id": "C1", "status": "investigating"}
    tools = {tool.name: tool for tool in build_candidate_tools(ctx)}
    proof_args = {
        "domain_id": "D1",
        "candidate_id": "C1",
        "attacker_reaches_producer": True,
        "producer_reaches_distinguished": True,
        "changed_branch_reaches_effect": True,
        "boundary_effect_unguarded": True,
        "evidence": "src/target.c:3, src/target.c:7, src/target.c:12",
        "counterevidence": "src/target.c:9 may terminate the producer path",
    }

    guarded = tools["record_domain_proof"].invoke(proof_args)
    assert "record_value_domain first" in guarded
    assert ctx.candidates["C1"]["status"] == "investigating"

    ctx.value_domains["D1"]["blocking_guard_locations"] = []
    unresolved = tools["record_domain_proof"].invoke(
        {
            **proof_args,
            "producer_reaches_distinguished": False,
            "changed_branch_reaches_effect": False,
        }
    )
    assert "producer reaches distinguished value" in unresolved
    assert "changed branch reaches effect" not in unresolved
    assert "read_domain_proof_refinement" in unresolved
    assert ctx.candidates["C1"]["status"] == "investigating"
    assert ctx.candidates["C1"]["next_check"] == (
        "Resolve: producer reaches distinguished value."
    )
    assert ctx.domain_proof_obligations["D1"] == ["producer_reaches_distinguished"]

    ctx.require_validated_candidate_before_finding = True
    reporting = {tool.name: tool for tool in build_reporting_tools(ctx)}
    rejected = reporting["record_finding"].invoke(
        {
            "candidate_id": "C1",
            "file": "src/target.c",
            "line_number": 12,
            "finding_type": "memory_safety",
            "severity": "high",
            "description": "Unresolved candidate must not escape.",
            "evidence_level": "static_corroboration",
        }
    )
    assert "already marked validated" in rejected


def test_state_interaction_gate_sequence_can_reach_candidate(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    source.parent.mkdir()
    source.write_text(
        """
        void reset(State *s) { memset(s->slots, -1, sizeof(s->slots)); }
        void update(State *s, int i) { s->slots[i] = s->generation; }
        int check(State *s, int i) { return s->slots[i] == 0xFFFF; }
        """,
        encoding="utf-8",
    )
    candidate_arguments = {
        "candidate_id": "C1",
        "status": "investigating",
        "file": "src/target.c",
        "line": 2,
        "hypothesis": "slots may store a generation that aliases reserved state",
        "attacker_control": "number of updates",
        "invariant": "live generation differs from the reserved value",
        "effect": "state validation bypass",
        "counterargument": "generation may be range limited",
        "next_check": "inspect whether generation can equal the -1 distinguished value",
        "evidence": "different representations share a comparison",
    }
    calls = [
        ToolCall("rank", "rank_source_windows", '{"path":"src/target.c"}'),
        ToolCall("w1", "read_ranked_window", '{"window_id":"W1"}'),
        ToolCall("packet", "read_state_interactions", '{"window_id":"W1"}'),
        ToolCall(
            "domain",
            "record_value_domain",
            json.dumps(
                {
                    "domain_id": "D1",
                    "guard": "none observed",
                    "assessment": "overlap_possible",
                    "evidence": "src/target.c:2 and src/target.c:3",
                    "next_check": "inspect whether generation can equal the -1 value",
                }
            ),
        ),
        ToolCall(
            "consequence_packet",
            "read_domain_consequences",
            '{"domain_id":"D1"}',
        ),
        ToolCall(
            "consequence",
            "record_domain_consequence",
            json.dumps(
                {
                    "domain_id": "D1",
                    "branch_effect": "reserved-state branch accepts a live generation",
                    "state_effect": "neighbor state is misclassified",
                    "security_effect": "unsafe state may reach a memory access",
                    "assessment": "security_effect_possible",
                    "evidence": "src/target.c:2 and src/target.c:3",
                    "next_check": "trace the changed branch to its first memory effect",
                }
            ),
        ),
        ToolCall("candidate", "record_candidate", json.dumps(candidate_arguments)),
        ToolCall(
            "candidate-drift",
            "record_candidate",
            json.dumps(
                {
                    **candidate_arguments,
                    "hypothesis": "slots allocation may be too small for generation writes",
                    "invariant": "slots allocation covers generation indexes",
                    "next_check": "inspect the allocation-size calculation",
                }
            ),
        ),
    ]

    class StubLLM:
        model_name = "stub"

        def __init__(self):
            self.index = 0

        async def achat(self, **_: object):
            class Response:
                first_text = ""
                texts = []
                reasoning_content = None
                provider_model_name = "stub"

                def __init__(self, tool_calls):
                    self.tool_calls = tool_calls
                    self.usage = Usage(prompt_tokens=10, completion_tokens=2, total_tokens=12)

            if self.index < len(calls):
                call = calls[self.index]
                self.index += 1
                return Response([call])
            response = Response([])
            response.first_text = "done"
            response.texts = ["done"]
            return response

    hunter, ctx = build_hunter_agent(
        file_target=_target("src/target.c"),
        repo_path=str(tmp_path),
        sandbox=None,
        llm=StubLLM(),
        session_id="state-interaction-sequence",
        prompt_bundle="generic-security-v1",
        scaffold_profile="state-interaction-ledger-v1",
        context_profile="compact-small-model-v1",
        max_steps_override=9,
        input_price_per_million=0.0,
        output_price_per_million=0.0,
    )
    ctx.trajectory_dir = tmp_path / "trajectory"

    result = asyncio.run(hunter.arun())

    assert result.stop_reason == "completed"
    assert ctx.source_windows_read == {"W1"}
    assert ctx.state_packets_read == {"W1"}
    assert ctx.value_domains["D1"]["assessment"] == "overlap_possible"
    assert ctx.domain_consequences["D1"]["assessment"] == "security_effect_possible"
    assert ctx.candidates["C1"]["status"] == "investigating"
    assert ctx.candidates["C1"]["hypothesis"] == candidate_arguments["hypothesis"]


def test_guided_window_gate_sequence_can_reach_candidate(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    source.parent.mkdir()
    lines = ["int harmless = 0;" for _ in range(240)]
    lines[20] = "memcpy(dst, input, input_len);"
    lines[110] = "state->generation = ++global_generation;"
    lines[200] = "if (index >= count) return -1;"
    source.write_text("\n".join(lines), encoding="utf-8")

    candidate_arguments = {
        "candidate_id": "C1",
        "status": "investigating",
        "file": "src/target.c",
        "line": 21,
        "hypothesis": "copy length may exceed the destination",
        "attacker_control": "input_len",
        "invariant": "copy fits",
        "effect": "out-of-bounds write",
        "counterargument": "a caller may cap input_len",
        "next_check": "inspect callers",
        "evidence": "copy uses external length",
    }
    calls = [
        ToolCall("rank", "rank_source_windows", '{"path":"src/target.c"}'),
        ToolCall("w1", "read_ranked_window", '{"window_id":"W1"}'),
        ToolCall("w2", "read_ranked_window", '{"window_id":"W2"}'),
        ToolCall("w3", "read_ranked_window", '{"window_id":"W3"}'),
        ToolCall("candidate", "record_candidate", json.dumps(candidate_arguments)),
    ]

    class StubLLM:
        model_name = "stub"

        def __init__(self):
            self.index = 0

        async def achat(self, **_: object):
            class Response:
                first_text = ""
                texts = []
                reasoning_content = None
                provider_model_name = "stub"

                def __init__(self, tool_calls):
                    self.tool_calls = tool_calls
                    self.usage = Usage(
                        prompt_tokens=10,
                        completion_tokens=2,
                        total_tokens=12,
                    )

            if self.index < len(calls):
                call = calls[self.index]
                self.index += 1
                return Response([call])
            response = Response([])
            response.first_text = "done"
            response.texts = ["done"]
            return response

    hunter, ctx = build_hunter_agent(
        file_target=_target("src/target.c"),
        repo_path=str(tmp_path),
        sandbox=None,
        llm=StubLLM(),
        session_id="guided-sequence",
        prompt_bundle="generic-security-v1",
        scaffold_profile="guided-window-ledger-v1",
        context_profile="compact-small-model-v1",
        max_steps_override=6,
        input_price_per_million=0.0,
        output_price_per_million=0.0,
    )
    ctx.trajectory_dir = tmp_path / "trajectory"

    result = asyncio.run(hunter.arun())

    assert result.stop_reason == "completed"
    assert ctx.source_windows_read == {"W1", "W2", "W3"}
    assert ctx.candidates["C1"]["status"] == "investigating"


def test_compact_context_reduces_static_payload_and_clips_tool_results() -> None:
    legacy, _ = build_hunter_agent(
        file_target=_target("src/codec_a.c"),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="legacy-context",
        prompt_bundle="generic-security-v1",
        scaffold_profile="window-ledger-v1",
        context_profile="legacy-context-v1",
    )
    compact, _ = build_hunter_agent(
        file_target=_target("src/codec_a.c"),
        repo_path=str(Path("tests/fixtures/vuln_samples/c_propagation")),
        sandbox=None,
        llm=MagicMock(),
        session_id="compact-context",
        prompt_bundle="generic-security-v1",
        scaffold_profile="window-ledger-v1",
        context_profile="compact-small-model-v1",
    )
    initial = [ChatMessage("user", "Hunt.")]
    manifest = GroundTruthManifest.load("evaluations/sourcehunt_ground_truth.yaml")

    assert compact.context_manager is not None
    assert compact.summarizer is None
    assert compact.tool_result_chars == 3_500
    assert estimate_request_tokens(
        initial, system=compact.prompt, tools=compact.tools
    ) < estimate_request_tokens(initial, system=legacy.prompt, tools=legacy.tools)
    assert len(compact._tool_output_text("read_source_file", {}, "x" * 10_000)) < 3_600
    require_generic_prompt(compact.prompt, manifest=manifest)


def test_compaction_preserves_durable_state_and_complete_protocol_groups() -> None:
    ctx = HunterContext(repo_path="/repo", file_path="src/parser.c")
    ctx.source_windows_ranked = True
    ctx.candidates = {
        "C1": {
            "candidate_id": "C1",
            "status": "investigating",
            "file": "src/parser.c",
            "line": 42,
            "hypothesis": "length may exceed allocation",
            "attacker_control": "packet length",
            "invariant": "copy fits",
            "effect": "out-of-bounds write",
            "counterargument": "caller may cap length",
            "next_check": "inspect caller cap",
            "evidence": "different size expressions",
        },
        "C0": {
            "candidate_id": "C0",
            "status": "rejected",
            "file": "src/parser.c",
            "line": 12,
            "hypothesis": "signed index",
            "counterargument": "range check dominates",
            "evidence": "all callers reject negatives",
            "next_check": "",
        },
    }
    ctx.trace_steps = [
        {
            "file": "src/parser.c",
            "line": 42,
            "function": "parse",
            "code_snippet": "copy(dst, src, len);",
            "note": "sink reached from input",
        }
    ]
    profile = get_context_profile("compact-small-model-v1")
    manager = SourceHuntContextManager(profile, ctx)
    messages = [ChatMessage("user", "Hunt for vulnerabilities.")]
    for index in range(8):
        call = ToolCall(f"call_{index}", "read_source_file", '{"path":"src/parser.c"}')
        messages.extend(
            [
                ChatMessage("assistant", "checking", tool_calls=[call]),
                ChatMessage("tool", "source\n" + "x" * 5_000, tool_response_call_id=call.call_id),
            ]
        )

    result = manager.compact(messages, system="short", tools=[])
    roles = [message.role for message in result.messages]
    checkpoint = next(message.content for message in result.messages if message.role == "system")

    assert result.after_tokens < result.before_tokens
    assert result.after_tokens <= profile.compact_to_tokens
    assert roles[:2] == ["user", "system"]
    assert roles[2:] == ["assistant", "tool", "assistant", "tool", "assistant", "tool"]
    assert "length may exceed allocation" in checkpoint
    assert "caller may cap length" in checkpoint
    assert "all callers reject negatives" in checkpoint
    assert "sink reached from input" in checkpoint


def test_unknown_profile_names_fail_closed() -> None:
    with pytest.raises(ValueError, match="Unknown prompt bundle"):
        get_prompt_bundle("unknown")
    with pytest.raises(ValueError, match="Unknown scaffold profile"):
        get_scaffold_profile("unknown")
    with pytest.raises(ValueError, match="Unknown context profile"):
        get_context_profile("unknown")
