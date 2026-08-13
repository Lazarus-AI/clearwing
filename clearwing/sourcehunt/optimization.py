"""Versioned, leakage-safe prompt and scaffold profiles for SourceHunt.

The optimization campaign treats prompts and agent topology as independent
variables.  This module keeps those variables explicit and provides a linter
for rejecting candidates that contain benchmark answers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

GENERIC_PROMPT_HEADER = """You are conducting a blind source-code security audit.

Project: {project_name}
Starting file: {file_path}
Language: {language}
Tags: {tags}
{seed_context_block}
"""


GENERIC_PROMPT_HEADER_COMPACT = """Blind source-code security audit.
Target: {file_path} ({language}; {tags})
{seed_context_block}
"""


GENERIC_INSTRUCTIONS_V1 = """Goal: find as many distinct, real, attacker-reachable vulnerabilities as possible.
Do not assume the target contains a bug, do not invent evidence, and do not report
the same root cause more than once.

Use this investigation loop:
1. ORIENT: read a narrow source window and identify external inputs, state, guards,
   allocations, lifetimes, and security-sensitive effects.
2. CANDIDATES: maintain a short queue of concrete hypotheses. For each, track the
   attacker-controlled value or event, violated invariant, reachable effect, and
   the strongest fact that might disprove it.
3. INVESTIGATE: choose the highest-value unresolved candidate. Follow callers,
   callees, definitions, and relevant state transitions with narrow reads/searches.
4. CHALLENGE: actively try to falsify the candidate. Check dominating validation,
   type/range limits, ownership and lifetime rules, error paths, configuration,
   reachability, and whether the supposed sink is actually security-relevant.
5. SUBMIT: when the entry-to-effect mechanism survives challenge, record its exact
   trace and submit it with the strongest evidence available. Then continue hunting
   for independent root causes until the budget is exhausted.

Prefer mechanisms over surface patterns. A suspicious API call is not a finding
without a reachable violating input and a security consequence. Dynamic evidence is
valuable but not mandatory when the source establishes the complete mechanism.
"""


GENERIC_INSTRUCTIONS_COMPACT_V1 = """Find distinct, real, attacker-reachable vulnerabilities; never invent evidence.
Read narrowly. Keep 1-3 concrete candidates: attacker control, violated invariant,
security effect, strongest counterargument, and one next check. Follow only the best
candidate through callers/callees and state transitions. Try to disprove it with
guards, bounds, ownership, lifetime, configuration, and reachability. Submit an
exact entry-to-effect trace only when it survives; then continue with independent
root causes. Suspicious APIs alone are not findings.
"""


GENERIC_DISCOVERY_V1 = GENERIC_PROMPT_HEADER + GENERIC_INSTRUCTIONS_V1


MINIMAL_LINEAR_INSTRUCTIONS = """Scaffold protocol:
- Keep the interaction linear: READ -> CANDIDATES -> INVESTIGATE -> CHALLENGE -> SUBMIT.
- Use the smallest useful source window or search result; expand only to resolve a
  named uncertainty.
- Keep candidate state in your reasoning instead of producing long progress essays.
- Before submitting, state the best counterargument and resolve it with source or
  runtime evidence.
- A submission must identify an attacker-controlled entry, violated invariant,
  reachable security effect, and exact supporting trace.
"""


MINIMAL_LINEAR_COMPACT_INSTRUCTIONS = """Protocol: READ -> CANDIDATES -> INVESTIGATE -> CHALLENGE -> SUBMIT.
Use narrow reads, expand only to answer a named uncertainty, and resolve the best
counterargument before submitting an exact attacker-entry-to-effect trace.
"""


CANDIDATE_LEDGER_INSTRUCTIONS = """Scaffold protocol:
- Use narrow READ and search actions. Do not sweep the file sequentially.
- Within the first two source actions, call record_candidate for one to three
  concrete hypotheses. If no strong candidate exists yet, record the best weak
  hypothesis and the exact search that would strengthen or reject it.
- Before each additional source action, select one candidate and resolve only its
  next_check. Update that candidate immediately after learning new evidence.
- Reject candidates aggressively when a guard or invariant disproves them. Replace
  rejected candidates with new hypotheses instead of continuing the same search.
- Validate the best surviving candidate, record its exact trace, submit it, and then
  continue with the remaining queue for independent root causes.
"""


CANDIDATE_LEDGER_COMPACT_INSTRUCTIONS = """Protocol: use narrow reads. Within two source actions, record 1-3 concrete
candidates. Resolve one candidate's next_check at a time; update or reject it
immediately. Persist an exact entry-to-effect trace before submitting, then seek
independent root causes.
"""


WINDOW_LEDGER_INSTRUCTIONS = """Scaffold protocol:
- Start by calling rank_source_windows on the assigned file. Treat its output only
  as a reading plan, never as vulnerability evidence.
- Read a small, diverse set of ranked windows before committing to a hypothesis;
  include representation/state, input-boundary, and effect/lifetime signals when
  available instead of selecting only familiar unsafe APIs.
- Use record_candidate to maintain concrete hypotheses and their strongest
  counterarguments. Resolve one narrow next_check at a time and reject aggressively.
- Validate the best surviving candidate, record an exact entry-to-effect trace,
  submit it, then continue with independent candidates.
"""


WINDOW_LEDGER_COMPACT_INSTRUCTIONS = """Protocol: call rank_source_windows first; it is only a reading plan. Inspect a
few signal-diverse narrow windows, then maintain 1-3 candidates with a strongest
counterargument and one next_check. Update or reject after each check. Persist an
exact entry-to-effect trace before submitting, then seek independent root causes.
"""


GUIDED_WINDOW_LEDGER_INSTRUCTIONS = """Protocol:
- Call rank_source_windows once, then read W1 with read_ranked_window.
- Before forming a candidate, read two more windows with different signal mixes.
- The anchors are only a reading plan. Compare the three mechanisms; do not commit
  to the first familiar pattern.
- Maintain 1-3 candidates. Resolve one next_check, then update or reject it.
- After compaction, obey the durable checkpoint's continuation; never rerank.
- Persist an exact entry-to-effect trace before submitting, then seek independent
root causes.
"""


STATE_INTERACTION_LEDGER_INSTRUCTIONS = """Protocol:
- Call rank_source_windows once, read W1, then call read_state_interactions(W1).
- The packet is only orientation. Call record_value_domain once using packet lines
  to decide whether producer and distinguished stored domains overlap. Treat them
  as overlapping unless a source-backed dominating guard excludes the value.
- If overlap is possible, call read_domain_consequences then
  record_domain_consequence before the first candidate. Form that candidate from
  the stored-state/producer interaction and its changed consumer branch.
- Resolve one next_check, then update or reject it. Do not rerank or sweep.
- Keep every update tied to the distinguished value. After source checks, call
  record_domain_proof. If it validates and seeds the exact trace, submit with
  candidate_id and static corroboration or stronger evidence.
"""


@dataclass(frozen=True)
class PromptBundle:
    """One immutable prompt candidate used as an optimization unit."""

    name: str
    discovery_template: str | None
    allow_solution_heuristics: bool
    allow_historical_context: bool

    @property
    def is_generic(self) -> bool:
        return self.discovery_template is not None


@dataclass(frozen=True)
class ScaffoldProfile:
    """Tool surface and control instructions independent of prompt wording."""

    name: str
    instructions: str = ""
    compact_instructions: str = ""
    constrained_tools: frozenset[str] | None = None
    deep_tools: frozenset[str] | None = None
    candidate_gate_after_source_actions: int = 0
    require_source_windows: bool = False
    ranked_windows_before_candidate: int = 0
    state_packets_before_candidate: int = 0
    value_domains_before_candidate: int = 0
    require_validated_candidate_before_finding: bool = False
    require_active_candidate_before_finding: bool = False
    enable_domain_proof_refinement: bool = False
    closing_steps: int = 0
    initial_source_action_retries: int = 0

    def tool_names(self, agent_mode: str) -> frozenset[str] | None:
        return self.deep_tools if agent_mode == "deep" else self.constrained_tools


@dataclass(frozen=True)
class ContextProfile:
    """Versioned request-context assembly policy for one hunter."""

    name: str
    strategy: str = "legacy"
    compact_at_tokens: int = 150_000
    compact_to_tokens: int = 120_000
    recent_protocol_groups: int = 3
    checkpoint_chars: int = 6_000
    tool_result_chars: int = 0
    compact_static_instructions: bool = False
    compact_tool_specs: bool = False


PROMPT_BUNDLES: dict[str, PromptBundle] = {
    "legacy-v1": PromptBundle(
        name="legacy-v1",
        discovery_template=None,
        allow_solution_heuristics=True,
        allow_historical_context=True,
    ),
    "generic-security-v1": PromptBundle(
        name="generic-security-v1",
        discovery_template=GENERIC_DISCOVERY_V1,
        allow_solution_heuristics=False,
        allow_historical_context=False,
    ),
}


SCAFFOLD_PROFILES: dict[str, ScaffoldProfile] = {
    "native-v1": ScaffoldProfile(name="native-v1"),
    "minimal-linear-v1": ScaffoldProfile(
        name="minimal-linear-v1",
        instructions=MINIMAL_LINEAR_INSTRUCTIONS,
        compact_instructions=MINIMAL_LINEAR_COMPACT_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "read_source_file",
                "grep_source",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "execute",
                "read_file",
                "record_trace_step",
                "record_finding",
            }
        ),
    ),
    "candidate-ledger-v1": ScaffoldProfile(
        name="candidate-ledger-v1",
        instructions=CANDIDATE_LEDGER_INSTRUCTIONS,
        compact_instructions=CANDIDATE_LEDGER_COMPACT_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
    ),
    "candidate-ledger-closure-v1": ScaffoldProfile(
        name="candidate-ledger-closure-v1",
        instructions=CANDIDATE_LEDGER_INSTRUCTIONS,
        compact_instructions=CANDIDATE_LEDGER_COMPACT_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
        closing_steps=3,
    ),
    "candidate-ledger-source-retry-v1": ScaffoldProfile(
        name="candidate-ledger-source-retry-v1",
        instructions=CANDIDATE_LEDGER_INSTRUCTIONS,
        compact_instructions=CANDIDATE_LEDGER_COMPACT_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
        initial_source_action_retries=1,
    ),
    "candidate-ledger-source-retry-active-v1": ScaffoldProfile(
        name="candidate-ledger-source-retry-active-v1",
        instructions=CANDIDATE_LEDGER_INSTRUCTIONS,
        compact_instructions=CANDIDATE_LEDGER_COMPACT_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
        initial_source_action_retries=1,
        require_active_candidate_before_finding=True,
    ),
    "window-ledger-v1": ScaffoldProfile(
        name="window-ledger-v1",
        instructions=WINDOW_LEDGER_INSTRUCTIONS,
        compact_instructions=WINDOW_LEDGER_COMPACT_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "rank_source_windows",
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "rank_source_windows",
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
        require_source_windows=True,
    ),
    "guided-window-ledger-v1": ScaffoldProfile(
        name="guided-window-ledger-v1",
        instructions=GUIDED_WINDOW_LEDGER_INSTRUCTIONS,
        compact_instructions=GUIDED_WINDOW_LEDGER_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "rank_source_windows",
                "read_ranked_window",
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "rank_source_windows",
                "read_ranked_window",
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=3,
        require_source_windows=True,
        ranked_windows_before_candidate=3,
    ),
    "state-interaction-ledger-v1": ScaffoldProfile(
        name="state-interaction-ledger-v1",
        instructions=STATE_INTERACTION_LEDGER_INSTRUCTIONS,
        compact_instructions=STATE_INTERACTION_LEDGER_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
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
        ),
        deep_tools=frozenset(
            {
                "rank_source_windows",
                "read_ranked_window",
                "read_state_interactions",
                "read_domain_consequences",
                "record_value_domain",
                "record_domain_consequence",
                "record_domain_proof",
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
        require_source_windows=True,
        ranked_windows_before_candidate=1,
        state_packets_before_candidate=1,
        value_domains_before_candidate=1,
        require_validated_candidate_before_finding=True,
    ),
    "proof-refinement-ledger-v1": ScaffoldProfile(
        name="proof-refinement-ledger-v1",
        instructions=STATE_INTERACTION_LEDGER_INSTRUCTIONS,
        compact_instructions=STATE_INTERACTION_LEDGER_INSTRUCTIONS,
        constrained_tools=frozenset(
            {
                "rank_source_windows",
                "read_ranked_window",
                "read_state_interactions",
                "read_domain_consequences",
                "read_domain_proof_refinement",
                "record_value_domain",
                "record_domain_consequence",
                "record_domain_proof",
                "read_source_file",
                "grep_source",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        deep_tools=frozenset(
            {
                "rank_source_windows",
                "read_ranked_window",
                "read_state_interactions",
                "read_domain_consequences",
                "read_domain_proof_refinement",
                "record_value_domain",
                "record_domain_consequence",
                "record_domain_proof",
                "execute",
                "read_file",
                "record_candidate",
                "record_trace_step",
                "record_finding",
            }
        ),
        candidate_gate_after_source_actions=2,
        require_source_windows=True,
        ranked_windows_before_candidate=1,
        state_packets_before_candidate=1,
        value_domains_before_candidate=1,
        require_validated_candidate_before_finding=True,
        enable_domain_proof_refinement=True,
    ),
}


CONTEXT_PROFILES: dict[str, ContextProfile] = {
    "legacy-context-v1": ContextProfile(name="legacy-context-v1"),
    "compact-small-model-v1": ContextProfile(
        name="compact-small-model-v1",
        strategy="deterministic-checkpoint",
        compact_at_tokens=12_000,
        compact_to_tokens=8_000,
        recent_protocol_groups=3,
        checkpoint_chars=6_000,
        tool_result_chars=3_500,
        compact_static_instructions=True,
        compact_tool_specs=True,
    ),
}


def get_prompt_bundle(name: str) -> PromptBundle:
    try:
        return PROMPT_BUNDLES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(PROMPT_BUNDLES))
        raise ValueError(f"Unknown prompt bundle {name!r}; choose one of: {choices}") from exc


def get_scaffold_profile(name: str) -> ScaffoldProfile:
    try:
        return SCAFFOLD_PROFILES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(SCAFFOLD_PROFILES))
        raise ValueError(f"Unknown scaffold profile {name!r}; choose one of: {choices}") from exc


def get_context_profile(name: str) -> ContextProfile:
    try:
        return CONTEXT_PROFILES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(CONTEXT_PROFILES))
        raise ValueError(f"Unknown context profile {name!r}; choose one of: {choices}") from exc


@dataclass(frozen=True)
class PromptLeakage:
    category: str
    value: str


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_COMMIT_RE = re.compile(r"(?<![0-9a-f])\b[0-9a-f]{12,40}\b(?![0-9a-f])", re.IGNORECASE)


def _case_value(case: Any, name: str, default: Any = None) -> Any:
    return case.get(name, default) if isinstance(case, dict) else getattr(case, name, default)


def _distinctive_symbol(value: str) -> bool:
    return len(value) >= 4 or any(marker in value for marker in ("_", ".", "::", "/"))


def manifest_forbidden_terms(manifest: Any) -> dict[str, set[str]]:
    """Extract answer-bearing terms without importing the evaluator models."""

    cases = _case_value(manifest, "cases", []) or []
    terms: dict[str, set[str]] = {
        "case_id": set(),
        "repository": set(),
        "cve": set(),
        "commit": set(),
        "target_file": set(),
        "target_symbol": set(),
        "solution_phrase": set(),
        "mechanism": set(),
        "expected_cwe": set(),
    }
    for case in cases:
        case_id = str(_case_value(case, "id", "")).strip()
        if case_id:
            terms["case_id"].add(case_id)
        repository = str(_case_value(case, "repository", "")).strip()
        if repository:
            terms["repository"].add(repository)
            repository_name = repository.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            if len(repository_name) >= 4:
                terms["repository"].add(repository_name)
        terms["cve"].update(str(value) for value in (_case_value(case, "cves", []) or []))
        for field in ("vulnerable_commit", "fixed_commit"):
            value = str(_case_value(case, field, "") or "").strip()
            if value:
                terms["commit"].add(value)

        truth = _case_value(case, "ground_truth", {}) or {}
        terms["target_file"].update(
            str(value) for value in (_case_value(truth, "target_files", []) or [])
        )
        for field in ("target_functions", "expected_fact_symbols"):
            for raw in _case_value(truth, field, []) or []:
                value = str(raw).strip()
                if value and _distinctive_symbol(value):
                    terms["target_symbol"].add(value)
        for step in _case_value(truth, "trace", []) or []:
            value = str(_case_value(step, "symbol", "")).strip()
            if value and _distinctive_symbol(value):
                terms["target_symbol"].add(value)
        for field in (
            "entry_points",
            "sources",
            "sinks",
            "transformations",
            "invariants",
            "guards",
            "trigger_constraints",
            "reproduction_behavior",
            "expected_proof_plans",
            "expected_predicates",
            "expected_evidence_kinds",
        ):
            terms["solution_phrase"].update(
                str(value) for value in (_case_value(truth, field, []) or [])
            )
        threat = _case_value(truth, "threat_model", {}) or {}
        for field in (
            "attacker_principal",
            "attacker_capabilities",
            "trust_boundary",
            "protected_asset",
            "capability_gained",
            "security_property_violated",
            "deployment_assumptions",
        ):
            raw = _case_value(threat, field, "")
            values = raw if isinstance(raw, list) else [raw]
            terms["solution_phrase"].update(str(value) for value in values)
        terms["mechanism"].update(
            str(value) for value in (_case_value(truth, "expected_mechanisms", []) or [])
        )
        terms["expected_cwe"].update(
            str(value) for value in (_case_value(truth, "expected_cwes", []) or [])
        )
    return terms


def lint_prompt_candidate(
    candidate: str,
    *,
    manifest: Any | None = None,
    forbidden_terms: dict[str, Iterable[str]] | None = None,
) -> list[PromptLeakage]:
    """Return every benchmark-answer leak in a proposed generic prompt."""

    leaks: set[PromptLeakage] = set()
    for match in _CVE_RE.finditer(candidate):
        leaks.add(PromptLeakage("cve", match.group(0)))
    for match in _COMMIT_RE.finditer(candidate):
        leaks.add(PromptLeakage("commit", match.group(0)))

    terms: dict[str, set[str]] = {}
    if manifest is not None:
        terms.update(manifest_forbidden_terms(manifest))
    if forbidden_terms:
        for category, values in forbidden_terms.items():
            terms.setdefault(category, set()).update(str(value) for value in values)

    normalized = candidate.casefold()
    for category, values in terms.items():
        for raw in values:
            value = raw.strip()
            if value and value.casefold() in normalized:
                leaks.add(PromptLeakage(category, value))
    return sorted(leaks, key=lambda item: (item.category, item.value.casefold()))


def require_generic_prompt(
    candidate: str,
    *,
    manifest: Any | None = None,
    forbidden_terms: dict[str, Iterable[str]] | None = None,
) -> None:
    leaks = lint_prompt_candidate(
        candidate,
        manifest=manifest,
        forbidden_terms=forbidden_terms,
    )
    if not leaks:
        return
    preview = ", ".join(f"{item.category}={item.value!r}" for item in leaks[:8])
    suffix = f" (+{len(leaks) - 8} more)" if len(leaks) > 8 else ""
    raise ValueError(f"Prompt candidate leaks benchmark answers: {preview}{suffix}")


def redact_benchmark_terms(text: str, manifest: Any) -> str:
    """Remove answer-bearing strings before trajectories reach a reflection LM."""

    redacted = _CVE_RE.sub("[case-specific-cve]", text)
    redacted = _COMMIT_RE.sub("[case-specific-commit]", redacted)
    terms = manifest_forbidden_terms(manifest)
    values = {
        value.strip()
        for category_values in terms.values()
        for value in category_values
        if value.strip()
    }
    for value in sorted(values, key=len, reverse=True):
        redacted = re.sub(re.escape(value), "[case-specific]", redacted, flags=re.IGNORECASE)
    return redacted


__all__ = [
    "CONTEXT_PROFILES",
    "GENERIC_DISCOVERY_V1",
    "GENERIC_INSTRUCTIONS_V1",
    "GENERIC_INSTRUCTIONS_COMPACT_V1",
    "GENERIC_PROMPT_HEADER",
    "PROMPT_BUNDLES",
    "SCAFFOLD_PROFILES",
    "ContextProfile",
    "PromptBundle",
    "PromptLeakage",
    "ScaffoldProfile",
    "get_prompt_bundle",
    "get_scaffold_profile",
    "get_context_profile",
    "lint_prompt_candidate",
    "manifest_forbidden_terms",
    "redact_benchmark_terms",
    "require_generic_prompt",
]
