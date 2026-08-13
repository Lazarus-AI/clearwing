"""Small-model candidate ledger for explicit hypothesis state."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import Field

from clearwing.findings.types import TraceStep
from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext


def _mentions_identifier(text: str, identifier: str) -> bool:
    return bool(re.search(rf"(?<!\w){re.escape(identifier)}(?!\w)", text, re.IGNORECASE))


def candidate_matches_domain(text: str, domain: dict) -> bool:
    """Return whether candidate prose stays tied to an extracted value domain.

    Extraction can legitimately leave a producer as ``unknown`` and can find
    no distinguished literal. Those placeholders are not evidence and must
    not become magic words that a hunter is forced to repeat.
    """

    normalized = text.casefold()
    placeholders = {"", "none", "unknown", "unresolved"}
    stored_state = str(domain.get("stored_state", "")).strip().casefold()
    if stored_state in placeholders or not _mentions_identifier(normalized, stored_state):
        return False

    producer_names = {
        str(value).strip().casefold()
        for value in (
            domain.get("producer_state", ""),
            *domain.get("producer_tokens", []),
        )
        if str(value).strip().casefold() not in placeholders
    }
    if producer_names and not any(
        _mentions_identifier(normalized, name) for name in producer_names
    ):
        return False

    distinguished_values = {
        str(value).strip().casefold()
        for value in domain.get("distinguished_tokens", [])
        if str(value).strip()
    }
    if distinguished_values and not any(
        value in normalized
        for value in distinguished_values | {"reserved", "sentinel", "distinguished"}
    ):
        return False
    return True


def _mentions_location(text: str, location: str) -> bool:
    path, _separator, line = location.rpartition(":")
    short_location = f"{Path(path).name}:{line}"
    return (
        location.casefold() in text
        or short_location.casefold() in text
        or bool(re.search(rf"\bline\s+{re.escape(line)}\b", text))
    )


def _domain_closure_error(
    plan: dict,
    *,
    guard: str,
    assessment: str,
    evidence: str,
) -> str | None:
    if assessment not in {"overlap_blocked", "disjoint"}:
        return None
    if guard.casefold() == "none observed":
        return (
            f"ERROR: {assessment} requires a source-backed dominating guard on the producer "
            "value. Record overlap_possible or unresolved instead."
        )
    producer_tokens = [
        str(token)
        for token in plan.get("producer_tokens", [plan.get("producer_state", "")])
        if token
    ]
    if not any(_mentions_identifier(guard, token) for token in producer_tokens):
        choices = ", ".join(producer_tokens) or "an extracted producer"
        return (
            f"ERROR: {assessment} guard must constrain the extracted producer chain "
            f"({choices}); unrelated allocation or index bounds do not separate value domains. "
            "Record overlap_possible or unresolved instead."
        )
    blocking_locations = [
        str(location) for location in plan.get("blocking_guard_locations", []) if location
    ]
    closure_text = f"{guard} {evidence}".casefold()
    location_matched = any(
        _mentions_location(closure_text, location) for location in blocking_locations
    )
    if not blocking_locations or not location_matched:
        choices = ", ".join(blocking_locations) or "none extracted"
        return (
            f"ERROR: {assessment} requires an extracted source guard that blocks the producer "
            f"before transfer ({choices}). Resets, resource estimates, and practical-impossibility "
            "claims do not prove disjoint value domains."
        )
    distinguished_tokens = [str(token) for token in plan.get("distinguished_tokens", []) if token]
    if distinguished_tokens and not any(
        token.casefold() in evidence.casefold() for token in distinguished_tokens
    ):
        choices = ", ".join(distinguished_tokens)
        return (
            f"ERROR: {assessment} evidence must show how the producer guard excludes a "
            f"distinguished stored value ({choices})."
        )
    return None


def _domain_next_check(ctx: HunterContext, domain_id: str, domain: dict) -> str:
    producer = str(domain.get("producer_state", "producer"))
    if producer.casefold() in {"", "none", "unknown", "unresolved"}:
        producer = next(
            (
                str(token)
                for token in domain.get("producer_tokens", [])
                if str(token).casefold() not in {"", "none", "unknown", "unresolved"}
            ),
            "the producer",
        )
    values = "/".join(str(value) for value in domain.get("distinguished_tokens", []) if value)
    values = values or "the distinguished value"
    guards = ", ".join(
        str(location) for location in domain.get("blocking_guard_locations", []) if location
    )
    consequence = ctx.domain_consequence_plans.get(domain_id, {})
    impacts = "/".join(str(token) for token in consequence.get("impact_tokens", [])[:2] if token)
    locations = ", ".join(
        str(location) for location in consequence.get("impact_locations", [])[:2] if location
    )
    boundary_facts = consequence.get("boundary_facts", [])
    guard_check = (
        f"verify whether the terminating guard at {guards} excludes it"
        if guards
        else "verify that no terminating producer guard excludes it"
    )
    if boundary_facts:
        fact = boundary_facts[0]
        impact_check = (
            f"then test whether the changed predicate can be true when {fact['token']} is at its "
            f"lower bound, allowing [{fact['expression']}] to reach {impacts or 'the memory effect'} "
            f"at {locations} without a dominating positive-bound guard"
        )
    elif impacts:
        impact_check = f"then follow {impacts} at {locations} to the first unsafe effect"
    else:
        impact_check = "then follow the changed consumer branch to the first unsafe effect"
    return f"Determine whether {producer} can equal {values}; {guard_check}; {impact_check}."


class RecordCandidateInput(ToolInputModel):
    candidate_id: str = Field(description="Short stable identifier, for example C1")
    status: Literal["pending", "investigating", "rejected", "validated"]
    file: str = Field(description="Repo-relative file containing the current evidence")
    line: int = Field(default=0, description="Best current 1-indexed line, or 0 if unknown")
    hypothesis: str = Field(description="Concrete vulnerability mechanism")
    attacker_control: str = Field(default="", description="Attacker-controlled input or event")
    invariant: str = Field(default="", description="Security invariant that may be violated")
    effect: str = Field(default="", description="Reachable security-sensitive effect")
    counterargument: str = Field(
        default="",
        description="Strongest guard, bound, or fact that might disprove the candidate",
    )
    next_check: str = Field(default="", description="One narrow read/search/test to resolve next")
    evidence: str = Field(default="", description="Concise evidence learned so far")


class RecordValueDomainInput(ToolInputModel):
    domain_id: str = Field(description="Opaque domain ID from read_state_interactions, for example D1")
    guard: str = Field(description="Dominating producer-value guard, or exactly 'none observed'")
    assessment: Literal["overlap_possible", "overlap_blocked", "disjoint", "unresolved"]
    evidence: str = Field(description="At least two packet locations supporting the assessment")
    next_check: str = Field(description="One narrow check that could confirm or refute it")


class RecordDomainConsequenceInput(ToolInputModel):
    domain_id: str = Field(description="Opaque domain ID from read_domain_consequences")
    branch_effect: str = Field(description="How branch behavior changes if domains overlap")
    state_effect: str = Field(description="Downstream state accepted, rejected, or misclassified")
    security_effect: str = Field(description="Potential memory, lifetime, privilege, or availability effect")
    assessment: Literal["security_effect_possible", "benign", "unresolved"]
    evidence: str = Field(description="At least two consequence-packet locations")
    next_check: str = Field(description="One narrow source or runtime check")


class RecordDomainProofInput(ToolInputModel):
    domain_id: str = Field(description="Opaque domain ID, for example D1")
    candidate_id: str = Field(description="Tracked candidate ID, for example C1")
    attacker_reaches_producer: bool
    producer_reaches_distinguished: bool
    changed_branch_reaches_effect: bool
    boundary_effect_unguarded: bool
    evidence: str = Field(description="Concise source locations supporting every true answer")
    counterevidence: str = Field(default="", description="Strongest unresolved counterevidence")


def _record_domain_proof(
    ctx: HunterContext,
    *,
    domain_id: str,
    candidate_id: str,
    attacker_reaches_producer: bool,
    producer_reaches_distinguished: bool,
    changed_branch_reaches_effect: bool,
    boundary_effect_unguarded: bool,
    evidence: str,
    counterevidence: str,
) -> str:
    normalized_id = domain_id.strip().upper()
    domain = ctx.value_domains.get(normalized_id)
    candidate = ctx.candidates.get(candidate_id)
    consequence_plan = ctx.domain_consequence_plans.get(normalized_id)
    if domain is None or consequence_plan is None:
        return f"ERROR: expand and record domain {normalized_id} before proving it."
    if candidate is None or ctx.domain_candidate_ids.get(normalized_id) != candidate_id:
        return f"ERROR: {candidate_id} is not the tracked candidate for {normalized_id}."
    if domain.get("blocking_guard_locations") and domain.get("assessment") in {
        "overlap_possible",
        "unresolved",
    }:
        locations = ", ".join(domain["blocking_guard_locations"])
        return (
            "ERROR: reassess the extracted terminating producer guard with "
            f"record_value_domain first ({locations})."
        )
    obligations = {
        "attacker_reaches_producer": attacker_reaches_producer,
        "producer_reaches_distinguished": producer_reaches_distinguished,
        "changed_branch_reaches_effect": changed_branch_reaches_effect,
        "boundary_effect_unguarded": boundary_effect_unguarded,
    }
    obligation_labels = {
        "attacker_reaches_producer": "attacker reaches producer",
        "producer_reaches_distinguished": "producer reaches distinguished value",
        "changed_branch_reaches_effect": "changed branch reaches effect",
        "boundary_effect_unguarded": "boundary effect lacks a dominating guard",
    }
    failed = [name for name, satisfied in obligations.items() if not satisfied]
    if ctx.enable_domain_proof_refinement:
        failed = failed[:1]
    ctx.domain_refinement_pending_proof.discard(normalized_id)
    if failed:
        if ctx.enable_domain_proof_refinement:
            ctx.domain_proof_obligations[normalized_id] = failed
        failed_labels = [obligation_labels[name] for name in failed]
        candidate["status"] = "investigating"
        candidate["counterargument"] = counterevidence or ", ".join(failed_labels)
        candidate["evidence"] = evidence
        candidate["next_check"] = "Resolve: " + "; ".join(failed_labels) + "."
        ctx.candidate_revision += 1
        if ctx.enable_domain_proof_refinement:
            return (
                f"Domain proof for {candidate_id} remains unresolved: "
                f"{'; '.join(failed_labels)}. Call read_domain_proof_refinement for this "
                "obligation, then call record_domain_proof again."
            )
        return (
            f"Domain proof for {candidate_id} remains unresolved: "
            f"{'; '.join(failed_labels)}. Resolve only these obligations."
        )
    if not consequence_plan.get("boundary_facts"):
        return "ERROR: no source-derived boundary effect was extracted for this domain."
    candidate["status"] = "validated"
    ctx.domain_proof_obligations.pop(normalized_id, None)
    candidate["evidence"] = evidence
    candidate["counterargument"] = counterevidence
    candidate["next_check"] = (
        "Submit this validated candidate with candidate_id, static_corroboration or stronger "
        "evidence, and the seeded trace."
    )
    ctx.domain_consequences[normalized_id] = {
        **ctx.domain_consequences.get(normalized_id, {}),
        "domain_id": normalized_id,
        "assessment": "security_effect_possible",
        "evidence": evidence,
        "next_check": candidate["next_check"],
    }
    if not ctx.trace_steps:
        trace_facts = [
            *domain.get("trace_facts", []),
            *consequence_plan.get("trace_facts", []),
        ]
        ctx.trace_steps.extend(
            TraceStep(
                file=str(fact["file"]),
                line=int(fact["line"]),
                code_snippet=str(fact["code_snippet"]),
                note=str(fact["role"]),
            )
            for fact in trace_facts
        )
    ctx.candidate_revision += 1
    return (
        f"Domain proof validated {candidate_id}; seeded {len(ctx.trace_steps)} exact trace steps. "
        "Call record_finding now with this candidate_id and "
        "evidence_level=static_corroboration or stronger."
    )


def _record_domain_consequence(
    ctx: HunterContext,
    *,
    domain_id: str,
    branch_effect: str,
    state_effect: str,
    security_effect: str,
    assessment: str,
    evidence: str,
    next_check: str,
) -> str:
    normalized_id = domain_id.strip().upper()
    plan = ctx.domain_consequence_plans.get(normalized_id)
    if plan is None:
        choices = ", ".join(ctx.domain_consequence_plans) or "none; expand a domain first"
        return f"ERROR: unknown consequence domain {domain_id!r}. Available: {choices}."
    domain = ctx.value_domains.get(normalized_id, {})
    if assessment == "benign" and domain.get("assessment") not in {
        "overlap_blocked",
        "disjoint",
    }:
        return (
            "ERROR: an overlapping producer/distinguished domain cannot be marked benign. "
            "First prove an extracted producer-blocking guard with record_value_domain, or "
            "keep this consequence unresolved while checking the branch-to-effect path."
        )
    impact_tokens = [str(token) for token in plan.get("impact_tokens", []) if token]
    if assessment == "security_effect_possible" and impact_tokens and not any(
        _mentions_identifier(next_check, token) for token in impact_tokens
    ):
        choices = ", ".join(impact_tokens)
        return (
            "ERROR: security_effect_possible next_check must follow an extracted changed "
            f"branch toward its memory effect ({choices}); do not switch to an unrelated "
            "allocation or index theory."
        )
    ctx.domain_consequences[normalized_id] = {
        "domain_id": normalized_id,
        "branch_effect": branch_effect,
        "state_effect": state_effect,
        "security_effect": security_effect,
        "assessment": assessment,
        "evidence": evidence,
        "next_check": next_check,
    }
    return (
        f"Domain consequence saved for {normalized_id}: {assessment}. "
        f"Next check: {next_check}"
    )


def build_candidate_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Build one upsert tool that echoes the complete active candidate queue."""

    def record_candidate(
        candidate_id: str,
        status: str,
        file: str,
        line: int = 0,
        hypothesis: str = "",
        attacker_control: str = "",
        invariant: str = "",
        effect: str = "",
        counterargument: str = "",
        next_check: str = "",
        evidence: str = "",
        **_: object,
    ) -> str:
        ctx.candidates[candidate_id] = {
            "candidate_id": candidate_id,
            "status": status,
            "file": file,
            "line": line,
            "hypothesis": hypothesis,
            "attacker_control": attacker_control,
            "invariant": invariant,
            "effect": effect,
            "counterargument": counterargument,
            "next_check": next_check,
            "evidence": evidence,
        }
        candidate_text = " ".join((hypothesis, invariant, evidence)).casefold()
        for domain_id, domain in ctx.value_domains.items():
            consequence = ctx.domain_consequences.get(domain_id, {})
            if consequence.get("assessment") == "benign":
                continue
            if candidate_matches_domain(candidate_text, domain):
                ctx.domain_candidate_ids[domain_id] = candidate_id
                if domain.get("assessment") in {"overlap_possible", "unresolved"}:
                    ctx.candidates[candidate_id]["next_check"] = _domain_next_check(
                        ctx,
                        domain_id,
                        domain,
                    )
        ctx.candidate_revision += 1
        active = [
            candidate
            for candidate in ctx.candidates.values()
            if candidate["status"] in {"pending", "investigating", "validated"}
        ]
        lines = [f"Candidate {candidate_id} saved. Active queue ({len(active)}):"]
        for candidate in active:
            location = candidate["file"]
            if candidate["line"]:
                location += f":{candidate['line']}"
            lines.append(
                f"- {candidate['candidate_id']} [{candidate['status']}] {location}: "
                f"{candidate['hypothesis']} | next: {candidate['next_check'] or 'unspecified'}"
            )
        return "\n".join(lines)

    def record_value_domain(
        domain_id: str,
        guard: str,
        assessment: str,
        evidence: str,
        next_check: str,
        **_: object,
    ) -> str:
        normalized_id = domain_id.strip().upper()
        plan = ctx.value_domain_plans.get(normalized_id)
        if plan is None:
            choices = ", ".join(ctx.value_domain_plans) or "none; read a state packet first"
            return f"ERROR: unknown value domain {domain_id!r}. Available: {choices}."
        normalized = str(plan["stored_state"])
        normalized_guard = guard.strip()
        closure_error = _domain_closure_error(
            plan,
            guard=normalized_guard,
            assessment=assessment,
            evidence=evidence,
        )
        if closure_error is not None:
            return closure_error
        ctx.value_domains[normalized_id] = {
            **plan,
            "domain_id": normalized_id,
            "guard": normalized_guard,
            "assessment": assessment,
            "evidence": evidence,
            "next_check": next_check,
        }
        return (
            f"Value-domain comparison saved for {normalized_id} ({normalized}): {assessment}. "
            f"Next check: {next_check}"
        )

    def record_domain_consequence(
        domain_id: str,
        branch_effect: str,
        state_effect: str,
        security_effect: str,
        assessment: str,
        evidence: str,
        next_check: str,
        **_: object,
    ) -> str:
        return _record_domain_consequence(
            ctx,
            domain_id=domain_id,
            branch_effect=branch_effect,
            state_effect=state_effect,
            security_effect=security_effect,
            assessment=assessment,
            evidence=evidence,
            next_check=next_check,
        )

    def record_domain_proof(
        domain_id: str,
        candidate_id: str,
        attacker_reaches_producer: bool,
        producer_reaches_distinguished: bool,
        changed_branch_reaches_effect: bool,
        boundary_effect_unguarded: bool,
        evidence: str,
        counterevidence: str = "",
        **_: object,
    ) -> str:
        return _record_domain_proof(
            ctx,
            domain_id=domain_id,
            candidate_id=candidate_id,
            attacker_reaches_producer=attacker_reaches_producer,
            producer_reaches_distinguished=producer_reaches_distinguished,
            changed_branch_reaches_effect=changed_branch_reaches_effect,
            boundary_effect_unguarded=boundary_effect_unguarded,
            evidence=evidence,
            counterevidence=counterevidence,
        )

    return [
        NativeToolSpec(
            name="record_candidate",
            description=(
                "Create or update one vulnerability hypothesis in the explicit candidate ledger. "
                "Use the same candidate_id to update status, counterevidence, and the next check."
            ),
            schema=RecordCandidateInput.model_json_schema(),
            handler=record_candidate,
        ),
        NativeToolSpec(
            name="record_value_domain",
            description=(
                "Compare one packet state's storage, distinguished states, producer domain, "
                "uses, and guards before selecting a vulnerability mechanism."
            ),
            schema=RecordValueDomainInput.model_json_schema(),
            handler=record_value_domain,
        ),
        NativeToolSpec(
            name="record_domain_consequence",
            description=(
                "Record whether an overlapping value domain changes a consumer branch and "
                "propagates to a security-sensitive effect."
            ),
            schema=RecordDomainConsequenceInput.model_json_schema(),
            handler=record_domain_consequence,
        ),
        NativeToolSpec(
            name="record_domain_proof",
            description=(
                "Resolve the tracked domain candidate with four explicit proof obligations. "
                "A complete proof validates the candidate and seeds exact trace steps."
            ),
            schema=RecordDomainProofInput.model_json_schema(),
            handler=record_domain_proof,
        ),
    ]


__all__ = ["build_candidate_tools", "candidate_matches_domain"]
